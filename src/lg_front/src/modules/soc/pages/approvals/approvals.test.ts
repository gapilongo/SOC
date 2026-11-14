import { describe, expect, it } from 'vitest';

import type { QueueFigures } from '../../api/fields';
import type { ActionOut } from '../../api/types';
import type { Principal } from '../../../../auth/store';
import {
  approvalAccess,
  approvalFigures,
  approvalReasonText,
  approverLabel,
  guardrailSummary,
  readBlastRadius,
  requesterLabel,
  reversibleText,
  scopeText,
  usageLevel,
  usageText,
} from './approvals';
import { legacyActionsTarget } from './redirect';

function principal(overrides: Partial<Principal> = {}): Principal {
  return { userId: 'u-1', email: 'x@acme.test', role: 'analyst', tenantId: 'acme', homeTenantId: 'acme', isPlatformAdmin: false, method: 'password', ...overrides };
}

const analyst = principal();
const admin = principal({ role: 'admin' });
const viewer = principal({ role: 'viewer' });

describe('approval access mirrors the API', () => {
  it('analysts approve low and medium risk and reject at any risk; high and critical are locked for an admin', () => {
    expect(approvalAccess(analyst, { risk_level: 'medium' })).toEqual({ approve: true, reject: true, lock: null });
    expect(approvalAccess(analyst, { risk_level: 'high' })).toEqual({ approve: false, reject: true, lock: 'High risk needs an admin to approve.' });
    expect(approvalAccess(analyst, { risk_level: 'critical' }).lock).toBe('Critical risk needs an admin to approve.');
    expect(approvalAccess(admin, { risk_level: 'critical' })).toEqual({ approve: true, reject: true, lock: null });
  });

  it('viewers, tenant overrides and unlinked identities get neither button, with the reason', () => {
    expect(approvalAccess(viewer, { risk_level: 'low' })).toEqual({ approve: false, reject: false, lock: 'Requires the analyst role.' });
    const override = principal({ role: 'admin', isPlatformAdmin: true, tenantId: 'globex' });
    expect(approvalAccess(override, { risk_level: 'low' }).lock).toMatch(/another tenant/);
    expect(approvalAccess(principal({ userId: null }), { risk_level: 'low' }).approve).toBe(false);
    expect(approvalAccess(null, { risk_level: 'low' }).lock).toBe('Sign in first.');
  });

  it('nobody approves what the autonomy policy disables, but it can still be rejected', () => {
    const disabled = { risk_level: 'high', guardrail: { verdict: 'blocked' as const, evaluated: 'now' as const, code: 'autonomy_disabled' } };
    const access = approvalAccess(admin, disabled);
    expect(access.approve).toBe(false);
    expect(access.reject).toBe(true);
    expect(access.lock).toMatch(/autonomy policy disables/);
    // Any other guardrail block leaves approval to the human (execution checks again).
    expect(approvalAccess(admin, { ...disabled, guardrail: { ...disabled.guardrail, code: 'protected_asset' } }).approve).toBe(true);
  });

  it('an unknown risk level cannot be approved', () => {
    expect(approvalAccess(admin, { risk_level: 'extreme' })).toMatchObject({ approve: false, lock: expect.stringMatching(/Unknown risk level/) });
  });
});

describe('guardrail summary', () => {
  it('is null on an older API or a malformed value', () => {
    expect(guardrailSummary({})).toBeNull();
    expect(guardrailSummary({ guardrail: null })).toBeNull();
    expect(guardrailSummary({ guardrail: { verdict: 'maybe' } as unknown as ActionOut['guardrail'] })).toBeNull();
  });

  it('says why a human must approve when it passed', () => {
    expect(guardrailSummary({ guardrail: { verdict: 'passed', evaluated: 'now', approval_reason: 'llm_only_evidence' } })).toEqual({
      verdict: 'passed',
      label: 'Passed (checked now)',
      detail: 'Containment on evidence from the model alone is never automatic.',
    });
    expect(guardrailSummary({ guardrail: { verdict: 'passed', evaluated: 'now' } })?.detail).toMatch(/autonomy policy asks/);
    expect(approvalReasonText('new_reason_code')).toBe('New reason code');
  });

  it('explains a block from its code, adding the server reason when it says more', () => {
    const s = guardrailSummary({ guardrail: { verdict: 'blocked', evaluated: 'recorded', code: 'protected_asset', reason: 'matches a protected host entry' } });
    expect(s?.label).toBe('Blocked');
    expect(s?.detail).toBe("The target is on the tenant's protected assets list. (matches a protected host entry)");
    expect(guardrailSummary({ guardrail: { verdict: 'blocked', evaluated: 'now', reason: 'custom' } })?.detail).toBe('custom');
    expect(guardrailSummary({ guardrail: { verdict: 'blocked', evaluated: 'now' } })?.detail).toBe('A guardrail blocks it.');
  });
});

describe('blast radius', () => {
  it('reads the full shape', () => {
    const b = readBlastRadius({
      blast_radius: { target_kind: 'host', scope_hosts: ['ws-1', 'ws-2'], hourly_limit: 10, executed_last_hour: 8, tenant_hourly_cap: 50, tenant_executed_last_hour: 50 },
    });
    expect(b).toEqual({ targetKind: 'host', scopeHosts: ['ws-1', 'ws-2'], type: { used: 8, limit: 10 }, tenant: { used: 50, limit: 50 } });
    expect(usageLevel(b!.type!)).toBe('near');
    expect(usageLevel(b!.tenant!)).toBe('reached');
    expect(usageText(b!.type!)).toBe('8 of 10 in the last hour');
    expect(scopeText(b!)).toBe('2 hosts: ws-1, ws-2');
  });

  it('is null when absent, empty or malformed (older APIs), and drops bad counts', () => {
    expect(readBlastRadius({})).toBeNull();
    expect(readBlastRadius({ blast_radius: null })).toBeNull();
    expect(readBlastRadius({ blast_radius: [] as unknown as ActionOut['blast_radius'] })).toBeNull();
    expect(readBlastRadius({ blast_radius: { target_kind: null, scope_hosts: [] } })).toBeNull();
    const b = readBlastRadius({ blast_radius: { target_kind: 'ip', executed_last_hour: -1, tenant_executed_last_hour: 3, tenant_hourly_cap: null } });
    expect(b).toEqual({ targetKind: 'ip', scopeHosts: [], type: null, tenant: { used: 3, limit: null } });
    expect(usageText(b!.tenant!)).toBe('3 in the last hour (no limit)');
    expect(usageLevel(b!.tenant!)).toBe('ok');
    expect(scopeText(b!)).toBe('One ip');
  });

  it('shortens a long host list', () => {
    expect(scopeText({ targetKind: 'host', scopeHosts: ['a', 'b', 'c', 'd', 'e'], type: null, tenant: null })).toBe('5 hosts: a, b, c, +2 more');
    expect(scopeText({ targetKind: null, scopeHosts: ['a'], type: null, tenant: null })).toBe('1 host: a');
    expect(scopeText({ targetKind: null, scopeHosts: [], type: { used: 1, limit: 2 }, tenant: null })).toBeNull();
  });
});

describe('labels', () => {
  it('reversibility, null when unknown', () => {
    expect(reversibleText({ reversible: true })?.reversible).toBe(true);
    expect(reversibleText({ reversible: false, irreversible_note: 'Passwords cannot be restored.' })?.text).toBe('No. Passwords cannot be restored.');
    expect(reversibleText({ reversible: false })?.text).toBe('No, it cannot be undone.');
    expect(reversibleText({})).toBeNull();
    expect(reversibleText({ reversible: null })).toBeNull();
  });

  it('who requested and who approved', () => {
    expect(requesterLabel('agent:workflow', 'u-1')).toBe('the alert workflow');
    expect(requesterLabel(null, 'u-1')).toBe('the alert workflow');
    expect(requesterLabel('u-1', 'u-1')).toBe('you');
    expect(requesterLabel('0f6c7f4e-1111-2222', 'u-1')).toBe('0f6c7f4e...');
    expect(approverLabel(null, 'u-1')).toBeNull();
    expect(approverLabel('policy:auto', 'u-1')).toBe('Automatic (autonomy policy)');
    expect(approverLabel('u-1', 'u-1')).toBe('Approved by you');
    expect(approverLabel('u-2', 'u-1')).toBe('Approved by u-2');
  });
});

describe('header figures', () => {
  const pending = [{ risk_level: 'high' }, { risk_level: 'medium' }, { risk_level: 'medium' }];

  it("use the dashboard's queue figures when the API sends them", () => {
    const queue = { pendingMine: 4, pendingTotal: 9, pendingByRisk: { high: 5, medium: 4 } } as unknown as QueueFigures;
    expect(approvalFigures(queue, pending, analyst, false)).toEqual({ mine: 4, total: 9, byRisk: { high: 5, medium: 4 }, exact: true });
  });

  it('else count the loaded pending actions', () => {
    expect(approvalFigures(null, pending, analyst, true)).toEqual({ mine: 2, total: 3, byRisk: { high: 1, medium: 2 }, exact: true });
    expect(approvalFigures(null, pending, viewer, false)).toMatchObject({ mine: 0, exact: false });
  });
});

describe('the /actions redirect', () => {
  it('sends the old approvals link and the bare page to the pending approvals', () => {
    expect(legacyActionsTarget('')).toBe('/approvals');
    expect(legacyActionsTarget('?status=awaiting_approval')).toBe('/approvals');
  });

  it('keeps any other ledger query, in the All actions view', () => {
    expect(legacyActionsTarget('?status=failed&risk_level=high')).toBe('/approvals?view=all&status=failed&risk_level=high');
    expect(legacyActionsTarget('?view=all&verification=failed')).toBe('/approvals?view=all&verification=failed');
  });
});
