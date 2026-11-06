import { screen } from '@testing-library/react';
import { describe, expect, it } from 'vitest';

import type { ActionOut, Page } from '../api/types';
import { NAV_ITEMS } from '../components/Layout';
import { RequireRole } from '../components/Guards';
import ApprovalsPage from '../pages/approvals/ApprovalsPage';
import { fakeApi, renderWithSession, signedInSession } from '../test/helpers';
import { approvalRoleFor, can, decisionBlockedReason, escalationDecisionBlockedReason, roleAtLeast } from './roles';
import type { Principal } from './store';

function principal(overrides: Partial<Principal> = {}): Principal {
  return { userId: 'u-1', email: 'x@acme.test', role: 'analyst', tenantId: 'acme', homeTenantId: 'acme', isPlatformAdmin: false, method: 'password', ...overrides };
}

describe('role checks mirror the API RBAC', () => {
  it('orders roles viewer < analyst < admin', () => {
    expect(roleAtLeast('admin', 'analyst')).toBe(true);
    expect(roleAtLeast('analyst', 'admin')).toBe(false);
    expect(roleAtLeast('viewer', 'viewer')).toBe(true);
    expect(roleAtLeast(null, 'viewer')).toBe(false);
    expect(roleAtLeast('superuser', 'viewer')).toBe(false);
  });

  it('gates approvals by risk level', () => {
    expect(approvalRoleFor('low')).toBe('analyst');
    expect(approvalRoleFor('critical')).toBe('admin');
    expect(can.approve(principal({ role: 'analyst' }), 'medium')).toBe(true);
    expect(can.approve(principal({ role: 'analyst' }), 'high')).toBe(false);
    expect(can.approve(principal({ role: 'admin' }), 'critical')).toBe(true);
    expect(can.approve(principal({ role: 'viewer' }), 'low')).toBe(false);
  });

  it('refuses personal decisions under a tenant override or without a linked user', () => {
    const override = principal({ role: 'admin', isPlatformAdmin: true, tenantId: 'globex' });
    expect(can.decide(override)).toBe(false);
    expect(can.claim(override)).toBe(false);
    expect(can.approve(override, 'low')).toBe(false);
    expect(can.admin(override)).toBe(true);
    expect(decisionBlockedReason(override)).toMatch(/another tenant/);
    const sso = principal({ userId: null, method: 'oidc' });
    expect(can.decide(sso)).toBe(false);
    expect(decisionBlockedReason(sso)).toMatch(/not linked/);
  });

  it('lets analysts reject at any risk but approve only low and medium', () => {
    const analyst = principal({ role: 'analyst' });
    expect(can.reject(analyst)).toBe(true);
    expect(can.approve(analyst, 'critical')).toBe(false);
    expect(can.reject(principal({ role: 'viewer' }))).toBe(false);
    expect(can.reject(principal({ role: 'admin', isPlatformAdmin: true, tenantId: 'globex' }))).toBe(false);
  });

  it('mirrors the API claim and decide rules for escalations', () => {
    const analyst = principal({ role: 'analyst', userId: 'u-1' });
    const admin = principal({ role: 'admin', userId: 'u-9' });
    const open = { status: 'open', assigned_to: null };
    const expired = { status: 'expired', assigned_to: 'u-2' };
    const mine = { status: 'claimed', assigned_to: 'u-1' };
    const theirs = { status: 'claimed', assigned_to: 'u-2' };
    const decided = { status: 'decided', assigned_to: 'u-1' };

    expect(can.claimEscalation(analyst, open)).toBe(true);
    // An SLA-expired escalation can still be claimed.
    expect(can.claimEscalation(analyst, expired)).toBe(true);
    expect(can.claimEscalation(analyst, mine)).toBe(false);
    // Taking over another analyst's claim is admin only.
    expect(can.claimEscalation(analyst, theirs)).toBe(false);
    expect(can.claimEscalation(admin, theirs)).toBe(true);
    expect(can.claimEscalation(admin, decided)).toBe(false);

    expect(can.decideEscalation(analyst, mine)).toBe(true);
    expect(can.decideEscalation(analyst, open)).toBe(true);
    expect(can.decideEscalation(analyst, expired)).toBe(true);
    expect(can.decideEscalation(analyst, theirs)).toBe(false);
    expect(escalationDecisionBlockedReason(analyst, theirs)).toMatch(/Claimed by another analyst/);
    expect(can.decideEscalation(admin, theirs)).toBe(true);
    expect(escalationDecisionBlockedReason(admin, theirs)).toBeNull();
    expect(can.decideEscalation(analyst, decided)).toBe(false);
  });

  it('shows admin navigation only to admins and the platform page only to platform admins', () => {
    const labels = (p: Principal) => NAV_ITEMS.filter((i) => i.allowed(p)).map((i) => i.label);
    expect(labels(principal({ role: 'viewer' }))).toEqual(['Overview', 'Escalations', 'Approvals', 'Alerts', 'Suppressions', 'Reports']);
    expect(labels(principal({ role: 'admin' }))).toContain('Audit log');
    expect(labels(principal({ role: 'admin' }))).toContain('Getting started');
    expect(labels(principal({ role: 'admin' }))).not.toContain('MSSP console');
    expect(labels(principal({ role: 'admin', isPlatformAdmin: true }))).toContain('MSSP console');
    // The console works across tenants: it is hidden while acting on one.
    expect(labels(principal({ role: 'admin', isPlatformAdmin: true, tenantId: 'globex' }))).not.toContain('MSSP console');
  });
});

describe('role-gated UI', () => {
  it('hides a page from roles that cannot use it', async () => {
    const { api } = fakeApi(() => []);
    const session = await signedInSession(api, { role: 'analyst' });
    renderWithSession(
      <RequireRole allowed={can.admin}>
        <p>secret admin page</p>
      </RequireRole>,
      session,
    );
    expect(screen.queryByText('secret admin page')).not.toBeInTheDocument();
    expect(screen.getByText(/do not have access/)).toBeInTheDocument();
  });

  it('offers approve only for risk levels the role may approve, and reject at any risk', async () => {
    const action = (id: string, risk: string): ActionOut => ({
      id,
      tenant_id: 'acme',
      alert_id: `alert-${id}`,
      action_type: 'block_ip',
      target: `203.0.113.${id.length}`,
      risk_level: risk,
      status: 'awaiting_approval',
      created_at: '2026-09-29T10:00:00Z',
      updated_at: '2026-09-29T10:00:00Z',
    });
    const page: Page<ActionOut> = { items: [action('a', 'medium'), action('bb', 'critical')], next_cursor: null };
    const { api } = fakeApi(() => page);
    const session = await signedInSession(api, { role: 'analyst' });
    renderWithSession(<ApprovalsPage />, session);
    const approve = await screen.findAllByRole('button', { name: 'Approve' });
    expect(approve.filter((b) => !(b as HTMLButtonElement).disabled)).toHaveLength(1);
    // The critical one is locked, and says why.
    const locked = approve.find((b) => (b as HTMLButtonElement).disabled);
    expect(locked).toHaveAccessibleDescription('Critical risk needs an admin to approve.');
    // The API lets analysts reject at any risk: rejecting a dangerous action is the safe choice.
    expect(screen.getAllByRole('button', { name: 'Reject' })).toHaveLength(2);
  });

  it('offers viewers neither approve nor reject', async () => {
    const page: Page<ActionOut> = {
      items: [
        {
          id: 'a1',
          tenant_id: 'acme',
          alert_id: 'alert-1',
          action_type: 'block_ip',
          target: '203.0.113.9',
          risk_level: 'low',
          status: 'awaiting_approval',
          created_at: '2026-09-29T10:00:00Z',
          updated_at: '2026-09-29T10:00:00Z',
        },
      ],
      next_cursor: null,
    };
    const { api } = fakeApi(() => page);
    const session = await signedInSession(api, { role: 'viewer' });
    renderWithSession(<ApprovalsPage />, session);
    expect(await screen.findByText('Requires the analyst role.')).toBeInTheDocument();
    expect(screen.queryByRole('button', { name: /Approve|Reject/ })).not.toBeInTheDocument();
  });
});
