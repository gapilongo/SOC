/**
 * One invented alert for the investigation view's tests: a Word attachment
 * that starts an encoded PowerShell (the scenario of the console v2
 * prototype, as far as today's API can carry it). Synthetic data only.
 */

import type { AlertDetailOut, AlertEventOut, EscalationOut, PreviewActionOut, ResponsePreviewOut } from '../api/types';

export const ALERT_ID = 'alert-48213';
export const ESCALATION_ID = 'esc-1';
const HASH = '5d1e0c9a7b3f4e2d8c6a1b0f9e8d7c6b5a4f3e2d1c0b9a8f7e6d5c4b3a29b07c';

export const inMinutes = (m: number) => new Date(Date.now() + m * 60_000).toISOString();

export function investigationAlert(overrides: Partial<AlertDetailOut> = {}): AlertDetailOut {
  return {
    id: ALERT_ID,
    tenant_id: 'acme',
    source_id: 'src-1',
    source_alert_id: 'wz-1',
    fingerprint: 'fp',
    title: 'Encoded PowerShell launched by Microsoft Word',
    severity: 'high',
    category: 'execution',
    status: 'waiting_human',
    occurred_at: '2026-11-14T09:41:52Z',
    ingested_at: '2026-11-14T09:44:26Z',
    updated_at: '2026-11-14T09:44:35Z',
    source_name: 'Wazuh manager',
    case_key: 'CASE-2291',
    summary: {
      escalation_id: ESCALATION_ID,
      triage: { rule_tp: ['office_spawns_script_host'], llm_tp: ['The PowerShell command is hidden and encoded.'], llm_fp: ['There is no sign yet that the attacker moved to other hosts.'] },
      analysis: {
        verdict: 'malicious',
        llm_used: true,
        conclusion: 'Word ran a hidden, encoded PowerShell command that downloaded a script from a three-day-old domain. Two minutes later the same host read LSASS memory.',
        reasoning: [
          'The script came from cdn-invoice-portal.example, a domain with a malicious reputation.',
          'The download address 203.0.113.50 has no reputation record.',
          'Word started PowerShell directly from an email attachment.',
        ],
        threat_indicators: ['Two minutes later the same host read LSASS memory.'],
      },
      decision: { route: 'escalate', reason: 'high severity alerts are closed only by an analyst', code: 'false_positive_review' },
    },
    normalized: {
      description: 'Rule 92213 (level 12): WINWORD.EXE spawned powershell.exe with an encoded command line.',
      rule_name: 'Office application starts a script host',
      entities: {
        hosts: ['WS-FIN-0142'],
        users: ['m.keller'],
        domains: ['cdn-invoice-portal.example', 'unchecked.example'],
        ips: ['203.0.113.50'],
        hashes: [HASH],
        processes: ['powershell.exe', 'WINWORD.EXE', 'rundll32.exe'],
      },
      mitre: { techniques: ['T1059.001', 'T1204.002'] },
    },
    findings: [
      {
        origin: 'threat_intel',
        kind: 'domain',
        target: 'cdn-invoice-portal.example',
        source: 'virustotal',
        status: 'ok',
        verdict: 'malicious',
        checked_at: '2026-11-14T09:44:28Z',
        cached: false,
        data: { malicious_engines: 14, total_engines: 91, registered: '2026-11-11', categories: ['phishing', 'malware'] },
      },
      { origin: 'threat_intel', kind: 'ip', target: '203.0.113.50', source: 'abuseipdb', status: 'not_found', verdict: 'unknown', checked_at: '2026-11-14T09:44:29Z', cached: false, data: {} },
      { origin: 'history', kind: 'host', target: 'WS-FIN-0142', source: 'history', status: 'ok', verdict: 'unknown', checked_at: '2026-11-14T09:44:30Z', cached: true, data: { earlier_alerts: 2 } },
      { origin: 'threat_intel', kind: 'hash', target: HASH, source: 'virustotal', status: 'error', verdict: 'unknown', checked_at: null, cached: false, data: {} },
    ],
    ...overrides,
  };
}

export function investigationEscalation(overrides: Partial<EscalationOut> = {}): EscalationOut {
  return {
    id: ESCALATION_ID,
    tenant_id: 'acme',
    alert_id: ALERT_ID,
    level: 'L2',
    status: 'claimed',
    reason: 'high severity alerts are closed only by an analyst',
    priority: 8,
    summary: { title: 'Encoded PowerShell launched by Microsoft Word', severity: 'high', verdict: 'malicious', llm_used: true },
    assigned_to: 'u-1',
    assigned_to_email: 'analyst@acme.test',
    claimed_at: inMinutes(-10),
    sla_deadline: inMinutes(12),
    routing: { code: 'false_positive_review', confidence: 62, band: null },
    alert_severity: 'high',
    version: 3,
    created_at: inMinutes(-18),
    updated_at: inMinutes(-10),
    ...overrides,
  };
}

let nextEventId = 0;

export function event(ts: string, event_type: string, node: string | null, data: Record<string, unknown> = {}, actor_type = 'system'): AlertEventOut {
  nextEventId += 1;
  return { id: nextEventId, alert_id: ALERT_ID, ts, node, event_type, actor_type, actor_id: null, data };
}

export function investigationEvents(): AlertEventOut[] {
  return [
    event('2026-11-14T09:44:26Z', 'node.completed', 'gate', { suppressed: false }),
    event('2026-11-14T09:44:27Z', 'node.completed', 'triage', { confidence: 62, rule_tp: 1, rule_fp: 0, llm_used: true }),
    event('2026-11-14T09:44:28Z', 'node.completed', 'correlation', { related_count: 2, indicators: 3, burst: false, llm_used: false }),
    event('2026-11-14T09:44:33Z', 'node.completed', 'analysis', { verdict: 'malicious', llm_used: true, tool_steps: 4 }),
    event('2026-11-14T09:44:34Z', 'node.completed', 'decide', { route: 'escalate', reason: 'high severity alerts are closed only by an analyst', code: 'false_positive_review' }),
    event('2026-11-14T09:44:35Z', 'node.completed', 'escalate', { escalation_id: ESCALATION_ID, level: 'L2', created: true, attached: false }),
  ];
}

export function plannedAction(action_type: string, target: string, overrides: Partial<PreviewActionOut> = {}): PreviewActionOut {
  return {
    action_type,
    target,
    description: '',
    risk: 'medium',
    reversible: true,
    inverse_action: null,
    irreversible_note: null,
    connector: { name: 'Defender for Endpoint', source: 'tenant', live: true, ready: true },
    guardrail: { verdict: 'passed', code: null, reason: null },
    autonomy: 'approval',
    without_preapproval: 'awaiting_approval',
    can_preapprove: true,
    role_lock: null,
    approval_entry: `${action_type}:${target}`,
    ...overrides,
  };
}

export function investigationPreview(actions?: PreviewActionOut[]): ResponsePreviewOut {
  return {
    escalation_id: ESCALATION_ID,
    alert_id: ALERT_ID,
    generated_at: inMinutes(0),
    threat_type: 'malware',
    evidence: 'analysis',
    dry_run_forced: false,
    actions: actions ?? [
      plannedAction('isolate_host', 'WS-FIN-0142', { risk: 'high', inverse_action: 'release_host', can_preapprove: false, role_lock: 'admin' }),
      plannedAction('kill_process', 'powershell.exe PID 7340', { reversible: false, irreversible_note: 'A stopped process is not restarted' }),
      plannedAction('block_domain', 'cdn-invoice-portal.example', { inverse_action: 'unblock_domain' }),
      plannedAction('reset_password', 'm.keller@acme.example', {
        risk: 'critical',
        reversible: false,
        guardrail: { verdict: 'blocked', code: 'autonomy_disabled', reason: 'The autonomy policy switches off critical-risk actions' },
        without_preapproval: 'blocked',
        can_preapprove: false,
        role_lock: 'disabled',
      }),
    ],
  };
}
