/** Integration kinds: their form fields, events and the config conversions between the form and the API. */

import { INTEGRATION_EVENTS, TICKETING_EVENTS, TICKETING_KINDS, type IntegrationKind, type IntegrationOut, type JsonObject } from '../../api/types';
import { getConfig } from '../../config';
import { parseJsonObject } from '../../lib/json';
import { secretField } from './MicrosoftIntegrationForm';

type FieldKind = 'text' | 'number' | 'bool' | 'list' | 'select' | 'pem';

interface FieldSpec {
  key: string;
  label: string;
  kind?: FieldKind;
  options?: readonly string[];
  placeholder?: string;
  hint?: string;
  required?: boolean;
}

interface KindSpec {
  label: string;
  config: FieldSpec[];
  secrets: FieldSpec[];
  note: string;
}

const RATE_LIMIT: FieldSpec = { key: 'rate_limit_per_minute', label: 'Rate limit (messages per minute)', kind: 'number', placeholder: 'default for the kind' };
const CA_CERT: FieldSpec = { key: 'ca_cert_pem', label: 'Private CA certificate (PEM, optional)', kind: 'pem' };

/** Form fields per integration kind (lg_sotf.integrations.config). */
export const KIND_SPECS: Record<IntegrationKind, KindSpec> = {
  slack: {
    label: 'Slack',
    note: 'Create a Slack app with an incoming webhook for the channel and paste the webhook URL. Approve/Reject buttons need the app\'s signing secret and a bot token with users:read.email (see docs/integrations.md).',
    config: [
      { key: 'channel_label', label: 'Channel (display only)', placeholder: '#soc-alerts' },
      { key: 'interactive_approvals', label: 'Approve and reject actions from Slack', kind: 'bool' },
      RATE_LIMIT,
    ],
    secrets: [
      { key: 'webhook_url', label: 'Incoming webhook URL', placeholder: 'https://hooks.slack.com/services/...', required: true },
      { key: 'signing_secret', label: 'Signing secret (interactive approvals)' },
      { key: 'bot_token', label: 'Bot token (interactive approvals)' },
    ],
  },
  teams: {
    label: 'Microsoft Teams',
    note: 'Use a Teams Workflows (Power Automate) flow "When a Teams webhook request is received" and paste its URL. Office 365 connectors are retired and not supported.',
    config: [RATE_LIMIT],
    secrets: [{ key: 'webhook_url', label: 'Workflow webhook URL', required: true }],
  },
  email: {
    label: 'Email',
    note: 'The SMTP server, credentials and sender address are install settings (integrations.smtp_*); only recipients are set here.',
    config: [
      { key: 'recipients', label: 'Recipients', kind: 'list', placeholder: 'soc@example.com, oncall@example.com', required: true },
      { key: 'subject_prefix', label: 'Subject prefix', placeholder: '[LG-SOTF]' },
      RATE_LIMIT,
    ],
    secrets: [],
  },
  webhook: {
    label: 'Generic webhook (signed JSON)',
    note: 'Each event is POSTed as lg-sotf.event.v1 JSON, signed with HMAC-SHA256 (X-LGSOTF-Signature, same scheme as the response webhook).',
    config: [{ key: 'url', label: 'Receiver URL', placeholder: 'https://soar.example.com/hooks/lgsotf', required: true }, RATE_LIMIT, CA_CERT],
    secrets: [{ key: 'signing_secret', label: 'Signing secret (16+ characters)', required: true }],
  },
  jira: {
    label: 'Jira',
    note: 'Jira Cloud: the account email and an API token. Jira Data Center: choose datacenter and use a personal access token.',
    config: [
      { key: 'base_url', label: 'Site URL', placeholder: 'https://your-site.atlassian.net', required: true },
      { key: 'deployment', label: 'Deployment', kind: 'select', options: ['cloud', 'datacenter'] },
      { key: 'email', label: 'Account email (Cloud)' },
      { key: 'project_key', label: 'Project key', placeholder: 'SOC', required: true },
      { key: 'issue_type', label: 'Issue type', placeholder: 'Task' },
      { key: 'labels', label: 'Labels', kind: 'list', placeholder: 'lg-sotf' },
      { key: 'min_level', label: 'Open tickets from level', kind: 'select', options: ['', 'L1', 'L2', 'L3'] },
      { key: 'resolve_transition', label: 'Resolve transition on decision (name or id)', placeholder: 'Done' },
      { key: 'comment_on_decision', label: 'Comment the analyst decision', kind: 'bool' },
      { key: 'response_actions', label: 'Use for the create_ticket response action', kind: 'bool' },
      RATE_LIMIT,
      CA_CERT,
    ],
    secrets: [{ key: 'api_token', label: 'API token / personal access token', required: true }],
  },
  servicenow: {
    label: 'ServiceNow',
    note: 'Incidents are created with the Table API. The user needs the itil role (or read/create/write ACLs on incident).',
    config: [
      { key: 'instance_url', label: 'Instance URL', placeholder: 'https://your-instance.service-now.com', required: true },
      { key: 'username', label: 'Username', required: true },
      { key: 'assignment_group', label: 'Assignment group (sys_id or name)' },
      { key: 'caller_id', label: 'Caller (sys_id)' },
      { key: 'category', label: 'Category' },
      { key: 'min_level', label: 'Open tickets from level', kind: 'select', options: ['', 'L1', 'L2', 'L3'] },
      { key: 'comment_field', label: 'Decision comment field', kind: 'select', options: ['work_notes', 'comments'] },
      { key: 'comment_on_decision', label: 'Comment the analyst decision', kind: 'bool' },
      { key: 'resolve_on_decision', label: 'Resolve the incident on a decision', kind: 'bool' },
      { key: 'resolve_state', label: 'Resolved state value', placeholder: '6' },
      { key: 'close_code', label: 'Close code', placeholder: 'Solution provided' },
      { key: 'response_actions', label: 'Use for the create_ticket response action', kind: 'bool' },
      RATE_LIMIT,
      CA_CERT,
    ],
    secrets: [{ key: 'password', label: 'Password', required: true }],
  },
  microsoft: {
    label: 'Microsoft 365 (direct response)',
    note: 'Executes approved actions directly in Microsoft 365 mail, Entra ID and Defender for Endpoint (docs/microsoft.md). One per tenant; it receives no events.',
    config: [],
    secrets: [],
  },
};

const BOOL_DEFAULTS: Record<string, boolean> = { comment_on_decision: true, response_actions: true };

export const EVENT_LABELS: Record<string, string> = {
  'escalation.created': 'Escalation opened',
  'escalation.sla_breached': 'Escalation SLA breached',
  'escalation.decided': 'Escalation decided',
  'action.awaiting_approval': 'Action awaiting approval',
  'action.executed': 'Action executed',
  'action.failed': 'Action failed',
  'action.verification_failed': 'Action not verified',
  'alert.critical_received': 'Critical alert received',
  'integration.test': 'Test message',
};

export const TICKET_EVENT_LABELS: Record<string, string> = {
  'escalation.created': 'Open a ticket when an escalation is opened',
  'escalation.decided': 'Comment (and resolve) when the escalation is decided',
};

export function isTicketing(kind: IntegrationKind): boolean {
  return TICKETING_KINDS.includes(kind);
}

export function eventsFor(kind: IntegrationKind): readonly string[] {
  if (kind === 'microsoft') return [];
  return isTicketing(kind) ? TICKETING_EVENTS : INTEGRATION_EVENTS;
}

/** Credential fields an integration still needs (the Microsoft one depends on its credential type). */
export function missingCredentials(i: IntegrationOut): string[] {
  if (i.kind === 'microsoft') {
    const field = secretField(i.config?.credential === 'client_secret' ? 'client_secret' : 'certificate');
    return i.secrets?.[field] ? [] : [field];
  }
  return (KIND_SPECS[i.kind]?.secrets ?? []).filter((f) => f.required && !i.secrets?.[f.key]).map((f) => f.key);
}

function toText(value: unknown): string {
  if (Array.isArray(value)) return value.map(String).join(', ');
  if (value === null || value === undefined) return '';
  return String(value);
}

/** The known fields of a stored config as form values, plus the rest as JSON. */
export function splitIntegrationConfig(kind: IntegrationKind, config: JsonObject | undefined): { values: Record<string, string>; flags: Record<string, boolean>; extra: string } {
  const spec = KIND_SPECS[kind];
  const values: Record<string, string> = {};
  const flags: Record<string, boolean> = {};
  const extra: JsonObject = {};
  for (const f of spec.config) if (f.kind === 'bool') flags[f.key] = BOOL_DEFAULTS[f.key] ?? false;
  for (const [k, v] of Object.entries(config ?? {})) {
    const field = spec.config.find((f) => f.key === k);
    if (!field) extra[k] = v;
    else if (field.kind === 'bool') flags[k] = Boolean(v);
    else values[k] = toText(v);
  }
  return { values, flags, extra: Object.keys(extra).length ? JSON.stringify(extra, null, 2) : '' };
}

/** Config JSON from the form (empty fields are left out so the server defaults apply). */
export function buildIntegrationConfig(kind: IntegrationKind, values: Record<string, string>, flags: Record<string, boolean>, extra: string): JsonObject {
  let out: JsonObject = {};
  if (extra.trim()) {
    out = { ...parseJsonObject(extra, 'Additional configuration') };
  }
  for (const f of KIND_SPECS[kind].config) {
    if (f.kind === 'bool') {
      out[f.key] = Boolean(flags[f.key]);
      continue;
    }
    const raw = (values[f.key] ?? '').trim();
    if (!raw) continue;
    if (f.kind === 'number') {
      const n = Number(raw);
      if (!Number.isInteger(n) || n < 1) throw new Error(`${f.label} must be a positive whole number.`);
      out[f.key] = n;
    } else if (f.kind === 'list') {
      out[f.key] = raw.split(/[\s,;]+/).filter(Boolean);
    } else {
      out[f.key] = raw;
    }
  }
  return out;
}

/** Where the Slack app posts button clicks (the API authenticates them with the app's signing secret). */
export function slackRequestUrl(integration: IntegrationOut): string {
  const base = getConfig().apiBaseUrl || window.location.origin;
  const query = new URLSearchParams({ tenant: integration.tenant_id, integration: integration.id });
  return `${base}/api/v1/integrations/slack/interactions?${query.toString()}`;
}
