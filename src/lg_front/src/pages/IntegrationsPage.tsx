import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { History, Pencil, PlugZap, Plus, Trash2 } from 'lucide-react';
import { useState, type FormEvent } from 'react';

import { endpoints } from '../api/endpoints';
import { afterIntegrationChange, afterIntegrationTest } from '../api/invalidate';
import { qk } from '../api/queryKeys';
import {
  INTEGRATION_EVENTS,
  INTEGRATION_KINDS,
  SEVERITIES,
  TICKETING_EVENTS,
  TICKETING_KINDS,
  type DeliveryOut,
  type IntegrationCreateIn,
  type IntegrationKind,
  type IntegrationOut,
  type IntegrationUpdateIn,
  type JsonObject,
  type MicrosoftTestReport as MicrosoftReport,
} from '../api/types';
import { useApi } from '../auth/AuthContext';
import { getConfig } from '../config';
import { Badge, type Tone } from '../components/Badge';
import { ConfirmDialog, Modal } from '../components/Dialog';
import { useToast } from '../components/Toast';
import {
  Button,
  Card,
  Checkbox,
  EmptyState,
  ErrorMessage,
  LoadingState,
  PageHeader,
  SelectField,
  TextAreaField,
  TextField,
} from '../components/ui';
import { formatDateTime, formatRelative, humanize } from '../lib/format';
import { MicrosoftIntegrationForm, secretField } from './integrations/MicrosoftIntegrationForm';
import { MicrosoftTestReport } from './integrations/MicrosoftTestReport';

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

const TICKET_EVENT_LABELS: Record<string, string> = {
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
    const parsed = JSON.parse(extra) as unknown;
    if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) throw new Error('Additional configuration must be a JSON object.');
    out = { ...(parsed as JsonObject) };
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

function IntegrationForm({
  integration,
  onClose,
  hasMicrosoft = false,
}: {
  integration: IntegrationOut | null;
  onClose: () => void;
  hasMicrosoft?: boolean;
}) {
  const api = useApi();
  const client = useQueryClient();
  const toast = useToast();
  const editing = integration !== null;
  const [kind, setKind] = useState<IntegrationKind>(integration?.kind ?? 'slack');
  const initial = splitIntegrationConfig(kind, integration?.config);
  const [name, setName] = useState(integration?.name ?? '');
  const [enabled, setEnabled] = useState(integration?.enabled ?? true);
  const [minSeverity, setMinSeverity] = useState(integration?.min_severity ?? 'low');
  const [events, setEvents] = useState<string[]>(integration?.events ?? ['escalation.created']);
  const [values, setValues] = useState<Record<string, string>>(initial.values);
  const [flags, setFlags] = useState<Record<string, boolean>>(initial.flags);
  const [extra, setExtra] = useState(initial.extra);
  const [secrets, setSecrets] = useState<Record<string, string>>({});
  const [cleared, setCleared] = useState<Record<string, boolean>>({});
  const [error, setError] = useState<unknown>(null);
  const spec = KIND_SPECS[kind];
  const allowed = eventsFor(kind);

  const changeKind = (next: IntegrationKind) => {
    const fresh = splitIntegrationConfig(next, {});
    setKind(next);
    setValues(fresh.values);
    setFlags(fresh.flags);
    setExtra('');
    setSecrets({});
    setEvents(isTicketing(next) ? [...TICKETING_EVENTS] : ['escalation.created', 'escalation.sla_breached', 'action.awaiting_approval']);
  };

  const m = useMutation({
    mutationFn: async () => {
      const config = buildIntegrationConfig(kind, values, flags, extra);
      const secret: Record<string, string | null> = {};
      for (const [k, v] of Object.entries(secrets)) if (v.trim()) secret[k] = v.trim();
      for (const [k, on] of Object.entries(cleared)) if (on) secret[k] = null;
      const chosen = events.filter((e) => allowed.includes(e));
      if (editing) {
        const body: IntegrationUpdateIn = { name: name.trim(), enabled, min_severity: minSeverity, events: chosen, config };
        if (Object.keys(secret).length) body.secret = secret;
        return endpoints.updateIntegration(api, integration.id, body);
      }
      const body: IntegrationCreateIn = { kind, name: name.trim(), enabled, min_severity: minSeverity, events: chosen, config };
      if (Object.keys(secret).length) body.secret = secret;
      return endpoints.createIntegration(api, body);
    },
    onSuccess: (saved) => {
      // Credentials leave component state as soon as they have been sent.
      setSecrets({});
      toast.success(`Integration ${saved.name} saved.`);
      void afterIntegrationChange(client);
      onClose();
    },
    onError: (err) => setError(err),
  });

  const submit = (e: FormEvent) => {
    e.preventDefault();
    setError(null);
    m.mutate();
  };

  const toggleEvent = (event: string, on: boolean) => setEvents(on ? [...events, event] : events.filter((x) => x !== event));

  if (kind === 'microsoft') return <MicrosoftIntegrationForm integration={integration} onClose={onClose} />;

  return (
    <Modal
      open
      onClose={onClose}
      size="lg"
      title={editing ? `Edit integration ${integration.name}` : 'Add integration'}
      footer={
        <>
          <Button onClick={onClose}>Cancel</Button>
          <Button type="submit" form="integration-form" variant="primary" busy={m.isPending}>
            {editing ? 'Save changes' : 'Create integration'}
          </Button>
        </>
      }
    >
      <form id="integration-form" onSubmit={submit} className="space-y-4" autoComplete="off">
        {error !== null && <ErrorMessage error={error} compact />}
        <div className="grid gap-3 sm:grid-cols-2">
          <SelectField label="Kind" value={kind} disabled={editing} onChange={(e) => changeKind(e.target.value as IntegrationKind)}>
            {INTEGRATION_KINDS.map((k) => (
              <option key={k} value={k} disabled={k === 'microsoft' && hasMicrosoft}>
                {KIND_SPECS[k].label}
                {k === 'microsoft' && hasMicrosoft ? ' (already configured)' : ''}
              </option>
            ))}
          </SelectField>
          <TextField label="Name" required maxLength={200} value={name} onChange={(e) => setName(e.target.value)} />
          <SelectField
            label="Minimum alert severity"
            value={minSeverity}
            onChange={(e) => setMinSeverity(e.target.value)}
            hint="Events about less severe alerts are not sent."
          >
            {SEVERITIES.map((s) => (
              <option key={s} value={s}>
                {s}
              </option>
            ))}
          </SelectField>
          <Checkbox label="Enabled" checked={enabled} onChange={(e) => setEnabled(e.target.checked)} className="self-end" />
        </div>
        <p className="text-sm text-secondary">{spec.note}</p>
        {kind === 'slack' && editing && flags.interactive_approvals && (
          <p className="text-xs text-secondary">
            Slack app Interactivity Request URL:{' '}
            <code className="select-all break-all rounded bg-raised-2 px-1 py-0.5">{slackRequestUrl(integration)}</code>
          </p>
        )}
        <fieldset>
          <legend className="mb-2 text-sm font-medium text-body">Events</legend>
          <div className="grid gap-2 sm:grid-cols-2">
            {allowed.map((event) => (
              <Checkbox
                key={event}
                label={isTicketing(kind) ? TICKET_EVENT_LABELS[event] ?? event : EVENT_LABELS[event] ?? event}
                checked={events.includes(event)}
                onChange={(e) => toggleEvent(event, e.target.checked)}
              />
            ))}
          </div>
        </fieldset>
        <fieldset className="grid gap-3 sm:grid-cols-2">
          <legend className="mb-2 text-sm font-medium text-body">Configuration</legend>
          {spec.config.map((f) =>
            f.kind === 'bool' ? (
              <Checkbox
                key={f.key}
                label={f.label}
                checked={Boolean(flags[f.key])}
                onChange={(e) => setFlags({ ...flags, [f.key]: e.target.checked })}
              />
            ) : f.kind === 'select' ? (
              <SelectField key={f.key} label={f.label} value={values[f.key] ?? ''} onChange={(e) => setValues({ ...values, [f.key]: e.target.value })}>
                {(f.options ?? []).map((o) => (
                  <option key={o} value={o}>
                    {o || 'any'}
                  </option>
                ))}
              </SelectField>
            ) : f.kind === 'pem' ? (
              <TextAreaField
                key={f.key}
                label={f.label}
                rows={3}
                wrapperClassName="sm:col-span-2"
                value={values[f.key] ?? ''}
                onChange={(e) => setValues({ ...values, [f.key]: e.target.value })}
                spellCheck={false}
              />
            ) : (
              <TextField
                key={f.key}
                label={f.label}
                placeholder={f.placeholder}
                required={f.required}
                inputMode={f.kind === 'number' ? 'numeric' : undefined}
                hint={f.kind === 'list' ? 'Separate entries with commas.' : f.hint}
                value={values[f.key] ?? ''}
                onChange={(e) => setValues({ ...values, [f.key]: e.target.value })}
              />
            ),
          )}
        </fieldset>
        <TextAreaField
          label="Additional configuration (JSON object, optional)"
          hint='Advanced keys, e.g. {"priority_map": {"critical": "Highest"}} for Jira.'
          rows={2}
          value={extra}
          onChange={(e) => setExtra(e.target.value)}
        />
        {spec.secrets.length > 0 && (
          <fieldset className="space-y-3 rounded-control border border-subtle p-3">
            <legend className="px-1 text-sm font-medium text-body">Credentials (write-only)</legend>
            <p className="text-xs text-muted">
              Stored encrypted and never shown again. {editing ? 'Leave a field empty to keep the stored value.' : ''}
            </p>
            <div className="grid gap-3 sm:grid-cols-2">
              {spec.secrets.map((f) => {
                const configured = Boolean(integration?.secrets?.[f.key]);
                return (
                  <div key={f.key} className="space-y-1">
                    <TextField
                      label={
                        <span className="inline-flex items-center gap-1.5">
                          {f.label}
                          {configured && <Badge tone="good">configured</Badge>}
                        </span>
                      }
                      type="password"
                      autoComplete="new-password"
                      placeholder={f.placeholder}
                      required={f.required && !configured}
                      disabled={cleared[f.key]}
                      value={secrets[f.key] ?? ''}
                      onChange={(e) => setSecrets({ ...secrets, [f.key]: e.target.value })}
                    />
                    {configured && !f.required && (
                      <Checkbox label="Remove" checked={Boolean(cleared[f.key])} onChange={(e) => setCleared({ ...cleared, [f.key]: e.target.checked })} />
                    )}
                  </div>
                );
              })}
            </div>
          </fieldset>
        )}
      </form>
    </Modal>
  );
}

const DELIVERY_TONE: Record<string, Tone> = { pending: 'info', sent: 'good', failed: 'warn', dead: 'critical' };

export function describeResult(d: DeliveryOut): string {
  const r = d.result ?? {};
  if (typeof r.ticket === 'string') return `ticket ${r.ticket}${r.created === false ? ' (existing)' : ''}`;
  if (typeof r.skipped === 'string') return `skipped: ${humanize(r.skipped)}`;
  if (typeof r.http_status === 'number') return `HTTP ${r.http_status}`;
  if (typeof r.recipients === 'number') return `${r.recipients} recipient(s)`;
  return '';
}

function DeliveryLog({ integration }: { integration: IntegrationOut }) {
  const api = useApi();
  const q = useQuery({
    queryKey: qk.integrations.deliveries(integration.id),
    queryFn: ({ signal }) => endpoints.deliveries(api, integration.id, signal),
    refetchInterval: 15_000,
  });
  return (
    <Card
      title={`Delivery log: ${integration.name}`}
      actions={
        <Button size="sm" onClick={() => void q.refetch()} busy={q.isFetching}>
          Refresh
        </Button>
      }
      className="mt-6"
    >
      {q.isPending && <LoadingState label="Loading deliveries" />}
      {q.isError && <ErrorMessage error={q.error} onRetry={() => void q.refetch()} compact />}
      {q.data && q.data.length === 0 && <EmptyState title="Nothing delivered yet">Events appear here once they are queued.</EmptyState>}
      {q.data && q.data.length > 0 && (
        <div className="overflow-x-auto">
          <table className="w-full min-w-[800px] text-left text-sm">
            <caption className="sr-only">Recent deliveries of {integration.name}</caption>
            <thead className="border-b border-subtle text-xs uppercase tracking-wide text-muted">
              <tr>
                <th scope="col" className="px-3 py-2">Queued</th>
                <th scope="col" className="px-3 py-2">Event</th>
                <th scope="col" className="px-3 py-2">Status</th>
                <th scope="col" className="px-3 py-2">Attempts</th>
                <th scope="col" className="px-3 py-2">Result</th>
              </tr>
            </thead>
            <tbody>
              {q.data.map((d) => (
                <tr key={d.id} className="border-b border-subtle align-top">
                  <td className="px-3 py-2 text-secondary">
                    <span title={formatDateTime(d.created_at)}>{formatRelative(d.created_at)}</span>
                  </td>
                  <td className="px-3 py-2">
                    <div className="text-fg">{EVENT_LABELS[d.event_type] ?? d.event_type}</div>
                    {d.operation !== 'notify' && <div className="text-xs text-muted">{humanize(d.operation)}</div>}
                    {d.title && <div className="max-w-md truncate text-xs text-muted" title={d.title}>{d.title}</div>}
                  </td>
                  <td className="px-3 py-2">
                    <Badge tone={DELIVERY_TONE[d.status] ?? 'neutral'}>{d.status}</Badge>
                    {(d.status === 'pending' || d.status === 'failed') && (
                      <div className="mt-1 text-xs text-muted">next {formatRelative(d.next_attempt_at)}</div>
                    )}
                  </td>
                  <td className="px-3 py-2 tabular-nums text-body">{d.attempts}</td>
                  <td className="px-3 py-2 text-xs">
                    {d.last_error ? <span className="break-words text-danger-fg">{d.last_error}</span> : <span className="text-secondary">{describeResult(d)}</span>}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </Card>
  );
}

export default function IntegrationsPage() {
  const api = useApi();
  const client = useQueryClient();
  const toast = useToast();
  const [editing, setEditing] = useState<IntegrationOut | null | 'new'>(null);
  const [deleting, setDeleting] = useState<IntegrationOut | null>(null);
  const [testing, setTesting] = useState<string | null>(null);
  const [logFor, setLogFor] = useState<string | null>(null);
  const [report, setReport] = useState<{ name: string; report: MicrosoftReport } | null>(null);
  const q = useQuery({ queryKey: qk.integrations.all, queryFn: ({ signal }) => endpoints.integrations(api, signal) });

  const del = useMutation({
    mutationFn: (i: IntegrationOut) => endpoints.deleteIntegration(api, i.id),
    onSuccess: (_, i) => {
      toast.success('Integration deleted.');
      setDeleting(null);
      if (logFor === i.id) setLogFor(null);
      void afterIntegrationChange(client);
    },
    onError: (err) => toast.error(err, 'Delete failed'),
  });

  const test = async (i: IntegrationOut) => {
    setTesting(i.id);
    try {
      const out = await endpoints.testIntegration(api, i.id);
      if (out.microsoft) setReport({ name: i.name, report: out.microsoft });
      if (out.ok) toast.success(`${i.name}: ${out.detail}.`);
      else toast.error(new Error(`${i.name}: ${out.detail}`));
    } catch (err) {
      toast.error(err, `${i.name}: test failed`);
    } finally {
      setTesting(null);
      void afterIntegrationTest(client, i.id);
    }
  };

  const selected = q.data?.find((i) => i.id === logFor) ?? null;

  return (
    <>
      <PageHeader
        title="Integrations"
        description="Send escalations, approvals and action outcomes to Slack, Teams, email or a signed webhook, open Jira or ServiceNow tickets for escalations, and execute approved actions directly in Microsoft 365. Notifications carry a summary and a link, never the raw alert."
        actions={
          <Button variant="primary" onClick={() => setEditing('new')} icon={<Plus className="h-4 w-4" aria-hidden="true" />}>
            Add integration
          </Button>
        }
      />
      {q.isPending && <LoadingState label="Loading integrations" />}
      {q.isError && <ErrorMessage error={q.error} onRetry={() => void q.refetch()} />}
      {q.data && q.data.length === 0 && (
        <EmptyState title="No integrations yet">Add a channel so analysts hear about escalations and approvals where they work.</EmptyState>
      )}
      {q.data && q.data.length > 0 && (
        <div className="overflow-x-auto rounded-card border border-subtle bg-raised">
          <table className="w-full min-w-[900px] text-left text-sm">
            <caption className="sr-only">Integrations</caption>
            <thead className="border-b border-subtle text-xs uppercase tracking-wide text-muted">
              <tr>
                <th scope="col" className="px-3 py-2">Name</th>
                <th scope="col" className="px-3 py-2">Kind</th>
                <th scope="col" className="px-3 py-2">Events</th>
                <th scope="col" className="px-3 py-2">Min severity</th>
                <th scope="col" className="px-3 py-2">Credentials</th>
                <th scope="col" className="px-3 py-2 text-right">Actions</th>
              </tr>
            </thead>
            <tbody>
              {q.data.map((i) => {
                const missing = missingCredentials(i);
                return (
                  <tr key={i.id} className="border-b border-subtle align-top">
                    <td className="px-3 py-2">
                      <div className="font-medium text-fg">{i.name}</div>
                      {!i.enabled && <Badge>disabled</Badge>}
                    </td>
                    <td className="px-3 py-2 text-body">{KIND_SPECS[i.kind]?.label ?? i.kind}</td>
                    <td className="px-3 py-2 text-xs text-secondary">
                      {i.events.length ? i.events.map((e) => EVENT_LABELS[e] ?? e).join(', ') : <span className="text-muted">none</span>}
                    </td>
                    <td className="px-3 py-2 capitalize text-body">{i.min_severity}</td>
                    <td className="px-3 py-2">
                      {missing.length ? <Badge tone="warn">missing {missing.join(', ')}</Badge> : <Badge tone="good">ok</Badge>}
                    </td>
                    <td className="px-3 py-2">
                      <div className="flex justify-end gap-1.5">
                        <Button size="sm" onClick={() => void test(i)} busy={testing === i.id} icon={<PlugZap className="h-3.5 w-3.5" aria-hidden="true" />} aria-label={`Test ${i.name}`}>
                          Test
                        </Button>
                        <Button
                          size="sm"
                          onClick={() => setLogFor(logFor === i.id ? null : i.id)}
                          aria-pressed={logFor === i.id}
                          icon={<History className="h-3.5 w-3.5" aria-hidden="true" />}
                          aria-label={`Delivery log of ${i.name}`}
                        >
                          Log
                        </Button>
                        <Button size="sm" onClick={() => setEditing(i)} icon={<Pencil className="h-3.5 w-3.5" aria-hidden="true" />} aria-label={`Edit ${i.name}`}>
                          Edit
                        </Button>
                        <Button size="sm" variant="destructive" onClick={() => setDeleting(i)} icon={<Trash2 className="h-3.5 w-3.5" aria-hidden="true" />} aria-label={`Delete ${i.name}`}>
                          Delete
                        </Button>
                      </div>
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      )}
      {selected && <DeliveryLog integration={selected} />}
      {editing !== null && (
        <IntegrationForm
          integration={editing === 'new' ? null : editing}
          onClose={() => setEditing(null)}
          hasMicrosoft={Boolean(q.data?.some((i) => i.kind === 'microsoft'))}
        />
      )}
      {report && (
        <Modal open onClose={() => setReport(null)} size="xl" title={`Connection test: ${report.name}`}>
          <MicrosoftTestReport report={report.report} />
        </Modal>
      )}
      <ConfirmDialog
        open={deleting !== null}
        title="Delete integration"
        confirmLabel="Delete integration"
        danger
        busy={del.isPending}
        onConfirm={() => deleting && del.mutate(deleting)}
        onCancel={() => setDeleting(null)}
      >
        Delete <strong>{deleting?.name}</strong>? Queued messages are dropped, its credentials are destroyed and its ticket links are removed
        (the tickets themselves stay in the external system).
      </ConfirmDialog>
    </>
  );
}
