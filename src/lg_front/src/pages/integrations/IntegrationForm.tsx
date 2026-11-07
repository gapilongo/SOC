/** The create and edit form of an outbound integration (the Microsoft kind has its own form). */

import { useMutation, useQueryClient } from '@tanstack/react-query';
import { useState, type FormEvent } from 'react';

import { endpoints } from '../../api/endpoints';
import { afterIntegrationChange } from '../../api/invalidate';
import { INTEGRATION_KINDS, SEVERITIES, TICKETING_EVENTS, isOneOf, type IntegrationCreateIn, type IntegrationKind, type IntegrationOut, type IntegrationUpdateIn, type Severity } from '../../api/types';
import { useApi } from '../../auth/AuthContext';
import { Badge } from '../../components/Badge';
import { Modal } from '../../components/Dialog';
import { useToast } from '../../components/Toast';
import { Button, Checkbox, ErrorMessage, SelectField, TextAreaField, TextField } from '../../components/ui';
import { MicrosoftIntegrationForm } from './MicrosoftIntegrationForm';
import { buildIntegrationConfig, EVENT_LABELS, eventsFor, isTicketing, KIND_SPECS, slackRequestUrl, splitIntegrationConfig, TICKET_EVENT_LABELS } from './specs';

export function IntegrationForm({
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
  // The page offers editing only for known kinds; a new integration starts as Slack.
  const storedKind = integration?.kind;
  const [kind, setKind] = useState<IntegrationKind>(isOneOf(INTEGRATION_KINDS, storedKind) ? storedKind : 'slack');
  const initial = splitIntegrationConfig(kind, integration?.config);
  const [name, setName] = useState(integration?.name ?? '');
  const [enabled, setEnabled] = useState(integration?.enabled ?? true);
  const storedSeverity = integration?.min_severity;
  const [minSeverity, setMinSeverity] = useState<Severity>(isOneOf(SEVERITIES, storedSeverity) ? storedSeverity : 'low');
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
            onChange={(e) => {
              if (isOneOf(SEVERITIES, e.target.value)) setMinSeverity(e.target.value);
            }}
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
