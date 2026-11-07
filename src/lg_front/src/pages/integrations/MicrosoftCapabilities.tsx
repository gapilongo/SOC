import { AlertTriangle } from 'lucide-react';
import { useState } from 'react';

import type { JsonObject, MicrosoftCapabilityOut } from '../../api/types';
import { Badge } from '../../components/Badge';
import { ConfirmDialog } from '../../components/Dialog';
import { Checkbox, SelectField, TextAreaField, TextField } from '../../components/ui';
import { humanize } from '../../lib/format';
import { asObject } from '../../lib/json';

/** Stored state of one capability (config.capabilities[key]). */
export interface CapabilityState {
  enabled: boolean;
  live: boolean;
  options: JsonObject;
}

export type CapabilityStates = Record<string, CapabilityState>;

export type OptionKind = 'bool' | 'int' | 'select' | 'text' | 'list';

export interface OptionField {
  key: string;
  label: string;
  kind: OptionKind;
  description?: string;
  min?: number;
  max?: number;
  maxLength?: number;
  choices?: string[];
}

function num(value: unknown): number | undefined {
  return typeof value === 'number' && Number.isFinite(value) ? value : undefined;
}

/**
 * Form fields from a capability's options JSON schema (pydantic): boolean ->
 * checkbox, integer -> number, enum -> select, string -> text, array of
 * strings -> textarea (one entry per line). Anything else is not rendered.
 */
export function optionFields(schema: JsonObject): OptionField[] {
  const out: OptionField[] = [];
  for (const [key, raw] of Object.entries(asObject(schema.properties))) {
    const prop = asObject(raw);
    const label = typeof prop.title === 'string' ? prop.title : humanize(key);
    const description = typeof prop.description === 'string' ? prop.description : undefined;
    const base = { key, label, description };
    if (Array.isArray(prop.enum)) out.push({ ...base, kind: 'select', choices: prop.enum.map(String) });
    else if (prop.type === 'boolean') out.push({ ...base, kind: 'bool' });
    else if (prop.type === 'integer') out.push({ ...base, kind: 'int', min: num(prop.minimum), max: num(prop.maximum) });
    else if (prop.type === 'string') out.push({ ...base, kind: 'text', maxLength: num(prop.maxLength) });
    else if (prop.type === 'array' && asObject(prop.items).type === 'string') out.push({ ...base, kind: 'list', maxLength: num(prop.maxItems) });
  }
  return out;
}

/** A typed option value from its form text (``undefined`` when empty). */
export function parseOption(field: OptionField, text: string): unknown {
  if (field.kind === 'list') return text.split('\n').map((l) => l.trim()).filter(Boolean);
  if (field.kind === 'int') {
    const trimmed = text.trim();
    if (!trimmed) return undefined;
    const n = Number(trimmed);
    if (!Number.isInteger(n)) throw new Error(`${field.label} must be a whole number.`);
    if (field.min !== undefined && n < field.min) throw new Error(`${field.label} must be at least ${field.min}.`);
    if (field.max !== undefined && n > field.max) throw new Error(`${field.label} must be at most ${field.max}.`);
    return n;
  }
  return text;
}

/** The capabilities section of the integration config (every catalog capability that is enabled or stored). */
export function capabilitiesConfig(states: CapabilityStates): JsonObject {
  const out: JsonObject = {};
  for (const [key, state] of Object.entries(states)) {
    out[key] = { enabled: state.enabled, live: state.enabled && state.live, options: state.options };
  }
  return out;
}

/** Initial states from the stored config, with each capability's option defaults. */
export function initialStates(catalog: MicrosoftCapabilityOut[], stored: JsonObject | undefined): CapabilityStates {
  const out: CapabilityStates = {};
  const saved = asObject(stored);
  for (const spec of catalog) {
    const entry = asObject(saved[spec.key]);
    if (!Object.keys(entry).length) continue;
    out[spec.key] = {
      enabled: entry.enabled === true,
      live: entry.live === true,
      options: { ...asObject(spec.options_defaults), ...asObject(entry.options) },
    };
  }
  return out;
}

const STANDARD_LIVE_TEXT =
  'Going live lets LG-SOTF change your Microsoft tenant for every approved action this capability executes. ' +
  'Until then it only rehearses: it reads what it would change and records a dry run.';

function OptionInput({ field, value, onChange, disabled }: { field: OptionField; value: unknown; onChange: (v: unknown) => void; disabled: boolean }) {
  const [draft, setDraft] = useState(Array.isArray(value) ? value.join('\n') : value === undefined || value === null ? '' : String(value));
  const [error, setError] = useState<string | null>(null);
  if (field.kind === 'bool') {
    return <Checkbox label={field.label} hint={field.description} checked={value === true} disabled={disabled} onChange={(e) => onChange(e.target.checked)} />;
  }
  if (field.kind === 'select') {
    return (
      <SelectField label={field.label} hint={field.description} value={String(value ?? '')} disabled={disabled} onChange={(e) => onChange(e.target.value)}>
        {(field.choices ?? []).map((c) => (
          <option key={c} value={c}>
            {humanize(c)}
          </option>
        ))}
      </SelectField>
    );
  }
  const commit = (text: string) => {
    setDraft(text);
    try {
      setError(null);
      onChange(parseOption(field, text));
    } catch (err) {
      setError((err as Error).message);
    }
  };
  if (field.kind === 'list') {
    return (
      <TextAreaField
        label={field.label}
        hint={field.description ?? `One per line${field.maxLength ? `, at most ${field.maxLength}` : ''}.`}
        rows={3}
        value={draft}
        disabled={disabled}
        onChange={(e) => commit(e.target.value)}
        className="font-sans"
      />
    );
  }
  return (
    <TextField
      label={field.label}
      hint={field.description ?? (field.kind === 'int' && field.min !== undefined ? `${field.min} to ${field.max}` : undefined)}
      inputMode={field.kind === 'int' ? 'numeric' : undefined}
      maxLength={field.kind === 'text' ? field.maxLength : undefined}
      value={draft}
      error={error}
      disabled={disabled}
      onChange={(e) => commit(e.target.value)}
    />
  );
}

function CapabilityCard({
  spec,
  state,
  cloud,
  conflicts,
  onChange,
}: {
  spec: MicrosoftCapabilityOut;
  state: CapabilityState;
  cloud: string;
  conflicts: string[];
  onChange: (next: CapabilityState) => void;
}) {
  const [confirmLive, setConfirmLive] = useState(false);
  const supported = spec.clouds.includes(cloud);
  const fields = optionFields(spec.options_schema);
  const title = `${spec.title} (${spec.key})`;
  return (
    <article className="rounded-control border border-subtle p-3" aria-label={title}>
      <header className="flex flex-wrap items-start justify-between gap-2">
        <div className="min-w-0">
          <h4 className="text-sm font-semibold text-fg">{spec.title}</h4>
          <p className="text-xs text-muted">
            {spec.key} · {spec.api === 'graph' ? 'Microsoft Graph' : 'Defender for Endpoint'}
            {spec.licence ? ` · ${spec.licence}` : ''}
          </p>
        </div>
        <div className="flex items-center gap-3">
          {state.enabled && (state.live ? <Badge tone="critical">live</Badge> : <Badge tone="info">rehearsal</Badge>)}
          <Checkbox
            label="Enabled"
            checked={state.enabled}
            disabled={!supported}
            onChange={(e) => onChange({ ...state, enabled: e.target.checked, live: e.target.checked ? state.live : false })}
          />
          <Checkbox
            label="Live"
            checked={state.live}
            disabled={!supported || !state.enabled}
            onChange={(e) => (e.target.checked ? setConfirmLive(true) : onChange({ ...state, live: false }))}
          />
        </div>
      </header>
      <p className="mt-2 text-sm text-secondary">{spec.description}</p>
      {!supported && <p className="mt-2 text-xs text-warn-fg">Not available in the {humanize(cloud)} cloud.</p>}
      {conflicts.length > 0 && (
        <p className="mt-2 flex items-center gap-1 text-xs text-warn-fg">
          <AlertTriangle className="h-3.5 w-3.5" aria-hidden="true" />
          Cannot be enabled together with {conflicts.join(', ')}.
        </p>
      )}
      <div className="mt-2 grid gap-3 sm:grid-cols-2">
        <div>
          <h5 className="mb-1 text-xs font-semibold uppercase tracking-wide text-muted">Actions</h5>
          <ul className="space-y-1 text-xs text-body">
            {Object.entries(spec.actions).map(([type, support]) => (
              <li key={type}>
                <span className="font-medium">{humanize(type)}</span>
                {support.reversible && <span className="text-ok-fg"> · reversible{support.inverse ? ` (${humanize(support.inverse)})` : ''}</span>}
                {support.restorative && <span className="text-muted"> · rollback only</span>}
                {support.irreversible_note && <span className="block text-warn-fg">{support.irreversible_note}</span>}
                {support.note && <span className="block text-muted">{support.note}</span>}
              </li>
            ))}
          </ul>
        </div>
        <div>
          <h5 className="mb-1 text-xs font-semibold uppercase tracking-wide text-muted">Permissions</h5>
          <ul className="space-y-1 text-xs text-body">
            {spec.permissions.map((p) => (
              <li key={`${p.api}:${p.role}`}>
                <code>{p.role}</code> <span className="text-muted">({p.api})</span>
                {!p.required && <span className="text-muted"> optional</span>}
                {p.when && <span className="text-muted"> when {p.when}</span>}
                {p.directory_role && <span className="block text-link">Entra role: {p.directory_role}</span>}
                {p.exchange_rbac && <span className="block text-link">Exchange RBAC: {p.exchange_rbac}</span>}
                <span className="block text-muted">{p.purpose}</span>
              </li>
            ))}
          </ul>
        </div>
      </div>
      {fields.length > 0 && (
        <fieldset className="mt-3 grid gap-3 sm:grid-cols-2">
          <legend className="mb-1 text-xs font-semibold uppercase tracking-wide text-muted">Options</legend>
          {fields.map((f) => (
            <OptionInput
              key={f.key}
              field={f}
              value={state.options[f.key]}
              disabled={!supported}
              onChange={(v) => {
                const options = { ...state.options };
                if (v === undefined) delete options[f.key];
                else options[f.key] = v;
                onChange({ ...state, options });
              }}
            />
          ))}
        </fieldset>
      )}
      <ConfirmDialog
        open={confirmLive}
        title={`Go live: ${spec.title}`}
        confirmLabel="Go live"
        danger
        onConfirm={() => {
          setConfirmLive(false);
          onChange({ ...state, live: true });
        }}
        onCancel={() => setConfirmLive(false)}
      >
        <p>{STANDARD_LIVE_TEXT}</p>
        {spec.live_confirmation && <p className="mt-2 font-medium">{spec.live_confirmation}</p>}
      </ConfirmDialog>
    </article>
  );
}

/** The catalog's capabilities as cards: enable, go live (confirmed), options, permissions, actions. */
export function MicrosoftCapabilities({
  catalog,
  states,
  cloud,
  onChange,
}: {
  catalog: MicrosoftCapabilityOut[];
  states: CapabilityStates;
  cloud: string;
  onChange: (next: CapabilityStates) => void;
}) {
  if (catalog.length === 0) {
    return <p className="text-sm text-muted">No capability is installed yet. The connection test still checks the credential.</p>;
  }
  return (
    <div className="space-y-3">
      {catalog.map((spec) => {
        const state = states[spec.key] ?? { enabled: false, live: false, options: { ...asObject(spec.options_defaults) } };
        const conflicts = state.enabled
          ? catalog
              .filter((other) => other.key !== spec.key && states[other.key]?.enabled)
              .filter((other) => spec.excludes.includes(other.key) || other.excludes.includes(spec.key))
              .map((other) => other.title)
          : [];
        return (
          <CapabilityCard
            key={spec.key}
            spec={spec}
            state={state}
            cloud={cloud}
            conflicts={conflicts}
            onChange={(next) => onChange({ ...states, [spec.key]: next })}
          />
        );
      })}
    </div>
  );
}
