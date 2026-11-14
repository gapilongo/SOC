/** Tenant settings: value reporting, the review policy (escalation SLAs, suggestions) and data retention. */

import { useState } from 'react';

import type { JsonObject, TenantSettingsOut } from '../../api/types';
import { Checkbox, TextField } from '../../../../components/ui';
import { asObject } from '../../../../lib/json';
import { Section, useSave } from './shared';

export function ReportingSection({ data }: { data: TenantSettingsOut }) {
  const current = asObject(data.settings.reporting).minutes_per_alert;
  const [minutes, setMinutes] = useState(typeof current === 'number' ? String(current) : '');
  const [localError, setLocalError] = useState<Error | null>(null);
  const save = useSave();
  const submit = () => {
    setLocalError(null);
    if (!minutes.trim()) {
      save.mutate({ reporting: { minutes_per_alert: null } });
      return;
    }
    const n = Number(minutes);
    if (!Number.isInteger(n) || n < 1 || n > 480) {
      setLocalError(new Error('Minutes per alert must be a whole number from 1 to 480.'));
      return;
    }
    save.mutate({ reporting: { minutes_per_alert: n } });
  };
  return (
    <Section
      title="Reporting"
      saveLabel="Save reporting"
      description="Analyst hours saved = alerts handled without a human x minutes per alert / 60. Set the minutes an analyst typically spends triaging one alert; it is an estimate and is labelled as one in every report."
      onSubmit={submit}
      busy={save.isPending}
      error={localError ?? save.error}
    >
      <TextField label="Minutes per alert" type="number" min={1} max={480} value={minutes} onChange={(e) => setMinutes(e.target.value)} hint="Empty uses the default (15)." wrapperClassName="max-w-xs" />
    </Section>
  );
}

export function ReviewSection({ data }: { data: TenantSettingsOut }) {
  const review = asObject(data.settings.review);
  const sla = asObject(review.sla_minutes);
  const [l1, setL1] = useState(typeof sla.L1 === 'number' ? String(sla.L1) : '');
  const [l2, setL2] = useState(typeof sla.L2 === 'number' ? String(sla.L2) : '');
  const [l3, setL3] = useState(typeof sla.L3 === 'number' ? String(sla.L3) : '');
  const [suggest, setSuggest] = useState(review.suggest_suppressions !== false);
  const [localError, setLocalError] = useState<Error | null>(null);
  const save = useSave();
  const submit = () => {
    setLocalError(null);
    const minutes: Record<string, number> = {};
    for (const [level, v] of [['L1', l1], ['L2', l2], ['L3', l3]] as const) {
      if (!v.trim()) continue;
      const n = Number(v);
      if (!Number.isInteger(n) || n < 1 || n > 43_200) {
        setLocalError(new Error(`${level} SLA must be 1 to 43200 minutes.`));
        return;
      }
      minutes[level] = n;
    }
    const next: JsonObject = { ...review, suggest_suppressions: suggest };
    if (Object.keys(minutes).length) next.sla_minutes = minutes;
    else delete next.sla_minutes;
    save.mutate({ review: next });
  };
  return (
    <Section title="Review policy" description="Escalation SLAs per level (minutes); empty fields use the defaults." onSubmit={submit} busy={save.isPending} error={localError ?? save.error}>
      <div className="grid gap-3 sm:grid-cols-3">
        <TextField label="L1 SLA (minutes)" type="number" min={1} value={l1} onChange={(e) => setL1(e.target.value)} />
        <TextField label="L2 SLA (minutes)" type="number" min={1} value={l2} onChange={(e) => setL2(e.target.value)} />
        <TextField label="L3 SLA (minutes)" type="number" min={1} value={l3} onChange={(e) => setL3(e.target.value)} />
      </div>
      <Checkbox label="Offer suppression suggestions from false-positive decisions" checked={suggest} onChange={(e) => setSuggest(e.target.checked)} />
    </Section>
  );
}

/** Merge patch for the retention section; an empty field removes that override. */
export function retentionPatch(alerts: string, indicators: string, limits: { min_days: number; max_days: number }): JsonObject | Error {
  const out: JsonObject = {};
  for (const [key, label, value] of [
    ['alerts_days', 'Alert retention', alerts],
    ['indicators_days', 'Indicator retention', indicators],
  ] as const) {
    if (!value.trim()) {
      out[key] = null;
      continue;
    }
    const n = Number(value);
    if (!Number.isInteger(n) || n < limits.min_days || n > limits.max_days) {
      return new Error(`${label} must be a whole number of days from ${limits.min_days} to ${limits.max_days}.`);
    }
    out[key] = n;
  }
  return { retention: out };
}

export function RetentionSection({ data }: { data: TenantSettingsOut }) {
  const retention = asObject(data.settings.retention);
  const limits = data.retention_limits ?? { min_days: 1, max_days: 99_999, alerts_days: 90, indicators_days: 30 };
  const [alerts, setAlerts] = useState(typeof retention.alerts_days === 'number' ? String(retention.alerts_days) : '');
  const [indicators, setIndicators] = useState(typeof retention.indicators_days === 'number' ? String(retention.indicators_days) : '');
  const [localError, setLocalError] = useState<Error | null>(null);
  const save = useSave();
  const submit = () => {
    setLocalError(null);
    const patch = retentionPatch(alerts, indicators, limits);
    if (patch instanceof Error) {
      setLocalError(patch);
      return;
    }
    save.mutate(patch);
  };
  return (
    <Section
      title="Data retention"
      description={`How long this tenant's finished alerts and indicator sightings are kept before the nightly purge removes them. Allowed: ${limits.min_days} to ${limits.max_days} days; empty fields use the installation default.`}
      onSubmit={submit}
      busy={save.isPending}
      error={localError ?? save.error}
    >
      <div className="grid gap-3 sm:grid-cols-2">
        <TextField
          label="Closed alerts (days)"
          type="number"
          min={limits.min_days}
          max={limits.max_days}
          value={alerts}
          onChange={(e) => setAlerts(e.target.value)}
          hint={`Installation default: ${limits.alerts_days} days. Alert timelines and the audit log follow installation settings.`}
        />
        <TextField
          label="Indicator sightings (days)"
          type="number"
          min={limits.min_days}
          max={limits.max_days}
          value={indicators}
          onChange={(e) => setIndicators(e.target.value)}
          hint={`Installation default: ${limits.indicators_days} days. Correlation looks back this far.`}
        />
      </div>
    </Section>
  );
}
