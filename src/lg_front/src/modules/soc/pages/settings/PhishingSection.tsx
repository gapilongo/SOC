/** Tenant settings: phishing context (protected brands, executives, trusted mail servers). */

import { useState } from 'react';

import type { JsonObject, TenantSettingsOut } from '../../../../api/types';
import { TextAreaField } from '../../../../components/ui';
import { asObject } from '../../../../lib/json';
import { Section, strings, useSave } from './shared';

/** Limits of the backend's PhishingSettings (lg_sotf.domain.phishing). */
export const PHISHING_FIELDS = [
  { key: 'protected_brands', label: 'Protected brands', max: 200, maxChars: 253 },
  { key: 'executives', label: 'Executives', max: 500, maxChars: 128 },
  { key: 'trusted_authserv_ids', label: 'Trusted mail servers (authserv-id)', max: 20, maxChars: 255 },
] as const;

export type PhishingKey = (typeof PHISHING_FIELDS)[number]['key'];

/** Replacement for the phishing section from one-entry-per-line text (commas are kept: "Smith, Jane"). */
export function phishingPatch(text: Record<PhishingKey, string>): JsonObject | Error {
  const section: Record<string, string[]> = {};
  for (const { key, label, max, maxChars } of PHISHING_FIELDS) {
    const entries = [...new Set(text[key].split('\n').map((l) => l.trim()).filter(Boolean))];
    if (entries.length > max) return new Error(`${label}: at most ${max} entries.`);
    const long = entries.find((e) => e.length > maxChars);
    if (long) return new Error(`${label}: "${long.slice(0, 40)}..." is longer than ${maxChars} characters.`);
    section[key] = entries;
  }
  return { phishing: Object.values(section).some((v) => v.length) ? section : null };
}

const PHISHING_HINTS: Record<PhishingKey, string> = {
  protected_brands: 'Brand names or domains that the look-alike and display-name checks protect.',
  executives: 'Display names attackers impersonate (CEO, CFO, ...).',
  trusted_authserv_ids: 'Your own receiving mail servers; only their Authentication-Results header is trusted.',
};

const PHISHING_PLACEHOLDERS: Record<PhishingKey, string> = {
  protected_brands: 'Example Bank\nexamplebank.example',
  executives: 'Jane Smith',
  trusted_authserv_ids: 'mx.corp.example',
};

export function PhishingSection({ data }: { data: TenantSettingsOut }) {
  const stored = asObject(data.settings.phishing);
  const [text, setText] = useState<Record<PhishingKey, string>>({
    protected_brands: strings(stored.protected_brands).join('\n'),
    executives: strings(stored.executives).join('\n'),
    trusted_authserv_ids: strings(stored.trusted_authserv_ids).join('\n'),
  });
  const [localError, setLocalError] = useState<Error | null>(null);
  const save = useSave();
  const submit = () => {
    setLocalError(null);
    const patch = phishingPatch(text);
    if (patch instanceof Error) {
      setLocalError(patch);
      return;
    }
    save.mutate(patch);
  };
  return (
    <Section
      title="Phishing context"
      saveLabel="Save phishing context"
      description="Used by the phishing signals on email alerts. One entry per line."
      onSubmit={submit}
      busy={save.isPending}
      error={localError ?? save.error}
    >
      {PHISHING_FIELDS.map(({ key, label }) => (
        <TextAreaField
          key={key}
          label={label}
          rows={4}
          value={text[key]}
          onChange={(e) => setText({ ...text, [key]: e.target.value })}
          placeholder={PHISHING_PLACEHOLDERS[key]}
          hint={PHISHING_HINTS[key]}
        />
      ))}
    </Section>
  );
}
