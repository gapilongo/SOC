/** Tenant settings: tenant-wide security (require MFA). */

import { useState } from 'react';

import type { TenantSettingsOut } from '../../../../api/types';
import { Checkbox } from '../../../../components/ui';
import { asObject } from '../../../../lib/json';
import { Section, useSave } from './shared';

export function SecuritySection({ data }: { data: TenantSettingsOut }) {
  const current = asObject(data.settings.security).require_mfa === true;
  const [requireMfa, setRequireMfa] = useState(current);
  const save = useSave();
  return (
    <Section
      title="Sign-in security"
      saveLabel="Save sign-in security"
      description="Local accounts (email and password). Single sign-on users get MFA from your identity provider."
      onSubmit={() => save.mutate({ security: { require_mfa: requireMfa } })}
      busy={save.isPending}
      error={save.error}
    >
      <Checkbox
        label="Require MFA for local accounts"
        hint="Users without an authenticator app must set one up right after their password at the next sign-in; existing sessions of those users end at their next refresh."
        checked={requireMfa}
        onChange={(e) => setRequireMfa(e.target.checked)}
      />
    </Section>
  );
}
