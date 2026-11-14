/**
 * What a change makes stale, declared once per kind of change.
 *
 * Pages call these after a mutation instead of invalidating keys themselves
 * (ESLint bans `invalidateQueries` elsewhere, except `lib/pagination.ts` for
 * live events and `auth/cacheBinding.ts` for session changes). Each policy
 * invalidates the listed keys in order and resolves once they have all been
 * refetched, exactly as the inline calls it replaced. The keys are the SOC's
 * own, with one exception: the setup wizard renames the tenant, which the
 * kernel's `GET /auth/me` shows.
 */

import type { QueryClient, QueryKey } from '@tanstack/react-query';

import { coreKeys } from '../../../api/queryKeys';
import { qk } from './queryKeys';

function invalidate(client: QueryClient, ...keys: QueryKey[]): Promise<void> {
  return Promise.all(keys.map((queryKey) => client.invalidateQueries({ queryKey }))).then(() => undefined);
}

// Alerts ---------------------------------------------------------------------

/** One alert changed (reprocessed): its drawer and every alert list. */
export const afterAlertChange = (client: QueryClient, alertId: string | null) =>
  invalidate(client, qk.alert.detail(alertId), qk.alerts.all);

/** Something was added to an alert's timeline (a note, an incident report). */
export const afterAlertTimelineChange = (client: QueryClient, alertId: string) => invalidate(client, qk.alert.events(alertId));

/** New alerts were created (sample alerts). */
export const afterAlertsAdded = (client: QueryClient) => invalidate(client, qk.alerts.all);

// Escalations ----------------------------------------------------------------

/**
 * An escalation changed (claimed, or found changed by someone else): the
 * lists, the decision page and the overview's queue figures.
 */
export const afterEscalationChange = (client: QueryClient) =>
  invalidate(client, qk.escalations.all, qk.escalation.all, qk.dashboard.all);

/** An escalation was decided: it, the alerts it resumed and the overview. */
export const afterEscalationDecision = (client: QueryClient) =>
  invalidate(client, qk.escalations.all, qk.escalation.all, qk.alerts.all, qk.dashboard.all);

/**
 * A bulk claim ran. Items commit one by one, so this runs whether the request
 * succeeded, partly failed or errored.
 */
export const afterBulkClaim = (client: QueryClient) =>
  invalidate(client, qk.escalations.all, qk.escalation.all, qk.alerts.all, qk.dashboard.all);

/**
 * A bulk close ran (committed items resumed their alerts). With
 * `suppressionProposed`, the proposed rule joins the suppressions list.
 */
export const afterBulkClose = (client: QueryClient, suppressionProposed = false) =>
  invalidate(
    client,
    qk.escalations.all,
    qk.escalation.all,
    qk.alerts.all,
    qk.alert.all,
    qk.dashboard.all,
    ...(suppressionProposed ? [qk.suppressions.all] : []),
  );

/** A suppression rule was proposed from decided escalations (disabled until an admin enables it). */
export const afterBulkSuppressionProposal = (client: QueryClient) => invalidate(client, qk.suppressions.all);

// Response actions -----------------------------------------------------------

/** An action changed (retried, rolled back, re-verified, or a decision failed). */
export const afterActionChange = (client: QueryClient) => invalidate(client, qk.actions.all);

/** An action was approved or rejected: it, the alert workflow it may resume and the approval counts. */
export const afterActionDecision = (client: QueryClient) => invalidate(client, qk.actions.all, qk.alerts.all, qk.dashboard.all);

// Blind audit ----------------------------------------------------------------

/**
 * A sample was labelled: the queue, the estimate, and (a malicious label opened one) the escalations and the
 * overview's queue figures.
 */
export const afterBlindAuditLabel = (client: QueryClient, escalationCreated: boolean) =>
  invalidate(
    client,
    qk.blindAudit.all,
    qk.reportBlindAudit.all,
    ...(escalationCreated ? [qk.escalations.all, qk.dashboard.all] : []),
  );

/** A sampling run was drawn: the queue, the runs and the estimate. */
export const afterBlindAuditSample = (client: QueryClient) => invalidate(client, qk.blindAudit.all, qk.reportBlindAudit.all);

/** A proof-of-value run was started or cancelled: the runs and each run's detail. */
export const afterPovRunChange = (client: QueryClient) => invalidate(client, qk.pov.all);

// Tenant configuration -------------------------------------------------------

export const afterSourceChange = (client: QueryClient) => invalidate(client, qk.sources.all);

export const afterSuppressionChange = (client: QueryClient) => invalidate(client, qk.suppressions.all);

/** Integrations changed (created, updated, deleted); their delivery logs too. */
export const afterIntegrationChange = (client: QueryClient) => invalidate(client, qk.integrations.all);

/** A connection test wrote a delivery to the integration's log. */
export const afterIntegrationTest = (client: QueryClient, integrationId: string) =>
  invalidate(client, qk.integrations.deliveries(integrationId));

/** Tenant settings were saved: they may complete the checklist's "autonomy reviewed" step. */
export const afterTenantSettingsChange = (client: QueryClient) => invalidate(client, qk.onboarding.all);

export const afterOnboardingChange = (client: QueryClient) => invalidate(client, qk.onboarding.all);

/** The setup wizard saved the tenant name: the header and the MSSP console show it. */
export const afterSetupSaved = (client: QueryClient) => invalidate(client, coreKeys.me.all, qk.platformTenants.all);

// Users and credentials ------------------------------------------------------

export const afterUserChange = (client: QueryClient) => invalidate(client, qk.users.all);

export const afterApiKeyChange = (client: QueryClient) => invalidate(client, qk.apiKeys.all);

/** Your MFA was turned on or off: your status and the users list (its MFA column). */
export const afterMfaChange = (client: QueryClient) => invalidate(client, qk.mfaStatus.all, qk.users.all);

/** New recovery codes: only your MFA status changes. */
export const afterRecoveryCodesChange = (client: QueryClient) => invalidate(client, qk.mfaStatus.all);

// Platform -------------------------------------------------------------------

/** A tenant was created or updated. */
export const afterTenantChange = (client: QueryClient) => invalidate(client, qk.platformTenants.all);
