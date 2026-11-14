/**
 * Response and request shapes of the SOC's part of the LG-SOTF API (see docs/api.md and the OpenAPI
 * document at /api/v1/openapi.json, which is the source of truth). The identity and envelope types
 * every module shares live in the kernel (src/api/types.ts) and are re-exported here, so the SOC's
 * pages have one place to import types from.
 */

import type { JsonObject, Open, Role, UserOut } from '../../../api/types';

export { isMfaChallenge, isOneOf } from '../../../api/types';
export type {
  JsonObject,
  LiveEvent,
  LoginOut,
  MeOut,
  MfaChallengeOut,
  MfaConfirmOut,
  MfaEnrollOut,
  Open,
  Page,
  Role,
  TokenOut,
  UserOut,
} from '../../../api/types';

export const ALERT_STATUSES = [
  'new',
  'queued',
  'processing',
  'waiting_human',
  'waiting_approval',
  'closed',
  'failed',
] as const;
export const SEVERITIES = ['info', 'low', 'medium', 'high', 'critical'] as const;
export const DISPOSITIONS = ['malicious', 'benign', 'inconclusive'] as const;
export const ESCALATION_STATUSES = ['open', 'claimed', 'decided', 'expired', 'cancelled'] as const;
export const ESCALATION_LEVELS = ['L1', 'L2', 'L3'] as const;
export const ACTION_STATUSES = [
  'proposed',
  'awaiting_approval',
  'approved',
  'rejected',
  'executing',
  'succeeded',
  'failed',
  'dry_run',
  'blocked',
] as const;
export const RISK_LEVELS = ['low', 'medium', 'high', 'critical'] as const;
/** Proof by re-query that a succeeded action is in effect (docs/microsoft.md "Verification"). */
export const VERIFICATION_STATES = ['pending', 'verified', 'failed', 'inconclusive'] as const;
export type VerificationState = (typeof VERIFICATION_STATES)[number];
export const DECISIONS = ['true_positive', 'false_positive', 'benign_positive', 'needs_more_info'] as const;
export const SOURCE_TYPES = ['splunk', 'qradar', 'sentinel', 'wazuh', 'crowdstrike', 'guardduty', 'webhook', 'file', 'm365_mailbox', 'imap'] as const;
export const API_KEY_SCOPES = ['ingest', 'read', 'write'] as const;
export const AUTONOMY_MODES = ['auto', 'approval', 'disabled'] as const;
/** Entity kinds of an `entities_preview`, in the order the API picks them. */
export const ENTITY_KINDS = ['user', 'host', 'ip', 'email', 'domain', 'url', 'process', 'hash'] as const;
/** Why an escalation was opened (`routing.code`); newer codes may appear, so readers accept any string. */
export const ROUTING_CODES = [
  'grey_zone',
  'false_positive_review',
  'inconclusive',
  'model_refused',
  'llm_normalized',
  'analyst_request',
  'response_review',
  'group_review',
] as const;
/** The two decisions a bulk close may record. */
export const BULK_CLOSE_DECISIONS = ['false_positive', 'benign_positive'] as const;
/** Escalation list orders (`GET /escalations?order=`); both are keyset-paginated. */
export const ESCALATION_ORDERS = ['created_at', 'sla_deadline'] as const;
/** Most escalations one bulk request takes (422 above). */
export const BULK_MAX_ITEMS = 50;

export type AlertStatus = (typeof ALERT_STATUSES)[number];
export type Disposition = (typeof DISPOSITIONS)[number];
export type EscalationStatus = (typeof ESCALATION_STATUSES)[number];
export type EscalationLevel = (typeof ESCALATION_LEVELS)[number];
export type ActionStatus = (typeof ACTION_STATUSES)[number];
export type RiskLevel = (typeof RISK_LEVELS)[number];
export type Severity = (typeof SEVERITIES)[number];
export type Decision = (typeof DECISIONS)[number];
export type SourceType = (typeof SOURCE_TYPES)[number];
export type ApiKeyScope = (typeof API_KEY_SCOPES)[number];
export type EntityKind = (typeof ENTITY_KINDS)[number];
export type RoutingCode = (typeof ROUTING_CODES)[number];
export type BulkCloseDecision = (typeof BULK_CLOSE_DECISIONS)[number];
export type EscalationOrder = (typeof ESCALATION_ORDERS)[number];

export interface MfaStatusOut {
  available: boolean;
  enabled: boolean;
  enabled_at?: string | null;
  pending?: boolean;
  recovery_codes_remaining?: number;
  required: boolean;
}

export interface RecoveryCodesOut {
  recovery_codes: string[];
}

export interface AlertOut {
  id: string;
  tenant_id: string;
  source_id: string;
  source_alert_id: string;
  fingerprint: string;
  title: string;
  severity: Open<Severity>;
  category?: string | null;
  status: Open<AlertStatus>;
  disposition?: Open<Disposition> | null;
  confidence?: number | null;
  threat_score?: number | null;
  priority?: number | null;
  assigned_to?: string | null;
  occurred_at: string;
  ingested_at: string;
  updated_at: string;
  closed_at?: string | null;
  summary?: JsonObject;
  case_key?: string | null;
  /** Name of the source; null once the source is deleted (newer APIs). */
  source_name?: string | null;
  /** First value of up to three entity kinds and how many each kind has; null without entities (newer APIs). */
  entities_preview?: EntitiesPreviewOut | null;
  /** The alert waits for its blind-audit label: its AI side (verdict, scores, summary) is withheld. */
  hidden_for_blind_audit?: boolean;
}

/** One entity value of a preview. */
export interface EntityRefOut {
  kind: EntityKind;
  value: string;
}

/**
 * `{items, counts}`: the first value of up to three entity kinds (users,
 * hosts, IPs, e-mails, domains, URLs, processes, hashes, in that order) and
 * how many values each kind present has. Read it with `readEntitiesPreview`
 * (api/fields.ts), which drops anything malformed.
 */
export interface EntitiesPreviewOut {
  items: EntityRefOut[];
  counts: Partial<Record<EntityKind, number>>;
}

/** One provider result of the analysis agent's lookups (`GET /alerts/{id}` `findings`). */
export interface FindingOut {
  origin: 'threat_intel' | 'history';
  kind: string;
  target: string;
  source: string;
  status: string;
  verdict: string;
  /** When the platform received the result; null for analyses recorded before it was stored. */
  checked_at?: string | null;
  /** Served from the provider cache. */
  cached?: boolean;
  data?: JsonObject;
}

export interface AlertDetailOut extends AlertOut {
  raw?: JsonObject;
  normalized?: JsonObject;
  /** Absent on older APIs. */
  findings?: FindingOut[];
}

/** `GET /alerts/counts`: alerts per status, all-time except `closed` (closed inside the window). */
export interface AlertCountsOut {
  by_status: Record<string, number>;
  closed_from: string;
  closed_to?: string | null;
  generated_at: string;
}

export interface AlertEventOut {
  id: number;
  alert_id: string;
  ts: string;
  node?: string | null;
  event_type: string;
  actor_type: string;
  actor_id?: string | null;
  data?: JsonObject;
}

export interface ReprocessOut {
  alert_id: string;
  status: string;
  entry_id: string;
}

export interface EscalationOut {
  id: string;
  tenant_id: string;
  alert_id: string;
  level: Open<EscalationLevel>;
  status: Open<EscalationStatus>;
  reason: string;
  priority: number;
  summary?: JsonObject;
  related_alert_ids?: string[];
  assigned_to?: string | null;
  sla_deadline?: string | null;
  decision?: string | null;
  decision_notes?: string | null;
  approved_actions?: string[];
  decided_by?: string | null;
  decided_at?: string | null;
  claimed_at?: string | null;
  version: number;
  created_at: string;
  updated_at: string;
  // Newer APIs (console redesign): every one may be absent or null. Read them through api/fields.ts.
  assigned_to_email?: string | null;
  decided_by_email?: string | null;
  /** The alert's severity. */
  alert_severity?: string | null;
  /** The detection rule name, else the alert title. */
  rule?: string | null;
  source_id?: string | null;
  source_name?: string | null;
  entities_preview?: EntitiesPreviewOut | null;
  /** First sentence of the analysis conclusion. */
  ai_reason?: string | null;
  /** Who wrote `ai_reason`; null on escalations opened before it was recorded. */
  ai_reason_source?: 'model' | 'rules' | null;
  /** Why the escalation was opened; null on escalations opened before it was recorded. */
  routing?: RoutingOut | null;
}

/** The confidence band that sent an alert to review (percent). */
export interface ReviewBandOut {
  min: number;
  max: number;
}

/** `{code, confidence, band}`: the routing code that opened an escalation; `band` only for a grey-zone confidence inside it. */
export interface RoutingOut {
  code: RoutingCode | (string & {});
  confidence?: number | null;
  band?: ReviewBandOut | null;
}

/** `GET /escalations/groups` item: active escalations sharing a source and rule. */
export interface EscalationGroupOut {
  source_id: string;
  source_name?: string | null;
  rule: string;
  size: number;
  unassigned: number;
  overdue: number;
  earliest_sla_deadline?: string | null;
  min_confidence?: number | null;
  max_confidence?: number | null;
  by_severity: Record<string, number>;
  /** Up to 10 ids, soonest deadline first. */
  escalation_ids: string[];
}

export interface EscalationGroupsOut {
  items: EscalationGroupOut[];
  /** More groups matched than were returned (at most 100). */
  truncated: boolean;
  generated_at: string;
}

/** One escalation of a bulk request, at the version the caller saw. */
export interface BulkItemIn {
  escalation_id: string;
  version: number;
}

export interface BulkClaimIn {
  items: BulkItemIn[];
}

export interface BulkCloseIn {
  items: BulkItemIn[];
  /** Required by the API. */
  notes: string;
  /** Default `false_positive`. */
  decision?: BulkCloseDecision;
  /** Propose one disabled suppression rule from the closed escalations. */
  propose_suppression?: boolean;
}

/** What the single-escalation endpoint would have answered for this item. */
export interface BulkErrorOut {
  status: number;
  code: string;
  message: string;
}

export interface BulkItemOut {
  escalation_id: string;
  ok: boolean;
  escalation?: EscalationOut | null;
  error?: BulkErrorOut | null;
  resumes_enqueued?: number;
  resumes_failed?: number;
}

/** Per-item results of a bulk claim or close (HTTP 200 even when items failed). */
export interface BulkOut {
  results: BulkItemOut[];
  succeeded: number;
  failed: number;
  /** The proposed rule, for a close with `propose_suppression`. */
  suppression?: SuppressionOut | null;
  suppression_created?: boolean | null;
}

export interface BulkProposeSuppressionIn {
  escalation_ids: string[];
  name?: string | null;
}

/** 201 with a new disabled rule, or 200 with the unexpired rule that already has the same match. */
export interface SuppressionProposalOut {
  suppression: SuppressionOut;
  created: boolean;
  escalation_ids: string[];
}

export interface PreviewConnectorOut {
  name: string;
  source: string;
  live?: boolean | null;
  ready: boolean;
}

export interface PreviewGuardrailOut {
  verdict: 'passed' | 'blocked';
  code?: string | null;
  reason?: string | null;
}

/** One action of a response preview, judged for the caller's role. */
export interface PreviewActionOut {
  action_type: string;
  target: string;
  description: string;
  risk: Open<RiskLevel>;
  reversible: boolean;
  inverse_action?: string | null;
  irreversible_note?: string | null;
  connector: PreviewConnectorOut;
  guardrail: PreviewGuardrailOut;
  autonomy: string;
  /** What happens to it if the analyst pre-approves nothing. */
  without_preapproval: 'automatic' | 'awaiting_approval' | 'blocked';
  can_preapprove: boolean;
  role_lock?: 'admin' | 'disabled' | null;
  /** The `approved_actions` entry that pre-approves this action in a decision. */
  approval_entry: string;
}

/** `GET /escalations/{id}/response-preview`: the plan a true-positive decision would produce (a dry run). */
export interface ResponsePreviewOut {
  escalation_id: string;
  alert_id: string;
  generated_at: string;
  threat_type: string;
  evidence: string;
  dry_run_forced: boolean;
  actions: PreviewActionOut[];
}

export interface FeedbackIn {
  confidence?: number | null;
  triage_correct?: boolean | null;
  correlation_helpful?: boolean | null;
  analysis_accurate?: boolean | null;
}

export interface DecisionIn {
  decision: Decision;
  version: number;
  notes?: string | null;
  approved_actions?: string[];
  feedback?: FeedbackIn | null;
  suggest_suppression?: boolean | null;
}

export interface DecisionOut {
  escalation: EscalationOut;
  approved_actions: string[];
  resumed_alert_ids: string[];
  own_review_alert_ids: string[];
  feedback_id?: string | null;
  suppression_suggestion_id?: string | null;
  resumes_enqueued: number;
  resumes_failed: number;
}

/** Whether an executed action can be rolled back now (reason code when not). */
export interface RollbackEligibility {
  available: boolean;
  action_type?: string | null;
  risk?: Open<RiskLevel> | null;
  until?: string | null;
  reason?: string | null;
}

export interface ActionOut {
  id: string;
  tenant_id: string;
  alert_id: string;
  action_type: string;
  target: string;
  params?: JsonObject;
  risk_level: Open<RiskLevel>;
  status: Open<ActionStatus>;
  blocked_reason?: string | null;
  requested_by?: string | null;
  approved_by?: string | null;
  approved_at?: string | null;
  executed_at?: string | null;
  connector?: string | null;
  result?: JsonObject | null;
  rollback_of?: string | null;
  created_at: string;
  updated_at: string;
  /** workflow: the alert's run executes it; scheduler: the background executor does. */
  execution_owner?: Open<'workflow' | 'scheduler'>;
  integration_id?: string | null;
  /** The direct connector's state: ids, per-target steps, reversible, rollback_until. */
  external_ref?: JsonObject | null;
  attempts?: number;
  verification?: VerificationState | null;
  verification_detail?: JsonObject | null;
  verify_deadline?: string | null;
  verified_at?: string | null;
  rollback?: RollbackEligibility;
  /** The live rollback of this action, if any. */
  rolled_back_by?: string | null;
  // Newer APIs (console redesign).
  /** Re-checked now for a pending action; the recorded result for a blocked one; null otherwise. */
  guardrail?: GuardrailOut | null;
  blast_radius?: BlastRadiusOut | null;
  /** Its type has an inverse action (null when unknown). */
  reversible?: boolean | null;
  irreversible_note?: string | null;
}

export interface GuardrailOut {
  verdict: 'passed' | 'blocked';
  /** `now`: checked again against the current policy; `recorded`: the result stored when it was blocked. */
  evaluated: 'now' | 'recorded';
  code?: string | null;
  reason?: string | null;
  /** Why a human must approve (`admin_approval_required`, `llm_only_evidence`, ...). */
  approval_reason?: string | null;
}

/** The scope of an action and, while it awaits approval, the hourly limits it will be checked against. */
export interface BlastRadiusOut {
  target_kind?: string | null;
  scope_hosts?: string[];
  hourly_limit?: number | null;
  executed_last_hour?: number | null;
  tenant_hourly_cap?: number | null;
  tenant_executed_last_hour?: number | null;
}

export interface RollbackOut {
  rollback: ActionOut;
  original: ActionOut;
  created: boolean;
}

export interface ApprovalOut {
  action: ActionOut;
  resumed_alert_ids: string[];
  resumes_enqueued: number;
  resumes_failed: number;
}

export interface SourceOut {
  id: string;
  tenant_id: string;
  type: string;
  name: string;
  enabled: boolean;
  config?: JsonObject;
  has_secret?: boolean;
  poll_interval_s: number;
  cursor_watermark?: string | null;
  last_polled_at?: string | null;
  next_poll_at?: string | null;
  consecutive_failures?: number;
  last_error?: string | null;
  health: string;
  created_at: string;
  updated_at: string;
}

export interface SourceCreateIn {
  id?: string | null;
  type: SourceType;
  name: string;
  enabled?: boolean;
  config?: JsonObject;
  secret?: Record<string, string> | null;
  poll_interval_s?: number;
}

export interface SourceUpdateIn {
  name?: string;
  enabled?: boolean;
  config?: JsonObject;
  /** Omit to keep the stored secret, `null` to remove it, an object to replace it. */
  secret?: Record<string, string> | null;
  poll_interval_s?: number;
}

export interface SourceTestOut {
  ok: boolean;
  detail: string;
}

export interface SuppressionOut {
  id: string;
  tenant_id: string;
  name: string;
  match: JsonObject;
  disposition: string;
  created_by?: string | null;
  source_feedback_id?: string | null;
  expires_at?: string | null;
  hit_count: number;
  last_hit_at?: string | null;
  enabled: boolean;
  created_at: string;
  updated_at: string;
}

export interface SuppressionCreateIn {
  name: string;
  match: JsonObject;
  expires_at?: string | null;
  enabled?: boolean;
}

export interface SuppressionUpdateIn {
  name?: string;
  match?: JsonObject;
  expires_at?: string | null;
  enabled?: boolean;
}

export interface UserCreateIn {
  email: string;
  role: Role;
  password?: string | null;
  is_active?: boolean;
  is_platform_admin?: boolean;
}

export interface UserUpdateIn {
  role?: Role;
  is_active?: boolean;
  password?: string;
  is_platform_admin?: boolean;
}

export interface ApiKeyOut {
  id: string;
  tenant_id: string;
  name: string;
  prefix: string;
  scopes: string[];
  created_by?: string | null;
  last_used_at?: string | null;
  revoked_at?: string | null;
  created_at: string;
}

export interface ApiKeyCreatedOut extends ApiKeyOut {
  key: string;
}

/** Install-level bounds and defaults for the tenant `retention` settings (days). */
export interface RetentionLimits {
  min_days: number;
  max_days: number;
  alerts_days: number;
  indicators_days: number;
}

export interface LlmTierCheckOut {
  tier: 'fast' | 'deep';
  model: string;
  ok: boolean;
  latency_ms: number;
  structured_output: string | null;
  error_code: string | null;
  error: string | null;
}

export interface LlmTestOut {
  provider: string;
  enabled: boolean;
  ok: boolean;
  tiers: LlmTierCheckOut[];
}

export interface TenantSettingsOut {
  tenant_id: string;
  name: string;
  status: string;
  settings: JsonObject;
  updated_at: string;
  retention_limits?: RetentionLimits | null;
}

export interface DashboardOut {
  window_hours: number;
  since: string;
  generated_at: string;
  alerts_total: number;
  by_status: Record<string, number>;
  by_severity: Record<string, number>;
  by_disposition: Record<string, number>;
  mtta_s?: number | null;
  mttr_s?: number | null;
  acknowledged: number;
  resolved: number;
  open_escalations: number;
  runs_by_status: Record<string, number>;
  queue_depth: number;
  llm_cost_usd: number;
  llm_tokens: number;
  /** Value tiles (definitions in docs/reporting.md). */
  handled_without_human?: number;
  needed_human?: number;
  handled_without_human_rate?: number | null;
  analyst_hours_saved?: number;
  minutes_per_alert?: number;
  /** Unassigned escalations past their SLA (newer APIs; the sidebar hides the count without it). */
  unassigned_breaching?: number;
  /** Pending actions the caller may approve (newer APIs; the sidebar hides the count without it). */
  pending_approvals?: number;
  // Escalation and approval queue figures (newer APIs): active (open or claimed) escalations right
  // now, not the window. Absent on older APIs; read them with `readQueueFigures` (api/fields.ts).
  overdue_escalations?: number;
  unassigned_escalations?: number;
  /** The earliest deadline still ahead. */
  next_sla_deadline?: string | null;
  /** Active escalations by their alert's severity. */
  open_escalations_by_severity?: Record<string, number>;
  /** Every action awaiting approval in the tenant. */
  pending_approvals_total?: number;
  pending_approvals_by_risk?: Record<string, number>;
  /** Active escalations assigned to the caller (computed per request). */
  my_claimed?: number;
  /** The deep-tier model that writes the analysis verdicts; null when LLM use is off. */
  llm_model?: string | null;
}

export interface UsageDayOut {
  day: string;
  model: string;
  agent: string;
  calls: number;
  input_tokens: number;
  output_tokens: number;
  cache_read_tokens: number;
  cache_write_tokens: number;
  cost_usd: string;
  refusals: number;
  errors: number;
}

export interface UsageOut {
  start: string;
  end: string;
  days: UsageDayOut[];
  total_calls: number;
  total_input_tokens: number;
  total_output_tokens: number;
  total_cost_usd: string;
}

export interface AuditEntryOut {
  id: number;
  tenant_id: string;
  ts: string;
  actor_type: string;
  actor_id?: string | null;
  action: string;
  resource_type: string;
  resource_id?: string | null;
  details?: JsonObject;
  prev_hash?: string | null;
  hash: string;
}

export interface AuditVerifyOut {
  ok: boolean;
  first_bad_id?: number | null;
  since?: string | null;
}

export const TENANT_PROFILES = ['conservative', 'balanced', 'autonomous'] as const;
export type TenantProfile = (typeof TENANT_PROFILES)[number];
export const QUOTA_KEYS = ['max_alerts_per_day', 'max_sources', 'max_users'] as const;
export type QuotaKey = (typeof QUOTA_KEYS)[number];
export type Quotas = Record<QuotaKey, number | null>;

export interface TenantCreateIn {
  id: string;
  name: string;
  admin_email?: string | null;
  admin_password?: string | null;
  profile?: TenantProfile | null;
  copy_settings_from?: string | null;
}

export interface TenantCreatedOut {
  id: string;
  name: string;
  status: string;
  created_at: string;
  admin?: UserOut | null;
  settings_keys?: string[];
}

export interface TenantStats {
  alerts_24h: number;
  alerts_today: number;
  last_ingest_at: string | null;
  open_escalations: number;
  overdue_escalations: number;
  sla_breaches_24h: number;
  /** Decimal serialized as a string. */
  llm_cost_mtd_usd: string;
  llm_tokens_mtd: number;
  users: number;
  sources: number;
}

export interface TenantSummaryOut {
  id: string;
  name: string;
  status: 'active' | 'suspended' | string;
  created_at: string;
  updated_at: string;
  /** Keyed by QuotaKey; a key the API does not send is unlimited. */
  quotas: Partial<Quotas>;
  quota_usage: Partial<Record<QuotaKey, { used: number; limit: number | null }>>;
  stats: TenantStats;
}

export interface TenantUpdateIn {
  name?: string;
  status?: 'active' | 'suspended';
  quotas?: Partial<Quotas>;
}

export interface PlatformEscalationOut {
  id: string;
  tenant_id: string;
  tenant_name: string;
  tenant_status: string;
  alert_id: string;
  alert_title: string | null;
  alert_severity: string | null;
  level: Open<EscalationLevel>;
  status: Open<EscalationStatus>;
  priority: number;
  reason: string;
  assigned_to: string | null;
  sla_deadline: string | null;
  overdue: boolean;
  created_at: string;
}

export interface TenantUsageOut {
  tenant_id: string;
  tenant_name: string;
  tenant_status: string;
  alerts_ingested: number;
  alerts_processed: number;
  alerts_rejected_quota: number;
  llm_calls: number;
  llm_input_tokens: number;
  llm_output_tokens: number;
  llm_cost_usd: string;
  active_users: number;
  users: number;
  sources: number;
}

export interface UsageReportOut {
  month: string;
  start: string;
  end: string;
  generated_at: string;
  tenants: TenantUsageOut[];
  totals: Record<string, unknown>;
}

export interface OnboardingStepOut {
  id: string;
  done: boolean;
  available: boolean;
}

export interface OnboardingStatusOut {
  tenant_id: string;
  steps: OnboardingStepOut[];
  completed: number;
  total: number;
  complete: boolean;
  dismissed: boolean;
  dismissed_at?: string | null;
  samples_sent: boolean;
  /** An alert (samples included) is closed or waits for an analyst or an approval. */
  first_verdict: boolean;
}

/** Where a language model runs: `cn` (hosted in China) is never offered and is flagged when configured. */
export type LlmResidency = 'eu' | 'local' | 'us' | 'cn' | 'offline' | 'unknown';
export type LlmProfileId = 'mistral_eu' | 'ollama_local' | 'self_hosted' | 'anthropic';

export interface EnvVarOut {
  name: string;
  value: string;
}

export interface LlmProfileOut {
  id: string;
  label: string;
  residency: Open<LlmResidency>;
  description: string;
  provider: string;
  fast_model: string;
  deep_model: string;
  env: EnvVarOut[];
}

export interface ConfiguredModelOut {
  provider: string;
  enabled: boolean;
  fast_model: string;
  deep_model: string;
  residency: Open<LlmResidency>;
  profile?: string | null;
}

/** First-run setup wizard (`/onboarding/setup`, the install's platform admin). */
export interface SetupOut {
  completed: boolean;
  completed_at?: string | null;
  tenant_id: string;
  tenant_name: string;
  organisation?: string | null;
  llm_profile?: string | null;
  default_llm_profile: string;
  configured_llm: ConfiguredModelOut;
  llm_profiles: LlmProfileOut[];
}

export interface SetupIn {
  organisation: string;
  tenant_name: string;
  llm_profile?: LlmProfileId | null;
}

export interface SampleAlertsOut {
  source_id: string;
  received: number;
  inserted: number;
  duplicates: number;
  enqueued: number;
  alert_ids: string[];
}

/** NIS2 incident report draft (`POST /alerts/{id}/incident-report`). */
export type IncidentReportStage = 'early_warning' | 'notification' | 'final';

export interface IncidentReportField {
  key: string;
  label: string;
  value: string | null;
  source: 'case_data' | 'requires_human' | 'ai_drafted';
  required: boolean;
  help?: string | null;
}

export interface IncidentReportOut {
  alert_id: string;
  stage: string;
  event_id: number;
  generated_at: string;
  disclaimer: string;
  deadline_hint: string;
  fields: IncidentReportField[];
  ai_narrative: { text: string; label: string; provider: string; model: string } | null;
  ai_narrative_error?: string | null;
  html: string;
}

/** `GET /platform/tenants/{id}/erasure`: whether a tenant can be erased now. */
export interface TenantErasureStatusOut {
  tenant_id: string;
  name: string;
  status: string;
  erasable: boolean;
  blockers: string[];
  erased_at: string | null;
}

/** `DELETE /platform/tenants/{id}` result. */
export interface TenantErasedOut {
  tenant_id: string;
  erased_at: string;
  deleted: Record<string, number>;
  redis_keys: number;
  queue_entries: number;
  audit_entries_retained: number;
}

// ------------------------------------------------------------ integrations

export const INTEGRATION_KINDS = ['slack', 'teams', 'email', 'webhook', 'jira', 'servicenow', 'microsoft'] as const;
export type IntegrationKind = (typeof INTEGRATION_KINDS)[number];
export const TICKETING_KINDS: readonly IntegrationKind[] = ['jira', 'servicenow'];
export const INTEGRATION_EVENTS = [
  'escalation.created',
  'escalation.sla_breached',
  'escalation.decided',
  'action.awaiting_approval',
  'action.executed',
  'action.failed',
  'action.verification_failed',
  'alert.critical_received',
] as const;
export const TICKETING_EVENTS = ['escalation.created', 'escalation.decided'] as const;

export interface IntegrationOut {
  id: string;
  tenant_id: string;
  kind: Open<IntegrationKind>;
  name: string;
  enabled: boolean;
  events: string[];
  min_severity: Open<Severity>;
  config: JsonObject;
  /** Which credential fields are configured; values are never returned. */
  secrets: Record<string, boolean>;
  created_at: string;
  updated_at: string;
}

export interface IntegrationCreateIn {
  kind: IntegrationKind;
  name: string;
  enabled?: boolean;
  events?: string[];
  min_severity?: Severity;
  config?: JsonObject;
  secret?: Record<string, string | null>;
}

export interface IntegrationUpdateIn {
  name?: string;
  enabled?: boolean;
  events?: string[];
  min_severity?: Severity;
  config?: JsonObject;
  /** Merge patch: a value replaces that credential, null removes it. */
  secret?: Record<string, string | null>;
}

export interface IntegrationTestOut {
  ok: boolean;
  detail: string;
  http_status?: number | null;
  /** The Microsoft connection test report (microsoft integrations only). */
  microsoft?: MicrosoftTestReport | null;
}

// ------------------------------------------------------------ Microsoft direct response

export const MICROSOFT_CLOUDS = ['global', 'usgov_gcc_high', 'usgov_dod'] as const;

export interface MicrosoftPermissionOut {
  api: 'graph' | 'defender';
  role: string;
  purpose: string;
  required: boolean;
  when: string;
  directory_role?: string | null;
  exchange_rbac?: string | null;
}

export interface MicrosoftActionSupportOut {
  reversible: boolean;
  rollback_window_s?: number | null;
  note: string;
  inverse?: string | null;
  risk?: string | null;
  restorative?: boolean;
  irreversible_note?: string;
}

/** One capability of GET /integrations/microsoft/catalog. */
export interface MicrosoftCapabilityOut {
  key: string;
  package: 'mail' | 'entra' | 'defender';
  api: 'graph' | 'defender';
  title: string;
  description: string;
  actions: Record<string, MicrosoftActionSupportOut>;
  permissions: MicrosoftPermissionOut[];
  /** JSON schema of the capability's options (pydantic). */
  options_schema: JsonObject;
  options_defaults: JsonObject;
  clouds: string[];
  licence: string;
  live_confirmation: string;
  excludes: string[];
}

export interface MicrosoftCatalogOut {
  capabilities: MicrosoftCapabilityOut[];
  clouds: Array<{ name: string; login_host: string; graph_host: string; defender_supported: boolean }>;
  defender_geos: string[];
}

export interface MicrosoftTokenCheck {
  status: 'ok' | 'failed' | 'not_needed';
  error?: string | null;
  aadsts?: number | null;
  hint?: string | null;
  roles?: string[] | null;
}

export interface MicrosoftPermissionCheck {
  role: string;
  api: string;
  status: 'granted' | 'missing' | 'unknown';
  via: 'token' | 'probe' | 'exchange_rbac' | 'directory_role';
  required: boolean;
  guidance?: string;
  /** Set when a grant defeats its intended scope (e.g. tenant-wide consent of an Exchange RBAC permission). */
  warning?: string;
}

export interface MicrosoftProbeCheck {
  name: string;
  status: 'ok' | 'forbidden' | 'not_licensed' | 'not_found' | 'error' | 'skipped';
  permission?: string | null;
  detail?: string;
}

export interface MicrosoftCapabilityCheck {
  status: 'ok' | 'missing_permission' | 'not_licensed' | 'unsupported_cloud' | 'error' | 'not_enabled' | 'unverified';
  enabled: boolean;
  live: boolean;
  permissions: MicrosoftPermissionCheck[];
  checks: MicrosoftProbeCheck[];
  detail?: string;
}

export interface MicrosoftTestReport {
  ok: boolean;
  tokens: Record<string, MicrosoftTokenCheck>;
  capabilities: Record<string, MicrosoftCapabilityCheck>;
  certificate?: { thumbprint_sha1: string; thumbprint_sha256: string; not_after: string; days_left: number } | null;
}

// ------------------------------------------------------------ response routing

export const ROUTE_NAMES = ['dry_run', 'webhook', 'ticketing', 'microsoft'] as const;

export interface RouteOut {
  connector: string;
  source: 'kill_switch' | 'tenant_dry_run' | 'sample' | 'pinned' | 'explicit' | 'ticketing' | 'capability' | 'default';
  capability?: string | null;
  live?: boolean | null;
  problem?: string | null;
}

export interface ResponseRoutesOut {
  dry_run_forced: boolean;
  routes: Record<string, RouteOut>;
}

export interface DeliveryOut {
  id: string;
  event_id: string;
  event_type: string;
  operation: string;
  status: Open<'pending' | 'sent' | 'failed' | 'dead'>;
  attempts: number;
  next_attempt_at: string;
  last_error?: string | null;
  result?: JsonObject | null;
  alert_id?: string | null;
  escalation_id?: string | null;
  title?: string | null;
  created_at: string;
  sent_at?: string | null;
}

export interface TicketOut {
  id: string;
  integration_id: string;
  system: string;
  alert_id: string;
  escalation_id?: string | null;
  external_key: string;
  external_url?: string | null;
  external_status?: string | null;
  resolved: boolean;
  resolved_by?: string | null;
  last_synced_at?: string | null;
  created_at: string;
}

// ------------------------------------------------------------------ reports

/**
 * A rate with its sample size and 95% Wilson interval (`<rate>_ci` fields; the shape the eval and PoV
 * reports share). `rate` and the bounds are null when `n` is 0.
 */
export interface RateInterval {
  rate: number | null;
  n: number;
  ci_low: number | null;
  ci_high: number | null;
}

/** One day (or the window's totals) of the value report; rates are fractions, null when undefined. */
export interface ValueMetrics {
  alerts_ingested: number;
  handled_without_human: number;
  needed_human: number;
  in_progress: number;
  handled_without_human_rate: number | null;
  handled_without_human_rate_ci?: RateInterval | null;
  analyst_hours_saved: number;
  auto_closed_benign: number;
  auto_contained: number;
  auto_contained_dry_run: number;
  escalated: number;
  human_decided: number;
  suppressed_by_rule: number;
  verdict_cache_hits: number;
  grouped_into_escalation: number;
  mean_time_to_verdict_s: number | null;
  verdicts: number;
  mtta_s: number | null;
  escalations_created: number;
  acknowledged: number;
  mttr_s: number | null;
  mttr_auto_s: number | null;
  mttr_human_s: number | null;
  resolved: number;
  sla_breaches: number;
  llm_cost_usd: number;
  llm_cost_per_alert_usd: number | null;
}

export interface ValueDay extends ValueMetrics {
  day: string;
}

export interface ValueReportOut {
  from: string;
  to: string;
  generated_at: string;
  minutes_per_alert: number;
  totals: ValueMetrics;
  escalations_breached: number;
  days: ValueDay[];
  notes: string[];
}

export type DataStatus = 'ok' | 'insufficient_data';

export interface AccuracyBlock {
  samples: number;
  status: DataStatus;
  /** confusion_matrix[analyst class][AI class] */
  confusion_matrix: Record<string, Record<string, number>>;
  agreement: number;
  agreement_rate: number | null;
  /** Wilson 95% interval: [low, high]. */
  agreement_ci95: number[] | null;
  analyst_malicious: number;
  false_negatives: number;
  false_negative_rate: number | null;
  /** Wilson 95% interval: [low, high]. */
  false_negative_ci95: number[] | null;
  analyst_benign: number;
  false_positives: number;
  false_positive_rate: number | null;
  ai_inconclusive: number;
  ai_inconclusive_rate: number | null;
  agreement_rate_ci?: RateInterval | null;
  false_negative_rate_ci?: RateInterval | null;
  false_positive_rate_ci?: RateInterval | null;
  ai_inconclusive_rate_ci?: RateInterval | null;
}

/** A feedback answer rate; `n`, `ci_low` and `ci_high` make it a RateInterval (absent from older APIs). */
export interface FeedbackRate {
  rate: number | null;
  samples: number;
  status: DataStatus;
  n?: number | null;
  ci_low?: number | null;
  ci_high?: number | null;
}

export interface AccuracyReportOut {
  from: string;
  to: string;
  generated_at: string;
  min_samples: number;
  low_score_below: number;
  high_score_from: number;
  overall: AccuracyBlock;
  by_model: Array<{ model: string; accuracy: AccuracyBlock }>;
  feedback: {
    total: number;
    by_decision: Record<string, number>;
    triage_correct: FeedbackRate;
    analysis_accurate: FeedbackRate;
    correlation_helpful: FeedbackRate;
    avg_review_duration_s: number | null;
  };
  notes: string[];
}

export type DetectionSuggestion = 'tune_rule' | 'candidate_suppression';

export interface DetectionOut {
  source_id: string;
  rule_field: 'rule_name' | 'title';
  rule: string;
  volume: number;
  decided: number;
  benign: number;
  benign_rate: number | null;
  benign_rate_ci?: RateInterval | null;
  malicious: number;
  auto_closed: number;
  analyst_false_positive: number;
  analyst_benign_positive: number;
  analyst_true_positive: number;
  median_severity: string | null;
  max_severity: string | null;
  max_confirmed_benign_severity: string | null;
  suggestion: DetectionSuggestion | null;
  reason: string;
  can_propose_suppression: boolean;
}

export interface DetectionsReportOut {
  from: string;
  to: string;
  generated_at: string;
  detections: DetectionOut[];
  truncated: boolean;
  limit: number;
  notes: string[];
}

export interface ProposeSuppressionIn {
  source_id: string;
  rule_field: 'rule_name' | 'title';
  rule: string;
  from?: string;
  to?: string;
}

export interface MonthlyReportOut {
  tenant_id: string;
  tenant_name: string;
  month: string;
  generated_at: string;
  value: ValueReportOut;
  accuracy: AccuracyReportOut;
  detections: DetectionsReportOut;
}

// ------------------------------------------------------------- blind audit

/** An analyst's label on a blind-audit sample (an auto-closed alert shown without the AI verdict). */
export const AUDIT_LABELS = ['malicious', 'benign', 'unsure'] as const;
export type AuditLabel = (typeof AUDIT_LABELS)[number];

/**
 * A sampled alert as its source sent it: nothing the AI concluded and not its id (the item id is the handle);
 * `raw`/`normalized` on the item read only.
 */
export interface BlindAlertOut {
  title: string;
  severity: Open<Severity>;
  source_id: string;
  source_name: string | null;
  category: string | null;
  occurred_at: string;
  ingested_at: string;
  entities_preview: EntitiesPreviewOut | null;
  raw: JsonObject | null;
  normalized: JsonObject | null;
}

/** The AI's side of a sample, sent only once it is labelled. */
export interface BlindAuditRevealOut {
  ai_class: Open<Disposition>;
  agreement: boolean | null;
  disposition: Open<Disposition> | null;
  confidence: number | null;
  threat_score: number | null;
  close_reason: string | null;
  routing_code: string | null;
  conclusion: string | null;
}

export interface BlindAuditItemOut {
  id: string;
  run_id: string;
  sample_rank: number;
  label: Open<AuditLabel> | null;
  notes: string | null;
  labelled_at: string | null;
  labelled_by: string | null;
  escalation_id: string | null;
  created_at: string;
  alert: BlindAlertOut;
  /** Null until the item is labelled. */
  reveal: BlindAuditRevealOut | null;
}

export interface BlindAuditLabelIn {
  label: AuditLabel;
  notes?: string | null;
}

export interface BlindAuditLabelOut {
  item: BlindAuditItemOut;
  escalation_id: string | null;
  escalation_created: boolean;
}

export interface BlindAuditSampleIn {
  from?: string | null;
  to?: string | null;
  /** Draw without recording; the only place for a caller's `seed`. */
  dry_run?: boolean;
  seed?: number | null;
  sample_rate?: number | null;
  min_per_week?: number | null;
  size?: number | null;
}

/** A sampling run: its window, seed, frame (eligible alerts) and label counts. */
export interface BlindAuditRunSummary {
  id: string;
  window_start: string;
  window_end: string;
  seed: number;
  /** Who chose the seed of a recorded run: always the server. */
  seed_source: string;
  sample_rate: number | null;
  min_sample: number;
  fixed_size: number | null;
  frame_size: number;
  sample_size: number;
  trigger: string;
  created_by: string | null;
  created_at: string;
  sampled: number;
  malicious: number;
  benign: number;
  unsure: number;
  agreed: number;
}

/** The stratified false-negative estimate: each run a stratum weighted by its frame. */
export interface BlindAuditEstimate {
  status: Open<'ok' | 'insufficient_data' | 'incomplete'>;
  /** Every sample of every run labelled. */
  complete: boolean;
  /** "6.7% (stratified over 1 run(s); n=30; 95% CI 1.8% to 21.3%)" or "Not enough data (n=4; at least 30 needed)". */
  summary: string;
  method: string;
  frame_size: number;
  /** The frames of the runs with a malicious-or-benign label (what the estimate scales to). */
  estimated_frame: number;
  effective_n: number | null;
  sampled: number;
  labelled: number;
  pending: number;
  malicious: number;
  benign: number;
  unsure: number;
  min_samples: number;
  false_negative_rate: RateInterval;
  agreement_rate: RateInterval;
  estimated_missed: number | null;
  estimated_missed_low: number | null;
  estimated_missed_high: number | null;
  /** Unsure and pending samples counted as malicious. */
  worst_case_rate: number | null;
  worst_case_rate_high: number | null;
  worst_case_missed: number | null;
  worst_case_missed_high: number | null;
}

/** One run as a stratum, with its own rate and 95% Wilson interval. */
export interface BlindAuditStratum {
  run_id: string;
  window_start: string;
  window_end: string;
  frame_size: number;
  sampled: number;
  labelled: number;
  pending: number;
  malicious: number;
  benign: number;
  unsure: number;
  complete: boolean;
  false_negative_rate: RateInterval;
}

/** Labels given by one organisation (`null`: the tenant's own people; else an MSSP under a grant). */
export interface OrganisationLabels {
  organisation: string | null;
  labelled: number;
  malicious: number;
  benign: number;
  unsure: number;
}

export interface BlindAuditReportOut {
  from: string;
  to: string;
  generated_at: string;
  estimate: BlindAuditEstimate;
  strata: BlindAuditStratum[];
  runs: BlindAuditRunSummary[];
  /** Time in the window no run covered: alerts closed then are in no frame. */
  uncovered: Array<{ from: string; to: string }>;
  labels_by_organisation: OrganisationLabels[];
  notes: string[];
}
