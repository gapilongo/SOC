/**
 * Response and request shapes of the LG-SOTF API (see docs/api.md and the
 * OpenAPI document at /api/v1/openapi.json, which is the source of truth).
 */

export type Role = 'viewer' | 'analyst' | 'admin';

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
export const DECISIONS = ['true_positive', 'false_positive', 'benign_positive', 'needs_more_info'] as const;
export const SOURCE_TYPES = ['splunk', 'qradar', 'sentinel', 'wazuh', 'crowdstrike', 'guardduty', 'webhook', 'file'] as const;
export const API_KEY_SCOPES = ['ingest', 'read', 'write'] as const;
export const AUTONOMY_MODES = ['auto', 'approval', 'disabled'] as const;

export type Severity = (typeof SEVERITIES)[number];
export type RiskLevel = (typeof RISK_LEVELS)[number];
export type Decision = (typeof DECISIONS)[number];
export type SourceType = (typeof SOURCE_TYPES)[number];
export type ApiKeyScope = (typeof API_KEY_SCOPES)[number];
export type AutonomyMode = (typeof AUTONOMY_MODES)[number];

export type JsonObject = Record<string, unknown>;

export interface Page<T> {
  items: T[];
  next_cursor?: string | null;
}

export interface UserOut {
  id: string;
  tenant_id: string;
  email: string;
  role: string;
  is_platform_admin: boolean;
  is_active: boolean;
  locked_until?: string | null;
  last_login_at?: string | null;
  created_at: string;
  updated_at: string;
  mfa_enabled?: boolean;
  /** Created by OIDC just-in-time provisioning; the identity provider owns the role. */
  oidc_provisioned?: boolean;
}

export interface TokenOut {
  access_token: string;
  token_type?: 'bearer';
  expires_in: number;
  user: UserOut;
  mfa_required?: false;
  /** Set when the sign-in used a recovery code. */
  recovery_codes_remaining?: number | null;
}

/** POST /auth/login when a second factor (or enrollment) must follow the password. */
export interface MfaChallengeOut {
  mfa_required: true;
  mfa_token: string;
  expires_in: number;
  enrollment_required: boolean;
  methods: Array<'totp' | 'recovery_code'>;
}

export type LoginOut = TokenOut | MfaChallengeOut;

export function isMfaChallenge(out: LoginOut): out is MfaChallengeOut {
  return (out as MfaChallengeOut).mfa_required === true;
}

export interface MfaEnrollOut {
  secret: string;
  otpauth_uri: string;
  /** Rows of '1' (dark) and '0' (light) modules, no quiet zone; null when the URI is too long. */
  qr?: string[] | null;
  expires_in: number;
}

export interface MfaConfirmOut {
  recovery_codes: string[];
  session?: TokenOut | null;
}

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

export interface MeOut {
  kind: 'user' | 'api_key';
  tenant_id: string;
  home_tenant_id: string;
  auth_method: string;
  role?: string | null;
  scopes?: string[];
  user_id?: string | null;
  api_key_id?: string | null;
  email?: string | null;
  is_platform_admin?: boolean;
  expires_at?: string | null;
}

export interface AlertOut {
  id: string;
  tenant_id: string;
  source_id: string;
  source_alert_id: string;
  fingerprint: string;
  title: string;
  severity: string;
  category?: string | null;
  status: string;
  disposition?: string | null;
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
}

export interface AlertDetailOut extends AlertOut {
  raw?: JsonObject;
  normalized?: JsonObject;
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
  level: string;
  status: string;
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

export interface ActionOut {
  id: string;
  tenant_id: string;
  alert_id: string;
  action_type: string;
  target: string;
  params?: JsonObject;
  risk_level: string;
  status: string;
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

export interface TenantSettingsOut {
  tenant_id: string;
  name: string;
  status: string;
  settings: JsonObject;
  updated_at: string;
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

export interface TenantCreateIn {
  id: string;
  name: string;
  admin_email?: string | null;
  admin_password?: string | null;
}

export interface TenantCreatedOut {
  id: string;
  name: string;
  status: string;
  created_at: string;
  admin?: UserOut | null;
}

/** Live event envelope pushed on /ws. */
export interface LiveEvent {
  type: 'alert.created' | 'alert.updated' | 'escalation.created' | 'escalation.updated' | 'action.updated';
  tenant_id: string;
  alert_id: string | null;
  data: JsonObject;
  ts: string;
}
