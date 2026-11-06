/** Typed wrappers for the API endpoints used by the web app. */

import type { ApiClient } from './client';
import type {
  AccuracyReportOut,
  ActionOut,
  AlertDetailOut,
  AlertEventOut,
  AlertOut,
  ApiKeyCreatedOut,
  ApiKeyOut,
  ApiKeyScope,
  ApprovalOut,
  AuditEntryOut,
  AuditVerifyOut,
  DashboardOut,
  DecisionIn,
  DeliveryOut,
  DecisionOut,
  DetectionsReportOut,
  EscalationOut,
  IncidentReportOut,
  IncidentReportStage,
  IntegrationCreateIn,
  IntegrationOut,
  IntegrationTestOut,
  IntegrationUpdateIn,
  JsonObject,
  LlmTestOut,
  MeOut,
  MicrosoftCatalogOut,
  MfaConfirmOut,
  MfaEnrollOut,
  MfaStatusOut,
  OnboardingStatusOut,
  Page,
  PlatformEscalationOut,
  RecoveryCodesOut,
  ResponseRoutesOut,
  RollbackOut,
  MonthlyReportOut,
  ProposeSuppressionIn,
  ReprocessOut,
  SampleAlertsOut,
  SourceCreateIn,
  SourceOut,
  SourceTestOut,
  SourceUpdateIn,
  SuppressionCreateIn,
  SuppressionOut,
  SuppressionUpdateIn,
  TenantCreateIn,
  TenantCreatedOut,
  TenantErasedOut,
  TenantErasureStatusOut,
  TenantSettingsOut,
  TenantSummaryOut,
  TenantUpdateIn,
  TicketOut,
  UsageOut,
  UsageReportOut,
  UserCreateIn,
  UserOut,
  UserUpdateIn,
  ValueReportOut,
} from './types';

export const PAGE_SIZE = 100;

const enc = encodeURIComponent;

export interface AlertFilters {
  status?: string[];
  severity?: string[];
  disposition?: string[];
  /** The API filters on one source id (a repeated parameter would keep only the last). */
  source_id?: string;
  q?: string;
  from?: string;
  to?: string;
}

export interface EscalationFilters {
  status?: string[];
  level?: string[];
  assigned_to?: string;
  alert_id?: string;
}

export interface ActionFilters {
  status?: string[];
  risk_level?: string[];
  alert_id?: string;
  /** A single action type (the API accepts one). */
  action_type?: string;
  verification?: string[];
}

export interface AuditFilters {
  action?: string;
  resource_type?: string;
  resource_id?: string;
  actor_id?: string;
  from?: string;
  to?: string;
}

export const endpoints = {
  /** Who the caller is, in the tenant it acts on (tenant_name on newer APIs). */
  me: (api: ApiClient, signal?: AbortSignal) => api.get<MeOut>('/auth/me', { signal }),

  dashboard: (api: ApiClient, windowHours: number, signal?: AbortSignal) =>
    api.get<DashboardOut>('/dashboard/summary', { query: { window_hours: windowHours }, signal }),

  alerts: (api: ApiClient, filters: AlertFilters, cursor?: string, signal?: AbortSignal) =>
    api.get<Page<AlertOut>>('/alerts', { query: { ...filters, cursor, limit: PAGE_SIZE }, signal }),
  alert: (api: ApiClient, id: string, signal?: AbortSignal) => api.get<AlertDetailOut>(`/alerts/${enc(id)}`, { signal }),
  alertEvents: (api: ApiClient, id: string, cursor?: string, signal?: AbortSignal) =>
    api.get<Page<AlertEventOut>>(`/alerts/${enc(id)}/events`, { query: { cursor, limit: 200 }, signal }),
  addNote: (api: ApiClient, id: string, text: string) => api.post<AlertEventOut>(`/alerts/${enc(id)}/notes`, { text }),
  reprocess: (api: ApiClient, id: string) => api.post<ReprocessOut>(`/alerts/${enc(id)}/reprocess`),

  escalations: (api: ApiClient, filters: EscalationFilters, cursor?: string, signal?: AbortSignal) =>
    api.get<Page<EscalationOut>>('/escalations', { query: { ...filters, cursor, limit: PAGE_SIZE }, signal }),
  escalation: (api: ApiClient, id: string, signal?: AbortSignal) =>
    api.get<EscalationOut>(`/escalations/${enc(id)}`, { signal }),
  claim: (api: ApiClient, id: string, version: number) =>
    api.post<EscalationOut>(`/escalations/${enc(id)}/claim`, { version }),
  decide: (api: ApiClient, id: string, body: DecisionIn) =>
    api.post<DecisionOut>(`/escalations/${enc(id)}/decision`, body),

  actions: (api: ApiClient, filters: ActionFilters, cursor?: string, signal?: AbortSignal) =>
    api.get<Page<ActionOut>>('/actions', { query: { ...filters, cursor, limit: PAGE_SIZE }, signal }),
  approve: (api: ApiClient, id: string, rejectRemaining: boolean) =>
    api.post<ApprovalOut>(`/actions/${enc(id)}/approve`, { reject_remaining: rejectRemaining }),
  reject: (api: ApiClient, id: string, rejectRemaining: boolean) =>
    api.post<ApprovalOut>(`/actions/${enc(id)}/reject`, { reject_remaining: rejectRemaining }),
  /** Roll back an executed action: a new action of the inverse type (approved at once when your role allows). */
  rollbackAction: (api: ApiClient, id: string, reason: string, approve = true) =>
    api.post<RollbackOut>(`/actions/${enc(id)}/rollback`, { reason, approve }),
  retryAction: (api: ApiClient, id: string, reason: string) => api.post<ActionOut>(`/actions/${enc(id)}/retry`, { reason }),
  verifyAction: (api: ApiClient, id: string) => api.post<ActionOut>(`/actions/${enc(id)}/verify`, {}),

  sources: (api: ApiClient, signal?: AbortSignal) => api.get<SourceOut[]>('/sources', { signal }),
  createSource: (api: ApiClient, body: SourceCreateIn) => api.post<SourceOut>('/sources', body),
  updateSource: (api: ApiClient, id: string, body: SourceUpdateIn) => api.patch<SourceOut>(`/sources/${enc(id)}`, body),
  deleteSource: (api: ApiClient, id: string) => api.del(`/sources/${enc(id)}`),
  testSource: (api: ApiClient, id: string) => api.post<SourceTestOut>(`/sources/${enc(id)}/test`),

  suppressions: (api: ApiClient, includeDisabled: boolean, signal?: AbortSignal) =>
    api.get<SuppressionOut[]>('/suppressions', { query: { include_disabled: includeDisabled }, signal }),
  createSuppression: (api: ApiClient, body: SuppressionCreateIn) => api.post<SuppressionOut>('/suppressions', body),
  updateSuppression: (api: ApiClient, id: string, body: SuppressionUpdateIn) =>
    api.patch<SuppressionOut>(`/suppressions/${enc(id)}`, body),
  deleteSuppression: (api: ApiClient, id: string) => api.del(`/suppressions/${enc(id)}`),

  users: (api: ApiClient, includeInactive: boolean, signal?: AbortSignal) =>
    api.get<UserOut[]>('/users', { query: { include_inactive: includeInactive }, signal }),
  createUser: (api: ApiClient, body: UserCreateIn) => api.post<UserOut>('/users', body),
  updateUser: (api: ApiClient, id: string, body: UserUpdateIn) => api.patch<UserOut>(`/users/${enc(id)}`, body),
  deleteUser: (api: ApiClient, id: string) => api.del(`/users/${enc(id)}`),
  resetUserMfa: (api: ApiClient, id: string) => api.post<void>(`/users/${enc(id)}/mfa/reset`),

  apiKeys: (api: ApiClient, includeRevoked: boolean, signal?: AbortSignal) =>
    api.get<ApiKeyOut[]>('/api-keys', { query: { include_revoked: includeRevoked }, signal }),
  createApiKey: (api: ApiClient, name: string, scopes: ApiKeyScope[]) =>
    api.post<ApiKeyCreatedOut>('/api-keys', { name, scopes }),
  revokeApiKey: (api: ApiClient, id: string) => api.del(`/api-keys/${enc(id)}`),

  mfaStatus: (api: ApiClient, signal?: AbortSignal) => api.get<MfaStatusOut>('/auth/mfa', { signal }),
  mfaEnroll: (api: ApiClient) => api.post<MfaEnrollOut>('/auth/mfa/enroll', {}),
  mfaConfirm: (api: ApiClient, code: string) => api.post<MfaConfirmOut>('/auth/mfa/confirm', { code }),
  mfaDisable: (api: ApiClient, password: string, code: string) => api.post<void>('/auth/mfa/disable', { password, code }),
  mfaRegenerate: (api: ApiClient, code: string) => api.post<RecoveryCodesOut>('/auth/mfa/recovery-codes', { code }),
  tenantSettings: (api: ApiClient, signal?: AbortSignal) => api.get<TenantSettingsOut>('/tenant/settings', { signal }),
  patchTenantSettings: (api: ApiClient, patch: JsonObject) => api.patch<TenantSettingsOut>('/tenant/settings', patch),
  testLlm: (api: ApiClient) => api.post<LlmTestOut>('/tenant/llm/test'),
  responseRoutes: (api: ApiClient, signal?: AbortSignal) => api.get<ResponseRoutesOut>('/tenant/response/routes', { signal }),

  llmUsage: (api: ApiClient, from: string, to: string, signal?: AbortSignal) =>
    api.get<UsageOut>('/usage/llm', { query: { from, to }, signal }),

  audit: (api: ApiClient, filters: AuditFilters, cursor?: string, signal?: AbortSignal) =>
    api.get<Page<AuditEntryOut>>('/audit', { query: { ...filters, cursor, limit: PAGE_SIZE }, signal }),
  verifyAudit: (api: ApiClient, from?: string) => api.get<AuditVerifyOut>('/audit/verify', { query: { from } }),

  // Platform endpoints act across tenants: they never carry the X-Tenant-ID override.
  createTenant: (api: ApiClient, body: TenantCreateIn) =>
    api.post<TenantCreatedOut>('/platform/tenants', body, { homeTenant: true }),
  platformTenants: (api: ApiClient, signal?: AbortSignal) =>
    api.get<TenantSummaryOut[]>('/platform/tenants', { signal, homeTenant: true }),
  updateTenant: (api: ApiClient, id: string, body: TenantUpdateIn) =>
    api.patch<TenantSummaryOut>(`/platform/tenants/${enc(id)}`, body, { homeTenant: true }),
  platformEscalations: (api: ApiClient, tenantId: string | undefined, cursor?: string, signal?: AbortSignal) =>
    api.get<Page<PlatformEscalationOut>>('/platform/escalations', {
      query: { tenant_id: tenantId, cursor, limit: PAGE_SIZE },
      signal,
      homeTenant: true,
    }),
  platformUsage: (api: ApiClient, month: string, signal?: AbortSignal) =>
    api.get<UsageReportOut>('/platform/usage', { query: { month }, signal, homeTenant: true }),

  onboardingStatus: (api: ApiClient, signal?: AbortSignal) =>
    api.get<OnboardingStatusOut>('/onboarding/status', { signal }),
  sendSampleAlerts: (api: ApiClient) => api.post<SampleAlertsOut>('/onboarding/sample-alerts'),
  markAutonomyReviewed: (api: ApiClient) => api.post<OnboardingStatusOut>('/onboarding/autonomy-reviewed'),
  dismissOnboarding: (api: ApiClient) => api.post<OnboardingStatusOut>('/onboarding/dismiss'),

  evidencePack: (api: ApiClient, id: string, format: 'json' | 'html') =>
    api.get<Blob>(`/alerts/${enc(id)}/evidence`, { query: { format }, responseType: 'blob' }),
  incidentReport: (api: ApiClient, id: string, stage: IncidentReportStage, includeAiNarrative: boolean) =>
    api.post<IncidentReportOut>(`/alerts/${enc(id)}/incident-report`, { stage, include_ai_narrative: includeAiNarrative }),
  tenantErasureStatus: (api: ApiClient, id: string) =>
    api.get<TenantErasureStatusOut>(`/platform/tenants/${enc(id)}/erasure`, { homeTenant: true }),
  exportTenant: (api: ApiClient, id: string) =>
    api.post<Blob>(`/platform/tenants/${enc(id)}/export`, undefined, { responseType: 'blob', homeTenant: true }),
  eraseTenant: (api: ApiClient, id: string) =>
    api.request<TenantErasedOut>('DELETE', `/platform/tenants/${enc(id)}`, { body: { confirm: id }, homeTenant: true }),


  integrations: (api: ApiClient, signal?: AbortSignal) => api.get<IntegrationOut[]>('/integrations', { signal }),
  microsoftCatalog: (api: ApiClient, signal?: AbortSignal) =>
    api.get<MicrosoftCatalogOut>('/integrations/microsoft/catalog', { signal }),
  createIntegration: (api: ApiClient, body: IntegrationCreateIn) => api.post<IntegrationOut>('/integrations', body),
  updateIntegration: (api: ApiClient, id: string, body: IntegrationUpdateIn) =>
    api.patch<IntegrationOut>(`/integrations/${enc(id)}`, body),
  deleteIntegration: (api: ApiClient, id: string) => api.del(`/integrations/${enc(id)}`),
  testIntegration: (api: ApiClient, id: string) => api.post<IntegrationTestOut>(`/integrations/${enc(id)}/test`),
  deliveries: (api: ApiClient, id: string, signal?: AbortSignal) =>
    api.get<DeliveryOut[]>(`/integrations/${enc(id)}/deliveries`, { query: { limit: 100 }, signal }),
  tickets: (api: ApiClient, filters: { alert_id?: string; escalation_id?: string[] }, signal?: AbortSignal) =>
    api.get<TicketOut[]>('/tickets', { query: { ...filters }, signal }),

  valueReport: (api: ApiClient, from: string, to: string, signal?: AbortSignal) =>
    api.get<ValueReportOut>('/reports/value', { query: { from, to }, signal }),
  accuracyReport: (api: ApiClient, from: string, to: string, signal?: AbortSignal) =>
    api.get<AccuracyReportOut>('/reports/accuracy', { query: { from, to }, signal }),
  detectionsReport: (api: ApiClient, from: string, to: string, signal?: AbortSignal) =>
    api.get<DetectionsReportOut>('/reports/detections', { query: { from, to }, signal }),
  /** Server-side CSV of the value daily series or the detections table. */
  reportCsv: (api: ApiClient, kind: 'value' | 'detections', from: string, to: string) =>
    api.get<string>(`/reports/${kind}`, { query: { from, to, format: 'csv' }, responseType: 'text', headers: { Accept: 'text/csv' } }),
  proposeSuppression: (api: ApiClient, body: ProposeSuppressionIn) =>
    api.post<SuppressionOut>('/reports/detections/propose-suppression', body),
  monthlyReport: (api: ApiClient, month: string, signal?: AbortSignal) =>
    api.get<MonthlyReportOut>('/reports/monthly', { query: { month, format: 'json' }, signal }),
  /** The self-contained monthly HTML report (to save and print). */
  monthlyReportHtml: (api: ApiClient, month: string) =>
    api.get<string>('/reports/monthly', { query: { month, format: 'html' }, responseType: 'text', headers: { Accept: 'text/html' } }),
};
