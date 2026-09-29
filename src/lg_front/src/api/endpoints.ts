/** Typed wrappers for the API endpoints used by the web app. */

import type { ApiClient } from './client';
import type {
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
  DecisionOut,
  EscalationOut,
  JsonObject,
  Page,
  ReprocessOut,
  SourceCreateIn,
  SourceOut,
  SourceTestOut,
  SourceUpdateIn,
  SuppressionCreateIn,
  SuppressionOut,
  SuppressionUpdateIn,
  TenantCreateIn,
  TenantCreatedOut,
  TenantSettingsOut,
  UsageOut,
  UserCreateIn,
  UserOut,
  UserUpdateIn,
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

  apiKeys: (api: ApiClient, includeRevoked: boolean, signal?: AbortSignal) =>
    api.get<ApiKeyOut[]>('/api-keys', { query: { include_revoked: includeRevoked }, signal }),
  createApiKey: (api: ApiClient, name: string, scopes: ApiKeyScope[]) =>
    api.post<ApiKeyCreatedOut>('/api-keys', { name, scopes }),
  revokeApiKey: (api: ApiClient, id: string) => api.del(`/api-keys/${enc(id)}`),

  tenantSettings: (api: ApiClient, signal?: AbortSignal) => api.get<TenantSettingsOut>('/tenant/settings', { signal }),
  patchTenantSettings: (api: ApiClient, patch: JsonObject) => api.patch<TenantSettingsOut>('/tenant/settings', patch),

  llmUsage: (api: ApiClient, from: string, to: string, signal?: AbortSignal) =>
    api.get<UsageOut>('/usage/llm', { query: { from, to }, signal }),

  audit: (api: ApiClient, filters: AuditFilters, cursor?: string, signal?: AbortSignal) =>
    api.get<Page<AuditEntryOut>>('/audit', { query: { ...filters, cursor, limit: PAGE_SIZE }, signal }),
  verifyAudit: (api: ApiClient, from?: string) => api.get<AuditVerifyOut>('/audit/verify', { query: { from } }),

  createTenant: (api: ApiClient, body: TenantCreateIn) => api.post<TenantCreatedOut>('/platform/tenants', body),
};
