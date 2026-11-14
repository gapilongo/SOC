/**
 * Contract check between the hand-written API types (types.ts) and the OpenAPI document
 * (docs/openapi.json, generated into schema.gen.ts by `npm run gen:api`). Compiled by `tsc -b`, never
 * imported, so it has no runtime cost; a drift fails the type check with the field that differs.
 *
 * - Responses: what the API sends (`Wire<Schemas['X']>`) must be assignable to the hand-written `X`,
 *   so the app never assumes a field or a value the API does not promise.
 * - Requests: the hand-written `XIn` must be assignable to `Schemas['XIn']`, so the app never sends a
 *   body the API would refuse.
 *
 * When a type is added on either side, give it a line here (README "API types").
 */

import type { components } from '../../../api/schema.gen';
import type {
  AccuracyBlock,
  AccuracyReportOut,
  ActionOut,
  AlertCountsOut,
  AlertDetailOut,
  AlertEventOut,
  AlertOut,
  ApiKeyCreatedOut,
  ApiKeyOut,
  ApprovalOut,
  AuditEntryOut,
  AuditVerifyOut,
  BlastRadiusOut,
  BlindAlertOut,
  BlindAuditEstimate,
  BlindAuditItemOut,
  BlindAuditLabelIn,
  BlindAuditLabelOut,
  BlindAuditReportOut,
  BlindAuditRevealOut,
  BlindAuditRunSummary,
  BlindAuditSampleIn,
  BlindAuditStratum,
  OrganisationLabels,
  BulkClaimIn,
  BulkCloseIn,
  BulkErrorOut,
  BulkItemIn,
  BulkItemOut,
  BulkOut,
  BulkProposeSuppressionIn,
  DashboardOut,
  DecisionIn,
  DecisionOut,
  DeliveryOut,
  DetectionOut,
  DetectionsReportOut,
  EntitiesPreviewOut,
  EntityRefOut,
  EscalationGroupOut,
  EscalationGroupsOut,
  EscalationOut,
  FeedbackIn,
  FeedbackRate,
  FindingOut,
  GuardrailOut,
  IncidentReportOut,
  IntegrationCreateIn,
  IntegrationOut,
  IntegrationTestOut,
  IntegrationUpdateIn,
  ConfiguredModelOut,
  EnvVarOut,
  LlmProfileOut,
  LlmTestOut,
  LlmTierCheckOut,
  MeOut,
  MfaChallengeOut,
  MfaConfirmOut,
  MfaEnrollOut,
  MfaStatusOut,
  MicrosoftActionSupportOut,
  MicrosoftCapabilityCheck,
  MicrosoftCapabilityOut,
  MicrosoftCatalogOut,
  MicrosoftPermissionCheck,
  MicrosoftPermissionOut,
  MicrosoftProbeCheck,
  MicrosoftTestReport,
  MicrosoftTokenCheck,
  MonthlyReportOut,
  OnboardingStatusOut,
  OnboardingStepOut,
  Page,
  PlatformEscalationOut,
  PreviewActionOut,
  PreviewConnectorOut,
  PreviewGuardrailOut,
  ProposeSuppressionIn,
  Quotas,
  RateInterval,
  RecoveryCodesOut,
  ReprocessOut,
  ResponsePreviewOut,
  ResponseRoutesOut,
  RetentionLimits,
  ReviewBandOut,
  RollbackEligibility,
  RollbackOut,
  RouteOut,
  RoutingOut,
  SampleAlertsOut,
  SetupIn,
  SetupOut,
  SourceCreateIn,
  SourceOut,
  SourceTestOut,
  SourceUpdateIn,
  SuppressionCreateIn,
  SuppressionOut,
  SuppressionProposalOut,
  SuppressionUpdateIn,
  TenantCreatedOut,
  TenantCreateIn,
  TenantErasedOut,
  TenantErasureStatusOut,
  TenantSettingsOut,
  TenantStats,
  TenantSummaryOut,
  TenantUpdateIn,
  TenantUsageOut,
  TicketOut,
  TokenOut,
  UsageDayOut,
  UsageOut,
  UsageReportOut,
  UserCreateIn,
  UserOut,
  UserUpdateIn,
  ValueDay,
  ValueMetrics,
  ValueReportOut,
} from './types';

type Schemas = components['schemas'];

/**
 * A response as it is on the wire: FastAPI serialises every field of a response model, defaults
 * included, so a field the schema marks optional (it has a default) is always present.
 */
type Wire<T> = T extends readonly (infer U)[] ? Wire<U>[] : T extends object ? { [K in keyof T]-?: Wire<Exclude<T[K], undefined>> } : T;

/** Fails to compile unless `Generated` (the API's response) is assignable to `Hand`. */
type Response<Generated extends Hand, Hand> = [Generated, Hand];

/** Fails to compile unless `Hand` (the body the app sends) is assignable to `Generated`. */
type Request<Hand extends Generated, Generated> = [Hand, Generated];

export interface ResponseContract {
  AccuracyBlock: Response<Wire<Schemas['AccuracyBlock']>, AccuracyBlock>;
  AccuracyReportOut: Response<Wire<Schemas['AccuracyReport']>, AccuracyReportOut>;
  BlindAlertOut: Response<Wire<Schemas['BlindAlertOut']>, BlindAlertOut>;
  BlindAuditEstimate: Response<Wire<Schemas['BlindAuditEstimate']>, BlindAuditEstimate>;
  BlindAuditItemOut: Response<Wire<Schemas['BlindAuditItemOut']>, BlindAuditItemOut>;
  BlindAuditLabelOut: Response<Wire<Schemas['BlindAuditLabelOut']>, BlindAuditLabelOut>;
  BlindAuditReportOut: Response<Wire<Schemas['BlindAuditReport']>, BlindAuditReportOut>;
  BlindAuditRevealOut: Response<Wire<Schemas['BlindAuditRevealOut']>, BlindAuditRevealOut>;
  BlindAuditRunSummary: Response<Wire<Schemas['BlindAuditRunSummary']>, BlindAuditRunSummary>;
  BlindAuditStratum: Response<Wire<Schemas['BlindAuditStratum']>, BlindAuditStratum>;
  OrganisationLabels: Response<Wire<Schemas['OrganisationLabels']>, OrganisationLabels>;
  ActionOut: Response<Wire<Schemas['ActionOut']>, ActionOut>;
  AlertCountsOut: Response<Wire<Schemas['AlertCountsOut']>, AlertCountsOut>;
  AlertDetailOut: Response<Wire<Schemas['AlertDetailOut']>, AlertDetailOut>;
  AlertEventOut: Response<Wire<Schemas['AlertEventOut']>, AlertEventOut>;
  AlertOut: Response<Wire<Schemas['AlertOut']>, AlertOut>;
  ApiKeyCreatedOut: Response<Wire<Schemas['ApiKeyCreatedOut']>, ApiKeyCreatedOut>;
  ApiKeyOut: Response<Wire<Schemas['ApiKeyOut']>, ApiKeyOut>;
  ApprovalOut: Response<Wire<Schemas['ApprovalOut']>, ApprovalOut>;
  AuditEntryOut: Response<Wire<Schemas['AuditEntryOut']>, AuditEntryOut>;
  AuditVerifyOut: Response<Wire<Schemas['AuditVerifyOut']>, AuditVerifyOut>;
  BlastRadiusOut: Response<Wire<Schemas['BlastRadiusOut']>, BlastRadiusOut>;
  BulkErrorOut: Response<Wire<Schemas['BulkErrorOut']>, BulkErrorOut>;
  BulkItemOut: Response<Wire<Schemas['BulkItemOut']>, BulkItemOut>;
  BulkOut: Response<Wire<Schemas['BulkOut']>, BulkOut>;
  DashboardOut: Response<Wire<Schemas['DashboardOut']>, DashboardOut>;
  DecisionOut: Response<Wire<Schemas['DecisionOut']>, DecisionOut>;
  DeliveryOut: Response<Wire<Schemas['DeliveryOut']>, DeliveryOut>;
  DetectionOut: Response<Wire<Schemas['Detection']>, DetectionOut>;
  DetectionsReportOut: Response<Wire<Schemas['DetectionsReport']>, DetectionsReportOut>;
  EntitiesPreviewOut: Response<Wire<Schemas['EntitiesPreviewOut']>, EntitiesPreviewOut>;
  EntityRefOut: Response<Wire<Schemas['EntityRefOut']>, EntityRefOut>;
  EscalationGroupOut: Response<Wire<Schemas['EscalationGroupOut']>, EscalationGroupOut>;
  EscalationGroupsOut: Response<Wire<Schemas['EscalationGroupsOut']>, EscalationGroupsOut>;
  EscalationOut: Response<Wire<Schemas['EscalationOut']>, EscalationOut>;
  FeedbackRate: Response<Wire<Schemas['FeedbackRate']>, FeedbackRate>;
  FindingOut: Response<Wire<Schemas['FindingOut']>, FindingOut>;
  GuardrailOut: Response<Wire<Schemas['GuardrailOut']>, GuardrailOut>;
  IncidentReportOut: Response<Wire<Schemas['IncidentReportOut']>, IncidentReportOut>;
  IntegrationOut: Response<Wire<Schemas['IntegrationOut']>, IntegrationOut>;
  IntegrationTestOut: Response<Wire<Schemas['IntegrationTestOut']>, IntegrationTestOut>;
  LlmTestOut: Response<Wire<Schemas['LLMTestOut']>, LlmTestOut>;
  LlmTierCheckOut: Response<Wire<Schemas['LLMTierCheckOut']>, LlmTierCheckOut>;
  MeOut: Response<Wire<Schemas['MeOut']>, MeOut>;
  MfaChallengeOut: Response<Wire<Schemas['MfaChallengeOut']>, MfaChallengeOut>;
  MfaConfirmOut: Response<Wire<Schemas['MfaConfirmOut']>, MfaConfirmOut>;
  MfaEnrollOut: Response<Wire<Schemas['MfaEnrollOut']>, MfaEnrollOut>;
  MfaStatusOut: Response<Wire<Schemas['MfaStatusOut']>, MfaStatusOut>;
  MicrosoftActionSupportOut: Response<Wire<Schemas['MicrosoftActionSupportOut']>, MicrosoftActionSupportOut>;
  MicrosoftCapabilityCheck: Response<Wire<Schemas['CapabilityCheck']>, MicrosoftCapabilityCheck>;
  MicrosoftCapabilityOut: Response<Wire<Schemas['MicrosoftCapabilityOut']>, MicrosoftCapabilityOut>;
  MicrosoftCatalogOut: Response<Wire<Schemas['MicrosoftCatalogOut']>, MicrosoftCatalogOut>;
  MicrosoftPermissionCheck: Response<Wire<Schemas['PermissionCheck']>, MicrosoftPermissionCheck>;
  MicrosoftPermissionOut: Response<Wire<Schemas['MicrosoftPermissionOut']>, MicrosoftPermissionOut>;
  MicrosoftProbeCheck: Response<Wire<Schemas['ProbeCheck']>, MicrosoftProbeCheck>;
  MicrosoftTestReport: Response<Wire<Schemas['MicrosoftTestReport']>, MicrosoftTestReport>;
  MicrosoftTokenCheck: Response<Wire<Schemas['TokenCheck']>, MicrosoftTokenCheck>;
  MonthlyReportOut: Response<Wire<Schemas['MonthlyReport']>, MonthlyReportOut>;
  OnboardingStatusOut: Response<Wire<Schemas['OnboardingStatusOut']>, OnboardingStatusOut>;
  OnboardingStepOut: Response<Wire<Schemas['OnboardingStepOut']>, OnboardingStepOut>;
  PlatformEscalationOut: Response<Wire<Schemas['PlatformEscalationOut']>, PlatformEscalationOut>;
  PreviewActionOut: Response<Wire<Schemas['PreviewActionOut']>, PreviewActionOut>;
  PreviewConnectorOut: Response<Wire<Schemas['PreviewConnectorOut']>, PreviewConnectorOut>;
  PreviewGuardrailOut: Response<Wire<Schemas['PreviewGuardrailOut']>, PreviewGuardrailOut>;
  RateInterval: Response<Wire<Schemas['RateInterval']>, RateInterval>;
  RecoveryCodesOut: Response<Wire<Schemas['RecoveryCodesOut']>, RecoveryCodesOut>;
  ReprocessOut: Response<Wire<Schemas['ReprocessOut']>, ReprocessOut>;
  ResponsePreviewOut: Response<Wire<Schemas['ResponsePreviewOut']>, ResponsePreviewOut>;
  ResponseRoutesOut: Response<Wire<Schemas['ResponseRoutesOut']>, ResponseRoutesOut>;
  RetentionLimits: Response<Wire<Schemas['RetentionLimitsOut']>, RetentionLimits>;
  ReviewBandOut: Response<Wire<Schemas['ReviewBandOut']>, ReviewBandOut>;
  RollbackEligibility: Response<Wire<Schemas['RollbackEligibilityOut']>, RollbackEligibility>;
  RollbackOut: Response<Wire<Schemas['RollbackOut']>, RollbackOut>;
  RouteOut: Response<Wire<Schemas['RouteOut']>, RouteOut>;
  RoutingOut: Response<Wire<Schemas['RoutingOut']>, RoutingOut>;
  SampleAlertsOut: Response<Wire<Schemas['SampleAlertsOut']>, SampleAlertsOut>;
  SetupOut: Response<Wire<Schemas['SetupOut']>, SetupOut>;
  ConfiguredModelOut: Response<Wire<Schemas['ConfiguredModelOut']>, ConfiguredModelOut>;
  EnvVarOut: Response<Wire<Schemas['EnvVarOut']>, EnvVarOut>;
  LlmProfileOut: Response<Wire<Schemas['LlmProfileOut']>, LlmProfileOut>;
  SourceOut: Response<Wire<Schemas['SourceOut']>, SourceOut>;
  SourceTestOut: Response<Wire<Schemas['SourceTestOut']>, SourceTestOut>;
  SuppressionOut: Response<Wire<Schemas['SuppressionOut']>, SuppressionOut>;
  SuppressionProposalOut: Response<Wire<Schemas['SuppressionProposalOut']>, SuppressionProposalOut>;
  TenantCreatedOut: Response<Wire<Schemas['TenantCreatedOut']>, TenantCreatedOut>;
  TenantErasedOut: Response<Wire<Schemas['TenantErasedOut']>, TenantErasedOut>;
  TenantErasureStatusOut: Response<Wire<Schemas['ErasureStatusOut']>, TenantErasureStatusOut>;
  TenantSettingsOut: Response<Wire<Schemas['TenantSettingsOut']>, TenantSettingsOut>;
  TenantStats: Response<Wire<Schemas['TenantStatsOut']>, TenantStats>;
  TenantSummaryOut: Response<Wire<Schemas['TenantSummaryOut']>, TenantSummaryOut>;
  TenantUsageOut: Response<Wire<Schemas['TenantUsageOut']>, TenantUsageOut>;
  TicketOut: Response<Wire<Schemas['TicketOut']>, TicketOut>;
  TokenOut: Response<Wire<Schemas['TokenOut']>, TokenOut>;
  UsageDayOut: Response<Wire<Schemas['UsageDayOut']>, UsageDayOut>;
  UsageOut: Response<Wire<Schemas['UsageOut']>, UsageOut>;
  UsageReportOut: Response<Wire<Schemas['UsageReportOut']>, UsageReportOut>;
  UserOut: Response<Wire<Schemas['UserOut']>, UserOut>;
  ValueDay: Response<Wire<Schemas['ValueDay']>, ValueDay>;
  ValueMetrics: Response<Wire<Schemas['ValueMetrics']>, ValueMetrics>;
  ValueReportOut: Response<Wire<Schemas['ValueReport']>, ValueReportOut>;
  Page_ActionOut: Response<Wire<Schemas['PageOut_ActionOut_']>, Page<ActionOut>>;
  Page_AlertEventOut: Response<Wire<Schemas['PageOut_AlertEventOut_']>, Page<AlertEventOut>>;
  Page_AlertOut: Response<Wire<Schemas['PageOut_AlertOut_']>, Page<AlertOut>>;
  Page_AuditEntryOut: Response<Wire<Schemas['PageOut_AuditEntryOut_']>, Page<AuditEntryOut>>;
  Page_BlindAuditItemOut: Response<Wire<Schemas['PageOut_BlindAuditItemOut_']>, Page<BlindAuditItemOut>>;
  Page_BlindAuditRunSummary: Response<Wire<Schemas['PageOut_BlindAuditRunSummary_']>, Page<BlindAuditRunSummary>>;
  Page_EscalationOut: Response<Wire<Schemas['PageOut_EscalationOut_']>, Page<EscalationOut>>;
  Page_PlatformEscalationOut: Response<Wire<Schemas['PageOut_PlatformEscalationOut_']>, Page<PlatformEscalationOut>>;
}

export interface RequestContract {
  BlindAuditLabelIn: Request<BlindAuditLabelIn, Schemas['BlindAuditLabelIn']>;
  BlindAuditSampleIn: Request<BlindAuditSampleIn, Schemas['BlindAuditSampleIn']>;
  BulkClaimIn: Request<BulkClaimIn, Schemas['BulkClaimIn']>;
  BulkCloseIn: Request<BulkCloseIn, Schemas['BulkCloseIn']>;
  BulkItemIn: Request<BulkItemIn, Schemas['BulkItemIn']>;
  BulkProposeSuppressionIn: Request<BulkProposeSuppressionIn, Schemas['BulkProposeSuppressionIn']>;
  DecisionIn: Request<DecisionIn, Schemas['DecisionIn']>;
  FeedbackIn: Request<FeedbackIn, Schemas['FeedbackIn']>;
  IntegrationCreateIn: Request<IntegrationCreateIn, Schemas['IntegrationCreateIn']>;
  IntegrationUpdateIn: Request<IntegrationUpdateIn, Schemas['IntegrationUpdateIn']>;
  ProposeSuppressionIn: Request<ProposeSuppressionIn, Schemas['ProposeSuppressionIn']>;
  SetupIn: Request<SetupIn, Schemas['SetupIn']>;
  SourceCreateIn: Request<SourceCreateIn, Schemas['SourceCreateIn']>;
  SourceUpdateIn: Request<SourceUpdateIn, Schemas['SourceUpdateIn']>;
  SuppressionCreateIn: Request<SuppressionCreateIn, Schemas['SuppressionCreateIn']>;
  SuppressionUpdateIn: Request<SuppressionUpdateIn, Schemas['SuppressionUpdateIn']>;
  TenantCreateIn: Request<TenantCreateIn, Schemas['TenantCreateIn']>;
  TenantUpdateIn: Request<TenantUpdateIn, Schemas['TenantUpdateIn']>;
  UserCreateIn: Request<UserCreateIn, Schemas['UserCreateIn']>;
  UserUpdateIn: Request<UserUpdateIn, Schemas['UserUpdateIn']>;
  Quotas: Request<Quotas, Schemas['QuotasIn']>;
}
