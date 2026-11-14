/**
 * The API shapes every module shares: who the caller is (sign-in, MFA, `GET /auth/me`), the paging
 * envelope, the live event envelope and the open-vocabulary helpers. A module's own request and
 * response types live in its API slice (`src/modules/<id>/api/types.ts`, ADR 0015). The OpenAPI
 * document at /api/v1/openapi.json is the source of truth; contract.check.ts holds these to it.
 */

export type Role = 'viewer' | 'analyst' | 'admin';

/**
 * A vocabulary field of a response: the values this app knows, or another string from a newer API
 * (tolerant reader: a rolling deploy must not break the UI). Narrow it before indexing a lookup table.
 */
export type Open<T extends string> = T | (string & {});

/** Narrows an open vocabulary value (or any input) to one of `values`. */
export function isOneOf<T extends string>(values: readonly T[], value: unknown): value is T {
  return typeof value === 'string' && (values as readonly string[]).includes(value);
}

export type JsonObject = Record<string, unknown>;

export interface Page<T> {
  items: T[];
  next_cursor?: string | null;
}

export interface UserOut {
  id: string;
  tenant_id: string;
  email: string;
  role: Open<Role>;
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

export interface MeOut {
  kind: 'user' | 'api_key';
  tenant_id: string;
  home_tenant_id: string;
  auth_method: string;
  role?: Open<Role> | null;
  scopes?: string[];
  user_id?: string | null;
  api_key_id?: string | null;
  email?: string | null;
  is_platform_admin?: boolean;
  expires_at?: string | null;
  /** Display name of `tenant_id` (newer APIs; the header falls back to the id). */
  tenant_name?: string | null;
}

/**
 * Live event envelope pushed on /ws. `type` is `<resource>.<change>`; each module's manifest lists the
 * types it listens to (`liveEvents`), and the socket drops the others.
 */
export interface LiveEvent {
  type: string;
  tenant_id: string;
  alert_id: string | null;
  data: JsonObject;
  ts: string;
}
