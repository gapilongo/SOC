/**
 * OIDC sign-in: authorization code flow with PKCE (S256), for a public
 * client. Tokens are kept in memory by the auth store; only the transient
 * PKCE verifier, state and nonce are kept in sessionStorage across the
 * redirect to the identity provider (they are useless without the
 * authorization code and are deleted as soon as the callback is handled).
 */

import type { OidcConfig } from '../config';

const PENDING_KEY = 'lg-sotf.oidc.pending';
const PENDING_MAX_AGE_MS = 10 * 60 * 1000;
export const CALLBACK_PATH = '/auth/callback';

export interface OidcEndpoints {
  authorization: string;
  token: string;
  endSession: string | null;
}

interface Pending {
  state: string;
  verifier: string;
  nonce: string;
  returnTo: string;
  createdAt: number;
}

export interface OidcTokens {
  token: string;
  expiresIn: number;
  refreshToken: string | null;
}

export class OidcError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'OidcError';
  }
}

export function base64url(bytes: Uint8Array): string {
  let bin = '';
  for (const b of bytes) bin += String.fromCharCode(b);
  return btoa(bin).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

export function randomToken(size = 32): string {
  const bytes = new Uint8Array(size);
  crypto.getRandomValues(bytes);
  return base64url(bytes);
}

export async function pkceChallenge(verifier: string): Promise<string> {
  const digest = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(verifier));
  return base64url(new Uint8Array(digest));
}

export function redirectUri(config: OidcConfig, origin: string = window.location.origin): string {
  return config.redirectUri ?? `${origin}${CALLBACK_PATH}`;
}

/** Only same-app relative paths may be used as a post-login destination (no open redirects). */
export function safeReturnTo(value: string | null | undefined): string {
  if (!value || !value.startsWith('/') || value.startsWith('//') || value.startsWith('/\\')) return '/';
  if (value.startsWith(CALLBACK_PATH) || value.startsWith('/login')) return '/';
  return value;
}

let discovered: { issuer: string; endpoints: OidcEndpoints } | null = null;

function trimSlash(value: string): string {
  return value.replace(/\/+$/, '');
}

/** Issuer identifiers match when they are equal up to a trailing '/'. */
export function sameIssuer(a: string, b: string): boolean {
  return trimSlash(a) === trimSlash(b);
}

function isHttpUrl(value: string): boolean {
  return value.startsWith('https://') || value.startsWith('http://');
}

/**
 * A URL the browser may be sent to on sign-out: https, or http on a
 * loopback host (local development). Anything else (javascript:, data:,
 * plain http to a remote host) is refused.
 */
export function safeNavigationUrl(value: unknown): string | null {
  if (typeof value !== 'string' || !value) return null;
  let parsed: URL;
  try {
    parsed = new URL(value);
  } catch {
    return null;
  }
  if (parsed.username || parsed.password) return null;
  if (parsed.protocol === 'https:') return value;
  const loopback = parsed.hostname === 'localhost' || parsed.hostname === '127.0.0.1' || parsed.hostname === '[::1]';
  return parsed.protocol === 'http:' && loopback ? value : null;
}

export async function endpoints(config: OidcConfig, fetchImpl: typeof fetch = fetch): Promise<OidcEndpoints> {
  if (config.authorizationEndpoint && config.tokenEndpoint) {
    return {
      authorization: config.authorizationEndpoint,
      token: config.tokenEndpoint,
      endSession: config.endSessionEndpoint,
    };
  }
  if (discovered && discovered.issuer === config.issuer) return discovered.endpoints;
  const response = await fetchImpl(`${trimSlash(config.issuer)}/.well-known/openid-configuration`, {
    headers: { Accept: 'application/json' },
    credentials: 'omit',
  });
  if (!response.ok) throw new OidcError('The identity provider could not be reached.');
  const doc = (await response.json()) as Record<string, unknown>;
  if (typeof doc.issuer !== 'string' || !sameIssuer(doc.issuer, config.issuer)) {
    throw new OidcError('The identity provider reported a different issuer.');
  }
  const auth = config.authorizationEndpoint ?? (typeof doc.authorization_endpoint === 'string' ? doc.authorization_endpoint : '');
  const token = config.tokenEndpoint ?? (typeof doc.token_endpoint === 'string' ? doc.token_endpoint : '');
  if (!isHttpUrl(auth)) throw new OidcError('Invalid authorization endpoint.');
  if (!isHttpUrl(token)) throw new OidcError('Invalid token endpoint.');
  // Navigated to on sign-out: an unsafe value from the discovery document is dropped.
  const endSession = config.endSessionEndpoint ?? safeNavigationUrl(doc.end_session_endpoint);
  const result = { authorization: auth, token, endSession };
  discovered = { issuer: config.issuer, endpoints: result };
  return result;
}

/** Build the authorization URL and remember the PKCE material for the callback. */
export async function beginLogin(
  config: OidcConfig,
  returnTo: string,
  deps: { fetchImpl?: typeof fetch; storage?: Storage; now?: () => number } = {},
): Promise<string> {
  const ep = await endpoints(config, deps.fetchImpl);
  const pending: Pending = {
    state: randomToken(),
    verifier: randomToken(48),
    nonce: randomToken(),
    returnTo: safeReturnTo(returnTo),
    createdAt: (deps.now ?? Date.now)(),
  };
  (deps.storage ?? sessionStorage).setItem(PENDING_KEY, JSON.stringify(pending));
  const url = new URL(ep.authorization);
  url.searchParams.set('response_type', 'code');
  url.searchParams.set('client_id', config.clientId);
  url.searchParams.set('redirect_uri', redirectUri(config));
  url.searchParams.set('scope', config.scope);
  url.searchParams.set('state', pending.state);
  url.searchParams.set('nonce', pending.nonce);
  url.searchParams.set('code_challenge', await pkceChallenge(pending.verifier));
  url.searchParams.set('code_challenge_method', 'S256');
  if (config.audience) url.searchParams.set('audience', config.audience);
  return url.toString();
}

function decodeJwtPayload(token: string): Record<string, unknown> | null {
  const parts = token.split('.');
  if (parts.length !== 3) return null;
  try {
    const json = atob(parts[1].replace(/-/g, '+').replace(/_/g, '/'));
    return JSON.parse(json) as Record<string, unknown>;
  } catch {
    return null;
  }
}

async function tokenRequest(tokenUrl: string, body: URLSearchParams, fetchImpl: typeof fetch): Promise<Record<string, unknown>> {
  const response = await fetchImpl(tokenUrl, {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded', Accept: 'application/json' },
    body: body.toString(),
    credentials: 'omit',
  });
  const data = (await response.json().catch(() => ({}))) as Record<string, unknown>;
  if (!response.ok) {
    const reason = typeof data.error === 'string' ? data.error : `status ${response.status}`;
    throw new OidcError(`The identity provider refused the sign-in (${reason}).`);
  }
  return data;
}

function pickToken(config: OidcConfig, data: Record<string, unknown>, now: number): OidcTokens {
  const refreshToken = typeof data.refresh_token === 'string' ? data.refresh_token : null;
  if (config.tokenType === 'id_token') {
    const idToken = typeof data.id_token === 'string' ? data.id_token : '';
    const payload = decodeJwtPayload(idToken);
    if (!idToken || !payload) throw new OidcError('The identity provider returned no ID token.');
    const exp = typeof payload.exp === 'number' ? payload.exp : 0;
    return { token: idToken, expiresIn: Math.max(1, Math.floor(exp - now / 1000)), refreshToken };
  }
  const accessToken = typeof data.access_token === 'string' ? data.access_token : '';
  if (!accessToken) throw new OidcError('The identity provider returned no access token.');
  const expiresIn = typeof data.expires_in === 'number' ? data.expires_in : 300;
  return { token: accessToken, expiresIn, refreshToken };
}

/** Handle the redirect back from the identity provider. */
export async function completeLogin(
  config: OidcConfig,
  callbackUrl: string,
  deps: { fetchImpl?: typeof fetch; storage?: Storage; now?: () => number } = {},
): Promise<OidcTokens & { returnTo: string }> {
  const storage = deps.storage ?? sessionStorage;
  const now = (deps.now ?? Date.now)();
  const raw = storage.getItem(PENDING_KEY);
  storage.removeItem(PENDING_KEY);
  const params = new URL(callbackUrl).searchParams;
  const error = params.get('error');
  if (error) throw new OidcError(`Sign-in was not completed (${error}).`);
  if (!raw) throw new OidcError('No sign-in is in progress in this tab. Start again.');
  const pending = JSON.parse(raw) as Pending;
  if (now - pending.createdAt > PENDING_MAX_AGE_MS) throw new OidcError('The sign-in took too long. Start again.');
  const state = params.get('state');
  const code = params.get('code');
  if (!state || state !== pending.state) throw new OidcError('The sign-in response did not match this session.');
  if (!code) throw new OidcError('The identity provider returned no authorization code.');
  const fetchImpl = deps.fetchImpl ?? fetch;
  const ep = await endpoints(config, fetchImpl);
  const data = await tokenRequest(
    ep.token,
    new URLSearchParams({
      grant_type: 'authorization_code',
      code,
      redirect_uri: redirectUri(config),
      client_id: config.clientId,
      code_verifier: pending.verifier,
    }),
    fetchImpl,
  );
  if (typeof data.id_token === 'string') {
    const payload = decodeJwtPayload(data.id_token);
    if (!payload || payload.nonce !== pending.nonce) throw new OidcError('The ID token nonce did not match.');
  }
  return { ...pickToken(config, data, now), returnTo: safeReturnTo(pending.returnTo) };
}

export async function refreshOidc(
  config: OidcConfig,
  refreshToken: string,
  fetchImpl: typeof fetch = fetch,
): Promise<OidcTokens | null> {
  const ep = await endpoints(config, fetchImpl);
  try {
    const data = await tokenRequest(
      ep.token,
      new URLSearchParams({ grant_type: 'refresh_token', refresh_token: refreshToken, client_id: config.clientId }),
      fetchImpl,
    );
    return pickToken(config, data, Date.now());
  } catch (err) {
    if (err instanceof OidcError) return null;
    throw err;
  }
}

/** The identity provider's end-session URL (RP-initiated logout), or null when it has none. */
export async function logoutUrl(config: OidcConfig, origin: string = window.location.origin, fetchImpl: typeof fetch = fetch): Promise<string | null> {
  let ep: OidcEndpoints;
  try {
    ep = await endpoints(config, fetchImpl);
  } catch {
    return null;
  }
  const endSession = ep.endSession && isHttpUrl(ep.endSession) ? ep.endSession : null;
  if (!endSession) return null;
  const url = new URL(endSession);
  url.searchParams.set('client_id', config.clientId);
  url.searchParams.set('post_logout_redirect_uri', `${origin}/login`);
  return url.toString();
}

/** Test hook. */
export function resetOidcDiscovery(): void {
  discovered = null;
}
