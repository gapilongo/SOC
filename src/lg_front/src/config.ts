/**
 * Runtime configuration.
 *
 * The container generates `/config.js` at start-up from environment
 * variables, so one image serves every environment and nothing is baked in
 * at build time. The file only ever carries public values (URLs, the OIDC
 * client id); secrets never reach the browser.
 */

export interface OidcConfig {
  /** Issuer URL; its discovery document supplies the endpoints unless they are given below. */
  issuer: string;
  clientId: string;
  scope: string;
  /** Extra `audience` parameter some identity providers need for API access tokens. */
  audience: string | null;
  /** Which token the API accepts from this issuer: the access token (default) or the ID token. */
  tokenType: 'access_token' | 'id_token';
  /** Absolute redirect URI; defaults to `<origin>/auth/callback`. */
  redirectUri: string | null;
  authorizationEndpoint: string | null;
  tokenEndpoint: string | null;
  endSessionEndpoint: string | null;
  /** Button label on the sign-in page. */
  label: string;
}

/** The product's own name. A brand may show another name; this one stays in "on LG-SOTF" and in technical text. */
export const PRODUCT_NAME = 'LG-SOTF';

/**
 * How the console presents itself: a name, a logo and one accent colour. Everything that shows the
 * console's name reads it here (`getBrand()`), so an MSSP's name appears in the rail, on the sign-in
 * page and in the browser tab alike. Severity, state and verdict colours are not part of a brand.
 */
export interface Brand {
  name: string;
  /** The line under the name in the rail. */
  tagline: string;
  /** Same-origin path of a logo image (the CSP allows `img-src 'self'`), or null for the built-in mark. */
  logoUrl: string | null;
  /** The accent as `#RRGGBB`, or null for the product's own (the values in theme/tokens.css). */
  accent: string | null;
}

/** The product's own brand: what the console shows when the configuration names none. */
export const PRODUCT_BRAND: Brand = { name: PRODUCT_NAME, tagline: 'Security operations', logoUrl: null, accent: null };

export interface RuntimeConfig {
  /** Origin (and optional path prefix) of the API; empty means same origin. No trailing slash. */
  apiBaseUrl: string;
  /** Full WebSocket URL of `/api/v1/ws`; empty derives it from apiBaseUrl or the page origin. */
  wsUrl: string;
  oidc: OidcConfig | null;
  brand: Brand;
}

declare global {
  interface Window {
    __LG_SOTF_CONFIG__?: unknown;
  }
}

function str(value: unknown): string {
  return typeof value === 'string' ? value.trim() : '';
}

function httpUrl(value: string, field: string, stripSlash = true): string {
  if (!value) return '';
  let parsed: URL;
  try {
    parsed = new URL(value);
  } catch {
    throw new Error(`config.${field} is not a URL`);
  }
  if (parsed.protocol !== 'https:' && parsed.protocol !== 'http:') {
    throw new Error(`config.${field} must be an http(s) URL`);
  }
  if (parsed.username || parsed.password) throw new Error(`config.${field} must not contain credentials`);
  return stripSlash ? value.replace(/\/+$/, '') : value;
}

function wsUrlValue(value: string): string {
  if (!value) return '';
  let parsed: URL;
  try {
    parsed = new URL(value);
  } catch {
    throw new Error('config.wsUrl is not a URL');
  }
  if (parsed.protocol !== 'wss:' && parsed.protocol !== 'ws:') throw new Error('config.wsUrl must be a ws(s) URL');
  return value;
}

function parseOidc(raw: unknown): OidcConfig | null {
  if (!raw || typeof raw !== 'object') return null;
  const o = raw as Record<string, unknown>;
  // Kept exactly as configured: issuers are compared as strings and some
  // providers (e.g. Auth0) end theirs with '/'.
  const issuer = httpUrl(str(o.issuer), 'oidc.issuer', false);
  const clientId = str(o.clientId);
  if (!issuer || !clientId) return null;
  const tokenType = str(o.tokenType) === 'id_token' ? 'id_token' : 'access_token';
  return {
    issuer,
    clientId,
    scope: str(o.scope) || 'openid profile email',
    audience: str(o.audience) || null,
    tokenType,
    redirectUri: httpUrl(str(o.redirectUri), 'oidc.redirectUri') || null,
    authorizationEndpoint: httpUrl(str(o.authorizationEndpoint), 'oidc.authorizationEndpoint') || null,
    tokenEndpoint: httpUrl(str(o.tokenEndpoint), 'oidc.tokenEndpoint') || null,
    endSessionEndpoint: httpUrl(str(o.endSessionEndpoint), 'oidc.endSessionEndpoint') || null,
    label: str(o.label) || 'Sign in with single sign-on',
  };
}

/** `brand` of the runtime configuration: `{ name, logoUrl, accent }`, each optional. */
function parseBrand(raw: unknown): Brand {
  if (!raw || typeof raw !== 'object') return PRODUCT_BRAND;
  const o = raw as Record<string, unknown>;
  const name = str(o.name);
  const logoUrl = str(o.logoUrl);
  const accent = str(o.accent);
  if (name.length > 40) throw new Error('config.brand.name is longer than 40 characters');
  if (logoUrl && !/^\/(?!\/)[A-Za-z0-9._~/-]*$/.test(logoUrl)) throw new Error('config.brand.logoUrl must be a path on this site, such as /brand/logo.svg');
  if (accent && !/^#[0-9a-f]{6}$/i.test(accent)) throw new Error('config.brand.accent must be a colour written as # and six hex digits');
  return {
    name: name || PRODUCT_NAME,
    // Another name runs on the product; the product itself says what it is for.
    tagline: name && name !== PRODUCT_NAME ? `on ${PRODUCT_NAME}` : PRODUCT_BRAND.tagline,
    logoUrl: logoUrl || null,
    accent: accent ? accent.toUpperCase() : null,
  };
}

/** Validate the raw `window.__LG_SOTF_CONFIG__` object (missing values fall back to same-origin defaults). */
export function parseConfig(raw: unknown): RuntimeConfig {
  const o = raw && typeof raw === 'object' ? (raw as Record<string, unknown>) : {};
  return {
    apiBaseUrl: httpUrl(str(o.apiBaseUrl), 'apiBaseUrl'),
    wsUrl: wsUrlValue(str(o.wsUrl)),
    oidc: parseOidc(o.oidc),
    brand: parseBrand(o.brand),
  };
}

let cached: RuntimeConfig | null = null;

export function getConfig(): RuntimeConfig {
  if (!cached) cached = parseConfig(typeof window === 'undefined' ? undefined : window.__LG_SOTF_CONFIG__);
  return cached;
}

/** The console's name, logo and accent (the product's own unless the configuration sets a brand). */
export function getBrand(): Brand {
  return getConfig().brand;
}

export const API_PREFIX = '/api/v1';

export function apiRoot(config: RuntimeConfig = getConfig()): string {
  return `${config.apiBaseUrl}${API_PREFIX}`;
}

/** The WebSocket endpoint: explicit `wsUrl`, else derived from `apiBaseUrl` or the page origin. */
export function wsEndpoint(config: RuntimeConfig = getConfig(), location: Pick<Location, 'protocol' | 'host'> = window.location): string {
  if (config.wsUrl) return config.wsUrl;
  if (config.apiBaseUrl) {
    const url = new URL(config.apiBaseUrl);
    const scheme = url.protocol === 'https:' ? 'wss:' : 'ws:';
    return `${scheme}//${url.host}${url.pathname.replace(/\/+$/, '')}${API_PREFIX}/ws`;
  }
  const scheme = location.protocol === 'https:' ? 'wss:' : 'ws:';
  return `${scheme}//${location.host}${API_PREFIX}/ws`;
}
