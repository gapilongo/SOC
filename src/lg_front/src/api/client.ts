/**
 * HTTP client for the LG-SOTF API.
 *
 * * Every request carries a generated `X-Request-ID` so failures can be
 *   correlated with server logs even when no response arrives.
 * * The access token comes from the auth bridge (memory only). On a 401 the
 *   client asks the bridge for a refresh (single-flight inside the store)
 *   and retries the request once with the new token.
 * * Error responses are parsed from the API envelope
 *   `{"error": {"code", "message", "request_id", "details"?}}` into
 *   {@link ApiError}; anything else becomes a generic error with the status.
 */

export interface AuthBridge {
  /** Current access token, or null when signed out. */
  getToken(): string | null;
  /** Obtain a new access token (single-flight); null when the session is gone. */
  refresh(): Promise<string | null>;
  /** Tenant a platform admin acts on (`X-Tenant-ID`), or null for the home tenant. */
  actingTenant(): string | null;
}

export type QueryValue = string | number | boolean | null | undefined | ReadonlyArray<string | number>;
export type Query = Record<string, QueryValue>;

export interface RequestOptions {
  query?: Query;
  body?: unknown;
  signal?: AbortSignal;
  /** Do not attach or refresh credentials (login). */
  anonymous?: boolean;
  /** Send cookies (the refresh cookie lives under /api/v1/auth). */
  credentials?: RequestCredentials;
  /** Extra headers. */
  headers?: Record<string, string>;
  /** Never send the X-Tenant-ID override (platform endpoints act across tenants). */
  homeTenant?: boolean;
  /** How to read a successful body: parsed JSON (default), text, or a Blob (downloads). */
  responseType?: 'json' | 'text' | 'blob';
}

export class ApiError extends Error {
  readonly status: number;
  readonly code: string;
  readonly requestId: string | null;
  readonly details: unknown;
  readonly retryAfter: number | null;

  constructor(init: {
    status: number;
    code: string;
    message: string;
    requestId?: string | null;
    details?: unknown;
    retryAfter?: number | null;
  }) {
    super(init.message);
    this.name = 'ApiError';
    this.status = init.status;
    this.code = init.code;
    this.requestId = init.requestId ?? null;
    this.details = init.details;
    this.retryAfter = init.retryAfter ?? null;
  }

  get isConflict(): boolean {
    return this.status === 409;
  }

  /** Human-readable list of validation problems (422 `details`), if any. */
  get detailMessages(): string[] {
    const d = this.details;
    if (!Array.isArray(d)) return [];
    return d
      .map((item) => {
        if (typeof item === 'string') return item;
        if (item && typeof item === 'object') {
          const rec = item as Record<string, unknown>;
          const loc = Array.isArray(rec.loc) ? rec.loc.filter((p) => p !== 'body').join('.') : '';
          const msg = typeof rec.msg === 'string' ? rec.msg : JSON.stringify(item);
          return loc ? `${loc}: ${msg}` : msg;
        }
        return String(item);
      })
      .slice(0, 20);
  }
}

const STATUS_TEXT: Record<number, string> = {
  400: 'The request was not accepted.',
  401: 'You are not signed in.',
  403: 'You do not have permission to do that.',
  404: 'Not found.',
  409: 'The item changed or is in a conflicting state.',
  413: 'The request is too large.',
  422: 'Some values are invalid.',
  429: 'Too many requests. Try again shortly.',
  500: 'The server hit an unexpected error.',
  502: 'The API is unreachable (bad gateway).',
  503: 'A backend service is unavailable.',
  504: 'The API did not respond in time.',
};

export function newRequestId(): string {
  const c = globalThis.crypto;
  if (c && typeof c.randomUUID === 'function') return `web-${c.randomUUID()}`;
  const bytes = new Uint8Array(16);
  c.getRandomValues(bytes);
  return `web-${Array.from(bytes, (b) => b.toString(16).padStart(2, '0')).join('')}`;
}

export function buildQuery(query?: Query): string {
  if (!query) return '';
  const params = new URLSearchParams();
  for (const [key, value] of Object.entries(query)) {
    if (value === undefined || value === null || value === '') continue;
    if (Array.isArray(value)) {
      for (const v of value) params.append(key, String(v));
    } else {
      params.append(key, String(value));
    }
  }
  const text = params.toString();
  return text ? `?${text}` : '';
}

async function parseError(response: Response, requestId: string): Promise<ApiError> {
  const headerId = response.headers.get('x-request-id');
  const retry = response.headers.get('retry-after');
  const retryAfter = retry && /^\d+$/.test(retry) ? Number(retry) : null;
  let code = `http_${response.status}`;
  let message = STATUS_TEXT[response.status] ?? `Request failed with status ${response.status}.`;
  let details: unknown;
  let bodyId: string | null = null;
  try {
    const text = await response.text();
    if (text) {
      const parsed = JSON.parse(text) as unknown;
      const env = parsed && typeof parsed === 'object' ? (parsed as Record<string, unknown>).error : undefined;
      if (env && typeof env === 'object') {
        const e = env as Record<string, unknown>;
        if (typeof e.code === 'string') code = e.code;
        if (typeof e.message === 'string' && e.message) message = e.message;
        if (typeof e.request_id === 'string') bodyId = e.request_id;
        details = e.details;
      }
    }
  } catch {
    // Not JSON (a proxy error page): keep the generic message.
  }
  return new ApiError({
    status: response.status,
    code,
    message,
    requestId: bodyId ?? headerId ?? requestId,
    details,
    retryAfter,
  });
}

export interface ApiClient {
  request<T>(method: string, path: string, options?: RequestOptions): Promise<T>;
  get<T>(path: string, options?: RequestOptions): Promise<T>;
  post<T>(path: string, body?: unknown, options?: RequestOptions): Promise<T>;
  patch<T>(path: string, body?: unknown, options?: RequestOptions): Promise<T>;
  del<T = void>(path: string, options?: RequestOptions): Promise<T>;
}

export function createApiClient(opts: {
  baseUrl: string;
  auth: AuthBridge;
  fetchImpl?: typeof fetch;
}): ApiClient {
  const doFetch = (...args: Parameters<typeof fetch>) => (opts.fetchImpl ?? globalThis.fetch)(...args);

  async function send(method: string, path: string, options: RequestOptions, token: string | null) {
    const requestId = newRequestId();
    const headers: Record<string, string> = {
      Accept: options.responseType && options.responseType !== 'json' ? '*/*' : 'application/json',
      'X-Request-ID': requestId,
      ...(options.headers ?? {}),
    };
    if (options.body !== undefined) headers['Content-Type'] = 'application/json';
    if (token) headers.Authorization = `Bearer ${token}`;
    const acting = options.anonymous || options.homeTenant ? null : opts.auth.actingTenant();
    if (acting) headers['X-Tenant-ID'] = acting;
    let response: Response;
    try {
      response = await doFetch(`${opts.baseUrl}${path}${buildQuery(options.query)}`, {
        method,
        headers,
        body: options.body === undefined ? undefined : JSON.stringify(options.body),
        signal: options.signal,
        credentials: options.credentials ?? 'same-origin',
        cache: 'no-store',
        redirect: 'error',
      });
    } catch (err) {
      if (err instanceof DOMException && err.name === 'AbortError') throw err;
      throw new ApiError({
        status: 0,
        code: 'network_error',
        message: 'The API could not be reached. Check your connection and try again.',
        requestId,
      });
    }
    return { response, requestId };
  }

  async function request<T>(method: string, path: string, options: RequestOptions = {}): Promise<T> {
    const token = options.anonymous ? null : opts.auth.getToken();
    let { response, requestId } = await send(method, path, options, token);
    if (response.status === 401 && !options.anonymous) {
      const fresh = await opts.auth.refresh();
      if (fresh) {
        ({ response, requestId } = await send(method, path, options, fresh));
      }
    }
    if (!response.ok) throw await parseError(response, requestId);
    if (response.status === 204) return undefined as T;
    if (options.responseType === 'blob') return (await response.blob()) as T;
    const text = await response.text();
    if (options.responseType === 'text') return text as T;
    return (text ? JSON.parse(text) : undefined) as T;
  }

  return {
    request,
    get: (path, options) => request('GET', path, options),
    post: (path, body, options) => request('POST', path, { ...options, body }),
    patch: (path, body, options) => request('PATCH', path, { ...options, body }),
    del: (path, options) => request('DELETE', path, options),
  };
}

/** Message suitable for display, with the request id when there is one. */
export function describeError(err: unknown): { message: string; requestId: string | null; details: string[] } {
  if (err instanceof ApiError) return { message: err.message, requestId: err.requestId, details: err.detailMessages };
  if (err instanceof Error) return { message: err.message, requestId: null, details: [] };
  return { message: 'Something went wrong.', requestId: null, details: [] };
}
