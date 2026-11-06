import { describe, expect, it, vi } from 'vitest';

import { ApiError, buildQuery, createApiClient, describeError, type AuthBridge } from './client';

function json(status: number, body: unknown, headers: Record<string, string> = {}) {
  return new Response(body === undefined ? null : JSON.stringify(body), { status, headers: { 'content-type': 'application/json', ...headers } });
}

function bridge(overrides: Partial<AuthBridge> = {}): AuthBridge {
  return { getToken: () => 'tok-1', refresh: vi.fn(async () => null), actingTenant: () => null, ...overrides };
}

function headerOf(call: unknown[], name: string): string | undefined {
  const init = call[1] as RequestInit;
  return (init.headers as Record<string, string>)[name];
}

describe('api client', () => {
  it('parses the error envelope with code, message, details and request id', async () => {
    const fetchImpl = vi.fn(async () =>
      json(422, { error: { code: 'invalid_settings', message: 'tenant settings are invalid', request_id: 'req-abc-12345', details: ['autonomy.low: bad value', { loc: ['body', 'name'], msg: 'field required' }] } }),
    );
    const api = createApiClient({ baseUrl: '/api/v1', auth: bridge(), fetchImpl });
    const err = await api.patch('/tenant/settings', {}).catch((e: unknown) => e);
    expect(err).toBeInstanceOf(ApiError);
    const e = err as ApiError;
    expect(e.status).toBe(422);
    expect(e.code).toBe('invalid_settings');
    expect(e.message).toBe('tenant settings are invalid');
    expect(e.requestId).toBe('req-abc-12345');
    expect(e.detailMessages).toEqual(['autonomy.low: bad value', 'name: field required']);
    expect(describeError(e)).toEqual({ message: 'tenant settings are invalid', requestId: 'req-abc-12345', details: e.detailMessages });
  });

  it('returns the raw body for text responses (CSV and HTML exports)', async () => {
    const fetchImpl = vi.fn(async () => new Response('day,alerts\r\n2026-09-01,3\r\n', { status: 200, headers: { 'content-type': 'text/csv' } }));
    const api = createApiClient({ baseUrl: '/api/v1', auth: bridge(), fetchImpl });
    const text = await api.get<string>('/reports/value', { query: { format: 'csv' }, responseType: 'text' });
    expect(text).toBe('day,alerts\r\n2026-09-01,3\r\n');
    expect(headerOf(fetchImpl.mock.calls[0] as unknown[], 'Authorization')).toBe('Bearer tok-1');
  });

  it('falls back to a generic message and the response request id for non-JSON errors', async () => {
    const fetchImpl = vi.fn(async () => new Response('<html>Bad gateway</html>', { status: 502, headers: { 'x-request-id': 'edge-req-99999' } }));
    const api = createApiClient({ baseUrl: '', auth: bridge(), fetchImpl });
    const e = (await api.get('/alerts').catch((x: unknown) => x)) as ApiError;
    expect(e.status).toBe(502);
    expect(e.code).toBe('http_502');
    expect(e.message).toMatch(/unreachable/);
    expect(e.requestId).toBe('edge-req-99999');
  });

  it('reports network failures with the request id it generated', async () => {
    const fetchImpl = vi.fn(async () => {
      throw new TypeError('Failed to fetch');
    });
    const api = createApiClient({ baseUrl: '', auth: bridge(), fetchImpl });
    const e = (await api.get('/alerts').catch((x: unknown) => x)) as ApiError;
    expect(e.status).toBe(0);
    expect(e.code).toBe('network_error');
    const sent = headerOf(fetchImpl.mock.calls[0] as unknown[], 'X-Request-ID');
    expect(sent).toMatch(/^[A-Za-z0-9._:-]{8,128}$/);
    expect(e.requestId).toBe(sent);
  });

  it('exposes Retry-After on 429', async () => {
    const fetchImpl = vi.fn(async () => json(429, { error: { code: 'rate_limited', message: 'slow down', request_id: 'r-12345678' } }, { 'retry-after': '17' }));
    const api = createApiClient({ baseUrl: '', auth: bridge(), fetchImpl });
    const e = (await api.get('/alerts').catch((x: unknown) => x)) as ApiError;
    expect(e.retryAfter).toBe(17);
  });

  it('refreshes once on 401 and retries with the new token', async () => {
    const fetchImpl = vi
      .fn()
      .mockResolvedValueOnce(json(401, { error: { code: 'unauthorized', message: 'expired', request_id: 'r-00000001' } }))
      .mockResolvedValueOnce(json(200, { ok: true }));
    const refresh = vi.fn(async () => 'tok-2');
    const api = createApiClient({ baseUrl: '/api/v1', auth: bridge({ refresh }), fetchImpl });
    await expect(api.get('/auth/me')).resolves.toEqual({ ok: true });
    expect(refresh).toHaveBeenCalledTimes(1);
    expect(headerOf(fetchImpl.mock.calls[0], 'Authorization')).toBe('Bearer tok-1');
    expect(headerOf(fetchImpl.mock.calls[1], 'Authorization')).toBe('Bearer tok-2');
  });

  it('surfaces the 401 when the session cannot be refreshed', async () => {
    const fetchImpl = vi.fn(async () => json(401, { error: { code: 'invalid_session', message: 'session ended', request_id: 'r-00000002' } }));
    const api = createApiClient({ baseUrl: '', auth: bridge(), fetchImpl });
    const e = (await api.get('/alerts').catch((x: unknown) => x)) as ApiError;
    expect(e.status).toBe(401);
    expect(fetchImpl).toHaveBeenCalledTimes(1);
  });

  it('never refreshes for anonymous calls such as login', async () => {
    const fetchImpl = vi.fn(async () => json(401, { error: { code: 'invalid_credentials', message: 'no', request_id: 'r-00000003' } }));
    const refresh = vi.fn(async () => 'x');
    const api = createApiClient({ baseUrl: '', auth: bridge({ refresh }), fetchImpl });
    await expect(api.post('/auth/login', { email: 'a', password: 'b' }, { anonymous: true })).rejects.toMatchObject({ code: 'invalid_credentials' });
    expect(refresh).not.toHaveBeenCalled();
    expect(headerOf(fetchImpl.mock.calls[0] as unknown[], 'Authorization')).toBeUndefined();
  });

  it('sends X-Tenant-ID when a platform admin acts on another tenant', async () => {
    const fetchImpl = vi.fn(async () => json(200, []));
    const api = createApiClient({ baseUrl: '', auth: bridge({ actingTenant: () => 'globex' }), fetchImpl });
    await api.get('/sources');
    expect(headerOf(fetchImpl.mock.calls[0] as unknown[], 'X-Tenant-ID')).toBe('globex');
    // Platform endpoints act across tenants and never carry the override.
    await api.get('/platform/tenants', { homeTenant: true });
    expect(headerOf(fetchImpl.mock.calls[1] as unknown[], 'X-Tenant-ID')).toBeUndefined();
    expect(headerOf(fetchImpl.mock.calls[1] as unknown[], 'Authorization')).toBe('Bearer tok-1');
  });

  it('returns undefined for 204 responses', async () => {
    const fetchImpl = vi.fn(async () => new Response(null, { status: 204 }));
    const api = createApiClient({ baseUrl: '', auth: bridge(), fetchImpl });
    await expect(api.del('/users/1')).resolves.toBeUndefined();
  });

  it('reads text and blob bodies on request, after a refresh-and-retry on 401', async () => {
    let calls = 0;
    const fetchImpl = vi.fn(async () => {
      calls += 1;
      if (calls === 1) return json(401, { error: { code: 'unauthorized', message: 'expired', request_id: 'r-00000001' } });
      return new Response('<!doctype html><title>pack</title>', { status: 200, headers: { 'content-type': 'text/html' } });
    });
    const refresh = vi.fn(async () => 'tok-2');
    const api = createApiClient({ baseUrl: '', auth: bridge({ refresh }), fetchImpl });
    await expect(api.get<string>('/alerts/a-1/evidence', { query: { format: 'html' }, responseType: 'text' })).resolves.toBe(
      '<!doctype html><title>pack</title>',
    );
    expect(refresh).toHaveBeenCalledTimes(1);
    expect(headerOf(fetchImpl.mock.calls[1] as unknown[], 'Authorization')).toBe('Bearer tok-2');
    expect(headerOf(fetchImpl.mock.calls[1] as unknown[], 'Accept')).toBe('*/*');

    const blob = await api.post<Blob>('/platform/tenants/acme/export', undefined, { responseType: 'blob' });
    expect(blob.type).toBe('text/html');
    expect(await blob.text()).toContain('pack');
  });

  it('still parses the error envelope when a blob was requested', async () => {
    const fetchImpl = vi.fn(async () => json(404, { error: { code: 'not_found', message: 'no such tenant', request_id: 'r-00000002' } }));
    const api = createApiClient({ baseUrl: '', auth: bridge(), fetchImpl });
    const e = (await api.post('/platform/tenants/x/export', undefined, { responseType: 'blob' }).catch((x: unknown) => x)) as ApiError;
    expect(e.code).toBe('not_found');
    expect(e.message).toBe('no such tenant');
  });

  it('builds repeated multi-valued query parameters and skips empty ones', () => {
    expect(buildQuery({ status: ['queued', 'failed'], q: '', cursor: undefined, limit: 100, from: null })).toBe('?status=queued&status=failed&limit=100');
    expect(buildQuery({})).toBe('');
  });
});

describe('successful bodies', () => {
  const client = (response: () => Response) => createApiClient({ baseUrl: '/api/v1', auth: bridge(), fetchImpl: vi.fn(async () => response()) });

  it('raises invalid_response for a 200 with an HTML page (a misrouted index.html)', async () => {
    const api = client(() => new Response('<!doctype html><html><body>app</body></html>', { status: 200, headers: { 'content-type': 'text/html', 'x-request-id': 'edge-req-4242' } }));
    const e = (await api.get('/alerts').catch((x: unknown) => x)) as ApiError;
    expect(e).toBeInstanceOf(ApiError);
    expect(e.status).toBe(200);
    expect(e.code).toBe('invalid_response');
    expect(e.requestId).toBe('edge-req-4242');
    expect(e.message).toMatch(/could not be read/);
  });

  it('raises invalid_response for a JSON content type with a body that is not JSON', async () => {
    const api = client(() => new Response('{"items": [', { status: 200, headers: { 'content-type': 'application/json' } }));
    const e = (await api.get('/alerts').catch((x: unknown) => x)) as ApiError;
    expect(e).toBeInstanceOf(ApiError);
    expect(e.code).toBe('invalid_response');
    expect(e.requestId).toMatch(/^web-/);
  });

  it('raises invalid_response for a JSON body without a JSON content type', async () => {
    const api = client(() => new Response('{"ok": true}', { status: 200, headers: { 'content-type': 'text/plain' } }));
    await expect(api.get('/alerts')).rejects.toMatchObject({ code: 'invalid_response', status: 200 });
  });

  it('accepts JSON media types with parameters and +json suffixes', async () => {
    const api = client(() => new Response('{"ok": true}', { status: 200, headers: { 'content-type': 'application/problem+json; charset=utf-8' } }));
    await expect(api.get('/alerts')).resolves.toEqual({ ok: true });
  });

  it('keeps empty bodies and 204 as undefined, whatever the content type', async () => {
    await expect(client(() => new Response('', { status: 200 })).post('/onboarding/dismiss')).resolves.toBeUndefined();
    await expect(client(() => new Response(null, { status: 204 })).del('/sources/s-1')).resolves.toBeUndefined();
    await expect(client(() => new Response('', { status: 202, headers: { 'content-type': 'text/html' } })).post('/x')).resolves.toBeUndefined();
  });

  it('still returns text bodies as text when asked', async () => {
    const api = client(() => new Response('<html>report</html>', { status: 200, headers: { 'content-type': 'text/html' } }));
    await expect(api.get('/reports/monthly', { responseType: 'text' })).resolves.toBe('<html>report</html>');
  });
});

