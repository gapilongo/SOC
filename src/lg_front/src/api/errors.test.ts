import { afterEach, describe, expect, it, vi } from 'vitest';

import { ApiError, createApiClient, describeError, newRequestId, type AuthBridge } from './client';

afterEach(() => {
  vi.unstubAllGlobals();
});

describe('ApiError', () => {
  it('tells a state conflict from a lost version race', () => {
    const race = new ApiError({ status: 409, code: 'version_conflict', message: 'changed' });
    expect(race.isConflict).toBe(true);
    expect(race.isStateConflict).toBe(false);
    for (const code of ['invalid_transition', 'already_in_state']) {
      const state = new ApiError({ status: 409, code, message: 'decided' });
      expect(state.isConflict).toBe(true);
      expect(state.isStateConflict).toBe(true);
    }
    const other = new ApiError({ status: 422, code: 'invalid_transition', message: 'no' });
    expect(other.isConflict).toBe(false);
    expect(other.isStateConflict).toBe(false);
    expect(other.requestId).toBeNull();
    expect(other.retryAfter).toBeNull();
  });

  it('words validation details whatever their shape, at most twenty', () => {
    const none = new ApiError({ status: 422, code: 'x', message: 'm', details: { not: 'a list' } });
    expect(none.detailMessages).toEqual([]);
    const mixed = new ApiError({
      status: 422,
      code: 'x',
      message: 'm',
      details: ['plain', { loc: ['body', 'quotas', 'alerts'], msg: 'too large' }, { msg: 'no location' }, { loc: 'body', code: 7 }, 42, null],
    });
    expect(mixed.detailMessages).toEqual(['plain', 'quotas.alerts: too large', 'no location', '{"loc":"body","code":7}', '42', 'null']);
    const many = new ApiError({ status: 422, code: 'x', message: 'm', details: Array.from({ length: 30 }, (_, i) => `problem ${i}`) });
    expect(many.detailMessages).toHaveLength(20);
  });
});

describe('error responses', () => {
  const auth: AuthBridge = { getToken: () => 'tok-1', refresh: async () => null, actingTenant: () => null };
  const failing = (response: Response) => createApiClient({ baseUrl: '/api/v1', auth, fetchImpl: async () => response });
  const caught = async (response: Response) => (await failing(response).get('/x').catch((e: unknown) => e)) as ApiError;

  it('falls back to the status when the body says nothing', async () => {
    const e = await caught(new Response(null, { status: 418, headers: { 'x-request-id': 'req-proxy-1', 'retry-after': '30' } }));
    expect(e).toBeInstanceOf(ApiError);
    expect([e.status, e.code, e.message, e.requestId, e.retryAfter]).toEqual([418, 'http_418', 'Request failed with status 418.', 'req-proxy-1', 30]);
    // A retry-after that is a date is not a number of seconds.
    expect((await caught(new Response(null, { status: 429, headers: { 'retry-after': 'Sat, 07 Nov 2026 12:00:00 GMT' } }))).retryAfter).toBeNull();
  });

  it('keeps the generic wording for a body that is not the error envelope', async () => {
    const page = await caught(new Response('<html>Bad gateway</html>', { status: 502 }));
    expect([page.code, page.message]).toEqual(['http_502', 'The API is unreachable (bad gateway).']);
    // With no id from the API or a proxy, the id the client sent is kept for support.
    expect(page.requestId).toMatch(/^web-/);
    for (const body of ['"a string"', '{"error":"flat"}', '{"error":{"code":5,"message":"","request_id":7}}']) {
      const e = await caught(new Response(body, { status: 500, headers: { 'content-type': 'application/json' } }));
      expect([e.code, e.message], body).toEqual(['http_500', 'The server hit an unexpected error.']);
      expect(e.requestId, body).toMatch(/^web-/);
    }
  });

  it('refuses a successful body that is not JSON, whatever its media type', async () => {
    const e = await caught(new Response('<html>app shell</html>', { status: 200 }));
    expect(e.code).toBe('invalid_response');
    const vendor = new Response('{"ok":true}', { status: 200, headers: { 'content-type': 'application/problem+json; charset=utf-8' } });
    await expect(failing(vendor).get('/x')).resolves.toEqual({ ok: true });
  });

  it('lets an aborted request surface as the abort it is', async () => {
    const abort = new DOMException('The operation was aborted.', 'AbortError');
    const api = createApiClient({
      baseUrl: '',
      auth,
      fetchImpl: async () => {
        throw abort;
      },
    });
    await expect(api.get('/x')).rejects.toBe(abort);
  });

  it('uses the browser fetch by default, and keepalive when asked', async () => {
    const fetchMock = vi.fn(async (..._args: Parameters<typeof fetch>) => new Response(null, { status: 204 }));
    vi.stubGlobal('fetch', fetchMock);
    const api = createApiClient({ baseUrl: '', auth });
    await expect(api.post('/auth/logout', undefined, { keepalive: true })).resolves.toBeUndefined();
    expect(fetchMock.mock.calls[0][1]).toMatchObject({ keepalive: true, method: 'POST' });
    await api.get('/x');
    expect(fetchMock.mock.calls[1][1]).not.toHaveProperty('keepalive');
  });
});

describe('describeError', () => {
  it('words any thrown value', () => {
    expect(describeError(new Error('network down'))).toEqual({ message: 'network down', requestId: null, details: [] });
    expect(describeError('nope')).toEqual({ message: 'Something went wrong.', requestId: null, details: [] });
    expect(describeError(undefined)).toEqual({ message: 'Something went wrong.', requestId: null, details: [] });
  });
});

describe('newRequestId', () => {
  it('uses a random UUID where the browser has one', () => {
    expect(newRequestId()).toMatch(/^web-[0-9a-f-]{36}$/);
  });

  it('falls back to random bytes in an older browser', () => {
    vi.stubGlobal('crypto', {
      getRandomValues: (bytes: Uint8Array) => {
        bytes.fill(171);
        return bytes;
      },
    });
    expect(newRequestId()).toBe(`web-${'ab'.repeat(16)}`);
  });
});
