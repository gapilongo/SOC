import { beforeEach, describe, expect, it, vi } from 'vitest';

import { parseConfig, type OidcConfig } from '../config';
import { beginLogin, completeLogin, endpoints, logoutUrl, pkceChallenge, resetOidcDiscovery, safeNavigationUrl, safeReturnTo } from './oidc';

const config = parseConfig({
  oidc: { issuer: 'https://idp.example', clientId: 'web', authorizationEndpoint: 'https://idp.example/authorize', tokenEndpoint: 'https://idp.example/token' },
}).oidc as OidcConfig;

function jwt(payload: object): string {
  const b64 = (o: object) => btoa(JSON.stringify(o)).replace(/=+$/, '').replace(/\+/g, '-').replace(/\//g, '_');
  return `${b64({ alg: 'RS256' })}.${b64(payload)}.sig`;
}

beforeEach(() => {
  sessionStorage.clear();
  resetOidcDiscovery();
});

describe('OIDC authorization code + PKCE', () => {
  it('uses the S256 challenge of the verifier', async () => {
    const verifier = 'dBjftJeZ4CVP-mJ92IaUpGj3yX5_H7ab0bKc8wGpQZ9';
    // SHA-256 of the verifier, base64url without padding (computed independently with Node's crypto).
    const expected = 'GBD8SYSfD1rr9PflvaMnExX45wcivrx_Z_5x_HvyqZ8';
    await expect(pkceChallenge(verifier)).resolves.toBe(expected);
  });

  it('builds the authorization request and completes it with the stored verifier', async () => {
    const url = new URL(await beginLogin(config, '/alerts?severity=high'));
    expect(url.origin + url.pathname).toBe('https://idp.example/authorize');
    const p = url.searchParams;
    expect(p.get('response_type')).toBe('code');
    expect(p.get('code_challenge_method')).toBe('S256');
    expect(p.get('client_id')).toBe('web');
    const state = p.get('state')!;
    const nonce = p.get('nonce')!;

    const fetchImpl = vi.fn(async (_url: RequestInfo | URL, init?: RequestInit) => {
      const body = new URLSearchParams(String(init?.body));
      expect(body.get('grant_type')).toBe('authorization_code');
      expect(await pkceChallenge(body.get('code_verifier')!)).toBe(p.get('code_challenge'));
      return new Response(JSON.stringify({ access_token: 'at', id_token: jwt({ nonce }), expires_in: 600, refresh_token: 'rt' }), { status: 200 });
    });
    const out = await completeLogin(config, `https://app.example/auth/callback?code=abc&state=${state}`, { fetchImpl: fetchImpl as unknown as typeof fetch });
    expect(out).toEqual({ token: 'at', expiresIn: 600, refreshToken: 'rt', returnTo: '/alerts?severity=high' });
    // The PKCE material is single use.
    expect(sessionStorage.length).toBe(0);
  });

  it('rejects a response whose state does not match', async () => {
    await beginLogin(config, '/');
    await expect(completeLogin(config, 'https://app.example/auth/callback?code=abc&state=forged')).rejects.toThrow(/did not match/);
  });

  it('rejects an ID token with the wrong nonce', async () => {
    const state = new URL(await beginLogin(config, '/')).searchParams.get('state');
    const fetchImpl = vi.fn(async () => new Response(JSON.stringify({ access_token: 'at', id_token: jwt({ nonce: 'other' }) }), { status: 200 }));
    await expect(completeLogin(config, `https://app.example/cb?code=c&state=${state}`, { fetchImpl: fetchImpl as unknown as typeof fetch })).rejects.toThrow(/nonce/);
  });

  it('only returns to same-app paths', () => {
    expect(safeReturnTo('/alerts')).toBe('/alerts');
    expect(safeReturnTo('https://evil.example')).toBe('/');
    expect(safeReturnTo('//evil.example')).toBe('/');
    expect(safeReturnTo('/\\evil.example')).toBe('/');
    expect(safeReturnTo('/login')).toBe('/');
    expect(safeReturnTo(null)).toBe('/');
  });
});

describe('OIDC logout', () => {
  it('builds the end-session URL with a post-logout redirect to the sign-in page', async () => {
    const withEnd = { ...config, endSessionEndpoint: 'https://idp.example/logout' };
    const url = new URL((await logoutUrl(withEnd, 'https://soc.example.com'))!);
    expect(url.origin + url.pathname).toBe('https://idp.example/logout');
    expect(url.searchParams.get('post_logout_redirect_uri')).toBe('https://soc.example.com/login');
    expect(url.searchParams.get('client_id')).toBe('web');
    await expect(logoutUrl(config, 'https://soc.example.com')).resolves.toBeNull();
  });
});

function discovery(doc: Record<string, unknown>) {
  return vi.fn(async (url: string) => {
    void url;
    return new Response(JSON.stringify(doc), { status: 200, headers: { 'Content-Type': 'application/json' } });
  }) as unknown as typeof fetch & { mock: { calls: unknown[][] } };
}

describe('OIDC discovery', () => {
  it('accepts an issuer that ends with a slash (Auth0 style)', async () => {
    const auth0 = parseConfig({ oidc: { issuer: 'https://tenant.auth0.example/', clientId: 'web' } }).oidc as OidcConfig;
    const fetchImpl = discovery({
      issuer: 'https://tenant.auth0.example/',
      authorization_endpoint: 'https://tenant.auth0.example/authorize',
      token_endpoint: 'https://tenant.auth0.example/oauth/token',
    });
    const ep = await endpoints(auth0, fetchImpl);
    expect(ep.authorization).toBe('https://tenant.auth0.example/authorize');
    // One slash before .well-known, whatever the configured form.
    expect(fetchImpl.mock.calls[0][0]).toBe('https://tenant.auth0.example/.well-known/openid-configuration');
  });

  it('still refuses a discovery document for another issuer', async () => {
    const cfg = parseConfig({ oidc: { issuer: 'https://idp.example', clientId: 'web' } }).oidc as OidcConfig;
    const fetchImpl = discovery({ issuer: 'https://evil.example', authorization_endpoint: 'https://evil.example/a', token_endpoint: 'https://evil.example/t' });
    await expect(endpoints(cfg, fetchImpl)).rejects.toThrow(/different issuer/);
  });

  it('drops an end-session endpoint that is not a safe http(s) URL', async () => {
    const cfg = parseConfig({ oidc: { issuer: 'https://idp.example', clientId: 'web' } }).oidc as OidcConfig;
    const fetchImpl = discovery({
      issuer: 'https://idp.example',
      authorization_endpoint: 'https://idp.example/authorize',
      token_endpoint: 'https://idp.example/token',
      end_session_endpoint: 'javascript:alert(document.domain)',
    });
    expect((await endpoints(cfg, fetchImpl)).endSession).toBeNull();
    await expect(logoutUrl(cfg, 'https://soc.example.com', fetchImpl)).resolves.toBeNull();
  });

  it('allows https end-session URLs, and plain http only on loopback', () => {
    expect(safeNavigationUrl('https://idp.example/logout')).toBe('https://idp.example/logout');
    expect(safeNavigationUrl('http://localhost:8080/logout')).toBe('http://localhost:8080/logout');
    expect(safeNavigationUrl('http://idp.example/logout')).toBeNull();
    expect(safeNavigationUrl('data:text/html,hi')).toBeNull();
    expect(safeNavigationUrl('https://u:p@idp.example/logout')).toBeNull();
    expect(safeNavigationUrl(42)).toBeNull();
  });
});
