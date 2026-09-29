import { describe, expect, it } from 'vitest';

import { parseConfig, wsEndpoint } from './config';

describe('runtime config', () => {
  it('defaults to same-origin API and WebSocket', () => {
    const cfg = parseConfig(undefined);
    expect(cfg).toEqual({ apiBaseUrl: '', wsUrl: '', oidc: null });
    expect(wsEndpoint(cfg, { protocol: 'https:', host: 'soc.example.com' })).toBe('wss://soc.example.com/api/v1/ws');
    expect(wsEndpoint(cfg, { protocol: 'http:', host: 'localhost:3000' })).toBe('ws://localhost:3000/api/v1/ws');
  });

  it('derives the WebSocket URL from a separate API origin and strips trailing slashes', () => {
    const cfg = parseConfig({ apiBaseUrl: 'https://api.example.com/' });
    expect(cfg.apiBaseUrl).toBe('https://api.example.com');
    expect(wsEndpoint(cfg)).toBe('wss://api.example.com/api/v1/ws');
    expect(wsEndpoint(parseConfig({ apiBaseUrl: 'https://a.example', wsUrl: 'wss://ws.example/api/v1/ws' }))).toBe('wss://ws.example/api/v1/ws');
  });

  it('rejects unsafe URLs', () => {
    expect(() => parseConfig({ apiBaseUrl: 'javascript:alert(1)' })).toThrow(/http/);
    expect(() => parseConfig({ apiBaseUrl: 'https://user:pw@api.example.com' })).toThrow(/credentials/);
    expect(() => parseConfig({ wsUrl: 'https://not-a-socket' })).toThrow(/ws/);
  });

  it('enables OIDC only with an issuer and a client id', () => {
    expect(parseConfig({ oidc: { issuer: 'https://idp.example' } }).oidc).toBeNull();
    const oidc = parseConfig({ oidc: { issuer: 'https://idp.example/', clientId: 'lg-sotf-web' } }).oidc;
    // The issuer is kept exactly as configured (compared as a string with the discovery document).
    expect(oidc).toMatchObject({ issuer: 'https://idp.example/', clientId: 'lg-sotf-web', scope: 'openid profile email', tokenType: 'access_token' });
  });
});
