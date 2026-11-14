import { describe, expect, it } from 'vitest';

import { getBrand, parseConfig, PRODUCT_BRAND, wsEndpoint } from './config';

describe('runtime config', () => {
  it('defaults to same-origin API and WebSocket', () => {
    const cfg = parseConfig(undefined);
    expect(cfg).toEqual({ apiBaseUrl: '', wsUrl: '', oidc: null, brand: PRODUCT_BRAND });
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

  it('shows the product under its own name unless a brand is configured', () => {
    expect(PRODUCT_BRAND).toEqual({ name: 'LG-SOTF', tagline: 'Security operations', logoUrl: null, accent: null });
    expect(parseConfig({ brand: 'nope' }).brand).toBe(PRODUCT_BRAND);
    expect(parseConfig({ brand: {} }).brand).toEqual(PRODUCT_BRAND);
    // Nothing is configured in the tests: the brand everything reads is the product's.
    expect(getBrand()).toBe(PRODUCT_BRAND);
  });

  it('reads a brand: a name, a logo on this site and one accent colour', () => {
    expect(parseConfig({ brand: { name: ' Brightwater SOC ', logoUrl: '/brand/logo.svg', accent: '#0f766e' } }).brand).toEqual({
      name: 'Brightwater SOC',
      tagline: 'on LG-SOTF',
      logoUrl: '/brand/logo.svg',
      accent: '#0F766E',
    });
    // An accent alone keeps the product's name and line.
    expect(parseConfig({ brand: { accent: '#B4471B' } }).brand).toEqual({ ...PRODUCT_BRAND, accent: '#B4471B' });
    expect(parseConfig({ brand: { name: 'LG-SOTF' } }).brand.tagline).toBe('Security operations');
  });

  it('refuses a brand that could not be shown safely', () => {
    expect(() => parseConfig({ brand: { name: 'x'.repeat(41) } })).toThrow(/longer than 40/);
    // The Content-Security-Policy allows images from this site only.
    expect(() => parseConfig({ brand: { logoUrl: 'https://cdn.example/logo.svg' } })).toThrow(/a path on this site/);
    expect(() => parseConfig({ brand: { logoUrl: '//cdn.example/logo.svg' } })).toThrow(/a path on this site/);
    expect(() => parseConfig({ brand: { accent: 'teal' } })).toThrow(/a colour such as #2F6FE4/);
  });
});
