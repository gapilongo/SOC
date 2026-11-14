/// <reference types="node" />
/**
 * The brand's accent through the design tokens: what one colour derives, the
 * WCAG AA checks it must pass before it is used, and the custom properties it
 * sets. The derived colours are also held against the page colours of
 * tokens.css itself, so a palette change cannot make a brand unreadable.
 */
import { render } from '@testing-library/react';
import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { afterEach, describe, expect, it, vi } from 'vitest';

import { applyBrand, brandProperties, contrast, deriveBrand, parseHex, useBrandAccent, type Rgb } from './brand';
import { ThemeProvider } from './theme';

const CSS = readFileSync(join(dirname(fileURLToPath(import.meta.url)), 'tokens.css'), 'utf8');

/** `--c-<name>` of the dark (first) and the light rule of tokens.css. */
function token(name: string): { dark: Rgb; light: Rgb } {
  const [dark, light] = [...CSS.matchAll(new RegExp(`--c-${name}:\\s*(\\d+)\\s+(\\d+)\\s+(\\d+)\\s*;`, 'g'))].map((m) => [Number(m[1]), Number(m[2]), Number(m[3])] as const);
  return { dark, light };
}

/** The three brands of the console v2 design: the product's blue, a teal and a rust. */
const PRESETS = ['#2F6FE4', '#0F766E', '#B4471B'];

function Accent({ accent }: { accent: string | null }) {
  useBrandAccent(accent);
  return null;
}

afterEach(() => {
  document.documentElement.removeAttribute('style');
  window.localStorage.clear();
});

describe('brand accent', () => {
  it('reads a hex colour and measures contrast as WCAG does', () => {
    expect(parseHex('#2F6FE4')).toEqual([47, 111, 228]);
    expect(contrast([255, 255, 255], [0, 0, 0])).toBeCloseTo(21, 5);
    expect(contrast([0, 0, 0], [255, 255, 255])).toBeCloseTo(21, 5);
    expect(contrast([255, 255, 255], parseHex('#2F6FE4'))).toBeCloseTo(4.65, 1);
  });

  it.each(PRESETS)('derives readable colours from %s, on the console v2 pages and on the pages of tokens.css', (accent) => {
    const { tokens, problems } = deriveBrand(accent);
    expect(problems).toEqual([]);
    expect(tokens.accent).toEqual(parseHex(accent));
    expect(contrast(tokens.onAccent, tokens.accent)).toBeGreaterThanOrEqual(4.5);
    // The hover is darker than the accent, never another hue.
    expect(contrast(tokens.accentHover, [255, 255, 255])).toBeGreaterThan(contrast(tokens.accent, [255, 255, 255]));
    for (const theme of ['light', 'dark'] as const) {
      // Links are text (4.5:1), the focus ring a control (3:1), on every surface a link sits on today.
      for (const surface of ['canvas', 'sidebar', 'raised', 'raised-2']) {
        expect(contrast(tokens.link[theme], token(surface)[theme]), `${accent} link on ${surface}, ${theme}`).toBeGreaterThanOrEqual(4.5);
      }
      expect(contrast(token('fg')[theme], tokens.selected[theme]), `${accent} text on a selected row, ${theme}`).toBeGreaterThanOrEqual(4.5);
    }
  });

  it('derives the product\'s own link colours from the product\'s accent, within a shade', () => {
    const { tokens } = deriveBrand('#2F6FE4');
    for (const theme of ['light', 'dark'] as const) {
      const own = token('link')[theme];
      tokens.link[theme].forEach((v, i) => expect(Math.abs(v - own[i]), `${theme} channel ${i}`).toBeLessThanOrEqual(24));
    }
  });

  it('puts dark text on a light accent', () => {
    const { tokens, problems } = deriveBrand('#FFD24A');
    expect(problems).toEqual([]);
    expect(tokens.onAccent).toEqual([14, 20, 27]);
  });

  it('refuses an accent that leaves text unreadable, naming the failing pair', () => {
    // Neither white nor dark text reaches 4.5:1 on a mid grey.
    expect(deriveBrand('#777777').problems).toEqual(['text on the accent is 4.48:1 and needs 4.5:1']);
    const root = document.createElement('div');
    expect(applyBrand('#777777', 'light', root)).toEqual(['text on the accent is 4.48:1 and needs 4.5:1']);
    expect(root.getAttribute('style')).toBeNull();
  });

  it('sets the brand tokens and the tokens that read them, for the theme in use', () => {
    const { tokens } = deriveBrand('#0F766E');
    const light = brandProperties(tokens, 'light');
    const dark = brandProperties(tokens, 'dark');
    expect(light['--brand-accent']).toBe('15 118 110');
    expect(light['--c-accent']).toBe('15 118 110');
    expect(light['--c-on-accent']).toBe('255 255 255');
    expect(light['--c-link']).toBe(light['--brand-link-light']);
    expect(dark['--c-link']).toBe(dark['--brand-link-dark']);
    expect(light['--c-focus']).toBe(light['--c-link']);
    expect(light['--c-selected']).toBe(light['--brand-selected-light']);
    expect(dark['--c-selected']).toBe(dark['--brand-selected-dark']);
    // Severity, state and verdict colours are not a brand's to set.
    expect(Object.keys(light).filter((k) => /sev|state|danger|warn|ok|mark/.test(k))).toEqual([]);

    const root = document.createElement('div');
    expect(applyBrand('#0F766E', 'dark', root)).toEqual([]);
    expect(root.style.getPropertyValue('--c-accent')).toBe('15 118 110');
    expect(root.style.getPropertyValue('--c-link')).toBe(dark['--c-link']);
  });

  it('leaves the token file alone when no accent is set', () => {
    const root = document.createElement('div');
    expect(applyBrand(null, 'light', root)).toEqual([]);
    expect(root.getAttribute('style')).toBeNull();
  });

  it('applies the accent to the page and follows the theme', () => {
    window.localStorage.setItem('lg-sotf.theme', 'light');
    const { unmount } = render(
      <ThemeProvider>
        <Accent accent="#B4471B" />
      </ThemeProvider>,
    );
    const light = document.documentElement.style.getPropertyValue('--c-link');
    expect(document.documentElement.style.getPropertyValue('--c-accent')).toBe('180 71 27');
    unmount();
    window.localStorage.setItem('lg-sotf.theme', 'dark');
    render(
      <ThemeProvider>
        <Accent accent="#B4471B" />
      </ThemeProvider>,
    );
    expect(document.documentElement.style.getPropertyValue('--c-link')).not.toBe(light);
  });

  it('warns and keeps the product colours when the configured accent fails', () => {
    const warn = vi.spyOn(console, 'warn').mockImplementation(() => undefined);
    render(
      <ThemeProvider>
        <Accent accent="#777777" />
      </ThemeProvider>,
    );
    expect(warn).toHaveBeenCalledWith('The brand accent #777777 is not used: text on the accent is 4.48:1 and needs 4.5:1.');
    expect(document.documentElement.style.getPropertyValue('--c-accent')).toBe('');
  });
});
