/// <reference types="node" />
/**
 * WCAG AA contrast of the design tokens, read from tokens.css itself so the
 * check follows every palette change: text 4.5:1 on every surface, controls,
 * focus ring, severity squares and state dots 3:1 (non-text contrast).
 */
import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

import { describe, expect, it } from 'vitest';

const CSS = readFileSync(join(dirname(fileURLToPath(import.meta.url)), 'tokens.css'), 'utf8');

type Palette = Record<string, [number, number, number]>;

/** The `--c-*` triplets of the first rule whose selector list contains `selector`. */
function palette(css: string, selector: string): Palette {
  const rule = new RegExp(`(^|\\n)([^{}]*?)\\{([^}]*)\\}`, 'g');
  for (const m of css.matchAll(rule)) {
    const selectors = m[2].replace(/\/\*[\s\S]*?\*\//g, '').split(',').map((s) => s.trim());
    if (!selectors.includes(selector)) continue;
    const out: Palette = {};
    for (const d of m[3].matchAll(/--c-([a-z0-9-]+):\s*(\d+)\s+(\d+)\s+(\d+)\s*;/g)) {
      out[d[1]] = [Number(d[2]), Number(d[3]), Number(d[4])];
    }
    return out;
  }
  throw new Error(`no rule for ${selector}`);
}

function luminance([r, g, b]: [number, number, number]): number {
  const lin = (v: number) => {
    const c = v / 255;
    return c <= 0.03928 ? c / 12.92 : ((c + 0.055) / 1.055) ** 2.4;
  };
  return 0.2126 * lin(r) + 0.7152 * lin(g) + 0.0722 * lin(b);
}

function contrast(a: [number, number, number], b: [number, number, number]): number {
  const [hi, lo] = [luminance(a), luminance(b)].sort((x, y) => y - x);
  return (hi + 0.05) / (lo + 0.05);
}

const SURFACES = ['canvas', 'sidebar', 'raised', 'raised-2', 'selected'];
const TEXT = ['fg', 'body', 'secondary', 'muted', 'eyebrow', 'link', 'danger-fg', 'warn', 'warn-fg', 'ok-fg'];
const GRAPHICS = [
  'control',
  'focus',
  'danger',
  'sev-critical',
  'sev-high',
  'sev-medium',
  'sev-low',
  'sev-info',
  'state-waiting',
  'state-approval',
  'state-processing',
  'state-ok',
  'state-bad',
];
const TINTS: Record<string, string[]> = {
  'tint-danger': ['fg', 'body', 'secondary', 'danger-fg'],
  'tint-warn': ['fg', 'body', 'secondary', 'warn-fg'],
  'tint-ok': ['fg', 'body', 'secondary', 'ok-fg'],
  'tint-info': ['fg', 'body', 'secondary', 'link'],
};

/** Every [foreground, background, minimum ratio] pair the design relies on. */
function pairs(): Array<[string, string, number]> {
  const out: Array<[string, string, number]> = [];
  for (const s of SURFACES) {
    for (const t of TEXT) out.push([t, s, 4.5]);
    for (const g of GRAPHICS) out.push([g, s, 3]);
  }
  out.push(['on-accent', 'accent', 4.5], ['on-accent', 'accent-hover', 4.5]);
  for (const [tint, fgs] of Object.entries(TINTS)) for (const f of fgs) out.push([f, tint, 4.5]);
  return out;
}

const THEMES = {
  dark: palette(CSS, "[data-theme='dark']"),
  light: palette(CSS, "[data-theme='light']"),
};

describe('design tokens', () => {
  it('parses both palettes with the same token names', () => {
    expect(Object.keys(THEMES.dark).length).toBeGreaterThan(35);
    expect(Object.keys(THEMES.light).sort()).toEqual(Object.keys(THEMES.dark).sort());
  });

  it('keeps the canvas colours of the dark theme', () => {
    expect(THEMES.dark.canvas).toEqual([10, 14, 19]);
    expect(THEMES.dark.raised).toEqual([16, 21, 28]);
    expect(THEMES.dark.fg).toEqual([230, 234, 240]);
    expect(THEMES.dark.focus).toEqual([138, 182, 255]);
  });

  it('computes WCAG contrast ratios', () => {
    expect(contrast([0, 0, 0], [255, 255, 255])).toBeCloseTo(21, 5);
    expect(contrast([255, 255, 255], [255, 255, 255])).toBeCloseTo(1, 5);
  });

  for (const [name, colours] of Object.entries(THEMES)) {
    it(`meets WCAG AA for every token pair in the ${name} theme`, () => {
      const failures = pairs()
        .map(([fg, bg, min]) => {
          expect(colours[fg], `${name}: --c-${fg}`).toBeDefined();
          expect(colours[bg], `${name}: --c-${bg}`).toBeDefined();
          const ratio = contrast(colours[fg], colours[bg]);
          return ratio < min ? `${fg} on ${bg}: ${ratio.toFixed(2)} < ${min}` : null;
        })
        .filter(Boolean);
      expect(failures).toEqual([]);
    });
  }
});
