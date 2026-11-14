/// <reference types="node" />
/**
 * WCAG AA contrast of the design tokens, read from tokens.css itself so the
 * check follows every palette change: text 4.5:1 on every surface, controls,
 * focus ring, severity bars, state and data marks 3:1 (non-text contrast).
 * It also holds the two dark blocks together and the row heights in step
 * with the windowed tables.
 */
import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

import { describe, expect, it } from 'vitest';

import { ROW_HEIGHT } from './density';

const CSS = readFileSync(join(dirname(fileURLToPath(import.meta.url)), 'tokens.css'), 'utf8').replace(/\/\*[\s\S]*?\*\//g, '');

type Rgb = [number, number, number];
type Palette = Record<string, Rgb>;

/** Every rule of the file as [selector list, declarations], with the rules inside `@media` lifted out. */
function rules(css: string): Array<[string[], string]> {
  const out: Array<[string[], string]> = [];
  for (const m of css.matchAll(/([^{}]+)\{([^{}]*)\}/g)) {
    // Inside an at-rule the match starts after its opening brace, so the prelude is the selector alone.
    const selectors = m[1].split(',').map((s) => s.trim());
    out.push([selectors, m[2]]);
  }
  return out;
}

const RULES = rules(CSS);

/** The declarations of the first rule whose selector list contains `selector`, as name -> raw value. */
function declarations(selector: string): Record<string, string> {
  const rule = RULES.find(([selectors]) => selectors.includes(selector));
  if (!rule) throw new Error(`no rule for ${selector}`);
  const out: Record<string, string> = {};
  for (const d of rule[1].matchAll(/--([a-z0-9-]+):\s*([^;]+);/g)) out[d[1]] = d[2].trim();
  return out;
}

const ROOT = declarations(':root');

/** The `--c-*` colours of a theme block, with `var(--brand-*)` resolved against `:root`. */
function palette(selector: string): Palette {
  const out: Palette = {};
  for (const [name, raw] of Object.entries(declarations(selector))) {
    if (!name.startsWith('c-')) continue;
    const ref = /^var\(--([a-z0-9-]+)\)$/.exec(raw);
    const value = ref ? ROOT[ref[1]] : raw;
    const rgb = /^(\d+)\s+(\d+)\s+(\d+)$/.exec(value ?? '');
    if (!rgb) throw new Error(`${selector}: --${name} is not an RGB triplet (${raw})`);
    out[name.slice(2)] = [Number(rgb[1]), Number(rgb[2]), Number(rgb[3])];
  }
  return out;
}

function luminance([r, g, b]: Rgb): number {
  const lin = (v: number) => {
    const c = v / 255;
    return c <= 0.03928 ? c / 12.92 : ((c + 0.055) / 1.055) ** 2.4;
  };
  return 0.2126 * lin(r) + 0.7152 * lin(g) + 0.0722 * lin(b);
}

function contrast(a: Rgb, b: Rgb): number {
  const [hi, lo] = [luminance(a), luminance(b)].sort((x, y) => y - x);
  return (hi + 0.05) / (lo + 0.05);
}

const SURFACES = ['canvas', 'sidebar', 'raised', 'raised-2', 'selected'];
const TEXT = ['fg', 'body', 'secondary', 'muted', 'link', 'danger-fg', 'warn', 'warn-fg', 'ok-fg'];
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

/** Text and marks used on the observation surface (the investigation's Observation component). */
const OBSERVED_TEXT = ['fg', 'body', 'secondary', 'muted', 'link'];
const OBSERVED_GRAPHICS = ['control', 'focus'];

/**
 * Data marks (who or what closed an alert) on the sheet. `data-2` on the light canvas is 2.7:1,
 * a recorded exception of the design (README section 4): it only fills a bar segment that is also
 * a labelled table row, separated from its neighbours by a gap.
 */
const DATA_MARKS = ['data-1', 'data-2', 'data-3', 'data-4'];
const DATA_EXCEPTIONS: Record<string, string[]> = { light: ['data-2'], dark: [] };

/** Every [foreground, background, minimum ratio] pair the design relies on. */
function pairs(theme: string): Array<[string, string, number]> {
  const out: Array<[string, string, number]> = [];
  for (const s of SURFACES) {
    for (const t of TEXT) out.push([t, s, 4.5]);
    for (const g of GRAPHICS) out.push([g, s, 3]);
  }
  out.push(['on-accent', 'accent', 4.5], ['on-accent', 'accent-hover', 4.5]);
  // The inverted controls (a pressed segment, a count, a toast): the canvas colour as text on `fg`.
  out.push(['canvas', 'fg', 4.5]);
  for (const [tint, fgs] of Object.entries(TINTS)) for (const f of fgs) out.push([f, tint, 4.5]);
  // The investigation view: what a tool returned sits on `observed`, with the decisive characters highlighted.
  for (const t of OBSERVED_TEXT) out.push([t, 'observed', 4.5]);
  for (const g of OBSERVED_GRAPHICS) out.push([g, 'observed', 3]);
  out.push(['mark-fg', 'mark', 4.5]);
  for (const d of DATA_MARKS) if (!DATA_EXCEPTIONS[theme].includes(d)) out.push([d, 'canvas', 3]);
  return out;
}

const THEMES: Record<string, Palette> = {
  dark: palette("[data-theme='dark']"),
  light: palette("[data-theme='light']"),
};

describe('design tokens', () => {
  it('parses both palettes with the same token names', () => {
    expect(Object.keys(THEMES.dark).length).toBeGreaterThan(40);
    expect(Object.keys(THEMES.light).sort()).toEqual(Object.keys(THEMES.dark).sort());
  });

  it('is light on :root and dark when the system asks for it, with the same dark values as the pinned dark theme', () => {
    expect(declarations(':root:not([data-theme=\'light\'])')).toEqual(declarations("[data-theme='dark']"));
    // Light is the block `:root` shares with a pinned light subtree.
    expect(RULES.some(([selectors]) => selectors.includes(':root') && selectors.includes("[data-theme='light']"))).toBe(true);
    expect(CSS).toMatch(/@media \(prefers-color-scheme: dark\)\s*\{\s*:root:not\(\[data-theme='light'\]\)/);
  });

  it('keeps the surfaces of the console v2 design', () => {
    expect(THEMES.dark.canvas).toEqual([20, 24, 30]);
    expect(THEMES.dark.raised).toEqual([27, 32, 40]);
    expect(THEMES.dark.fg).toEqual([230, 234, 240]);
    expect(THEMES.dark.focus).toEqual([138, 182, 255]);
    expect(THEMES.light.canvas).toEqual([251, 252, 253]);
    expect(THEMES.light.selected).toEqual([227, 235, 250]);
  });

  it('reads the accent, link, focus and selection from the brand', () => {
    for (const block of ["[data-theme='light']", "[data-theme='dark']"]) {
      const d = declarations(block);
      expect(d['c-accent']).toBe('var(--brand-accent)');
      expect(d['c-on-accent']).toBe('var(--brand-on-accent)');
      expect(d['c-link']).toMatch(/^var\(--brand-link-(light|dark)\)$/);
      expect(d['c-focus']).toBe(d['c-link']);
      expect(d['c-selected']).toMatch(/^var\(--brand-selected-(light|dark)\)$/);
    }
  });

  it('keeps the row heights in step with the windowed tables', () => {
    const px = (name: string) => Number(/^(\d+)px$/.exec(ROOT[name] ?? '')?.[1]);
    expect(px('row-h-dense')).toBe(ROW_HEIGHT.dense);
    expect(px('row-h-compact')).toBe(ROW_HEIGHT.compact);
    expect(px('row-h-relaxed')).toBe(ROW_HEIGHT.comfortable);
    expect(ROOT['row-h']).toBe('var(--row-h-compact)');
    expect(declarations(":root[data-density='dense']")['row-h']).toBe('var(--row-h-dense)');
    expect(declarations(":root[data-density='comfortable']")['row-h']).toBe('var(--row-h-relaxed)');
    // Row targets are at least 24 px high (WCAG 2.5.8).
    expect(px('row-h-dense')).toBeGreaterThanOrEqual(24);
    expect(px('ctl-h-sm')).toBeGreaterThanOrEqual(24);
    expect(px('ctl-h-touch')).toBe(44);
  });

  it('computes WCAG contrast ratios', () => {
    expect(contrast([0, 0, 0], [255, 255, 255])).toBeCloseTo(21, 5);
    expect(contrast([255, 255, 255], [255, 255, 255])).toBeCloseTo(1, 5);
  });

  for (const [name, colours] of Object.entries(THEMES)) {
    it(`meets WCAG AA for every token pair in the ${name} theme`, () => {
      const failures = pairs(name)
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

  it('records the one exception of the design, and only that one', () => {
    expect(contrast(THEMES.light['data-2'], THEMES.light.canvas)).toBeLessThan(3);
    expect(contrast(THEMES.dark['data-2'], THEMES.dark.canvas)).toBeGreaterThanOrEqual(3);
  });
});
