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

const CSS = readFileSync(join(dirname(fileURLToPath(import.meta.url)), 'tokens.css'), 'utf8');

/** Every value of a custom property of tokens.css that is a colour triplet, in the file's order. */
function values(property: string): Rgb[] {
  return [...CSS.matchAll(new RegExp(`${property}:\\s*(\\d+)\\s+(\\d+)\\s+(\\d+)\\s*;`, 'g'))].map((m) => [Number(m[1]), Number(m[2]), Number(m[3])] as const);
}

/** `--c-<name>` in the light rule (the first in tokens.css) and in the dark one. */
function token(name: string): { light: Rgb; dark: Rgb } {
  const [light, dark] = values(`--c-${name}`);
  return { light, dark };
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
      // Links are text (4.5:1), the focus ring a control (3:1), on every surface a link sits on.
      for (const surface of ['canvas', 'sidebar', 'raised', 'raised-2']) {
        expect(contrast(tokens.link[theme], token(surface)[theme]), `${accent} link on ${surface}, ${theme}`).toBeGreaterThanOrEqual(4.5);
      }
      expect(contrast(token('fg')[theme], tokens.selected[theme]), `${accent} text on a selected row, ${theme}`).toBeGreaterThanOrEqual(4.5);
    }
  });

  it('derives the product\'s own link colours from the product\'s accent, within a shade', () => {
    const { tokens } = deriveBrand('#2F6FE4');
    for (const theme of ['light', 'dark'] as const) {
      const [own] = values(`--brand-link-${theme}`);
      tokens.link[theme].forEach((v, i) => expect(Math.abs(v - own[i]), `${theme} channel ${i}`).toBeLessThanOrEqual(24));
      // The selection is the accent over the page, exactly as the token file has it.
      expect(tokens.selected[theme]).toEqual(values(`--brand-selected-${theme}`)[0]);
    }
    expect(tokens.accent).toEqual(values('--brand-accent')[0]);
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
    expect(applyBrand('#777777', root)).toEqual(['text on the accent is 4.48:1 and needs 4.5:1']);
    expect(root.getAttribute('style')).toBeNull();
  });

  it('sets the brand tokens that tokens.css reads, and nothing else', () => {
    const { tokens } = deriveBrand('#0F766E');
    const set = brandProperties(tokens);
    expect(set['--brand-accent']).toBe('15 118 110');
    expect(set['--brand-on-accent']).toBe('255 255 255');
    // Every property it sets is one the token file declares and reads for the accent, links, focus and selection.
    for (const name of Object.keys(set)) {
      expect(values(name), name).toHaveLength(1);
      expect(CSS, name).toContain(`var(${name})`);
    }
    // Severity, state and verdict colours are not a brand's to set.
    expect(Object.keys(set).filter((k) => !k.startsWith('--brand-'))).toEqual([]);

    const root = document.createElement('div');
    expect(applyBrand('#0F766E', root)).toEqual([]);
    expect(root.style.getPropertyValue('--brand-accent')).toBe('15 118 110');
    expect(root.style.getPropertyValue('--brand-link-dark')).toBe(set['--brand-link-dark']);
  });

  it('leaves the token file alone when no accent is set', () => {
    const root = document.createElement('div');
    expect(applyBrand(null, root)).toEqual([]);
    expect(root.getAttribute('style')).toBeNull();
  });

  it('applies the accent to the page', () => {
    render(<Accent accent="#B4471B" />);
    expect(document.documentElement.style.getPropertyValue('--brand-accent')).toBe('180 71 27');
    expect(document.documentElement.style.getPropertyValue('--brand-link-light')).not.toBe('');
  });

  it('warns and keeps the product colours when the configured accent fails', () => {
    const warn = vi.spyOn(console, 'warn').mockImplementation(() => undefined);
    render(<Accent accent="#777777" />);
    expect(warn).toHaveBeenCalledWith('The brand accent #777777 is not used: text on the accent is 4.48:1 and needs 4.5:1.');
    expect(document.documentElement.style.getPropertyValue('--brand-accent')).toBe('');
  });
});
