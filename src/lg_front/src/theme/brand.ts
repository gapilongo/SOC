/**
 * The brand's one accent colour, applied through the design tokens.
 *
 * An MSSP sets one value (`brand.accent` of the runtime configuration). The
 * hover, link, focus and selection colours are derived from it, checked for
 * WCAG AA contrast, and written as custom properties on `<html>`: the
 * `--brand-*` tokens of console v2, and the `--c-*` tokens that read them, so
 * every component that uses `bg-accent`, `text-link` or `bg-selected` follows
 * without knowing a brand exists. Severity, state and verdict colours are
 * never touched.
 *
 * An accent that fails a check is refused: nothing is applied, the product's
 * own colours stay, and the failing pair is named. With no accent set
 * (the default) nothing is written and tokens.css alone decides.
 */

import { useEffect } from 'react';

import { useTheme, type ResolvedTheme } from './theme';

export type Rgb = readonly [number, number, number];

const WHITE: Rgb = [255, 255, 255];
const BLACK: Rgb = [0, 0, 0];
/** Text and page colours of console v2 (theme/tokens.css `--c-fg`, `--c-canvas`) the derived colours are checked on. */
const FG: Record<ResolvedTheme, Rgb> = { light: [14, 20, 27], dark: [230, 234, 240] };
const CANVAS: Record<ResolvedTheme, Rgb> = { light: [251, 252, 253], dark: [20, 24, 30] };
/** How much of the accent a selected row carries over the page. */
const SELECTED: Record<ResolvedTheme, number> = { light: 0.12, dark: 0.24 };
/** A link is as readable as the product's own (6.3:1 on the light page, 8.7:1 on the dark one). */
const LINK_CONTRAST: Record<ResolvedTheme, number> = { light: 6, dark: 8 };
const TEXT_MIN = 4.5;

export function parseHex(hex: string): Rgb {
  const n = Number.parseInt(hex.slice(1), 16);
  return [(n >> 16) & 255, (n >> 8) & 255, n & 255];
}

/** `share` of `a` over `b`. */
function mix(a: Rgb, b: Rgb, share: number): Rgb {
  return [0, 1, 2].map((i) => Math.round(a[i] * share + b[i] * (1 - share))) as unknown as Rgb;
}

function luminance(c: Rgb): number {
  const [r, g, b] = c.map((v) => {
    const s = v / 255;
    return s <= 0.03928 ? s / 12.92 : ((s + 0.055) / 1.055) ** 2.4;
  });
  return 0.2126 * r + 0.7152 * g + 0.0722 * b;
}

/** WCAG contrast ratio of two colours. */
export function contrast(a: Rgb, b: Rgb): number {
  const [hi, lo] = [luminance(a), luminance(b)].sort((x, y) => y - x);
  return (hi + 0.05) / (lo + 0.05);
}

/** The accent moved towards `end` until it reaches `target` contrast on `surface`. */
function toward(accent: Rgb, end: Rgb, surface: Rgb, target: number): Rgb {
  let colour = accent;
  for (let share = 1; share > 0 && contrast(colour, surface) < target; share -= 0.02) colour = mix(accent, end, share);
  return colour;
}

export interface BrandTokens {
  accent: Rgb;
  accentHover: Rgb;
  onAccent: Rgb;
  link: Record<ResolvedTheme, Rgb>;
  selected: Record<ResolvedTheme, Rgb>;
}

/** Everything derived from one accent, and the pairs that fail WCAG AA (empty when the accent is usable). */
export function deriveBrand(accentHex: string): { tokens: BrandTokens; problems: string[] } {
  const accent = parseHex(accentHex);
  // White text where it is readable (the product's own choice), otherwise whichever of white and dark reads better.
  const white = contrast(WHITE, accent);
  const onAccent = white >= TEXT_MIN || white >= contrast(FG.light, accent) ? WHITE : FG.light;
  const tokens: BrandTokens = {
    accent,
    accentHover: mix(accent, BLACK, 0.88),
    onAccent,
    link: { light: toward(accent, BLACK, CANVAS.light, LINK_CONTRAST.light), dark: toward(accent, WHITE, CANVAS.dark, LINK_CONTRAST.dark) },
    selected: { light: mix(accent, CANVAS.light, SELECTED.light), dark: mix(accent, CANVAS.dark, SELECTED.dark) },
  };
  const pairs: Array<[string, Rgb, Rgb]> = [
    ['text on the accent', onAccent, accent],
    ['link colour on the light page', tokens.link.light, CANVAS.light],
    ['link colour on the dark page', tokens.link.dark, CANVAS.dark],
    ['text on a selected row, light theme', FG.light, tokens.selected.light],
    ['text on a selected row, dark theme', FG.dark, tokens.selected.dark],
  ];
  const problems = pairs.flatMap(([what, text, surface]) => {
    const ratio = contrast(text, surface);
    return ratio >= TEXT_MIN ? [] : [`${what} is ${ratio.toFixed(2)}:1 and needs ${TEXT_MIN}:1`];
  });
  return { tokens, problems };
}

const triplet = (c: Rgb) => c.join(' ');

/** The custom properties a brand sets, for the theme in use. */
export function brandProperties(tokens: BrandTokens, theme: ResolvedTheme): Record<string, string> {
  const brand = {
    '--brand-accent': triplet(tokens.accent),
    '--brand-accent-hover': triplet(tokens.accentHover),
    '--brand-on-accent': triplet(tokens.onAccent),
    '--brand-link-light': triplet(tokens.link.light),
    '--brand-link-dark': triplet(tokens.link.dark),
    '--brand-selected-light': triplet(tokens.selected.light),
    '--brand-selected-dark': triplet(tokens.selected.dark),
  };
  return {
    ...brand,
    '--c-accent': brand['--brand-accent'],
    '--c-accent-hover': brand['--brand-accent-hover'],
    '--c-on-accent': brand['--brand-on-accent'],
    '--c-link': triplet(tokens.link[theme]),
    '--c-focus': triplet(tokens.link[theme]),
    '--c-selected': triplet(tokens.selected[theme]),
  };
}

/**
 * Apply `accent` (`#RRGGBB`, or null for the product's own colours) to `root`. Returns the failing
 * contrast pairs; when there are any, nothing is applied.
 */
export function applyBrand(accent: string | null, theme: ResolvedTheme, root: HTMLElement = document.documentElement): string[] {
  if (!accent) return [];
  const { tokens, problems } = deriveBrand(accent);
  if (problems.length > 0) return problems;
  // Set through the CSSOM, which the Content-Security-Policy (style-src 'self') allows.
  for (const [name, value] of Object.entries(brandProperties(tokens, theme))) root.style.setProperty(name, value);
  return [];
}

/** Keeps the brand's colours applied as the theme changes. Call once, under the ThemeProvider. */
export function useBrandAccent(accent: string | null): void {
  const { resolved } = useTheme();
  useEffect(() => {
    const problems = applyBrand(accent, resolved);
    if (problems.length > 0) console.warn(`The brand accent ${accent} is not used: ${problems.join('; ')}.`);
  }, [accent, resolved]);
}
