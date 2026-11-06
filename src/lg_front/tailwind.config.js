import plugin from 'tailwindcss/plugin';

/** A colour backed by a design token (src/theme/tokens.css), with opacity support. */
const token = (name) => `rgb(var(--c-${name}) / <alpha-value>)`;

/** @type {import('tailwindcss').Config} */
export default {
  content: ['./index.html', './src/**/*.{ts,tsx}'],
  // Themes switch through <html data-theme>, not the `dark:` variant: every colour is a token.
  darkMode: ['selector', '[data-theme="dark"]'],
  theme: {
    // The palette is the token set only: Tailwind's default greys and hues are not generated,
    // so a hard-coded `bg-slate-900` cannot creep back in (eslint bans them too).
    colors: {
      transparent: 'transparent',
      current: 'currentColor',
      inherit: 'inherit',
      black: '#000000',
      white: '#FFFFFF',
      canvas: token('canvas'),
      sidebar: token('sidebar'),
      raised: { DEFAULT: token('raised'), 2: token('raised-2') },
      selected: token('selected'),
      subtle: token('subtle'),
      strong: token('strong'),
      control: token('control'),
      fg: token('fg'),
      body: token('body'),
      secondary: token('secondary'),
      muted: token('muted'),
      eyebrow: token('eyebrow'),
      accent: { DEFAULT: token('accent'), hover: token('accent-hover') },
      'on-accent': token('on-accent'),
      link: { DEFAULT: token('link'), hover: token('link-hover') },
      focus: token('focus'),
      sev: {
        critical: token('sev-critical'),
        high: token('sev-high'),
        medium: token('sev-medium'),
        low: token('sev-low'),
        info: token('sev-info'),
      },
      state: {
        waiting: token('state-waiting'),
        approval: token('state-approval'),
        processing: token('state-processing'),
        ok: token('state-ok'),
        bad: token('state-bad'),
      },
      danger: { DEFAULT: token('danger'), fg: token('danger-fg') },
      warn: { DEFAULT: token('warn'), fg: token('warn-fg') },
      ok: { fg: token('ok-fg') },
      tint: {
        danger: token('tint-danger'),
        warn: token('tint-warn'),
        ok: token('tint-ok'),
        info: token('tint-info'),
      },
    },
    extend: {
      fontFamily: {
        sans: ['Inter', 'system-ui', '-apple-system', 'Segoe UI', 'Roboto', 'sans-serif'],
        mono: ['"JetBrains Mono"', 'ui-monospace', 'SFMono-Regular', 'Menlo', 'Consolas', 'monospace'],
      },
      // Type scale: 11 eyebrow (2xs), 12 meta (xs), 13 table and controls (ctl), 14 body (sm),
      // 16 panel title (base), 20 page title (xl), 28 display. Names avoid the colour names
      // (`text-body` is a colour).
      fontSize: {
        '2xs': ['11px', { lineHeight: '16px' }],
        ctl: ['13px', { lineHeight: '18px' }],
        display: ['28px', { lineHeight: '34px', letterSpacing: '-0.01em' }],
      },
      borderRadius: {
        tag: '6px',
        control: '8px',
        card: '12px',
      },
      boxShadow: {
        popover: 'var(--shadow-popover)',
        // The 3 px inset bar of attention / approval cards and banners.
        'bar-attention': 'inset 3px 0 0 rgb(var(--c-state-waiting))',
        'bar-approval': 'inset 3px 0 0 rgb(var(--c-state-approval))',
        'bar-warning': 'inset 3px 0 0 rgb(var(--c-state-bad))',
        'bar-info': 'inset 3px 0 0 rgb(var(--c-link))',
      },
      outlineColor: { DEFAULT: token('focus') },
      ringColor: { DEFAULT: token('focus') },
    },
  },
  plugins: [
    plugin(({ addVariant }) => {
      // Touch screens: controls grow to 44 px (WCAG 2.5.5 target size).
      addVariant('touch', '@media (pointer: coarse)');
    }),
  ],
};
