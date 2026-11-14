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
      observed: token('observed'),
      mark: { DEFAULT: token('mark'), fg: token('mark-fg') },
      subtle: token('subtle'),
      strong: token('strong'),
      control: token('control'),
      fg: token('fg'),
      body: token('body'),
      secondary: token('secondary'),
      muted: token('muted'),
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
      // Who or what closed an alert: the AI, a suppression rule, an earlier verdict, a person.
      data: { 1: token('data-1'), 2: token('data-2'), 3: token('data-3'), 4: token('data-4') },
    },
    // Corners are tokens: 2 px tags, 3 px controls and framed surfaces. `rounded-full` stays for dots and avatars.
    borderRadius: {
      none: '0',
      DEFAULT: 'var(--r-control)',
      sm: 'var(--r-tag)',
      tag: 'var(--r-tag)',
      control: 'var(--r-control)',
      card: 'var(--r-surface)',
      full: '9999px',
    },
    extend: {
      fontFamily: {
        sans: ['var(--font-sans)'],
        mono: ['var(--font-mono)'],
      },
      // Type scale (tokens.css): 11 label (2xs), 12 meta (xs), 13 tables and controls (ctl), 14 body (sm),
      // 15 section title (base), 18 lead figure (lg), 20 page title (xl), 22 statement (2xl), 30 display.
      // Names avoid the colour names (`text-body` is a colour).
      fontSize: {
        '2xs': ['var(--text-2xs)', { lineHeight: 'var(--leading-2xs)' }],
        xs: ['var(--text-xs)', { lineHeight: 'var(--leading-xs)' }],
        ctl: ['var(--text-ctl)', { lineHeight: 'var(--leading-ctl)' }],
        sm: ['var(--text-sm)', { lineHeight: 'var(--leading-sm)' }],
        base: ['var(--text-base)', { lineHeight: 'var(--leading-base)' }],
        lg: ['var(--text-lg)', { lineHeight: 'var(--leading-lg)', letterSpacing: '-0.01em' }],
        xl: ['var(--text-xl)', { lineHeight: 'var(--leading-xl)', letterSpacing: '-0.01em' }],
        '2xl': ['var(--text-2xl)', { lineHeight: 'var(--leading-2xl)', letterSpacing: '-0.015em' }],
        headline: ['var(--text-headline)', { lineHeight: 'var(--leading-headline)', letterSpacing: '-0.017em' }],
        display: ['var(--text-display)', { lineHeight: 'var(--leading-display)', letterSpacing: '-0.02em' }],
      },
      // 1.5 px: the ring of a mark (a voice, an open square). 3 px: the double rule on the left of what a tool returned.
      borderWidth: { 1.5: '1.5px', 3: '3px' },
      // Labels in capitals are tracked out: 0.05em on tags and column headings, 0.06em on eyebrows.
      letterSpacing: { label: '0.05em', eyebrow: '0.06em' },
      // Control heights and row density as sizes: `h-ctl`, `min-h-ctl-touch`, `h-row`, `w-ctl`.
      spacing: {
        'ctl-sm': 'var(--ctl-h-sm)',
        ctl: 'var(--ctl-h)',
        'ctl-lg': 'var(--ctl-h-lg)',
        'ctl-touch': 'var(--ctl-h-touch)',
        row: 'var(--row-h)',
        'cell-y': 'var(--cell-py)',
        rail: 'var(--rail-w)',
        top: 'var(--top-h)',
      },
      boxShadow: {
        popover: 'var(--shadow-popover)',
        // The 2 px inset bar of attention / approval panels and of the current row.
        'bar-attention': 'inset 2px 0 0 rgb(var(--c-state-waiting))',
        'bar-approval': 'inset 2px 0 0 rgb(var(--c-state-approval))',
        'bar-warning': 'inset 2px 0 0 rgb(var(--c-state-bad))',
        'bar-info': 'inset 2px 0 0 rgb(var(--c-link))',
        'bar-accent': 'inset 2px 0 0 rgb(var(--c-accent))',
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
