import js from '@eslint/js';
import jsxA11y from 'eslint-plugin-jsx-a11y';
import reactHooks from 'eslint-plugin-react-hooks';
import reactRefresh from 'eslint-plugin-react-refresh';
import globals from 'globals';
import tseslint from 'typescript-eslint';

// Syntax bans, grouped so a file-level exemption can drop one group and keep the others
// (ESLint replaces the whole `no-restricted-syntax` list per file).
const CACHE_CLEAR = [
  {
    selector:
      "CallExpression[callee.property.name='clear'][callee.object.name=/^(client|queryClient|qc)$/], CallExpression[callee.property.name='clear'][callee.object.callee.name='useQueryClient'], CallExpression[callee.property.name='clear'][callee.object.callee.property.name=/^get(Query|Mutation)Cache$/]",
    message:
      'Do not clear the React Query cache directly: a mounted observer keeps rendering removed data. Use forgetCachedData from auth/cacheBinding.ts.',
  },
];
const QUERY_KEY_LITERAL = [
  {
    selector: "Property[key.name='queryKey'][value.type='ArrayExpression']",
    message: "Build query keys with the module's api/queryKeys.ts (qk), not array literals.",
  },
  {
    selector: "CallExpression[callee.property.name=/^(get|set)QueryData$/][arguments.0.type='ArrayExpression']",
    message: "Build query keys with the module's api/queryKeys.ts (qk), not array literals.",
  },
];
const INVALIDATE = [
  {
    selector: "CallExpression[callee.property.name='invalidateQueries']",
    message: "Use a named policy from the module's api/invalidate.ts (or invalidateBounded from lib/pagination.ts).",
  },
];

// Property bans, grouped the same way (ESLint replaces the whole `no-restricted-properties` list per file).
const STORAGE_PROPS = [
  { object: 'window', property: 'localStorage', message: 'Credentials must never be persisted.' },
];
const OBJECT_URL = [
  {
    object: 'URL',
    property: 'createObjectURL',
    message: 'Download or open files through lib/download.ts (safe filename, URL revoked afterwards).',
  },
];

// The palette is the design tokens (src/theme/tokens.css, tailwind.config.js): Tailwind's default
// greys and hues are not generated, so a class such as `bg-slate-900` would silently do nothing.
const PALETTE_RE =
  '/(^|[\\s:])(bg|text|border|divide|outline|ring|ring-offset|from|via|to|fill|stroke|accent|caret|decoration|shadow|placeholder)-(slate|gray|zinc|neutral|stone|red|orange|amber|yellow|lime|green|emerald|teal|cyan|sky|blue|indigo|violet|purple|fuchsia|pink|rose)-[0-9]/';
const PALETTE = [
  {
    selector: `Literal[value=${PALETTE_RE}], TemplateElement[value.raw=${PALETTE_RE}]`,
    message: 'Use the design-token colours (bg-raised, text-muted, border-control, sev-*, state-*), not Tailwind palette classes.',
  },
];

// Layer boundaries (README "Structure", roadmap FE9): app -> pages -> components -> shared kernel
// (api, auth, live, lib, theme). Imports point down only. Tests are exempt: they compose layers.
const UP_TO_PAGES_OR_APP = {
  regex: '^(\\.\\./)+(pages|app)(/|$)',
  message: 'Layer boundary: the shared kernel and components must not import pages or the app shell.',
};
// The generated OpenAPI types (npm run gen:api) are read only by src/api: the hand-written types.ts
// files stay the app's vocabulary, and each contract.check.ts holds its types to the schema through
// api/contract.ts.
const SCHEMA_GEN = {
  regex: '(^|/)api/schema\\.gen$',
  message: "Import API types from the module's api/types.ts; only src/api reads the generated schema (a contract check uses api/contract.ts).",
};
const DATA_IN_COMPONENTS = {
  regex: '^(\\.\\./)+api/endpoints$',
  message: 'Components are presentational: a widget that fetches data belongs to its feature under pages/.',
};
const REACT_QUERY_IN_COMPONENTS = {
  name: '@tanstack/react-query',
  message: 'Components are presentational: a widget that fetches data belongs to its feature under pages/.',
};
const UP_TO_COMPONENTS = {
  regex: '^(\\.\\./)+components(/|$)',
  message: 'Layer boundary: the shared kernel (api, auth, live, lib, theme) must not import components.',
};

export default tseslint.config(
  { ignores: ['dist', 'coverage', 'node_modules', 'public/config.js', 'test-results', 'playwright-report', 'src/api/schema.gen.ts'] },
  {
    extends: [js.configs.recommended, ...tseslint.configs.recommended, jsxA11y.flatConfigs.recommended],
    files: ['**/*.{ts,tsx}'],
    languageOptions: {
      ecmaVersion: 2022,
      globals: { ...globals.browser },
    },
    plugins: {
      'react-hooks': reactHooks,
      'react-refresh': reactRefresh,
    },
    rules: {
      ...reactHooks.configs.recommended.rules,
      // eslint-plugin-react-hooks 7 adds the React Compiler rules to `recommended`. These four flag
      // existing code (refs read during render, setState in effects, Date.now() in render, the
      // virtualizer's unmemoizable API); each needs a component refactor, not a dependency bump.
      // Turn them back on as that code is reworked.
      'react-hooks/refs': 'off',
      'react-hooks/set-state-in-effect': 'off',
      'react-hooks/purity': 'off',
      'react-hooks/incompatible-library': 'off',
      // Pages export small pure helpers next to the component for unit tests; that only
      // affects development hot reload granularity.
      'react-refresh/only-export-components': 'off',
      '@typescript-eslint/no-unused-vars': ['error', { argsIgnorePattern: '^_', varsIgnorePattern: '^_' }],
      '@typescript-eslint/consistent-type-imports': 'error',
      'no-restricted-globals': [
        'error',
        { name: 'localStorage', message: 'Credentials must never be persisted; keep tokens in memory.' },
      ],
      'no-restricted-properties': ['error', ...STORAGE_PROPS, ...OBJECT_URL],
      'no-console': ['error', { allow: ['warn', 'error'] }],
      eqeqeq: ['error', 'always'],
      'no-restricted-syntax': ['error', ...CACHE_CLEAR, ...QUERY_KEY_LITERAL, ...INVALIDATE, ...PALETTE],
      'no-restricted-imports': ['error', { patterns: [SCHEMA_GEN] }],
    },
  },
  {
    files: ['src/{auth,live,lib,theme}/**/*.{ts,tsx}'],
    rules: {
      'no-restricted-imports': ['error', { patterns: [UP_TO_PAGES_OR_APP, UP_TO_COMPONENTS, SCHEMA_GEN] }],
    },
  },
  {
    files: ['src/api/**/*.{ts,tsx}'],
    rules: {
      'no-restricted-imports': ['error', { patterns: [UP_TO_PAGES_OR_APP, UP_TO_COMPONENTS] }],
    },
  },
  {
    files: ['src/components/**/*.{ts,tsx}'],
    rules: {
      'no-restricted-imports': ['error', { paths: [REACT_QUERY_IN_COMPONENTS], patterns: [UP_TO_PAGES_OR_APP, DATA_IN_COMPONENTS, SCHEMA_GEN] }],
    },
  },
  {
    // The one owner of session cache clearing.
    files: ['src/auth/cacheBinding.ts'],
    rules: {
      'no-restricted-syntax': ['error', ...QUERY_KEY_LITERAL, ...PALETTE],
    },
  },
  {
    // The owners of invalidation: each module's named policies, and bounded refetch for paged lists and live events.
    files: ['src/modules/*/api/invalidate.ts', 'src/lib/pagination.ts'],
    rules: {
      'no-restricted-syntax': ['error', ...CACHE_CLEAR, ...QUERY_KEY_LITERAL, ...PALETTE],
    },
  },
  {
    // The one owner of browser storage: display preferences only (theme, row density), never credentials.
    files: ['src/lib/prefs.ts'],
    rules: {
      'no-restricted-properties': ['error', ...OBJECT_URL],
    },
  },
  {
    // The one owner of object URLs.
    files: ['src/lib/download.ts'],
    rules: {
      'no-restricted-properties': ['error', ...STORAGE_PROPS],
    },
  },
  {
    files: ['src/**/*.test.{ts,tsx}', 'src/test/**'],
    rules: {
      // Tests assert that nothing is written to browser storage.
      'no-restricted-globals': 'off',
      'no-restricted-properties': 'off',
      // Tests build and tear down their own query clients.
      'no-restricted-syntax': 'off',
      // Tests compose layers (a page inside the shell, a guard around a page), but read API types
      // from api/types.ts like the app.
      'no-restricted-imports': ['error', { patterns: [SCHEMA_GEN] }],
    },
  },
  {
    files: ['vite.config.ts', 'eslint.config.js', 'tailwind.config.js', 'postcss.config.js'],
    languageOptions: { globals: { ...globals.node } },
  },
  {
    // Playwright end-to-end suite: runs in Node and inspects the page's storage to prove no token is kept.
    files: ['e2e/**/*.ts', 'playwright.config.ts'],
    languageOptions: { globals: { ...globals.node } },
    rules: {
      'no-restricted-globals': 'off',
      'no-restricted-properties': 'off',
    },
  },
);
