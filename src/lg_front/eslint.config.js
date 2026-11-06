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

export default tseslint.config(
  { ignores: ['dist', 'coverage', 'node_modules', 'public/config.js', 'test-results', 'playwright-report'] },
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
      // Pages export small pure helpers next to the component for unit tests; that only
      // affects development hot reload granularity.
      'react-refresh/only-export-components': 'off',
      '@typescript-eslint/no-unused-vars': ['error', { argsIgnorePattern: '^_', varsIgnorePattern: '^_' }],
      '@typescript-eslint/consistent-type-imports': 'error',
      'no-restricted-globals': [
        'error',
        { name: 'localStorage', message: 'Credentials must never be persisted; keep tokens in memory.' },
      ],
      'no-restricted-properties': [
        'error',
        { object: 'window', property: 'localStorage', message: 'Credentials must never be persisted.' },
      ],
      'no-console': ['error', { allow: ['warn', 'error'] }],
      eqeqeq: ['error', 'always'],
      'no-restricted-syntax': ['error', ...CACHE_CLEAR],
    },
  },
  {
    // The one owner of session cache clearing.
    files: ['src/auth/cacheBinding.ts'],
    rules: {
      'no-restricted-syntax': 'off',
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
