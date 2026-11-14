// @vitest-environment node
/**
 * The module boundary of ADR 0015, checked against the real ESLint config: each case is a file that
 * does not exist, linted as if it sat at that path.
 */
import { readFileSync } from 'node:fs';
import path from 'node:path';

import { ESLint } from 'eslint';
import { beforeAll, describe, expect, it, vi } from 'vitest';

const ROOT = path.resolve(__dirname, '../..');

// ESLint loads its whole config for the first file: slow on a busy runner.
vi.setConfig({ testTimeout: 60_000 });
let eslint: ESLint;

beforeAll(() => {
  eslint = new ESLint({ cwd: ROOT });
});

/** The boundary messages ESLint reports for `code` at `file` (relative to the frontend root). */
async function boundaryErrors(file: string, code: string): Promise<string[]> {
  const [result] = await eslint.lintText(code, { filePath: path.join(ROOT, file) });
  return result.messages.filter((m) => m.ruleId === 'lg-sotf/module-boundary' || m.ruleId === 'no-restricted-imports').map((m) => m.message);
}

describe('module boundary (ESLint)', () => {
  it('lets a module use its own files, the kernel and components', async () => {
    const code = [
      "import { qk } from '../api/queryKeys';",
      "import { useApi } from '../../../auth/AuthContext';",
      "import { Button } from '../../../components/ui';",
      "import { defineSlot } from '../../../core/slots';",
      'export const x = [qk, useApi, Button, defineSlot];',
    ].join('\n');
    expect(await boundaryErrors('src/modules/voc/pages/FindingsPage.tsx', code)).toEqual([]);
  });

  it('lets a module import another module through its public.ts, and nothing deeper', async () => {
    const ok = "import { alertsHref } from '../../soc/public';\nexport const x = alertsHref;";
    expect(await boundaryErrors('src/modules/voc/pages/FindingsPage.tsx', ok)).toEqual([]);
    for (const deep of ['../../soc/lib/links', '../../soc/api/queryKeys', '../../soc/pages/alerts/AlertsPage', '../../soc', '../../soc/index']) {
      const errors = await boundaryErrors('src/modules/voc/pages/FindingsPage.tsx', `import x from '${deep}';\nexport default x;`);
      expect(errors, deep).toEqual(['Module boundary: import the "soc" module only through modules/soc/public.ts.']);
    }
    // A lazy import of another module's internals is refused as well.
    const lazy = "export const load = () => import('../../soc/pages/alerts/AlertsPage');";
    expect(await boundaryErrors('src/modules/voc/pages/FindingsPage.tsx', lazy)).toHaveLength(1);
  });

  it('lets only the registry import a module, and only its manifest', async () => {
    expect(await boundaryErrors('src/app/modules.ts', "import { soc } from '../modules/soc';\nexport const MODULES = [soc];")).toEqual([]);
    expect(await boundaryErrors('src/app/modules.ts', "import { qk } from '../modules/soc/api/queryKeys';\nexport const x = qk;")).toEqual([
      expect.stringContaining('the shell reaches modules only through the registry'),
    ]);
    for (const file of ['src/app/shell/Header.tsx', 'src/app/Layout.tsx', 'src/app/routes.tsx', 'src/pages/Login.tsx', 'src/main.tsx']) {
      const up = path.relative(path.dirname(file), 'src/modules/soc/pages/platform/TenantSwitcher');
      const errors = await boundaryErrors(file, `import { TenantSwitcher } from '${up.startsWith('.') ? up : `./${up}`}';\nexport const x = TenantSwitcher;`);
      expect(errors, file).toEqual([expect.stringContaining('the shell reaches modules only through the registry')]);
    }
  });

  it('keeps the kernel and components free of modules', async () => {
    for (const file of ['src/api/hooks.ts', 'src/auth/roles.ts', 'src/live/LiveProvider.tsx', 'src/lib/format.ts', 'src/core/module.ts', 'src/components/Slot.tsx', 'src/components/ui/Tabs.tsx']) {
      const up = path.relative(path.dirname(file), 'src/modules/soc/public');
      const errors = await boundaryErrors(file, `import { alertsHref } from '${up}';\nexport const x = alertsHref;`);
      expect(errors.length, file).toBeGreaterThan(0);
      expect(errors.join(' '), file).toMatch(/must not import/);
    }
  });

  it('keeps a module out of the shell', async () => {
    const errors = await boundaryErrors('src/modules/voc/pages/FindingsPage.tsx', "import { REGISTRY } from '../../../app/routes';\nexport const x = REGISTRY;");
    expect(errors).toEqual([expect.stringContaining('a module must not import the shell')]);
  });

  it('makes a manifest reach its pages through lazy() only', async () => {
    const eager = "import FindingsPage from './pages/FindingsPage';\nexport const voc = { id: 'voc', routes: [{ Page: FindingsPage }] };";
    expect(await boundaryErrors('src/modules/voc/index.ts', eager)).toEqual([expect.stringContaining('only through lazy(')]);
    const lazy = [
      "import { lazy } from 'react';",
      "import { vocKeys } from './api/queryKeys';",
      "const FindingsPage = lazy(() => import('./pages/FindingsPage'));",
      "export const voc = { id: 'voc', routes: [{ Page: FindingsPage }], keys: vocKeys };",
    ].join('\n');
    expect(await boundaryErrors('src/modules/voc/index.ts', lazy)).toEqual([]);
  });

  it('rests on the app having no path alias: the rule resolves relative imports only', () => {
    const tsconfig = readFileSync(path.join(ROOT, 'tsconfig.app.json'), 'utf8');
    expect(tsconfig).not.toMatch(/"(paths|baseUrl)"/);
    expect(readFileSync(path.join(ROOT, 'vite.config.ts'), 'utf8')).not.toMatch(/\balias\b/);
    // A bare specifier is a package, never a module of the app.
    expect(readFileSync(path.join(ROOT, 'eslint-rules/module-boundary.js'), 'utf8')).toContain("startsWith('.')");
  });

  it('exempts tests, which compose layers', async () => {
    const code = "import { soc } from '../modules/soc';\nimport { qk } from '../modules/soc/api/queryKeys';\nexport const x = [soc, qk];";
    expect(await boundaryErrors('src/app/anything.test.tsx', code)).toEqual([]);
  });
});
