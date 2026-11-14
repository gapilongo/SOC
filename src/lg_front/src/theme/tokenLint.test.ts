// @vitest-environment node
/// <reference types="node" />
/**
 * The token lint (eslint.config.js): a raw hex colour or an arbitrary size
 * utility fails `npm run lint`, in a page, a component or the shell alike; layout
 * widths, grid templates, anchors and issue numbers do not. Run through
 * ESLint itself with the repository's configuration, so the test follows it.
 */
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

import { ESLint } from 'eslint';
import { beforeAll, describe, expect, it } from 'vitest';

const ROOT = join(dirname(fileURLToPath(import.meta.url)), '..', '..');

let eslint: ESLint;
beforeAll(() => {
  eslint = new ESLint({ cwd: ROOT });
});

/** The messages ESLint reports for a component whose root element has these attributes. */
async function lint(attributes: string, file = 'src/modules/soc/pages/Probe.tsx'): Promise<string[]> {
  const code = `export function Probe() {\n  return <div ${attributes} />;\n}\n`;
  const [result] = await eslint.lintText(code, { filePath: join(ROOT, file) });
  return result.messages.map((m) => m.message);
}

describe('token lint', () => {
  it('refuses a raw hex colour in a style, an SVG attribute or a class', async () => {
    for (const attributes of [
      `style={{ color: '#3987e5' }}`,
      `style={{ background: '#D95926' }}`,
      `data-fill="#fff"`,
      `className="bg-[#0A0E13]"`,
      'className={`border ${"x"} text-[#8AB6FF80]`}',
    ]) {
      const messages = await lint(attributes);
      expect(messages, attributes).toHaveLength(1);
      expect(messages[0]).toMatch(/not a raw hex colour/);
    }
  }, 60_000);

  it('refuses an arbitrary size utility: type, line height, tracking, height, radius, border, spacing', async () => {
    for (const cls of [
      'text-[13.5px]',
      'leading-[1.3]',
      'tracking-[0.05em]',
      'h-[34px]',
      'min-h-[22px]',
      'rounded-[3px]',
      'rounded-t-[2px]',
      'border-[1.5px]',
      'border-l-[3px]',
      'p-[18px]',
      'md:pl-[18px]',
      'mt-[7px]',
      '-mt-[7px]',
      'gap-[5px]',
      'min-[900px]:h-[36px]',
    ]) {
      const messages = await lint(`className="flex ${cls} items-center"`);
      expect(messages, cls).toHaveLength(1);
      expect(messages[0]).toMatch(/not an arbitrary value/);
    }
  }, 60_000);

  it('applies in components and in template strings too', async () => {
    expect(await lint(`className="h-[34px]"`, 'src/components/ui/Probe.tsx')).toHaveLength(1);
    expect(await lint('className={`flex ${"x"} h-[34px]`}', 'src/components/Probe.tsx')).toHaveLength(1);
  }, 60_000);

  it('leaves tokens, layout widths, grid templates, breakpoints, anchors and issue numbers alone', async () => {
    for (const attributes of [
      `className="h-ctl min-h-ctl-touch h-row rounded-control text-ctl tracking-label border-1.5 border-l-3 px-2.5"`,
      `className="w-[232px] min-w-[900px] max-w-[62em] max-h-[90vh] grid-cols-[40px_minmax(0,1fr)] min-[900px]:table z-[60]"`,
      `className="min-w-[min(20rem,100%)] flex-[1_1_380px] [text-wrap:balance]"`,
      `id="x" data-href="#main"`,
      `title="see #411 and #88"`,
      `style={{ color: 'rgb(var(--c-data-1))' }}`,
    ]) {
      expect(await lint(attributes), attributes).toEqual([]);
    }
  }, 60_000);

  it('exempts no file: the shell is held to both rules like every page', async () => {
    for (const file of ['src/app/Layout.tsx', 'src/app/shell/Rail.tsx', 'src/app/shell/TopBar.tsx']) {
      expect(await lint(`className="md:pl-[232px]"`, file), file).toHaveLength(1);
      expect(await lint(`className="min-h-[34px]"`, file), file).toHaveLength(1);
      expect(await lint(`style={{ color: '#3987e5' }}`, file), file).toHaveLength(1);
      // The rail's width and the top bar's height are tokens.
      expect(await lint(`className="w-rail pl-rail h-top min-h-ctl touch:min-h-ctl-touch"`, file), file).toEqual([]);
    }
  }, 60_000);
});
