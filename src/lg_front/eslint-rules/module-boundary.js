// The module boundary (ADR 0015), as one ESLint rule. It resolves each relative import against the
// file that holds it, so the same rule works at any folder depth:
//
// - a module (src/modules/<id>/) imports another module only through its public.ts;
// - the shell (src/app, src/pages, src/main.tsx) imports a module only in the registry
//   (src/app/modules.ts), and there only the module's manifest (src/modules/<id>/index.ts);
// - the kernel (api, auth, live, lib, theme, core, config) and components never import a module;
// - a module never imports the shell;
// - a manifest reaches its pages only through lazy(): a static import of ./pages/ is refused, so a
//   module that is switched off is never downloaded.
//
// Tests are exempt (they compose layers); the config turns the rule off for them.

import path from 'node:path';

const KERNEL = new Set(['api', 'auth', 'live', 'lib', 'theme', 'core', 'config', 'config.ts']);
const SHELL = new Set(['app', 'pages', 'main.tsx']);

/** Where a path under src/ belongs: { layer, module?, rest } or null outside src/. */
function classify(file) {
  const parts = file.split(path.sep);
  const src = parts.lastIndexOf('src');
  if (src < 0) return null;
  const [top, ...rest] = parts.slice(src + 1);
  if (top === 'modules' && rest.length > 0) return { layer: 'module', module: rest[0], rest: rest.slice(1).join('/') };
  if (top === 'components') return { layer: 'components' };
  if (KERNEL.has(top)) return { layer: 'kernel' };
  if (SHELL.has(top)) return { layer: 'shell', rest: [top, ...rest].join('/') };
  return { layer: 'other' };
}

const stripExt = (p) => p.replace(/\.(ts|tsx|js|jsx)$/, '');

/** The message for importing `to` from `from`, or null when it is allowed. `isStatic`: not a dynamic import(). */
export function violation(from, to, isStatic) {
  if (!from || !to) return null;
  if (to.layer === 'module') {
    const target = stripExt(to.rest);
    if (from.layer === 'module') {
      if (from.module !== to.module) {
        return target === 'public' ? null : `Module boundary: import the "${to.module}" module only through modules/${to.module}/public.ts.`;
      }
      if (isStatic && stripExt(from.rest) === 'index' && /^pages(\/|$)/.test(target)) {
        return 'A module manifest reaches its pages only through lazy(() => import(...)), so an unused module is never downloaded.';
      }
      return null;
    }
    if (from.layer === 'shell') {
      if (stripExt(from.rest) === 'app/modules' && (target === '' || target === 'index')) return null;
      return 'Module boundary: the shell reaches modules only through the registry (src/app/modules.ts imports each manifest; everything else derives from it).';
    }
    if (from.layer === 'kernel' || from.layer === 'components') {
      return 'Module boundary: the shared kernel and components must not import a module. Move the shared part down, or use an extension point (core/slots.ts).';
    }
    return null;
  }
  if (to.layer === 'shell' && from.layer === 'module') {
    return 'Module boundary: a module must not import the shell (src/app, src/pages). Use the kernel, components or an extension point.';
  }
  return null;
}

/** @type {import('eslint').Rule.RuleModule} */
export const moduleBoundary = {
  meta: {
    type: 'problem',
    docs: { description: 'Enforce the frontend module boundary (ADR 0015).' },
    schema: [],
  },
  create(context) {
    const from = classify(context.filename);
    const check = (node, source, isStatic) => {
      if (!source || typeof source.value !== 'string' || !source.value.startsWith('.')) return;
      const to = classify(path.resolve(path.dirname(context.filename), source.value));
      const message = violation(from, to, isStatic);
      if (message) context.report({ node, message });
    };
    return {
      ImportDeclaration: (node) => check(node, node.source, true),
      ExportNamedDeclaration: (node) => check(node, node.source, true),
      ExportAllDeclaration: (node) => check(node, node.source, true),
      ImportExpression: (node) => check(node, node.source, false),
    };
  },
};

export default { rules: { 'module-boundary': moduleBoundary } };
