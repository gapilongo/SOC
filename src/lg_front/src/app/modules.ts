/**
 * The module registry: the services this console is built from (ADR 0015).
 *
 * Adding a service is its folder under `src/modules/` and one entry here.
 * Routes, the sidebar, navigation counts, the live-event mapping, the
 * extension points and the shell tests are all derived from this list
 * (src/app/registry.ts); nothing else in the shell names a module.
 */

import type { ModuleManifest } from '../core/module';
import { soc } from '../modules/soc';

export const MODULES: readonly ModuleManifest[] = [soc];
