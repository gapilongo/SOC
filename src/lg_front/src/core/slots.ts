/**
 * Named extension points (ADR 0015).
 *
 * An extension point ("slot") is a place where one part of the console lets
 * modules render something: the shell's tenant control, the space next to an
 * entity on an alert. The owner defines the slot and the props it passes;
 * a module contributes a component for it in its manifest. With no
 * contribution the slot renders nothing (or the owner's fallback), so the
 * owner's code does not change when a module arrives or is switched off.
 *
 * The owner renders a slot with `SlotOutlet` (components/Slot.tsx).
 */

import type { ComponentType } from 'react';

import type { Principal } from '../auth/store';

/** A slot whose contributions receive props `P`. */
export interface Slot<P extends object> {
  readonly id: string;
  /** Type marker only: never set. */
  readonly _props?: (props: P) => void;
}

/** Declare a slot. `id` is `<owner>.<place>`, for example `alert.entity`. */
export function defineSlot<P extends object = Record<string, never>>(id: string): Slot<P> {
  return { id };
}

export interface Contribution<P extends object = object> {
  slot: Slot<P>;
  /** Loaded with `lazy()`: a manifest never imports widget code directly. */
  Component: ComponentType<P>;
  /** Render only for these principals (default: everyone); a false result never loads the component. */
  when?: (p: Principal | null) => boolean;
}

/** A module's contribution to `slot`, for the `extensions` list of its manifest. */
export function contribute<P extends object>(
  slot: Slot<P>,
  Component: ComponentType<P>,
  options: { when?: (p: Principal | null) => boolean } = {},
): Contribution {
  return { slot, Component, when: options.when } as unknown as Contribution;
}

// Slots owned by the shell ---------------------------------------------------

/**
 * The tenant control at the left of the header. A contribution replaces the
 * plain tenant name for the principals it applies to (the tenant switcher of
 * platform admins). Props: the current tenant's display name.
 */
export const SHELL_HEADER_TENANT = defineSlot<{ label: string }>('shell.header.tenant');

/** Full-width notices between the header and the page (the acting-tenant banner). */
export const SHELL_BANNER = defineSlot('shell.banner');
