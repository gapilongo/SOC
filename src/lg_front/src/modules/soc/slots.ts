/**
 * Extension points the SOC module owns (ADR 0015). Another module reaches
 * them through `public.ts` and contributes a component in its manifest; with
 * no contribution a slot renders nothing.
 */

import { defineSlot } from '../../core/slots';

/**
 * Next to each entity of an alert, in the alert panel and on the decision
 * page's Entities tab. Props: the entity's kind as the normalized record
 * names it (`hosts`, `users`, `ips`, ...) and its value. A vulnerability
 * module would say here whether the host has open findings.
 */
export const ALERT_ENTITY = defineSlot<{ kind: string; value: string }>('alert.entity');
