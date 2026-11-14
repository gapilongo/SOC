import { endpoints } from '../../api/endpoints';
import type { ApiClient } from '../../../../api/client';
import type { EscalationOut } from '../../api/types';
import { can } from '../../../../auth/roles';
import type { Principal } from '../../../../auth/store';
import { DEFAULT_STATUS } from './queueParams';

/** Pages of the SLA-ordered queue read while looking for the next escalation. */
export const NEXT_SEARCH_PAGES = 4;
const NEXT_PAGE_SIZE = 50;

/**
 * The next escalation in SLA order (overdue first) that `principal` may
 * decide, other than `excludeId`; null when none is waiting.
 */
export async function findNextEscalation(api: ApiClient, principal: Principal | null, excludeId: string): Promise<EscalationOut | null> {
  let cursor: string | undefined;
  for (let i = 0; i < NEXT_SEARCH_PAGES; i += 1) {
    const page = await endpoints.escalations(api, { status: DEFAULT_STATUS, order: 'sla_deadline' }, cursor, undefined, NEXT_PAGE_SIZE);
    const items = Array.isArray(page.items) ? page.items : [];
    const hit = items.find((e) => e.id !== excludeId && can.decideEscalation(principal, e));
    if (hit) return hit;
    if (!page.next_cursor) return null;
    cursor = page.next_cursor;
  }
  return null;
}
