/**
 * The SOC module's public surface: the only file of this module another
 * module may import (ESLint enforces it, ADR 0015). Keep it small: links
 * into the SOC's pages and the extension points the SOC owns. It imports no
 * page code.
 */

export { ALERT_ENTITY } from './slots';
export { alertHref, alertsHref, APPROVALS_HREF, escalationHref, escalationQueueHref } from './lib/links';
