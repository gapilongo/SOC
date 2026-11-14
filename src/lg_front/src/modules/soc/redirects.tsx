import { Navigate, useLocation } from 'react-router-dom';

import { APPROVALS_HREF } from './lib/links';

/**
 * Where an old `/actions` link goes: the pending approvals for
 * `/actions` and `/actions?status=awaiting_approval` (the old approvals link,
 * still in notifications and bookmarks); the "All actions" view with the same
 * filters for any other ledger query.
 */
export function legacyActionsTarget(search: string): string {
  const params = new URLSearchParams(search);
  const pendingOnly = [...params.keys()].every((k) => k === 'status') && params.getAll('status').every((s) => s === 'awaiting_approval');
  if (pendingOnly) return APPROVALS_HREF;
  const out = new URLSearchParams({ view: 'all' });
  for (const [key, value] of params) if (key !== 'view') out.append(key, value);
  return `${APPROVALS_HREF}?${out.toString()}`;
}

/** `/actions` (the page before it was renamed Approvals) redirects to `/approvals`. */
export function LegacyActionsRedirect() {
  const { search, hash } = useLocation();
  return <Navigate to={`${legacyActionsTarget(search)}${hash}`} replace />;
}
