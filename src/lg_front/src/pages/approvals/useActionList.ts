import { endpoints, type ActionFilters } from '../../api/endpoints';
import { qk } from '../../api/queryKeys';
import type { ActionOut } from '../../api/types';
import { useApi } from '../../auth/AuthContext';
import { useKeysetList } from '../../lib/pagination';

/** The action ledger with these filters, newest first, keyset-paged ("Load more"). */
export function useActionList(filters: ActionFilters, refetchInterval: number | false) {
  const api = useApi();
  return useKeysetList({
    queryKey: qk.actions.list(filters),
    fetchPage: (cursor, signal) => endpoints.actions(api, filters, cursor, signal),
    itemKey: (a: ActionOut) => a.id,
    refetchInterval,
  });
}

export type ActionList = ReturnType<typeof useActionList>;
