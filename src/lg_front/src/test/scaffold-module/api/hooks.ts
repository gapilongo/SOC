/** The scaffold module's read hooks, on the shared API client. */

import { useQuery } from '@tanstack/react-query';

import { useApi } from '../../../auth/AuthContext';
import { scaffoldKeys } from './queryKeys';

/** How many things wait (GET /scaffold/things/count), for the nav count; undefined until known or when none. */
export function useThingCount(): number | undefined {
  const api = useApi();
  const q = useQuery({
    queryKey: scaffoldKeys.things.count,
    queryFn: ({ signal }) => api.get<{ count: number }>('/scaffold/things/count', { signal }),
  });
  const n = q.data?.count;
  return typeof n === 'number' && n > 0 ? n : undefined;
}
