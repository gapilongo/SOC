import { describe, expect, it } from 'vitest';

import { autonomyPatch, storedAutonomy } from './ResponseSections';

describe('autonomy settings', () => {
  it('merges legacy response.autonomy and writes one top-level map', () => {
    const settings = { autonomy: { low: 'auto' }, response: { autonomy: { low: 'approval', high: 'disabled' } } };
    expect(storedAutonomy(settings)).toEqual({ low: 'approval', high: 'disabled' });
    expect(autonomyPatch(settings, { low: 'auto', medium: '', high: 'approval' })).toEqual({ autonomy: { low: 'auto', high: 'approval' }, response: { autonomy: null } });
    expect(autonomyPatch({}, {})).toEqual({ autonomy: null });
  });
});
