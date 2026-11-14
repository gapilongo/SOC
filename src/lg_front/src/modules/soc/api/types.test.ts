import { describe, expect, it } from 'vitest';

import { SEVERITIES, isOneOf } from './types';

describe('isOneOf', () => {
  it('narrows an open vocabulary value to the known ones', () => {
    expect(isOneOf(SEVERITIES, 'high')).toBe(true);
    expect(isOneOf(SEVERITIES, 'severe')).toBe(false);
    expect(isOneOf(SEVERITIES, undefined)).toBe(false);
    expect(isOneOf(SEVERITIES, 3)).toBe(false);
  });
});
