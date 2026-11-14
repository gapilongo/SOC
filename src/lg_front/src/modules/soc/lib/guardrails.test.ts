import { describe, expect, it } from 'vitest';

import { GUARDRAIL_REASONS, describeBlockedReason } from './guardrails';

describe('describeBlockedReason', () => {
  it('explains the internal-sender block instead of showing the code', () => {
    const text = describeBlockedReason('internal_sender');
    expect(text).toBe(GUARDRAIL_REASONS.internal_sender);
    expect(text).not.toContain('internal_sender');
    expect(text).toMatch(/own domains/);
  });

  it('keeps the detail after a known code', () => {
    expect(describeBlockedReason('invalid_email: not-an-address')).toBe(
      `${GUARDRAIL_REASONS.invalid_email} (not-an-address)`,
    );
  });

  it('explains the reviewer rejection codes', () => {
    expect(describeBlockedReason('rejected_by_reviewer')).toBe(GUARDRAIL_REASONS.rejected_by_reviewer);
    expect(describeBlockedReason('rejected_with_remaining')).toBe(GUARDRAIL_REASONS.rejected_with_remaining);
  });

  it('returns an unknown code unchanged', () => {
    expect(describeBlockedReason('some_future_code')).toBe('some_future_code');
  });
});
