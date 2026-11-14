import { screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { describe, expect, it } from 'vitest';

import type { LlmTestOut } from '../../api/types';
import { fakeApi, renderWithSession, signedInSession } from '../../../../test/helpers';
import { formatLatency, LlmTestCard } from './LlmTestCard';

const RESULT: LlmTestOut = {
  provider: 'ollama',
  enabled: true,
  ok: false,
  tiers: [
    { tier: 'fast', model: 'local/qwen3:8b', ok: true, latency_ms: 1840, structured_output: 'json_schema', error_code: null, error: null },
    {
      tier: 'deep',
      model: 'local/qwen3:32b',
      ok: false,
      latency_ms: 35,
      structured_output: 'json_schema',
      error_code: 'http_error',
      error: 'HTTP 404: the model or endpoint path was not found (for Ollama: pull the model; check llm.base_url ends in /v1)',
    },
  ],
};

describe('LlmTestCard', () => {
  it('runs the probe and shows each tier', async () => {
    const { api, calls } = fakeApi(() => RESULT);
    renderWithSession(<LlmTestCard />, await signedInSession(api, { role: 'admin' }));
    await userEvent.click(screen.getByRole('button', { name: 'Test model' }));
    await waitFor(() => expect(screen.getByText('check failed')).toBeInTheDocument());
    expect(calls).toEqual([{ method: 'POST', path: '/tenant/llm/test', body: undefined, query: undefined }]);
    expect(screen.getByText('local/qwen3:8b')).toBeInTheDocument();
    expect(screen.getByText('1.8 s')).toBeInTheDocument();
    expect(screen.getByText('http error')).toBeInTheDocument();
    expect(screen.getByText(/pull the model/)).toBeInTheDocument();
  });

  it('formats latency', () => {
    expect(formatLatency(340)).toBe('340 ms');
    expect(formatLatency(12_345)).toBe('12.3 s');
  });
});
