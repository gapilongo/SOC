import { screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

import { apiError, fakeApi, renderWithSession, signedInSession } from '../../../../test/helpers';
import { EvidenceActions } from './EvidenceActions';

describe('EvidenceActions', () => {
  const created: Blob[] = [];
  let clicked: string[] = [];

  beforeEach(() => {
    created.length = 0;
    clicked = [];
    URL.createObjectURL = vi.fn((b: Blob | MediaSource) => {
      created.push(b as Blob);
      return `blob:test/${created.length}`;
    });
    URL.revokeObjectURL = vi.fn();
    vi.spyOn(HTMLAnchorElement.prototype, 'click').mockImplementation(function (this: HTMLAnchorElement) {
      clicked.push(this.download);
    });
  });

  afterEach(() => vi.restoreAllMocks());

  it('downloads the JSON and HTML packs and opens the HTML in a new tab', async () => {
    const { api, calls } = fakeApi((method, path) => {
      if (method === 'GET' && path === '/alerts/alert%201/evidence') return new Blob(['{}'], { type: 'application/json' });
      throw new Error(`unexpected ${method} ${path}`);
    });
    const open = vi.spyOn(window, 'open').mockImplementation(() => null);
    const session = await signedInSession(api, { role: 'viewer' });
    renderWithSession(<EvidenceActions alertId="alert 1" />, session);

    await userEvent.click(screen.getByRole('button', { name: 'Download JSON' }));
    await waitFor(() => expect(clicked).toEqual(['evidence-alert_1.json']));
    await userEvent.click(screen.getByRole('button', { name: 'Download HTML' }));
    await waitFor(() => expect(clicked).toEqual(['evidence-alert_1.json', 'evidence-alert_1.html']));
    await userEvent.click(screen.getByRole('button', { name: 'Open HTML' }));
    await waitFor(() => expect(open).toHaveBeenCalledWith(expect.stringMatching(/^blob:/), '_blank', 'noopener'));

    expect(calls.map((c) => c.query)).toEqual([{ format: 'json' }, { format: 'html' }, { format: 'html' }]);
    expect(created[created.length - 1].type).toBe('text/html');
  });

  it('reports a failed export', async () => {
    const { api } = fakeApi(() => {
      throw apiError(404, 'not_found', 'alert not found');
    });
    const session = await signedInSession(api, { role: 'viewer' });
    renderWithSession(<EvidenceActions alertId="a-1" />, session);
    await userEvent.click(screen.getByRole('button', { name: 'Download JSON' }));
    expect(await screen.findByText(/alert not found/)).toBeInTheDocument();
    expect(clicked).toEqual([]);
  });
});
