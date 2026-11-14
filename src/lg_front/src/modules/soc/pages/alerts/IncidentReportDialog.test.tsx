import { screen, waitFor, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { describe, expect, it, vi } from 'vitest';

import type { IncidentReportOut } from '../../api/types';
import { fakeApi, renderWithSession, signedInSession } from '../../../../test/helpers';
import { AI_LABEL, IncidentReportDialog } from './IncidentReportDialog';

const DISCLAIMER = 'Draft for a human to complete and submit; LG-SOTF does not submit reports to CSIRTs or authorities.';

function report(stage: string, withAi: boolean): IncidentReportOut {
  return {
    alert_id: 'a-1',
    stage,
    event_id: 42,
    generated_at: '2026-09-30T10:00:00Z',
    disclaimer: DISCLAIMER,
    deadline_hint: 'within 72 hours of becoming aware',
    fields: [
      { key: 'severity', label: 'Severity and impact', value: 'high', source: 'case_data', required: true, help: null },
      { key: 'contact', label: 'Point of contact', value: null, source: 'requires_human', required: true, help: 'Who the CSIRT should call.' },
    ],
    ai_narrative: withAi ? { text: 'The attacker <b>phished</b> a user.', label: AI_LABEL, provider: 'fake', model: 'fake-fast' } : null,
    ai_narrative_error: null,
    html: '<!doctype html><title>draft</title>',
  };
}

describe('IncidentReportDialog', () => {
  it('posts the chosen stage and shows the disclaimer, fields and the AI badge', async () => {
    const { api, calls } = fakeApi((method, path, body) => {
      if (method === 'POST' && path === '/alerts/a-1/incident-report') {
        const b = body as { stage: string; include_ai_narrative: boolean };
        return report(b.stage, b.include_ai_narrative);
      }
      throw new Error(`unexpected ${method} ${path}`);
    });
    const session = await signedInSession(api);
    const { client } = renderWithSession(<IncidentReportDialog alertId="a-1" open onClose={vi.fn()} />, session);
    const invalidate = vi.spyOn(client, 'invalidateQueries');

    await userEvent.click(screen.getByLabelText(/Incident notification \(72 h\)/));
    await userEvent.click(screen.getByRole('button', { name: 'Generate draft' }));

    expect(await screen.findByText(DISCLAIMER)).toBeInTheDocument();
    expect(calls[0].body).toEqual({ stage: 'notification', include_ai_narrative: true });
    expect(screen.getByText('within 72 hours of becoming aware')).toBeInTheDocument();
    expect(screen.getByText('— to be completed by you —')).toBeInTheDocument();
    expect(screen.getByText('Needs your input')).toBeInTheDocument();
    const narrative = screen.getByRole('region', { name: 'AI-drafted narrative' });
    expect(within(narrative).getByText(AI_LABEL)).toBeInTheDocument();
    // Model output is shown as text, never as markup.
    expect(within(narrative).getByText('The attacker <b>phished</b> a user.')).toBeInTheDocument();
    await waitFor(() => expect(invalidate).toHaveBeenCalledWith({ queryKey: ['alert', 'a-1', 'events'] }));
  });

  it('can leave the AI narrative out', async () => {
    const { api, calls } = fakeApi((_m, _p, body) => report((body as { stage: string }).stage, false));
    const session = await signedInSession(api);
    renderWithSession(<IncidentReportDialog alertId="a-1" open onClose={vi.fn()} />, session);

    await userEvent.click(screen.getByLabelText(/Include AI-drafted narrative/));
    await userEvent.click(screen.getByRole('button', { name: 'Generate draft' }));

    expect(await screen.findByText(DISCLAIMER)).toBeInTheDocument();
    expect(calls[0].body).toEqual({ stage: 'early_warning', include_ai_narrative: false });
    expect(screen.queryByRole('region', { name: 'AI-drafted narrative' })).not.toBeInTheDocument();
  });
});
