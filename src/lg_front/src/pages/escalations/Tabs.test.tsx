import { render, screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { useState } from 'react';
import { describe, expect, it } from 'vitest';

import { Tabs } from './Tabs';

const TABS = [
  { id: 'a', label: 'Alpha' },
  { id: 'b', label: 'Beta' },
  { id: 'c', label: 'Gamma' },
] as const;

function Harness() {
  const [tab, setTab] = useState<'a' | 'b' | 'c'>('a');
  return (
    <>
      <button type="button">before</button>
      <Tabs label="Sections" tabs={TABS} value={tab} onChange={setTab}>
        <p>Panel {tab}</p>
      </Tabs>
    </>
  );
}

describe('Tabs', () => {
  it('is an ARIA tablist with one selected tab controlling the labelled panel', () => {
    render(<Harness />);
    expect(screen.getByRole('tablist', { name: 'Sections' })).toBeInTheDocument();
    const tabs = screen.getAllByRole('tab');
    expect(tabs.map((t) => t.getAttribute('aria-selected'))).toEqual(['true', 'false', 'false']);
    expect(tabs.map((t) => t.tabIndex)).toEqual([0, -1, -1]);
    const panel = screen.getByRole('tabpanel', { name: 'Alpha' });
    expect(panel).toHaveTextContent('Panel a');
    expect(tabs[0]).toHaveAttribute('aria-controls', panel.id);
  });

  it('moves with the arrow keys (wrapping), Home and End, and Tab enters at the selected tab', async () => {
    const user = userEvent.setup();
    render(<Harness />);
    await user.click(screen.getByRole('button', { name: 'before' }));
    await user.tab();
    expect(screen.getByRole('tab', { name: 'Alpha' })).toHaveFocus();
    await user.keyboard('{ArrowRight}');
    expect(screen.getByRole('tab', { name: 'Beta' })).toHaveFocus();
    expect(screen.getByRole('tab', { name: 'Beta' })).toHaveAttribute('aria-selected', 'true');
    expect(screen.getByRole('tabpanel')).toHaveTextContent('Panel b');
    await user.keyboard('{End}');
    expect(screen.getByRole('tab', { name: 'Gamma' })).toHaveFocus();
    await user.keyboard('{ArrowRight}');
    expect(screen.getByRole('tab', { name: 'Alpha' })).toHaveFocus();
    await user.keyboard('{ArrowLeft}');
    expect(screen.getByRole('tab', { name: 'Gamma' })).toHaveAttribute('aria-selected', 'true');
    await user.keyboard('{Home}');
    expect(screen.getByRole('tabpanel', { name: 'Alpha' })).toBeInTheDocument();
    await user.keyboard('x');
    // Tab leaves the tablist for the panel.
    await user.tab();
    expect(screen.getByRole('tabpanel')).toHaveFocus();
    await user.click(screen.getByRole('tab', { name: 'Gamma' }));
    expect(screen.getByRole('tabpanel')).toHaveTextContent('Panel c');
  });
});
