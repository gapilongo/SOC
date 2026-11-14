import { render, screen, within } from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';
import { describe, expect, it } from 'vitest';

import { EntityChip, EntityList, TabLinks, Tabs, Timeline, type TimelineEntry } from './index';

const ENTRIES: TimelineEntry[] = [
  { id: 1, title: 'Alert ingested', ts: '2026-11-07T10:00:00Z', time: '7 Nov 10:00', byline: 'by system', note: 'node ingest' },
  { id: 2, title: 'Note', ts: '2026-11-07T10:05:00Z', time: '7 Nov 10:05', byline: 'by analyst u-1', detail: 'Called the user.\nNot them.' },
  { id: 3, title: 'Closed', ts: '2026-11-07T10:09:00Z', time: '7 Nov 10:09' },
];

describe('Timeline', () => {
  it.each(['rail', 'rows'] as const)('%s: lists the events in order with their time, actor, step and detail', (variant) => {
    render(<Timeline variant={variant} entries={ENTRIES} className="extra" />);
    const list = screen.getByRole('list');
    expect(list).toHaveClass('extra');
    const items = within(list).getAllByRole('listitem');
    expect(items.map((li) => within(li).getByText(/Alert ingested|Note|Closed/).textContent)).toEqual(['Alert ingested', 'Note', 'Closed']);
    expect(items[0]).toHaveTextContent('by system');
    expect(items[0]).toHaveTextContent('node ingest');
    expect(within(items[0]).getByText('7 Nov 10:00')).toHaveAttribute('datetime', '2026-11-07T10:00:00Z');
    expect(within(items[1]).getByText(/Called the user/)).toHaveClass('whitespace-pre-wrap');
    // An entry with nothing but a title and a time shows just those.
    expect(items[2]).toHaveTextContent(/^Closed\s*7 Nov 10:09$/);
  });

  it('defaults to the rail', () => {
    render(<Timeline entries={ENTRIES.slice(0, 1)} />);
    expect(screen.getByRole('list')).toHaveClass('border-l');
  });
});

describe('EntityList', () => {
  const GROUPS = [
    { kind: 'hosts', label: 'Hosts', values: ['LT-1', 'LT-1', 'SRV-9'] },
    { kind: 'ips', label: 'IP addresses', values: ['192.0.2.10'] },
  ];

  it.each(['stacked', 'columns'] as const)('%s: names each kind and shows every value as a chip', (layout) => {
    render(<EntityList layout={layout} groups={GROUPS} />);
    expect(screen.getByText('Hosts').tagName).toBe('DT');
    expect(screen.getByText('IP addresses').tagName).toBe('DT');
    // Repeated values are all shown.
    expect(screen.getAllByText('LT-1')).toHaveLength(2);
    expect(screen.getByText('192.0.2.10').tagName).toBe('CODE');
  });

  it('renders what the caller adds after a value, with its kind', () => {
    render(<EntityList groups={GROUPS} after={(kind, value) => (kind === 'hosts' && value === 'SRV-9' ? <a href="/findings">2 findings</a> : null)} />);
    const link = screen.getByRole('link', { name: '2 findings' });
    expect(link.previousElementSibling).toHaveTextContent('SRV-9');
  });

  it('offers the chip on its own', () => {
    render(<EntityChip className="extra">j.doe</EntityChip>);
    expect(screen.getByText('j.doe')).toHaveClass('extra', 'font-mono');
  });
});

describe('tabs', () => {
  it('underline tabs are the same ARIA tabs with another look', () => {
    render(
      <Tabs variant="underline" label="Report" tabs={[{ id: 'a', label: 'Value' }, { id: 'b', label: 'Accuracy' }]} value="b" onChange={() => undefined}>
        <p>Panel</p>
      </Tabs>,
    );
    expect(screen.getByRole('tablist', { name: 'Report' })).toHaveClass('border-b');
    expect(screen.getByRole('tab', { name: 'Accuracy' })).toHaveAttribute('aria-selected', 'true');
    expect(screen.getByRole('tab', { name: 'Accuracy' })).toHaveClass('border-accent');
    expect(screen.getByRole('tab', { name: 'Value' })).toHaveClass('border-transparent');
    expect(screen.getByRole('tabpanel', { name: 'Accuracy' })).toHaveTextContent('Panel');
  });

  it('link tabs are a nav of links with the current one marked', () => {
    render(
      <MemoryRouter>
        <TabLinks
          label="Alert views"
          current="closed"
          tabs={[
            { id: 'open', to: '/alerts', label: 'Open', trailing: <span>3</span> },
            { id: 'closed', to: '/alerts?view=closed', label: 'Closed' },
          ]}
        />
      </MemoryRouter>,
    );
    const nav = screen.getByRole('navigation', { name: 'Alert views' });
    expect(within(nav).queryByRole('tab')).not.toBeInTheDocument();
    expect(within(nav).getByRole('link', { name: 'Closed' })).toHaveAttribute('aria-current', 'page');
    const open = within(nav).getByRole('link', { name: 'Open 3' });
    expect(open).not.toHaveAttribute('aria-current');
    expect(open).toHaveAttribute('href', '/alerts');
  });
});
