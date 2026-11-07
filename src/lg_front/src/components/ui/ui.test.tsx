import { render, screen, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { useState } from 'react';
import { describe, expect, it, vi } from 'vitest';

import { DispositionBadge, RiskBadge, SeverityBadge, StatusBadge, statusTone, Badge } from '../Badge';
import {
  Banner,
  Button,
  Card,
  Checkbox,
  CountChip,
  DefinitionList,
  EmptyState,
  ErrorMessage,
  FilterChip,
  isSeverity,
  JsonBlock,
  PageHeader,
  SelectField,
  SeverityTag,
  StatePill,
  TextAreaField,
  TextField,
  Segmented,
  ToggleGroup,
  VisuallyHidden,
  buttonClass,
} from '.';
import { apiError } from '../../test/helpers';

describe('Button', () => {
  it('renders each variant and size, secondary/36 px by default', () => {
    render(
      <>
        <Button>Default</Button>
        <Button variant="primary" size="lg">
          Primary
        </Button>
        <Button variant="quiet" size="sm">
          Quiet
        </Button>
        <Button variant="destructive">Delete</Button>
      </>,
    );
    const def = screen.getByRole('button', { name: 'Default' });
    expect(def).toHaveAttribute('type', 'button');
    expect(def.className).toContain('border-control');
    expect(def.className).toContain('min-h-9');
    expect(def.className).toContain('touch:min-h-11');
    expect(screen.getByRole('button', { name: 'Primary' }).className).toMatch(/min-h-10.*bg-accent/);
    expect(screen.getByRole('button', { name: 'Quiet' }).className).toContain('min-h-8');
    expect(screen.getByRole('button', { name: 'Quiet' }).className).toContain('text-link');
    expect(screen.getByRole('button', { name: 'Delete' }).className).toContain('border-danger');
  });

  it('is square when it only has an icon, and disabled while busy', async () => {
    const onClick = vi.fn();
    render(
      <>
        <Button aria-label="Close" icon={<svg data-testid="icon" />} onClick={onClick} />
        <Button busy onClick={onClick}>
          Saving
        </Button>
        <Button disabled onClick={onClick}>
          Off
        </Button>
      </>,
    );
    expect(screen.getByRole('button', { name: 'Close' }).className).toContain('w-9');
    const busy = screen.getByRole('button', { name: 'Saving' });
    expect(busy).toBeDisabled();
    expect(busy).toHaveAttribute('aria-busy', 'true');
    expect(screen.getByRole('button', { name: 'Off' }).className).toContain('disabled:opacity-50');
    await userEvent.click(busy);
    await userEvent.click(screen.getByRole('button', { name: 'Off' }));
    expect(onClick).not.toHaveBeenCalled();
    await userEvent.click(screen.getByRole('button', { name: 'Close' }));
    expect(onClick).toHaveBeenCalledTimes(1);
  });
});

describe('Card, PageHeader and Banner', () => {
  it('renders a titled card with actions and the inset bar variants', () => {
    render(
      <>
        <Card title="Queue" actions={<Button>Act</Button>}>
          body
        </Card>
        <Card variant="attention">waiting</Card>
        <Card variant="approval">approve</Card>
      </>,
    );
    expect(screen.getByRole('heading', { name: 'Queue', level: 2 })).toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'Act' })).toBeInTheDocument();
    const attention = screen.getByText('waiting').closest('section');
    expect(attention).toHaveAttribute('data-variant', 'attention');
    expect(attention?.className).toContain('shadow-bar-attention');
    expect(screen.getByText('approve').closest('section')?.className).toContain('shadow-bar-approval');
    expect(screen.getByText('body').closest('section')).not.toHaveAttribute('data-variant');
  });

  it('renders the page header', () => {
    render(<PageHeader title="Alerts" description="Newest first" actions={<Button>Export</Button>} />);
    expect(screen.getByRole('heading', { name: 'Alerts', level: 1 })).toBeInTheDocument();
    expect(screen.getByText('Newest first')).toBeInTheDocument();
  });

  it('renders banners by tone with a title, text and actions', () => {
    render(
      <>
        <Banner title="Simulated evidence" role="note" actions={<Button>Details</Button>}>
          Not from a live connector.
        </Banner>
        <Banner tone="info">Context only</Banner>
        <Banner tone="attention" title="Waiting" />
      </>,
    );
    const warning = screen.getByRole('note');
    expect(warning).toHaveAttribute('data-tone', 'warning');
    expect(warning.className).toContain('shadow-bar-warning');
    expect(within(warning).getByText('Simulated evidence')).toBeInTheDocument();
    expect(within(warning).getByRole('button', { name: 'Details' })).toBeInTheDocument();
    expect(screen.getByText('Context only').closest('[data-tone]')?.className).toContain('shadow-bar-info');
    expect(screen.getByText('Waiting').closest('[data-tone]')?.className).toContain('shadow-bar-attention');
  });
});

describe('severity, state and counts', () => {
  it('shows severity as a square plus the word', () => {
    render(
      <>
        <SeverityTag value="critical" />
        <SeverityTag value="weird" />
        <SeverityTag value={null} />
        <RiskBadge value="high" />
        <SeverityBadge value="low" />
      </>,
    );
    const critical = screen.getByText('critical');
    expect(critical).toHaveAttribute('data-severity', 'critical');
    expect(critical.querySelector('[aria-hidden="true"]')?.className).toContain('bg-sev-critical');
    expect(screen.getByText('weird').querySelector('[aria-hidden="true"]')?.className).toContain('bg-sev-info');
    expect(screen.getByText('-')).toBeInTheDocument();
    expect(screen.getByText(/high\s+risk/)).toBeInTheDocument();
    expect(screen.getByText('low')).toBeInTheDocument();
    expect(isSeverity('medium')).toBe(true);
    expect(isSeverity('urgent')).toBe(false);
  });

  it('shows states as neutral pills with a coloured dot', () => {
    render(
      <>
        <StatePill tone="approval">Waiting for approval</StatePill>
        <StatusBadge value="waiting_human" />
        <StatusBadge value="mystery_state" />
        <StatusBadge value={undefined} />
        <DispositionBadge value="malicious" />
        <DispositionBadge value={null} />
        <Badge tone="good">healthy</Badge>
      </>,
    );
    const pill = screen.getByText('Waiting for approval');
    expect(pill).toHaveAttribute('data-tone', 'approval');
    expect(pill.className).toContain('bg-raised-2');
    expect(pill.querySelector('[aria-hidden="true"]')?.className).toContain('bg-state-approval');
    expect(screen.getByText('waiting human')).toHaveAttribute('data-tone', 'waiting');
    expect(screen.getByText('mystery state')).toHaveAttribute('data-tone', 'neutral');
    expect(screen.getByText('malicious')).toHaveAttribute('data-tone', 'bad');
    expect(screen.getByText('pending')).toBeInTheDocument();
    expect(screen.getByText('healthy')).toHaveAttribute('data-tone', 'ok');
    expect(statusTone('awaiting_approval')).toBe('approval');
    // Only the map's own keys count: an inherited property is an unknown status.
    expect(statusTone('toString')).toBe('neutral');
  });

  it('gives a count chip its meaning for screen readers', () => {
    render(
      <a href="/escalations">
        Escalations <CountChip count={3} tone="warn" meaning=" unassigned escalations breaching SLA" />
      </a>,
    );
    expect(screen.getByRole('link')).toHaveAccessibleName('Escalations 3 unassigned escalations breaching SLA');
    expect(screen.getByText('3', { exact: false })).toHaveAttribute('data-tone', 'warn');
  });

  it('hides text visually but keeps it for assistive technology', () => {
    render(
      <button type="button">
        <VisuallyHidden>Open menu</VisuallyHidden>
      </button>,
    );
    expect(screen.getByRole('button', { name: 'Open menu' })).toBeInTheDocument();
    expect(screen.getByText('Open menu')).toHaveClass('sr-only');
  });
});

const SEVERITY_OPTIONS = [
  { value: 'critical', label: 'Critical' },
  { value: 'high', label: 'High' },
  { value: 'medium', label: 'Medium' },
];

function Filter({ multiple = true, initial = [] as string[] }) {
  const [value, setValue] = useState<string[]>(initial);
  return (
    <>
      <FilterChip label="Severity" options={SEVERITY_OPTIONS} value={value} onChange={setValue} multiple={multiple} />
      <button type="button">After</button>
    </>
  );
}

describe('FilterChip', () => {
  it('summarises the selection on the chip', () => {
    render(<Filter initial={['high', 'medium']} />);
    const chip = screen.getByRole('button', { name: 'Severity: High, Medium' });
    expect(chip).toHaveAttribute('aria-haspopup', 'listbox');
    expect(chip).toHaveAttribute('aria-expanded', 'false');
    expect(chip.className).toContain('border-link');
  });

  it('opens with the keyboard, toggles options and returns focus on Escape', async () => {
    const user = userEvent.setup();
    render(<Filter />);
    const chip = screen.getByRole('button', { name: 'Severity: Any' });
    chip.focus();
    await user.keyboard('{ArrowDown}');
    const list = screen.getByRole('listbox', { name: 'Severity' });
    expect(chip).toHaveAttribute('aria-expanded', 'true');
    expect(list).toHaveFocus();
    expect(list).toHaveAttribute('aria-multiselectable', 'true');
    expect(list.getAttribute('aria-activedescendant')).toBe(screen.getByRole('option', { name: 'Critical' }).id);

    await user.keyboard('{ArrowDown}{Enter}');
    expect(screen.getByRole('option', { name: 'High' })).toHaveAttribute('aria-selected', 'true');
    await user.keyboard('{End} ');
    expect(screen.getByRole('option', { name: 'Medium' })).toHaveAttribute('aria-selected', 'true');
    await user.keyboard('{Home}{ArrowUp}');
    expect(list.getAttribute('aria-activedescendant')).toBe(screen.getByRole('option', { name: 'Critical' }).id);
    await user.keyboard('{ArrowDown} ');
    expect(screen.getByRole('option', { name: 'High' })).toHaveAttribute('aria-selected', 'false');

    await user.keyboard('{Escape}');
    expect(screen.queryByRole('listbox')).not.toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'Severity: Medium' })).toHaveFocus();
  });

  it('opens on ArrowUp at the last option and closes on Tab', async () => {
    const user = userEvent.setup();
    render(<Filter />);
    screen.getByRole('button', { name: 'Severity: Any' }).focus();
    await user.keyboard('{ArrowUp}');
    const list = screen.getByRole('listbox');
    expect(list.getAttribute('aria-activedescendant')).toBe(screen.getByRole('option', { name: 'Medium' }).id);
    await user.keyboard('{Tab}');
    expect(screen.queryByRole('listbox')).not.toBeInTheDocument();
  });

  it('selects one value and closes in single-choice mode; clicking outside closes', async () => {
    const user = userEvent.setup();
    render(<Filter multiple={false} />);
    await user.click(screen.getByRole('button', { name: 'Severity: Any' }));
    expect(screen.getByRole('listbox')).not.toHaveAttribute('aria-multiselectable');
    await user.click(screen.getByRole('option', { name: 'High' }));
    expect(screen.queryByRole('listbox')).not.toBeInTheDocument();
    const chip = screen.getByRole('button', { name: 'Severity: High' });
    expect(chip).toHaveFocus();

    await user.click(chip);
    await user.click(screen.getByRole('option', { name: 'High' }));
    expect(screen.getByRole('button', { name: 'Severity: Any' })).toBeInTheDocument();

    await user.click(screen.getByRole('button', { name: 'Severity: Any' }));
    expect(screen.getByRole('listbox')).toBeInTheDocument();
    await user.click(screen.getByRole('button', { name: 'After' }));
    expect(screen.queryByRole('listbox')).not.toBeInTheDocument();
  });

  it('toggles closed when the chip is clicked again', async () => {
    const user = userEvent.setup();
    render(<Filter />);
    const chip = screen.getByRole('button', { name: 'Severity: Any' });
    await user.click(chip);
    await user.hover(screen.getByRole('option', { name: 'Medium' }));
    expect(screen.getByRole('listbox').getAttribute('aria-activedescendant')).toBe(screen.getByRole('option', { name: 'Medium' }).id);
    await user.click(chip);
    expect(screen.queryByRole('listbox')).not.toBeInTheDocument();
  });
});

describe('fields', () => {
  it('labels inputs and wires hints and errors', () => {
    render(
      <>
        <TextField label="Email" hint="Work address" error="Required" />
        <SelectField label="Role">
          <option>analyst</option>
        </SelectField>
        <TextAreaField label="Notes" />
        <Checkbox label="Remember" hint="On this device" />
      </>,
    );
    const email = screen.getByLabelText('Email');
    expect(email).toHaveAccessibleDescription('Work address Required');
    expect(email).toHaveAttribute('aria-invalid', 'true');
    expect(email.className).toContain('h-9');
    expect(screen.getByLabelText('Role').tagName).toBe('SELECT');
    expect(screen.getByLabelText('Notes').tagName).toBe('TEXTAREA');
    expect(screen.getByLabelText('Remember')).toHaveAccessibleDescription('On this device');
  });
});

describe('feedback and misc', () => {
  it('renders empty and error states', async () => {
    const retry = vi.fn();
    render(
      <>
        <EmptyState title="Queue clear">Nothing unassigned.</EmptyState>
        <ErrorMessage error={apiError(500, 'internal', 'Server error', 'req-test-0002')} onRetry={retry} />
      </>,
    );
    expect(screen.getByText('Queue clear')).toBeInTheDocument();
    expect(screen.getByRole('alert')).toHaveTextContent('Server error');
    expect(screen.getByText('req-test-0002')).toBeInTheDocument();
    await userEvent.click(screen.getByRole('button', { name: 'Retry' }));
    expect(retry).toHaveBeenCalled();
  });

  it('renders toggle groups, JSON blocks and definition lists', async () => {
    const onChange = vi.fn();
    render(
      <>
        <ToggleGroup label="Status" options={['new', 'waiting_human']} value={['new']} onChange={onChange} />
        <JsonBlock label="Raw" value={{ a: 1 }} />
        <DefinitionList items={[['Owner', 'Analyst A']]} />
      </>,
    );
    expect(screen.getByRole('button', { name: 'new' })).toHaveAttribute('aria-pressed', 'true');
    await userEvent.click(screen.getByRole('button', { name: 'waiting human' }));
    expect(onChange).toHaveBeenCalledWith(['new', 'waiting_human']);
    await userEvent.click(screen.getByRole('button', { name: 'new' }));
    expect(onChange).toHaveBeenLastCalledWith([]);
    expect(screen.getByRole('region', { name: 'Raw' })).toHaveTextContent('"a": 1');
    expect(screen.getByText('Analyst A')).toBeInTheDocument();
  });
});

describe('Segmented and button-styled links', () => {
  it('picks one option with native radios and names the short labels', async () => {
    function Harness() {
      const [value, setValue] = useState(24);
      return (
        <>
          <Segmented
            label="Time window"
            options={[
              { value: 24, label: '24h', title: 'Last 24 hours' },
              { value: 168, label: '7d', title: 'Last 7 days' },
              { value: 720, label: '30d' },
            ]}
            value={value}
            onChange={setValue}
          />
          <output>{value}</output>
        </>
      );
    }
    render(<Harness />);
    const group = screen.getByRole('group', { name: 'Time window' });
    expect(within(group).getByRole('radio', { name: 'Last 24 hours' })).toBeChecked();
    await userEvent.click(within(group).getByRole('radio', { name: 'Last 7 days' }));
    expect(screen.getByText('168')).toBeInTheDocument();
    await userEvent.click(within(group).getByRole('radio', { name: '30d' }));
    expect(within(group).getByRole('radio', { name: '30d' })).toBeChecked();
  });

  it('gives links the button classes without disabled-state variants', () => {
    expect(buttonClass()).toContain('border-control');
    expect(buttonClass('primary', 'sm', 'self-start')).toContain('min-h-8');
    expect(buttonClass('primary')).not.toContain('enabled:');
    expect(buttonClass('quiet')).toContain('text-link');
    expect(buttonClass('destructive')).toContain('text-danger-fg');
  });
});
