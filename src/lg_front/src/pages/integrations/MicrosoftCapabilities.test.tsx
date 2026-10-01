import { render, screen, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { useState } from 'react';
import { describe, expect, it } from 'vitest';

import { ISOLATION, QUARANTINE } from '../../test/microsoft';
import {
  capabilitiesConfig,
  initialStates,
  MicrosoftCapabilities,
  optionFields,
  parseOption,
  type CapabilityStates,
} from './MicrosoftCapabilities';

function Harness({ initial = {}, cloud = 'global' }: { initial?: CapabilityStates; cloud?: string }) {
  const [states, setStates] = useState<CapabilityStates>(initial);
  return (
    <>
      <MicrosoftCapabilities catalog={[ISOLATION, QUARANTINE]} states={states} cloud={cloud} onChange={setStates} />
      <output data-testid="config">{JSON.stringify(capabilitiesConfig(states))}</output>
    </>
  );
}

function config(): Record<string, { enabled: boolean; live: boolean; options: Record<string, unknown> }> {
  return JSON.parse(screen.getByTestId('config').textContent ?? '{}');
}

describe('capability options from the JSON schema', () => {
  it('maps the allowed field types to inputs and skips the rest', () => {
    const fields = optionFields(ISOLATION.options_schema);
    expect(fields.map((f) => [f.key, f.kind])).toEqual([
      ['isolation_type', 'select'],
      ['max_machines', 'int'],
      ['comment_prefix', 'text'],
      ['allow_servers', 'bool'],
      ['excluded_tags', 'list'],
    ]);
    const max = fields[1];
    expect(parseOption(max, '3')).toBe(3);
    expect(parseOption(max, '')).toBeUndefined();
    expect(() => parseOption(max, '11')).toThrow(/at most 10/);
    expect(() => parseOption(max, '1.5')).toThrow(/whole number/);
    expect(parseOption(fields[4], 'a\n\n b \n')).toEqual(['a', 'b']);
  });

  it('starts from the stored config with defaults', () => {
    const states = initialStates([ISOLATION], { 'defender.isolation': { enabled: true, options: { max_machines: 4 } } });
    expect(states['defender.isolation']).toEqual({
      enabled: true,
      live: false,
      options: { ...ISOLATION.options_defaults, max_machines: 4 },
    });
  });
});

describe('MicrosoftCapabilities', () => {
  it('enables, confirms going live and edits options', async () => {
    render(<Harness />);
    const card = screen.getByRole('article', { name: /Machine isolation/ });
    expect(within(card).getByText('Machine.Isolate')).toBeInTheDocument();
    expect(within(card).getByText(/reversible \(release host\)/i)).toBeInTheDocument();
    const live = within(card).getByLabelText('Live');
    expect(live).toBeDisabled();
    await userEvent.click(within(card).getByLabelText('Enabled'));
    expect(config()['defender.isolation']).toMatchObject({ enabled: true, live: false });

    await userEvent.click(within(card).getByLabelText('Live'));
    const dialog = await screen.findByRole('dialog', { name: /Go live: Machine isolation/ });
    expect(within(dialog).getByText(/lose network access until released/)).toBeInTheDocument();
    await userEvent.click(within(dialog).getByRole('button', { name: 'Cancel' }));
    expect(config()['defender.isolation'].live).toBe(false);
    await userEvent.click(within(card).getByLabelText('Live'));
    await userEvent.click(within(await screen.findByRole('dialog')).getByRole('button', { name: 'Go live' }));
    expect(config()['defender.isolation'].live).toBe(true);

    await userEvent.selectOptions(within(card).getByLabelText('Isolation type'), 'Selective');
    const max = within(card).getByLabelText('Max machines');
    await userEvent.clear(max);
    await userEvent.type(max, '3');
    await userEvent.type(within(card).getByLabelText('Excluded tags'), 'vip{enter}lab');
    expect(config()['defender.isolation'].options).toMatchObject({ isolation_type: 'Selective', max_machines: 3, excluded_tags: ['vip', 'lab'] });

    await userEvent.click(within(card).getByLabelText('Enabled'));
    expect(config()['defender.isolation']).toMatchObject({ enabled: false, live: false });
  });

  it('warns about excluded pairs and unsupported clouds', async () => {
    render(<Harness initial={{ 'defender.isolation': { enabled: true, live: false, options: {} } }} />);
    const quarantine = screen.getByRole('article', { name: /Stop and quarantine/ });
    await userEvent.click(within(quarantine).getByLabelText('Enabled'));
    expect(within(quarantine).getByText(/Cannot be enabled together with Machine isolation/)).toBeInTheDocument();
  });

  it('disables capabilities the cloud does not support', () => {
    render(<Harness cloud="usgov_dod" />);
    const card = screen.getByRole('article', { name: /Machine isolation/ });
    expect(within(card).getByLabelText('Enabled')).toBeDisabled();
    expect(within(card).getByText(/Not available in the usgov dod cloud/i)).toBeInTheDocument();
  });
});
