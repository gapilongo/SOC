/**
 * The search field and command palette (Ctrl+K): its ARIA roles and focus
 * trap, the keyboard path, what it finds (pages from the registry, a
 * module's records with their tenant, tenants for a platform admin,
 * commands), and the rule that a command which changes something never runs
 * from it.
 */
import { fireEvent, screen, waitFor, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { useState } from 'react';
import { useLocation } from 'react-router-dom';
import { afterEach, describe, expect, it } from 'vitest';

import type { Principal } from '../../auth/store';
import { fakeApi, renderWithSession, signedInSession } from '../../test/helpers';
import { tenant } from '../../test/tenants';
import type { Registry } from '../registry';
import { REGISTRY } from '../routes';
import CommandPalette, { commandItems, pageItems } from './CommandPalette';

const ALERTS = [
  { id: 'a-1', title: 'Encoded PowerShell launched by Word on WS-FIN-0142', severity: 'high', status: 'escalated' },
  { id: 'a-2', title: 'LSASS memory read on WS-FIN-0142', severity: 'critical', status: 'new' },
];
const TENANTS = [tenant('acme', 'Acme (MSSP)'), tenant('globex', 'Globex Corp'), tenant('initech', 'Initech')];

function principal(overrides: Partial<Principal> = {}): Principal {
  return { userId: 'u-1', email: 'x@acme.test', role: 'analyst', tenantId: 'acme', homeTenantId: 'acme', isPlatformAdmin: false, method: 'password', ...overrides };
}

function Host({ registry }: { registry: Registry }) {
  const [open, setOpen] = useState(false);
  const [keys, setKeys] = useState(true);
  const location = useLocation();
  return (
    <>
      <button onClick={() => setOpen(true)}>Open search</button>
      <p data-testid="where">{`${location.pathname}${location.search}`}</p>
      {open && <CommandPalette registry={registry} tenantLabel="Acme Corp" singleKeys={keys} onSingleKeys={setKeys} onClose={() => setOpen(false)} />}
    </>
  );
}

async function openPalette(overrides: object = {}, { alerts = ALERTS as unknown, registry = REGISTRY } = {}) {
  const user = userEvent.setup();
  const { api, calls } = fakeApi((_method, path) => {
    if (path === '/alerts') {
      if (alerts instanceof Error) throw alerts;
      return { items: alerts, next_cursor: null };
    }
    if (path === '/platform/tenants') return TENANTS;
    return [];
  });
  const session = await signedInSession(api, overrides);
  renderWithSession(<Host registry={registry} />, session);
  const opener = screen.getByRole('button', { name: 'Open search' });
  await user.click(opener);
  const dialog = screen.getByRole('dialog', { name: 'Search and commands' });
  const field = within(dialog).getByRole('combobox', { name: 'Search' });
  const options = () => within(dialog).queryAllByRole('option');
  const lines = () => options().map((o) => o.textContent);
  const active = () => document.getElementById(field.getAttribute('aria-activedescendant') ?? '-');
  return { user, calls, session, opener, dialog, field, options, lines, active, where: () => screen.getByTestId('where').textContent };
}

afterEach(() => {
  window.localStorage.clear();
  delete document.documentElement.dataset.theme;
  delete document.documentElement.dataset.density;
});

describe('search and commands', () => {
  it('is a modal dialog with a combobox that keeps the focus', async () => {
    const { user, dialog, field, options, active, opener } = await openPalette();
    expect(dialog).toHaveAttribute('aria-modal', 'true');
    expect(field).toHaveFocus();
    expect(field).toHaveAttribute('aria-expanded', 'true');
    expect(field).toHaveAttribute('aria-autocomplete', 'list');
    expect(field).toHaveAttribute('placeholder', 'Search pages and alerts. Type > for commands');
    const list = within(dialog).getByRole('listbox', { name: 'Results' });
    expect(field).toHaveAttribute('aria-controls', list.id);
    // The first option is highlighted, and the field says which.
    expect(active()).toBe(options()[0]);
    expect(options()[0]).toHaveAttribute('aria-selected', 'true');
    expect(options().filter((o) => o.getAttribute('aria-selected') === 'true')).toHaveLength(1);
    expect(within(dialog).getByRole('status')).toHaveTextContent(`${options().length} results`);
    expect(dialog).toHaveTextContent('in Acme Corp');

    // Tab and Shift+Tab stay in the field: nothing behind the dialog is reachable.
    await user.tab();
    expect(field).toHaveFocus();
    await user.tab({ shift: true });
    expect(field).toHaveFocus();
    // Escape closes and puts the focus back where it was.
    await user.keyboard('{Escape}');
    expect(screen.queryByRole('dialog')).not.toBeInTheDocument();
    expect(opener).toHaveFocus();
  });

  it('lists the pages the person may open, from the registry, then the commands', async () => {
    const { lines, calls } = await openPalette({ role: 'analyst' });
    expect(lines().slice(0, 8)).toEqual([
      'PageOverviewWork',
      'PageQueueWork',
      // The older list is in no group of the rail, and still found by name.
      'PageEscalations',
      'PageApprovalsWork',
      'PageAlertsDetect and respond',
      'PageSuppressionsDetect and respond',
      'PageBlind auditDetect and respond',
      'PageReportsAssure',
    ]);
    // A page reached from a menu is found too; an admin's page is not offered to an analyst.
    expect(lines()).toContain('PageAccount security');
    expect(lines().some((l) => l?.includes('Sources'))).toBe(false);
    expect(lines().some((l) => l?.startsWith('Do'))).toBe(true);
    // Nothing was typed: nothing was asked of the API, and no tenant list for someone with one tenant.
    expect(calls).toEqual([]);

    const forAdmin = pageItems(REGISTRY, principal({ role: 'admin', isPlatformAdmin: true }));
    expect(forAdmin.map((i) => i.title)).toEqual(expect.arrayContaining(['Sources', 'Connect Wazuh', 'New proof of value']));
    // A page is listed as the rail names it, with its own title beside the group: either name finds it.
    expect(Object.fromEntries(forAdmin.filter((i) => i.detail?.includes(' · ')).map((i) => [i.title, i.detail]))).toEqual({
      'AI usage and cost': 'Assure · LLM usage',
      'People and keys': 'Configure · Users and API keys',
      Tenants: 'Platform · MSSP console',
    });
    expect(pageItems(REGISTRY, null)).toEqual([]);
  });

  it('moves with the arrow keys, wrapping at both ends, and opens with Enter', async () => {
    const { user, options, active, where } = await openPalette();
    await user.keyboard('{ArrowDown}');
    expect(active()).toBe(options()[1]);
    expect(options()[1]).toHaveAttribute('aria-selected', 'true');
    await user.keyboard('{ArrowUp}{ArrowUp}');
    expect(active()).toBe(options().at(-1));
    await user.keyboard('{ArrowDown}');
    expect(active()).toBe(options()[0]);

    await user.keyboard('appr');
    expect(options()[0]).toHaveTextContent('PageApprovalsWork');
    expect(active()).toBe(options()[0]);
    await user.keyboard('{Enter}');
    expect(screen.queryByRole('dialog')).not.toBeInTheDocument();
    expect(where()).toBe('/approvals');
  });

  it('finds alerts by title through the SOC search, names their tenant, and offers the full list', async () => {
    const { user, calls, lines, where, dialog } = await openPalette();
    await user.keyboard('w');
    // One character asks nothing.
    await new Promise((r) => setTimeout(r, 300));
    expect(calls).toEqual([]);
    await user.keyboard('s-fin');
    await waitFor(() => expect(lines()).toContain('AlertEncoded PowerShell launched by Word on WS-FIN-0142High · Escalated · Acme Corp'));
    // One request for what was typed in the end, not one per key.
    expect(calls).toEqual([{ method: 'GET', path: '/alerts', body: undefined, query: { q: 'ws-fin', limit: 8 } }]);
    expect(lines()).toEqual([
      'AlertEncoded PowerShell launched by Word on WS-FIN-0142High · Escalated · Acme Corp',
      'AlertLSASS memory read on WS-FIN-0142Critical · New · Acme Corp',
      'FindAll alerts with "ws-fin" in the titleAcme Corp',
    ]);
    await waitFor(() => expect(within(dialog).getByRole('status')).toHaveTextContent('3 results'));
    await user.click(screen.getByRole('option', { name: /LSASS memory read/ }));
    expect(screen.queryByRole('dialog')).not.toBeInTheDocument();
    expect(where()).toBe('/alerts/a-2');
  });

  it('opens the alert list for the words typed', async () => {
    const { user, where } = await openPalette();
    await user.keyboard('ws-fin');
    await user.click(await screen.findByRole('option', { name: /All alerts with "ws-fin" in the title/ }));
    expect(where()).toBe('/alerts?q=ws-fin&view=all');
  });

  it('says so when nothing matches, and when a search failed', async () => {
    const none = await openPalette({}, { alerts: [] });
    await none.user.keyboard('zzzz');
    // Until the search has answered, the list offers the search itself.
    await waitFor(() => expect(none.calls).toHaveLength(1));
    expect(none.lines()).toEqual(['FindAll alerts with "zzzz" in the titleAcme Corp']);
    await none.user.keyboard('{Escape}');

    await none.user.click(none.opener);
    await none.user.keyboard('>zzzz');
    const dialog = screen.getByRole('dialog', { name: 'Search and commands' });
    expect(within(dialog).queryAllByRole('option')).toEqual([]);
    expect(dialog).toHaveTextContent('Nothing matches in Acme Corp.');
    expect(within(dialog).getByRole('status')).toHaveTextContent('Nothing matches in Acme Corp');
    // Enter and the arrows do nothing on an empty list.
    await none.user.keyboard('{ArrowDown}{Enter}');
    expect(screen.getByRole('dialog', { name: 'Search and commands' })).toBeInTheDocument();
  });

  it('keeps pages and commands working when a module\'s search fails', async () => {
    const { user, dialog, lines } = await openPalette({}, { alerts: new Error('down') });
    await user.keyboard('alerts');
    expect(await within(dialog).findByText('The search for alerts failed. Pages and commands still work.')).toBeInTheDocument();
    expect(lines()[0]).toBe('PageAlertsDetect and respond');
  });

  it('lists commands only after ">", each a link that says which page it opens', async () => {
    const { user, lines, calls } = await openPalette({ role: 'admin' });
    await user.keyboard('>');
    expect(lines()).toEqual([
      'DoApprove or reject waiting actionsopens Approvals, runs nothing',
      'DoWrite a suppression ruleopens Suppressions, runs nothing',
      'DoConnect an alert sourceopens Sources, runs nothing',
      'DoAdd a person or an API keyopens Users and API keys, runs nothing',
      'DoStart a proof of valueopens New proof of value, runs nothing',
      'DoTheme: follow the systemdisplay setting',
      'DoTheme: lightdisplay setting',
      'DoTheme: darkdisplay setting',
      'DoRows: densedisplay setting',
      'DoRows: compactdisplay setting',
      'DoRows: comfortabledisplay setting',
      'DoSingle-key shortcuts: turn offdisplay setting',
    ]);
    // No record search in command mode.
    await user.keyboard(' source');
    await new Promise((r) => setTimeout(r, 300));
    expect(lines()).toEqual(['DoConnect an alert sourceopens Sources, runs nothing']);
    expect(calls.filter((c) => c.path === '/alerts')).toEqual([]);
  });

  it('never runs a command that changes something: it opens the page where the act is confirmed', async () => {
    const { user, calls, where } = await openPalette({ role: 'admin' });
    await user.keyboard('>suppression');
    await user.keyboard('{Enter}');
    expect(where()).toBe('/suppressions');
    // Nothing was written: the palette made no request other than reads.
    expect(calls.filter((c) => c.method !== 'GET')).toEqual([]);
    // By construction: a module's command is a link and has no callback to run.
    for (const p of [principal(), principal({ role: 'admin' }), principal({ role: 'admin', isPlatformAdmin: true })]) {
      const items = commandItems(REGISTRY, p);
      expect(items.length).toBeGreaterThan(0);
      for (const item of items) {
        expect(item).toHaveProperty('to');
        expect(item).not.toHaveProperty('act');
        expect(item.detail).toMatch(/^opens .+, runs nothing$/);
      }
    }
    for (const command of REGISTRY.commands) expect(Object.keys(command).sort()).toEqual(['allowed', 'enabled', 'label', 'module', 'to']);
    // The role decides which commands are offered.
    expect(commandItems(REGISTRY, principal({ role: 'viewer' })).map((i) => i.title)).toEqual(['Approve or reject waiting actions']);
    expect(commandItems(REGISTRY, null)).toEqual([]);
  });

  it('names a command\'s page even when the page has no name', () => {
    const registry = { routes: REGISTRY.routes, commands: [{ label: 'Open the old actions page', to: '/actions', allowed: () => true, enabled: () => true, module: 'soc' }] };
    expect(commandItems(registry, principal())[0].detail).toBe('opens its page, runs nothing');
  });

  it('changes display settings at once: theme, rows, single-key shortcuts', async () => {
    const { user, opener } = await openPalette();
    await user.keyboard('>theme dark{Enter}');
    expect(document.documentElement.dataset.theme).toBe('dark');
    await user.click(opener);
    await user.keyboard('>theme light{Enter}');
    expect(document.documentElement.dataset.theme).toBe('light');
    await user.click(opener);
    await user.keyboard('>follow{Enter}');
    expect(window.localStorage.getItem('lg-sotf.theme')).toBe('system');
    await user.click(opener);
    await user.keyboard('>rows comf{Enter}');
    expect(document.documentElement.dataset.density).toBe('comfortable');
    await user.click(opener);
    await user.keyboard('>rows compact{Enter}');
    expect(document.documentElement.dataset.density).toBe('compact');
    await user.click(opener);
    await user.keyboard('>rows dense{Enter}');
    expect(document.documentElement.dataset.density).toBe('dense');
    await user.click(opener);
    await user.keyboard('>single{Enter}');
    expect(await screen.findByText('Single-key shortcuts are off. Ctrl K, Tab and Enter always work.')).toBeInTheDocument();
    await user.click(opener);
    await user.keyboard('>single');
    expect(screen.getByRole('option', { name: /Single-key shortcuts: turn on/ })).toBeInTheDocument();
  });

  it('lets a platform admin find a tenant and work in it', async () => {
    const { user, calls, lines, session } = await openPalette({ role: 'admin', is_platform_admin: true }, { alerts: [] });
    await waitFor(() => expect(calls.map((c) => c.path)).toEqual(['/platform/tenants']));
    // Tenants are listed once something is typed.
    expect(lines().some((l) => l?.startsWith('Tenant'))).toBe(false);
    await user.keyboard('acme');
    await waitFor(() => expect(lines()).toContain('TenantAcme (MSSP)acme · you are here'));
    await user.keyboard('{Backspace}{Backspace}{Backspace}{Backspace}glob');
    await waitFor(() => expect(lines()).toContain('TenantGlobex Corpglobex'));
    await user.click(screen.getByRole('option', { name: /Globex Corp/ }));
    expect(session.auth.getState().actingTenant).toBe('globex');
    expect(await screen.findByText("Working in Globex Corp. Every request is recorded in that tenant's audit log.")).toBeInTheDocument();
  });

  it('closes on a press outside and highlights the option under the pointer', async () => {
    const { user, options, active, dialog } = await openPalette();
    await user.hover(options()[3]);
    expect(active()).toBe(options()[3]);
    // Pressing an option does not take the focus out of the field.
    fireEvent.pointerDown(options()[3]);
    expect(within(dialog).getByRole('combobox')).toHaveFocus();
    await user.click(dialog.previousElementSibling as HTMLElement);
    expect(screen.queryByRole('dialog')).not.toBeInTheDocument();
  });

  it('searches nothing for someone with no module to search', async () => {
    const { user, lines, calls, field } = await openPalette({}, { registry: { ...REGISTRY, searches: [] } });
    expect(field).toHaveAttribute('placeholder', 'Search pages. Type > for commands');
    await user.keyboard('alerts');
    await new Promise((r) => setTimeout(r, 300));
    expect(lines()).toEqual(['PageAlertsDetect and respond']);
    expect(calls).toEqual([]);
  });
});
