/**
 * The analyst workflow through the real UI, against a running stack:
 * security headers and sign-in, provisioning (API key, analyst, viewer),
 * the Overview updating live after alerts arrive through the ingest API,
 * alert filters and pagination, the alert timeline, claiming and deciding
 * the escalation as an analyst (the expected response plan names every
 * target before anything is pre-approved, and the decision page passes axe
 * with the plan open), approving its response as an admin until
 * the alert closes, role gating for analyst and viewer, sign-out, and no
 * token in browser storage. The Content-Security-Policy is checked on the
 * wire and in the browser (no violations on any page), and the main pages
 * pass axe (no serious or critical WCAG 2.2 A or AA violation).
 */
import { expect, test, type APIRequestContext, type Page } from '@playwright/test';

import {
  API,
  assertAccessible,
  assertNoTokenInStorage,
  decisionForm,
  escalationQueue,
  escalationRow,
  findEscalation,
  getAlert,
  ingest,
  newSession,
  randomPassword,
  requiredEnv,
  responsePlan,
  screenshot,
  signIn,
  signOut,
  statValue,
  waitForAlert,
  type AlertState,
  type Credentials,
  verdictRadio,
} from './support';

test.describe.configure({ mode: 'serial' });

const run = `e2e${Date.now().toString(36)}`;
const admin: Credentials = { email: requiredEnv('E2E_ADMIN_EMAIL'), password: requiredEnv('E2E_ADMIN_PASSWORD') };
const analyst: Credentials = { email: `analyst-${run}@e2e.example.com`, password: randomPassword() };
const viewer: Credentials = { email: `viewer-${run}@e2e.example.com`, password: randomPassword() };
const BEACON_TITLE = `Possible C2 beacon from workstation ws-${run}`;
const BURST = 104; // with the beacon: more than one page (100) of this run's alerts
const SEVERITIES = ['low', 'medium', 'high'] as const;

let apiKey = '';
let beaconId = '';
// The first burst alert: sign-in anomalies like it are escalated to an analyst (grey zone).
let escalatedId = '';
const ESCALATED_TITLE = `Unusual sign-in pattern ${run} #0`;

function octet(seed: number): number {
  return 1 + (seed % 250);
}

function beacon(): object {
  const seed = Date.now();
  return {
    source_alert_id: `${run}-beacon`,
    title: BEACON_TITLE,
    description: 'Periodic beacon to a command and control server; malware suspected.',
    severity: 'medium',
    occurred_at: new Date().toISOString(),
    entities: {
      ips: [`198.51.100.${octet(seed)}`],
      hosts: [`ws-${run}`],
      users: [`u-${run}`],
      hashes: [Buffer.from(run.padEnd(16, '0')).toString('hex').slice(0, 32)],
      processes: ['powershell.exe'],
    },
  };
}

function burst(n: number): object {
  return {
    source_alert_id: `${run}-burst-${n}`,
    title: `Unusual sign-in pattern ${run} #${n}`,
    severity: SEVERITIES[n % SEVERITIES.length],
    occurred_at: new Date().toISOString(),
    entities: { users: [`user${n}-${run}`], hosts: [`host-${n % 7}-${run}`] },
  };
}

const expectedBySeverity = (sev: string) =>
  Array.from({ length: BURST }, (_, n) => SEVERITIES[n % SEVERITIES.length]).filter((s) => s === sev).length + (sev === 'medium' ? 1 : 0);

/** Search the All view for `title`, open its row and return the alert side panel. */
async function openAlertFromList(page: Page, title: string) {
  await page.goto('/alerts?view=all');
  const search = page.getByRole('searchbox', { name: 'Search titles' });
  await search.fill(title);
  await search.press('Enter');
  await expect(page).toHaveURL(/[?&]q=/);
  const row = page.getByRole('row', { name: new RegExp(title.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')) });
  await expect(row).toHaveCount(1);
  await row.click();
  const panel = page.getByRole('complementary', { name: title });
  await expect(panel).toBeVisible();
  return panel;
}

/** Rows of the All actions ledger (/approvals?view=all) for this alert. */
function actionRows(page: Page, alertId: string) {
  return page.getByRole('row').filter({ has: page.getByRole('button', { name: `Open alert ${alertId}` }) });
}

/** Pending approval cards (/approvals) for this alert. */
function pendingCards(page: Page, alertId: string) {
  return page.getByRole('listitem').filter({ has: page.getByRole('button', { name: `Open alert ${alertId}` }) });
}

test('security headers on every document, and the admin signs in under the CSP', async ({ browser, request }) => {
  for (const path of ['/login', '/', '/alerts', '/config.js']) {
    const r = await request.get(path);
    expect(r.status(), path).toBe(200);
    const csp = r.headers()['content-security-policy'] ?? '';
    expect(csp, `CSP on ${path}`).toContain("default-src 'none'");
    expect(csp).toContain("script-src 'self'");
    expect(csp).toContain("style-src 'self'");
    expect(csp).toContain("frame-ancestors 'none'");
    expect(csp).not.toContain('unsafe-inline');
    expect(csp).not.toContain('unsafe-eval');
    expect(r.headers()['x-frame-options']).toBe('DENY');
    expect(r.headers()['x-content-type-options']).toBe('nosniff');
    expect(r.headers()['referrer-policy']).toBe('no-referrer');
  }
  const config = await (await request.get('/config.js')).text();
  expect(config).not.toMatch(/secret|password|eyJ/i);

  const { context, page, watch } = await newSession(browser);
  await page.goto('/login');
  await screenshot(page, '01-login');
  await signIn(page, admin);
  await expect(page.getByRole('status').filter({ hasText: /^Live$/ })).toBeVisible();
  await assertNoTokenInStorage(page);
  const refresh = (await context.cookies()).find((c) => c.name === 'lgsotf_refresh');
  expect(refresh, 'refresh cookie').toBeTruthy();
  expect(refresh?.httpOnly).toBe(true);
  expect(refresh?.sameSite).toBe('Strict');
  // A reload restores the session from the HttpOnly refresh cookie, not from storage.
  await page.reload();
  await expect(page.getByRole('heading', { name: 'Overview', level: 1 })).toBeVisible();
  await assertNoTokenInStorage(page);
  await watch.assertClean();
  await context.close();
});

test('the admin creates an API key, an analyst and a viewer in the UI', async ({ browser }) => {
  const { context, page, watch } = await newSession(browser);
  await signIn(page, admin);
  await page.getByRole('navigation', { name: 'Main' }).getByRole('link', { name: 'Users and API keys' }).click();
  await expect(page.getByRole('heading', { name: 'Users and API keys', level: 1 })).toBeVisible();

  await page.getByRole('button', { name: 'Create key' }).click();
  let dialog = page.getByRole('dialog', { name: 'Create API key' });
  await dialog.getByLabel('Name').fill(`e2e ingest ${run}`);
  await dialog.getByLabel('read', { exact: true }).check();
  await dialog.getByRole('button', { name: 'Create key' }).click();
  dialog = page.getByRole('dialog', { name: `API key e2e ingest ${run} created` });
  apiKey = await dialog.locator('#new-api-key').inputValue();
  expect(apiKey.length).toBeGreaterThan(20);
  await dialog.getByRole('button', { name: 'I have stored the key' }).click();
  await expect(page.getByText(`e2e ingest ${run}`)).toBeVisible();
  await expect(page.getByText(apiKey)).toHaveCount(0);

  for (const [who, role] of [
    [analyst, 'analyst'],
    [viewer, 'viewer'],
  ] as const) {
    await page.getByRole('button', { name: 'Add user' }).click();
    const form = page.getByRole('dialog', { name: 'Add user' });
    await form.getByLabel('Email').fill(who.email);
    await form.getByLabel('Role').selectOption(role);
    await form.getByLabel('Password (optional)').fill(who.password);
    await form.getByRole('button', { name: 'Create user' }).click();
    await expect(form).toBeHidden();
    await expect(page.getByRole('row').filter({ hasText: who.email })).toContainText(role);
  }
  await assertNoTokenInStorage(page);
  await watch.assertClean();
  await context.close();
});

test('the Overview updates live when alerts arrive through the ingest API', async ({ browser, request }) => {
  const { context, page, watch } = await newSession(browser);
  await signIn(page, admin);
  await expect(page.getByRole('status').filter({ hasText: /^Live$/ })).toBeVisible();
  const before = await statValue(page, 'Alerts ingested');

  const items = await ingest(request, apiKey, [beacon(), ...Array.from({ length: BURST }, (_, n) => burst(n))]);
  expect(items.filter((i) => i.status === 'inserted')).toHaveLength(BURST + 1);
  beaconId = items[0].alert_id as string;
  escalatedId = items[1].alert_id as string;

  // No navigation, no Refresh click: the WebSocket events refresh the page.
  await expect.poll(() => statValue(page, 'Alerts ingested'), { timeout: 90_000, intervals: [1_000] }).toBe(before + BURST + 1);
  await screenshot(page, '02-overview');
  await watch.assertClean();
  await context.close();
});

const SETTLED = ['waiting_human', 'waiting_approval', 'closed'];

/**
 * Wait until the beacon needs something from a person (an open escalation or
 * an action awaiting approval) or is closed. The alert status alone is not
 * enough: right after a decision it still reads waiting_human until the
 * worker takes the resume.
 */
async function nextRequest(request: APIRequestContext, alertId: string): Promise<AlertState> {
  const headers = { 'X-API-Key': apiKey };
  const deadline = Date.now() + 150_000;
  let last: AlertState | null = null;
  while (Date.now() < deadline) {
    last = await getAlert(request, apiKey, alertId);
    if (last.status === 'closed') return last;
    if (last.status === 'waiting_human') {
      const r = await request.get(`${API}/escalations`, { params: { alert_id: alertId, status: 'open' }, headers });
      if (((await r.json()) as { items: unknown[] }).items.length > 0) return last;
    }
    if (last.status === 'waiting_approval') {
      const r = await request.get(`${API}/actions`, { params: { alert_id: alertId, status: 'awaiting_approval' }, headers });
      if (((await r.json()) as { items: unknown[] }).items.length > 0) return last;
    }
    await new Promise((r) => setTimeout(r, 1_000));
  }
  throw new Error(`alert ${alertId} asked nobody for anything within the timeout (last status: ${last?.status})`);
}

test('alerts: filters, pagination and the alert timeline', async ({ browser, request }) => {
  await waitForAlert(request, apiKey, beaconId, SETTLED);
  const { context, page, watch } = await newSession(browser);
  await signIn(page, admin);
  await page.getByRole('navigation', { name: 'Main' }).getByRole('link', { name: 'Alerts' }).click();
  await expect(page.getByRole('heading', { name: 'Alerts', level: 1 })).toBeVisible();
  await screenshot(page, '03-alerts');

  // The default view lists what needs an analyst; this run's alerts are in every status.
  const views = page.getByRole('navigation', { name: 'Alert views' });
  await expect(views.getByRole('link', { name: /^Needs analyst/ })).toHaveAttribute('aria-current', 'page');
  await views.getByRole('link', { name: 'All', exact: true }).click();
  await expect(page).toHaveURL(/view=all/);
  const search = page.getByRole('searchbox', { name: 'Search titles' });
  await search.fill(run);
  await search.press('Enter');
  await expect(page).toHaveURL(new RegExp(`q=${run}`));
  const footer = page.getByText(/rows? loaded/);
  await expect(footer).toHaveText('100 rows loaded, more available');
  await page.getByRole('button', { name: 'Load more' }).click();
  await expect(footer).toHaveText(`${BURST + 1} rows loaded`);
  await expect(page.getByRole('grid', { name: 'Alerts' })).toHaveAttribute('aria-rowcount', String(BURST + 2));

  // Severity is a filter chip: a listbox of several choices, kept in the URL.
  await page.getByRole('button', { name: /^Severity:/ }).click();
  const severity = page.getByRole('listbox', { name: 'Severity' });
  await severity.getByRole('option', { name: 'High', exact: true }).click();
  await expect(severity.getByRole('option', { name: 'High', exact: true })).toHaveAttribute('aria-selected', 'true');
  await expect(page).toHaveURL(/severity=high/);
  await expect(footer).toHaveText(`${expectedBySeverity('high')} rows loaded`);
  await severity.getByRole('option', { name: 'Medium', exact: true }).click();
  await expect(footer).toHaveText(`${expectedBySeverity('high') + expectedBySeverity('medium')} rows loaded`);
  await page.keyboard.press('Escape');
  await expect(severity).toBeHidden();
  await expect(page.getByRole('button', { name: /^Severity:/ })).toContainText('High, Medium');
  // Every rendered row respects the filter.
  const labels = await page.getByRole('grid', { name: 'Alerts' }).getByRole('row').evaluateAll((rows) =>
    rows.map((r) => r.getAttribute('aria-label')).filter(Boolean),
  );
  expect(labels.length).toBeGreaterThan(0);
  for (const label of labels) expect(label).toMatch(/^(high|medium) alert: /);
  await page.getByRole('button', { name: 'Clear filters' }).click();
  await expect(page).not.toHaveURL(/severity=/);

  const panel = await openAlertFromList(page, BEACON_TITLE);
  const timeline = panel.getByRole('region', { name: 'Timeline' }).locator('li');
  await expect.poll(() => timeline.count()).toBeGreaterThanOrEqual(3);
  await expect(panel.getByRole('heading', { name: 'Automated triage' })).toBeVisible();
  await expect(panel.getByLabel('Add a note')).toBeVisible();
  await panel.getByRole('heading', { name: 'Timeline' }).scrollIntoViewIfNeeded();
  await screenshot(page, '04-alert-timeline');
  await watch.assertClean();
  await context.close();
});

test('a viewer reads everything but sees no administration', async ({ browser }) => {
  const { context, page, watch } = await newSession(browser);
  await signIn(page, viewer);
  const nav = page.getByRole('navigation', { name: 'Main' });
  await expect(nav.getByRole('link', { name: 'Alerts' })).toBeVisible();
  for (const adminOnly of ['Users and API keys', 'Audit log', 'Tenant settings', 'Sources', 'LLM usage']) {
    await expect(nav.getByRole('link', { name: adminOnly })).toHaveCount(0);
  }
  await page.goto('/users');
  await expect(page.getByRole('heading', { name: 'You do not have access to this page' })).toBeVisible();
  const panel = await openAlertFromList(page, BEACON_TITLE);
  await expect(panel.getByLabel('Add a note')).toHaveCount(0);
  await expect(panel.getByRole('button', { name: 'Reprocess' })).toHaveCount(0);
  await expect(panel.getByRole('button', { name: 'Claim', exact: true })).toHaveCount(0);
  await assertNoTokenInStorage(page);
  await watch.assertClean();
  await context.close();
});

test('an analyst has no administration either', async ({ browser }) => {
  const { context, page, watch } = await newSession(browser);
  await signIn(page, analyst);
  const nav = page.getByRole('navigation', { name: 'Main' });
  await expect(nav.getByRole('link', { name: 'Escalations' })).toBeVisible();
  for (const adminOnly of ['Users and API keys', 'Audit log', 'Tenant settings', 'Sources', 'LLM usage']) {
    await expect(nav.getByRole('link', { name: adminOnly })).toHaveCount(0);
  }
  await page.goto('/audit');
  await expect(page.getByRole('heading', { name: 'You do not have access to this page' })).toBeVisible();
  await watch.assertClean();
  await context.close();
});

/**
 * With True positive chosen, the expected response plan opens under the
 * investigation, outside the form: every planned action names what it acts
 * on (`target`, an entity of the alert, among them), the page passes axe in
 * both themes with the plan open, and an action is pre-approved only after
 * its target was read.
 */
async function reviewResponsePlan(page: Page, target: string) {
  await verdictRadio(page, 'True positive').check();
  const plan = responsePlan(page);
  const actions = plan.getByRole('list', { name: 'Planned actions' }).getByRole('listitem');
  await expect(actions.first()).toBeVisible();
  for (const action of await actions.all()) await expect(action.locator('code')).toHaveText(/\S/);
  await expect(actions.filter({ has: page.locator('code', { hasText: target }) }).first()).toBeVisible();
  await expect(decisionForm(page).getByRole('list', { name: 'Planned actions' })).toHaveCount(0);
  await assertAccessible(page, 'decision page with the response plan open');
  await page.getByRole('banner').getByTitle('Light', { exact: true }).click();
  await expect(page.locator('html')).toHaveAttribute('data-theme', 'light');
  await assertAccessible(page, 'decision page with the response plan open (light theme)');
  await page.getByRole('banner').getByTitle('Dark', { exact: true }).click();
  await expect(page.locator('html')).toHaveAttribute('data-theme', 'dark');

  const mine = actions.filter({ has: page.getByRole('checkbox', { disabled: false }) }).first();
  await expect(mine.locator('code')).toHaveText(/\S/);
  await mine.getByRole('checkbox').check();
  await expect(mine).toContainText('Pre-approved: runs after your decision');
  await expect(decisionForm(page)).toContainText('1 action is pre-approved.');
}

/**
 * Viewer gating in the queue and on the decision page, then the analyst
 * claims the escalation from its queue row, reviews the response plan a true
 * positive would start (`planTarget` is an entity it must name) and records
 * `decision` on its decision page (/escalations/:id).
 */
async function decideAsAnalyst(
  viewerPage: Page,
  analystPage: Page,
  title: string,
  decision: 'True positive' | 'False positive',
  planTarget: string,
  shots: boolean,
) {
  await test.step('viewer: the escalation is visible but cannot be claimed or decided', async () => {
    const page = viewerPage;
    const row = await findEscalation(page, title);
    await expect(row.getByRole('button')).toHaveCount(0);
    await expect(row.getByRole('checkbox')).toHaveCount(0);
    await expect(page.getByRole('region', { name: 'Bulk actions' })).toHaveCount(0);
    await row.getByRole('link', { name: title, exact: true }).click();
    await expect(page.getByRole('heading', { name: title, level: 1 })).toBeVisible();
    await expect(page.getByRole('button', { name: 'Claim', exact: true })).toHaveCount(0);
    await expect(decisionForm(page).getByRole('button', { name: 'Record decision' })).toBeDisabled();
    await expect(verdictRadio(page, decision)).toBeDisabled();
    await expect(decisionForm(page)).toContainText('Requires the analyst role.');
  });
  await test.step(`analyst: claim from the queue, then decide ${decision} on the decision page`, async () => {
    const page = analystPage;
    const row = await findEscalation(page, title);
    await expect(row).toContainText('Unassigned');
    await row.getByRole('button', { name: `Claim ${title}`, exact: true }).click();
    await expect(page.getByRole('status').filter({ hasText: 'Escalation claimed.' })).toBeVisible();
    await expect(row.getByRole('link', { name: `Decide ${title}`, exact: true })).toBeVisible();
    await expect(row).toContainText('You');
    await row.getByRole('link', { name: `Decide ${title}`, exact: true }).click();
    await expect(page).toHaveURL(/\/escalations\/[^/?]+/);
    await expect(page.getByRole('heading', { name: title, level: 1 })).toBeVisible();
    await expect(page.getByText(/^Claimed by you/)).toBeVisible();
    await expect(page.getByRole('tablist', { name: 'Investigation sections' })).toBeVisible();
    const form = decisionForm(page);
    await expect(form.getByRole('button', { name: 'Record decision' })).toBeDisabled();
    await reviewResponsePlan(page, planTarget);
    await verdictRadio(page, decision).check();
    // Only a true positive has a response plan; any other verdict closes it and sends no pre-approval.
    await expect(responsePlan(page)).toHaveCount(decision === 'True positive' ? 1 : 0);
    await form.getByLabel(/^Notes for the record/).fill(`e2e ${run}: ${decision}.`);
    await form.getByText('Rate the automated triage (optional)').click();
    await form.getByLabel('Triage correct').selectOption('yes');
    if (shots) {
      // The "Escalation claimed." notice would cover the form in the picture.
      const notices = page.getByRole('button', { name: 'Dismiss notification' });
      for (const notice of await notices.all()) await notice.click();
      await expect(notices).toHaveCount(0);
      await screenshot(page, '06-decision');
    }
    await form.getByRole('button', { name: 'Record decision' }).click();
    await expect(page.getByRole('status').filter({ hasText: /Decision recorded; \d+ alert\(s\) resumed\./ })).toBeVisible();
    await expect(page.getByText(`Decided: ${decision}`)).toBeVisible();
    await expect(form).toHaveCount(0);
    // The decided escalation leaves the default (open, claimed, expired) queue.
    await page.getByRole('link', { name: 'Escalations', exact: true }).first().click();
    await expect(page.getByRole('heading', { name: 'Escalations', level: 1 })).toBeVisible();
    await expect(escalationQueue(page).or(page.getByText('Nothing in this view'))).toBeVisible();
    await expect(escalationRow(page, title)).toHaveCount(0);
  });
}

test('an analyst claims and decides an escalation, and the alert closes', async ({ browser, request }) => {
  const v = await newSession(browser);
  const a = await newSession(browser);
  await signIn(v.page, viewer);
  await signIn(a.page, analyst);

  const waiting = await nextRequest(request, escalatedId);
  expect(waiting.status, 'the sign-in alert waits for an analyst').toBe('waiting_human');
  await decideAsAnalyst(v.page, a.page, ESCALATED_TITLE, 'False positive', `host-0-${run}`, true);

  const closed = await waitForAlert(request, apiKey, escalatedId, ['closed']);
  expect(closed.disposition).toBe('benign');
  const panel = await openAlertFromList(a.page, ESCALATED_TITLE);
  await expect(panel.getByText('Closed', { exact: true }).first()).toBeVisible();
  await expect(panel.getByText('Benign', { exact: true }).first()).toBeVisible();
  // The escalation box says who decided, and the timeline records it.
  await expect(panel.getByText(/^Decided false positive by You/)).toBeVisible();
  await expect(panel.getByText(/^analyst[ ._]decision$/i).first()).toBeVisible();
  for (const s of [v, a]) {
    await assertNoTokenInStorage(s.page);
    await s.watch.assertClean();
    await s.context.close();
  }
});

/**
 * Works the C2 alert to closure the way a SOC does, whatever order the
 * workflow asks in: pending response actions are approved by the admin (the
 * first time after checking viewer and analyst gating on them), and an
 * escalation, if the workflow raises one, is decided by the analyst.
 */
test('response approval: role gating, the admin approves, the alert closes as malicious', async ({ browser, request }) => {
  const v = await newSession(browser);
  const a = await newSession(browser);
  const ad = await newSession(browser);
  await signIn(v.page, viewer);
  await signIn(a.page, analyst);
  await signIn(ad.page, admin);
  let approved = 0;

  const approve = async () => {
    if (approved === 0) {
      await test.step('viewer: pending actions are visible but cannot be approved or rejected', async () => {
        await v.page.goto('/approvals');
        const rows = pendingCards(v.page, beaconId);
        await expect(rows.first()).toBeVisible();
        await expect(v.page.getByRole('button', { name: 'Approve', exact: true })).toHaveCount(0);
        await expect(v.page.getByRole('button', { name: 'Reject', exact: true })).toHaveCount(0);
        await expect(rows.first()).toContainText('Requires the analyst role.');
      });
      await test.step('analyst: approve only low and medium risk, reject at any risk', async () => {
        await a.page.goto('/approvals');
        const rows = pendingCards(a.page, beaconId);
        await expect(rows.first()).toBeVisible();
        const n = await rows.count();
        expect(n).toBeGreaterThan(0);
        for (let i = 0; i < n; i += 1) {
          const row = rows.nth(i);
          // Found by content, not position: the card's layout changes between releases.
          const risk = ((await row.getByText(/^(low|medium|high|critical) risk$/i).first().textContent()) ?? '').trim().toLowerCase();
          await expect(row.getByRole('button', { name: 'Reject', exact: true })).toBeVisible();
          if (risk.includes('high') || risk.includes('critical')) {
            // Locked, with the reason next to it.
            await expect(row.getByRole('button', { name: 'Approve', exact: true })).toBeDisabled();
            await expect(row).toContainText('needs an admin');
          } else {
            await expect(row.getByRole('button', { name: 'Approve', exact: true })).toBeEnabled();
          }
        }
      });
    }
    await test.step("admin: approve one action and reject the alert's other pending actions", async () => {
      const page = ad.page;
      await page.goto('/approvals');
      const row = pendingCards(page, beaconId).first();
      await expect(row).toBeVisible();
      if (approved === 0) await screenshot(page, '07-approvals');
      await row.getByRole('button', { name: 'Approve', exact: true }).click();
      const dialog = page.getByRole('dialog', { name: /^Approve / });
      await dialog.getByLabel("Reject the alert's other pending actions").check();
      await dialog.getByRole('button', { name: 'Approve action' }).click();
      await expect(dialog).toBeHidden();
      await expect(page.getByRole('status').filter({ hasText: /^Approved / })).toBeVisible();
    });
    approved += 1;
  };

  let state = await nextRequest(request, beaconId);
  expect(state.status, 'the C2 alert asks for approval of its planned response').toBe('waiting_approval');
  for (let round = 0; round < 6 && state.status !== 'closed'; round += 1) {
    if (state.status === 'waiting_human') await decideAsAnalyst(v.page, a.page, BEACON_TITLE, 'True positive', `ws-${run}`, false);
    else await approve();
    state = await nextRequest(request, beaconId);
  }
  expect(state.status).toBe('closed');
  expect(state.disposition).toBe('malicious');
  expect(approved).toBeGreaterThanOrEqual(1);

  // The approved action ran as a dry run (response.dry_run defaults to true); the rest were rejected.
  const page = ad.page;
  await page.goto('/approvals?view=all');
  const rows = actionRows(page, beaconId);
  await expect(rows.filter({ hasText: 'Recorded only (dry run)' }).first()).toBeVisible();
  await expect(rows.filter({ hasText: 'awaiting approval' })).toHaveCount(0);
  const panel = await openAlertFromList(page, BEACON_TITLE);
  await expect(panel.getByText('Closed', { exact: true }).first()).toBeVisible();
  await expect(panel.getByText('Malicious', { exact: true }).first()).toBeVisible();
  // The approved action ran as a dry run: the panel warns about it.
  await expect(panel.getByRole('alert').filter({ hasText: 'The response ran as a dry run.' })).toBeVisible();
  for (const s of [v, a, ad]) {
    await assertNoTokenInStorage(s.page);
    await s.watch.assertClean();
    await s.context.close();
  }
});

// Each page is also checked with axe (WCAG 2.2 A and AA): a serious or critical violation fails.
test('main pages render under the CSP (and screenshots for the README)', async ({ browser }) => {
  const { context, page, watch } = await newSession(browser);
  await signIn(page, admin);
  const pages: [string, string, string][] = [
    ['/alerts', 'Alerts', '03-alerts'],
    ['/escalations', 'Escalations', '05-escalations'],
    ['/escalations?status=decided', 'Escalations', '05-escalations-decided'],
    ['/approvals?view=all', 'Approvals', '07-approvals-ledger'],
    ['/suppressions', 'Suppressions', '08-suppressions'],
    ['/sources', 'Sources', '09-sources'],
    ['/users', 'Users and API keys', '10-users'],
    ['/settings', 'Tenant settings', '11-settings'],
    ['/usage', 'LLM usage', '12-usage'],
    ['/audit', 'Audit log', '13-audit'],
    // Last: the summary is cached for 15 seconds, so it now reflects the decisions above.
    ['/', 'Overview', '02-overview'],
  ];
  for (const [path, heading, shot] of pages) {
    await page.goto(path);
    await expect(page.getByRole('heading', { name: heading, level: 1 })).toBeVisible();
    await expect(page.getByText(/^Loading/)).toHaveCount(0);
    await expect(page.getByRole('alert').filter({ hasText: /error|failed/i })).toHaveCount(0);
    await screenshot(page, shot);
    await assertAccessible(page, path);
  }
  // The theme switch in the header: the Overview in the light theme passes axe as well.
  await page.getByRole('banner').getByTitle('Light', { exact: true }).click();
  await expect(page.locator('html')).toHaveAttribute('data-theme', 'light');
  await screenshot(page, '02-overview-light');
  await assertAccessible(page, '/ (light theme)');
  await page.getByRole('banner').getByTitle('Dark', { exact: true }).click();
  await expect(page.locator('html')).toHaveAttribute('data-theme', 'dark');
  // The audit log recorded the analyst's claim and decision and the admin's approval.
  await page.goto('/audit');
  await expect(page.getByText('escalation.claimed').first()).toBeVisible();
  await expect(page.getByText('escalation.decided').first()).toBeVisible();
  await expect(page.getByText('response_action.approved').first()).toBeVisible();
  await watch.assertClean();
  await context.close();
});

test('sign-out ends the session: no token left, the refresh cookie no longer works', async ({ browser }) => {
  const { context, page, watch } = await newSession(browser);
  await signIn(page, analyst);
  await page.goto('/alerts');
  await signOut(page);
  await assertNoTokenInStorage(page);
  await page.goto('/alerts');
  await expect(page.getByRole('heading', { name: 'Sign in' })).toBeVisible();
  await expect(page).toHaveURL(/\/login/);
  // Nothing of the previous session is readable without signing in again.
  const status = await page.evaluate(async (api) => (await fetch(`${api}/alerts?limit=1`)).status, API);
  expect(status).toBe(401);
  const refresh = await page.evaluate(async (api) => (await fetch(`${api}/auth/refresh`, { method: 'POST' })).status, API);
  expect(refresh).toBe(401);
  await watch.assertClean();
  await context.close();
});

