/**
 * Reopen from the case page (PRD-2.9a), through the real UI against a
 * running stack.
 *
 * The tenant lets the AI close alerts on the model's word; a routine alert
 * closes that way; a threat a model judged arrives on the same host and is
 * escalated, so the safety net links the closed alert to the threat's case.
 * An analyst opens that case, reopens the linked alert with a reason, and
 * the alert waits for a person in the case. The audit log names the analyst
 * and the reason. The page passes axe in both themes, with the dialog open
 * and after the reopening, and fits a phone.
 */
import { expect, test, type APIRequestContext } from '@playwright/test';

import {
  API,
  assertAccessible,
  assertNoSideScroll,
  getAlert,
  ingest,
  newSession,
  randomPassword,
  requiredEnv,
  screenshot,
  setTheme,
  signIn,
  waitForAlert,
  type Credentials,
} from './support';

const run = `ro${Date.now().toString(36)}`;
const admin: Credentials = { email: requiredEnv('E2E_ADMIN_EMAIL'), password: requiredEnv('E2E_ADMIN_PASSWORD') };
const analyst: Credentials = { email: `analyst-${run}@e2e.example.com`, password: randomPassword() };
const HOST = `ws-${run}`;
// The demo model reads keywords. It calls this benign ("expected"), and the rule's name holds no benign
// word, so there is no approved benign evidence: only the models close it.
const ROUTINE_TITLE = `Windows logon success ${run}`;
const ROUTINE_TEXT = 'An expected logon.';
// It calls this malicious, below the response policy's threshold: at medium severity the alert goes to an
// analyst as a threat only a model stands behind. (Three threat words: the host's history, which the model
// is shown, carries the routine alert's benign one.)
const THREAT_TITLE = `Suspicious lateral movement ${run}`;
const THREAT_TEXT = 'Possible credential dumping with mimikatz on the workstation.';
const REASON = `This logon is the first step of the attack on ${HOST}.`;

async function bearer(request: APIRequestContext): Promise<Record<string, string>> {
  const r = await request.post(`${API}/auth/login`, { data: admin });
  expect(r.status(), await r.text()).toBe(200);
  return { Authorization: `Bearer ${((await r.json()) as { access_token: string }).access_token}` };
}

async function closureTier(request: APIRequestContext, auth: Record<string, string>, tier: 'off' | 'auto_full_audit'): Promise<void> {
  const r = await request.patch(`${API}/tenant/settings`, { data: { ai_closure: { tier } }, headers: auth });
  expect(r.status(), await r.text()).toBe(200);
}

test('an analyst reopens an alert the AI closed from its case page, with a reason', async ({ browser, request }) => {
  test.setTimeout(420_000);
  const auth = await bearer(request);
  const user = await request.post(`${API}/users`, { data: { email: analyst.email, role: 'analyst', password: analyst.password }, headers: auth });
  expect(user.status(), await user.text()).toBe(201);
  const analystId = ((await user.json()) as { id: string }).id;
  const created = await request.post(`${API}/api-keys`, { data: { name: `e2e reopen ${run}`, scopes: ['ingest', 'read'] }, headers: auth });
  expect(created.status(), await created.text()).toBe(201);
  const key = ((await created.json()) as { key: string }).key;

  let closedId = '';
  let caseId = '';
  await closureTier(request, auth, 'auto_full_audit');
  try {
    await test.step('the AI closes a routine alert on the model’s word', async () => {
      const [item] = await ingest(request, key, [
        {
          source_alert_id: `${run}-routine`,
          title: ROUTINE_TITLE,
          rule_name: '60106: Windows logon success',
          description: ROUTINE_TEXT,
          severity: 'low',
          occurred_at: new Date().toISOString(),
          entities: { hosts: [HOST] },
        },
      ]);
      closedId = item.alert_id as string;
      const alert = await waitForAlert(request, key, closedId, ['closed', 'waiting_human', 'waiting_approval']);
      expect(alert.status, 'the routine alert should close without a person').toBe('closed');
      const detail = (await getAlert(request, key, closedId)) as unknown as { summary: { close_reason?: string } };
      expect(detail.summary.close_reason).toBe('ai_closed:audit_required');
    });

    await test.step('a threat a model judged on the same host opens a case, and the closed alert is linked to it', async () => {
      const [item] = await ingest(request, key, [
        {
          source_alert_id: `${run}-threat`,
          title: THREAT_TITLE,
          description: THREAT_TEXT,
          severity: 'medium',
          occurred_at: new Date().toISOString(),
          entities: { hosts: [HOST], users: [`u-${run}`] },
        },
      ]);
      const threatId = item.alert_id as string;
      await waitForAlert(request, key, threatId, ['waiting_human']);
      const detail = (await getAlert(request, key, threatId)) as unknown as { summary: { escalation_id?: string } };
      caseId = detail.summary.escalation_id ?? '';
      expect(caseId, 'the threat has a case').not.toBe('');
      const view = await request.get(`${API}/cases/${caseId}`, { headers: auth });
      expect(view.status(), await view.text()).toBe(200);
      const linked = ((await view.json()) as { alerts: Array<{ id: string; role: string; can_reopen: boolean }> }).alerts.find((a) => a.id === closedId);
      expect(linked, 'the closed alert is in the case').toMatchObject({ role: 'linked', can_reopen: true });
    });
  } finally {
    // The other specs expect the default: the AI closes nothing on the model's word.
    await closureTier(request, auth, 'off');
  }

  const { context, page, watch } = await newSession(browser);
  await signIn(page, analyst);
  await page.goto(`/cases/${caseId}`);
  await expect(page.getByRole('heading', { name: THREAT_TITLE, level: 1 })).toBeVisible();
  const alerts = page.getByRole('region', { name: 'Alerts in this case' });
  const row = alerts.locator(`tr[data-alert="${closedId}"]`);
  const dialog = page.getByRole('dialog', { name: 'Reopen this alert' });

  await test.step('the linked alert has Reopen and Flag; the dialog asks for a reason, in both themes', async () => {
    await expect(row).toHaveAttribute('data-role', 'linked');
    await expect(row.getByRole('button', { name: /^Flag/ })).toBeVisible();
    await assertAccessible(page, 'case page with reopen controls');
    await row.getByRole('button', { name: /^Reopen/ }).click();
    await expect(dialog).toBeVisible();
    await expect(dialog.getByRole('button', { name: 'Reopen alert' })).toBeDisabled();
    await assertAccessible(page, 'reopen dialog');
    await dialog.getByRole('button', { name: 'Cancel' }).click();
    await expect(dialog).toBeHidden();
    await setTheme(page, 'light');
    await assertAccessible(page, 'case page with reopen controls (light theme)');
    await row.getByRole('button', { name: /^Reopen/ }).click();
    await assertAccessible(page, 'reopen dialog (light theme)');
  });

  await test.step('with a reason the alert is reopened and waits for a person in this case', async () => {
    await dialog.getByRole('textbox', { name: /Why reopen it/ }).fill(REASON);
    await screenshot(page, '05c-case-reopen-dialog');
    await dialog.getByRole('button', { name: 'Reopen alert' }).click();
    await expect(dialog).toBeHidden();
    await expect(row).toHaveAttribute('data-role', 'reopened');
    await expect(row).toHaveAttribute('data-state', 'open');
    await expect(row).toContainText('Reopened by you');
    await expect(row.locator('q')).toHaveText(REASON);
    await expect(row.getByRole('button')).toHaveCount(0); // it is open again: nothing left to reopen
    const timeline = page.getByRole('region', { name: 'Timeline', exact: true });
    await expect(timeline.getByText("An analyst reopened this alert, which the AI had closed on the model's word.")).toBeVisible();
    await screenshot(page, '05c-case-reopened');
    await assertAccessible(page, 'case page after the reopening (light theme)');
    await page.setViewportSize({ width: 390, height: 844 });
    await assertNoSideScroll(page, 'the case page after the reopening at 390 px');
    await assertAccessible(page, 'case page after the reopening at 390 px (light theme)');
    await page.setViewportSize({ width: 1440, height: 900 });
    await setTheme(page, 'dark');
    await assertAccessible(page, 'case page after the reopening');
  });

  await test.step('the alert waits for a person, and the audit log says who reopened it and why', async () => {
    expect((await getAlert(request, key, closedId)).status).toBe('waiting_human');
    const audit = await request.get(`${API}/audit?action=alert.reopened&limit=50`, { headers: auth });
    expect(audit.status(), await audit.text()).toBe(200);
    const entries = ((await audit.json()) as { items: Array<{ resource_id: string; actor_id: string; details: Record<string, unknown> }> }).items;
    const entry = entries.find((e) => e.resource_id === closedId);
    expect(entry, 'the reopening is audited').toBeDefined();
    expect(entry?.actor_id).toBe(analystId);
    expect(entry?.details).toMatchObject({ reason: 'analyst_reopen', note: REASON, mode: 'folded', escalation_id: caseId });
  });

  await watch.assertClean();
  await context.close();
});
