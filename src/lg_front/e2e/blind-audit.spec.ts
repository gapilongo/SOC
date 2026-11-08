/**
 * The blind audit through the real UI (PRD-10.2), against a running stack:
 * alerts that automation closes as benign are sampled on demand, the API
 * hides the AI verdict of an unlabelled sample, an admin labels samples with
 * the keyboard (the verdict is revealed only after the label; a malicious
 * label opens an escalation), the Reports page shows the estimate with the
 * small-sample wording, and the Blind audit page passes axe in both themes
 * and fits a phone screen.
 */
import { expect, test, type APIRequestContext } from '@playwright/test';

import { API, assertAccessible, ingest, newSession, requiredEnv, screenshot, signIn, waitForAlert, type Credentials } from './support';

test.describe.configure({ mode: 'serial' });

const run = `ba${Date.now().toString(36)}`;
const admin: Credentials = { email: requiredEnv('E2E_ADMIN_EMAIL'), password: requiredEnv('E2E_ADMIN_PASSWORD') };
// Plenty of benign signals for the triage: these close without an analyst.
const TITLES = [0, 1].map((i) => `Scheduled backup test ${run} #${i}`);
// Keys of the AI's side of an alert; none may be in a sample before its label.
const AI_KEYS = ['disposition', 'confidence', 'threat_score', 'summary', 'verdict', 'conclusion', 'ai_class', 'agreement'];

let token = '';

async function bearer(request: APIRequestContext): Promise<Record<string, string>> {
  if (!token) {
    const r = await request.post(`${API}/auth/login`, { data: admin });
    expect(r.status(), await r.text()).toBe(200);
    token = ((await r.json()) as { access_token: string }).access_token;
  }
  return { Authorization: `Bearer ${token}` };
}

function aiKeysIn(value: unknown, found: string[] = []): string[] {
  if (Array.isArray(value)) value.forEach((v) => aiKeysIn(v, found));
  else if (value && typeof value === 'object') {
    for (const [k, v] of Object.entries(value)) {
      if (AI_KEYS.includes(k)) found.push(k);
      aiKeysIn(v, found);
    }
  }
  return found;
}

test('auto-closed alerts are sampled and the API hides their verdict until labelled', async ({ request }) => {
  // Up to about 8 minutes: a run only covers alerts closed at least 5 minutes ago.
  test.setTimeout(600_000);
  const auth = await bearer(request);
  const created = await request.post(`${API}/api-keys`, { data: { name: `e2e blind audit ${run}`, scopes: ['ingest', 'read'] }, headers: auth });
  expect(created.status(), await created.text()).toBe(201);
  const key = ((await created.json()) as { key: string }).key;
  const items = await ingest(
    request,
    key,
    TITLES.map((title, i) => ({
      source_alert_id: `${run}-${i}`,
      title,
      // Triage takes false-positive evidence from the detection rule's name, never the title (AI-E6.3).
      rule_name: 'scheduled-backup-maintenance-test',
      description: 'Known scheduled backup update test; benign maintenance noise, informational.',
      severity: 'info',
      occurred_at: new Date().toISOString(),
    })),
  );
  for (const item of items) {
    const alert = await waitForAlert(request, key, item.alert_id as string, ['closed', 'waiting_human', 'waiting_approval']);
    expect(alert.status, `${alert.title} should close without an analyst`).toBe('closed');
    expect(alert.disposition).not.toBe('malicious');
  }

  // Runs on demand, each from where the last one ended to 5 minutes ago (a close still committing is never
  // missed): repeat until a run's frame holds our alerts.
  type Item = { id: string; alert: Record<string, unknown> & { title: string } };
  let ours: Item[] = [];
  let listed: { items: Item[] } = { items: [] };
  for (let attempt = 0; attempt < 16 && ours.length < 2; attempt += 1) {
    const sampled = await request.post(`${API}/blind-audit/runs`, { data: { size: 2000 }, headers: auth });
    expect([201, 400], await sampled.text()).toContain(sampled.status());
    if (sampled.status() === 201) {
      const runOut = (await sampled.json()) as { frame_size: number; sample_size: number; seed_source: string };
      expect(runOut.sample_size).toBe(runOut.frame_size);
      expect(runOut.seed_source).toBe('server');
    }
    const queue = await request.get(`${API}/blind-audit/items?status=pending&limit=200`, { headers: auth });
    expect(queue.status()).toBe(200);
    listed = (await queue.json()) as { items: Item[] };
    ours = listed.items.filter((i) => i.alert.title.includes(run));
    if (ours.length < 2) await new Promise((r) => setTimeout(r, 30_000));
  }
  expect(ours).toHaveLength(2);
  expect(aiKeysIn(listed)).toEqual([]);
  expect(ours.every((i) => !('id' in i.alert))).toBe(true);
  // The alert's own route withholds the verdict too, for an admin's token and a read key alike.
  for (const item of items) {
    for (const headers of [auth, { 'X-API-Key': key }]) {
      const alert = (await (await request.get(`${API}/alerts/${item.alert_id}`, { headers })).json()) as Record<string, unknown>;
      expect(alert.hidden_for_blind_audit).toBe(true);
      expect(alert.disposition).toBeNull();
    }
  }
  const detail = await request.get(`${API}/blind-audit/items/${ours[0].id}`, { headers: auth });
  const body = (await detail.json()) as { reveal: unknown };
  expect(body.reveal).toBeNull();
  expect(aiKeysIn(body)).toEqual([]);
});

test('an admin labels samples with the keyboard and sees the verdict only afterwards', async ({ browser }) => {
  const { context, page, watch } = await newSession(browser);
  await signIn(page, admin);
  await page.getByRole('navigation', { name: 'Main' }).getByRole('link', { name: 'Blind audit' }).click();
  await expect(page.getByRole('heading', { name: 'Blind audit', level: 1 })).toBeVisible();
  const queue = page.getByRole('list', { name: 'Samples waiting for a label' });

  await queue.getByRole('button', { name: new RegExp(TITLES[0]) }).click();
  await expect(page.getByRole('heading', { name: TITLES[0] })).toBeVisible();
  await expect(page.getByRole('form', { name: 'Your label' })).toBeVisible();
  await expect(page.getByText('AI verdict when sampled')).toHaveCount(0);
  await screenshot(page, '15-blind-audit');
  await assertAccessible(page, '/blind-audit');
  await page.keyboard.press('b');
  await expect(page.getByText('AI verdict when sampled')).toBeVisible();
  await expect(page.getByRole('status').filter({ hasText: 'You labelled it benign.' })).toBeVisible();
  await assertAccessible(page, '/blind-audit (verdict revealed)');
  await page.keyboard.press('n');

  await queue.getByRole('button', { name: new RegExp(TITLES[1]) }).click();
  await expect(page.getByRole('heading', { name: TITLES[1] })).toBeVisible();
  await page.keyboard.press('m');
  await expect(page.getByText('You disagree with the AI.')).toBeVisible();
  const escalation = page.getByRole('link', { name: 'open the escalation' });
  await expect(escalation).toHaveAttribute('href', /^\/escalations\/.+/);

  // The estimate: two labels are far from enough.
  await page.goto('/reports');
  await page.getByRole('tab', { name: 'Blind audit' }).click();
  await expect(page.getByText('Missed threats among auto-closed (FN rate)')).toBeVisible();
  await expect(page.getByText(/Not enough data \(n=\d+; at least 30 needed\)/).first()).toBeVisible();
  await assertAccessible(page, '/reports (blind audit)');

  // Light theme and a phone screen.
  await page.goto('/blind-audit');
  await expect(page.getByRole('heading', { name: 'Blind audit', level: 1 })).toBeVisible();
  await page.getByRole('banner').getByTitle('Light', { exact: true }).click();
  await expect(page.locator('html')).toHaveAttribute('data-theme', 'light');
  // Let the colour transitions settle: axe must read the light theme's final colours.
  await page.waitForFunction(() => document.getAnimations().every((a) => a.playState !== 'running'));
  await assertAccessible(page, '/blind-audit (light theme)');
  await page.getByRole('banner').getByTitle('Dark', { exact: true }).click();
  await expect(page.locator('html')).toHaveAttribute('data-theme', 'dark');
  await page.setViewportSize({ width: 390, height: 844 });
  await page.waitForFunction(() => document.getAnimations().every((a) => a.playState !== 'running'));
  await expect(page.getByRole('heading', { name: 'Blind audit', level: 1 })).toBeVisible();
  const overflow = await page.evaluate(() => document.documentElement.scrollWidth - document.documentElement.clientWidth);
  expect(overflow).toBeLessThanOrEqual(0);
  await assertAccessible(page, '/blind-audit (phone)');
  await watch.assertClean();
  await context.close();
});
