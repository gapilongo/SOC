/**
 * The first-run setup wizard through the real UI, on a phone (390 px wide):
 * the bootstrap admin confirms their account, names the organisation and the
 * first tenant, keeps the EU model profile the wizard preselects and tests the
 * configured model, sends the sample alerts and waits for the first verdict,
 * then finishes on the Overview and follows the proof-of-value link. Every
 * step passes axe, in the dark theme and (the model step) the light one, and
 * the page never scrolls sideways. The time from sign-in to the first verdict
 * is recorded against the 30-minute budget (PRD-13.1); the fresh-database
 * rehearsal of the same flow is tests/integration/e2e/test_first_run.py.
 *
 * Runs after triage.spec.ts (files run in name order), so it does not change
 * what that scenario sees; against a stack where setup is already done it
 * opens the wizard directly.
 */
import { expect, test, type Page } from '@playwright/test';

import { BASE_URL, PageWatch, assertAccessible, requiredEnv, screenshot, signIn, type Credentials } from './support';

const BUDGET_MS = 30 * 60 * 1000;
const admin: Credentials = { email: requiredEnv('E2E_ADMIN_EMAIL'), password: requiredEnv('E2E_ADMIN_PASSWORD') };

async function noSideScroll(page: Page, label: string): Promise<void> {
  const overflow = await page.evaluate(() => document.documentElement.scrollWidth - document.documentElement.clientWidth);
  expect(overflow, `horizontal scroll on ${label}`).toBeLessThanOrEqual(0);
}

async function checkStep(page: Page, heading: string, shot: string): Promise<void> {
  await expect(page.getByRole('heading', { name: heading })).toBeVisible();
  await expect(page.getByText(/^Loading/)).toHaveCount(0);
  await screenshot(page, shot);
  await assertAccessible(page, `${heading} (390 px)`);
  await noSideScroll(page, heading);
}

async function pickTheme(page: Page, theme: 'Light' | 'Dark'): Promise<void> {
  await page.getByRole('button', { name: /^Account: / }).click();
  await page.getByRole('menuitemradio', { name: `${theme} theme` }).click();
  await expect(page.locator('html')).toHaveAttribute('data-theme', theme.toLowerCase());
  await page.keyboard.press('Escape');
}

test('the setup wizard takes a fresh install to its first triaged alert and the proof of value', async ({ browser }) => {
  const context = await browser.newContext({ baseURL: BASE_URL(), viewport: { width: 390, height: 844 }, colorScheme: 'dark' });
  const page = await context.newPage();
  const watch = await PageWatch.attach(page);
  const started = Date.now();
  await signIn(page, admin);

  // The Overview invites the platform admin until setup is done.
  const start = page.getByRole('link', { name: 'Start setup' });
  const invited = await start.waitFor({ timeout: 10_000 }).then(
    () => true,
    () => false,
  );
  if (invited) {
    await screenshot(page, '20-setup-callout');
    await assertAccessible(page, '/ with the setup callout (390 px)');
    await start.click();
  } else {
    await page.goto('/setup');
  }
  await expect(page.getByRole('heading', { name: 'Set up LG-SOTF', level: 1 })).toBeVisible();

  // 1. The admin.
  await checkStep(page, 'Step 1 of 5: Your account', '21-setup-account');
  await expect(page.getByRole('main').getByText(admin.email)).toBeVisible();
  await page.getByRole('button', { name: 'Confirm and continue' }).click();

  // 2. Organisation and first tenant.
  await checkStep(page, 'Step 2 of 5: Organisation', '22-setup-organisation');
  await page.getByLabel('Organisation').fill('E2E Example Org');
  await page.getByLabel('First tenant').fill('E2E Example SOC');
  await page.getByRole('button', { name: 'Save and continue' }).click();

  // 3. The model: an EU profile is preselected; the configured (offline) model is tested.
  await checkStep(page, 'Step 3 of 5: Language model', '23-setup-model');
  await expect(page.getByRole('radio', { name: /Mistral AI \(EU\)/ })).toBeChecked();
  await page.getByRole('button', { name: 'Test model' }).click();
  await expect(page.getByText('both tiers answered')).toBeVisible();
  await pickTheme(page, 'Light');
  await screenshot(page, '23-setup-model-light');
  await assertAccessible(page, 'Step 3 of 5 (390 px, light theme)');
  await pickTheme(page, 'Dark');
  await page.getByRole('button', { name: 'Save and continue' }).click();

  // 4. Sample alerts until the first verdict.
  await checkStep(page, 'Step 4 of 5: Sample alerts', '24-setup-samples');
  await page.getByRole('button', { name: /^Send sample alerts/ }).click();
  await expect(page.getByText(/^First alert triaged/)).toBeVisible({ timeout: 180_000 });
  const firstVerdictMs = Date.now() - started;
  await assertAccessible(page, 'Step 4 of 5 after the first verdict (390 px)');
  await page.getByRole('button', { name: 'Continue', exact: true }).click();

  // 5. Finish, then the Overview links to the proof of value.
  await checkStep(page, 'Step 5 of 5: Finish', '25-setup-finish');
  await expect(page.getByRole('main').getByText('E2E Example Org')).toBeVisible();
  await page.getByRole('button', { name: 'Finish setup' }).click();
  await expect(page.getByRole('heading', { name: 'Overview', level: 1 })).toBeVisible();
  const pov = page.getByRole('link', { name: 'Start a proof of value' });
  await expect(pov).toBeVisible();
  await expect(page.getByRole('link', { name: 'Start setup' })).toHaveCount(0);
  await assertAccessible(page, '/ after setup (390 px)');
  await noSideScroll(page, 'the Overview after setup');
  await pov.click();
  await expect(page.getByRole('heading', { name: 'Proof of value', level: 1 })).toBeVisible();
  await assertAccessible(page, '/pov (390 px)');

  const timing = { budget_s: BUDGET_MS / 1000, time_to_first_triage_s: Number((firstVerdictMs / 1000).toFixed(1)) };
  test.info().annotations.push({ type: 'time_to_first_triage_s', description: String(timing.time_to_first_triage_s) });
  await test.info().attach('first-run-timing', { body: JSON.stringify(timing), contentType: 'application/json' });
  expect(firstVerdictMs).toBeLessThanOrEqual(BUDGET_MS);
  await watch.assertClean();
  await context.close();
});
