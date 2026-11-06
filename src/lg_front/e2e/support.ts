/** Shared helpers for the end-to-end suite (see playwright.config.ts). */
import { expect, type APIRequestContext, type Browser, type BrowserContext, type Locator, type Page } from '@playwright/test';
import { mkdirSync } from 'node:fs';
import { join } from 'node:path';

export const API = '/api/v1';

export function requiredEnv(name: string): string {
  const value = process.env[name];
  if (!value) throw new Error(`${name} is not set (see playwright.config.ts)`);
  return value;
}

export const BASE_URL = () => requiredEnv('E2E_BASE_URL');

export interface Credentials {
  email: string;
  password: string;
}

/** A password that satisfies auth.password_min_length and is never reused between runs. */
export function randomPassword(): string {
  const bytes = new Uint8Array(18);
  crypto.getRandomValues(bytes);
  return `E2e-${Buffer.from(bytes).toString('base64url')}`;
}

/**
 * Records Content-Security-Policy violations and uncaught page errors. The
 * `securitypolicyviolation` listener is installed before any page script
 * runs; console messages catch violations reported by the browser itself.
 */
export class PageWatch {
  readonly cspConsole: string[] = [];
  readonly pageErrors: string[] = [];

  constructor(private readonly page: Page) {
    page.on('console', (m) => {
      if (/content security policy/i.test(m.text())) this.cspConsole.push(m.text());
    });
    page.on('pageerror', (e) => this.pageErrors.push(e.message));
  }

  static async attach(page: Page): Promise<PageWatch> {
    await page.addInitScript(() => {
      const w = window as unknown as { __cspViolations: string[] };
      w.__cspViolations = [];
      document.addEventListener('securitypolicyviolation', (e) => {
        w.__cspViolations.push(`${e.violatedDirective} ${e.blockedURI}`);
      });
    });
    return new PageWatch(page);
  }

  /** No CSP violation and no uncaught error so far on the current document and every earlier one. */
  async assertClean(): Promise<void> {
    const inPage = await this.page
      .evaluate(() => (window as unknown as { __cspViolations?: string[] }).__cspViolations ?? [])
      .catch(() => [] as string[]);
    expect(this.cspConsole, 'CSP violations reported on the console').toEqual([]);
    expect(inPage, 'securitypolicyviolation events').toEqual([]);
    expect(this.pageErrors, 'uncaught page errors').toEqual([]);
  }
}

export async function newSession(browser: Browser): Promise<{ context: BrowserContext; page: Page; watch: PageWatch }> {
  const context = await browser.newContext({ baseURL: BASE_URL(), viewport: { width: 1440, height: 900 }, colorScheme: 'dark' });
  const page = await context.newPage();
  const watch = await PageWatch.attach(page);
  return { context, page, watch };
}

export async function signIn(page: Page, who: Credentials): Promise<void> {
  await page.goto('/login');
  await expect(page.getByRole('heading', { name: 'Sign in' })).toBeVisible();
  await page.getByLabel('Email').fill(who.email);
  await page.getByLabel('Password').fill(who.password);
  await page.getByRole('button', { name: 'Sign in' }).click();
  await expect(page.getByRole('heading', { name: 'Overview', level: 1 })).toBeVisible();
  await expect(page.getByTestId('tenant-name')).not.toHaveText('-');
}

export async function signOut(page: Page): Promise<void> {
  // Sign out lives in the account menu of the header.
  await page.getByRole('button', { name: /^Account: / }).click();
  await page.getByRole('menu', { name: 'Account' }).getByRole('menuitem', { name: 'Sign out' }).click();
  await expect(page.getByRole('heading', { name: 'Sign in' })).toBeVisible();
}

/** Every value in localStorage and sessionStorage, as `area:key=value`. */
export async function browserStorage(page: Page): Promise<string[]> {
  return page.evaluate(() => {
    const out: string[] = [];
    for (const [area, store] of [
      ['local', window.localStorage],
      ['session', window.sessionStorage],
    ] as const) {
      for (let i = 0; i < store.length; i += 1) {
        const key = store.key(i) as string;
        out.push(`${area}:${key}=${store.getItem(key) ?? ''}`);
      }
    }
    return out;
  });
}

/** A JWT (three base64url segments starting with a JSON header). */
export const JWT_PATTERN = /eyJ[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]*/;

export async function assertNoTokenInStorage(page: Page): Promise<void> {
  const entries = await browserStorage(page);
  for (const entry of entries) {
    expect(entry, 'a token in browser storage').not.toMatch(JWT_PATTERN);
    expect(entry.toLowerCase(), 'a token-named entry in browser storage').not.toMatch(/(access|refresh|id)_?token/);
  }
  const cookies = await page.evaluate(() => document.cookie);
  expect(cookies, 'a script-readable token cookie').not.toMatch(JWT_PATTERN);
}

/** The number shown on a dashboard stat tile (e.g. "Alerts"). */
export async function statValue(page: Page, label: string): Promise<number> {
  // An Overview KPI: <div><dt>label</dt><dd>value</dd><dd>sub</dd></div> inside a <dl>.
  const tile = page
    .locator('main dl > div')
    .filter({ has: page.locator('dt').getByText(label, { exact: true }) })
    .first();
  const text = (await tile.locator('dd').first().textContent()) ?? '';
  const n = Number(text.replace(/[^0-9]/g, ''));
  if (!Number.isFinite(n) || text.trim() === '') throw new Error(`stat ${label} has no number: ${JSON.stringify(text)}`);
  return n;
}

// ----------------------------------------------------------------------------- escalations

function escapeRegExp(text: string): string {
  return text.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

/** The escalation queue's table region (pages/escalations/QueueTable.tsx). */
export function escalationQueue(page: Page): Locator {
  return page.getByRole('region', { name: 'Escalation queue' });
}

/** The queue row whose title link is exactly `title`. */
export function escalationRow(page: Page, title: string): Locator {
  return escalationQueue(page).getByRole('row').filter({ has: page.getByRole('link', { name: title, exact: true }) });
}

/**
 * Open the escalation queue (waiting escalations, SLA order) and return the
 * row of `title`, loading further pages of the queue as needed.
 */
export async function findEscalation(page: Page, title: string): Promise<Locator> {
  await page.goto('/escalations');
  await expect(page.getByRole('heading', { name: 'Escalations', level: 1 })).toBeVisible();
  const row = escalationRow(page, title);
  const rows = escalationQueue(page).getByRole('row');
  // The header row plus at least one escalation.
  await expect.poll(() => rows.count()).toBeGreaterThan(1);
  for (let i = 0; i < 20 && (await row.count()) === 0; i += 1) {
    const more = page.getByRole('button', { name: 'Load more', exact: true });
    if ((await more.count()) === 0) break;
    const before = await rows.count();
    await more.click();
    await expect.poll(() => rows.count()).toBeGreaterThan(before);
  }
  await expect(row).toHaveCount(1);
  return row;
}

/** The decision form of an escalation's decision page (/escalations/:id). */
export function decisionForm(page: Page): Locator {
  return page.getByRole('form', { name: 'Your decision' });
}

/** A verdict radio of the decision form; its accessible name starts with the verdict, then its hint. */
export function verdictRadio(page: Page, label: 'True positive' | 'False positive' | 'Benign positive'): Locator {
  return decisionForm(page).getByRole('radio', { name: new RegExp(`^${escapeRegExp(label)}`) });
}

export async function screenshot(page: Page, name: string): Promise<void> {
  const dir = process.env.E2E_SCREENSHOTS;
  if (!dir) return;
  mkdirSync(dir, { recursive: true });
  // Let entrance transitions and pending fetches finish so the picture shows settled data.
  await page.waitForLoadState('networkidle').catch(() => undefined);
  await page.screenshot({ path: join(dir, `${name}.png`), animations: 'disabled' });
}

// ----------------------------------------------------------------------------- API (machine access)

export interface IngestItem {
  status: string;
  alert_id?: string;
}

export async function ingest(request: APIRequestContext, key: string, alerts: object[]): Promise<IngestItem[]> {
  const items: IngestItem[] = [];
  for (let i = 0; i < alerts.length; i += 50) {
    const r = await request.post(`${API}/ingest/alerts`, { data: alerts.slice(i, i + 50), headers: { 'X-API-Key': key } });
    expect(r.status(), await r.text()).toBe(202);
    items.push(...((await r.json()) as { items: IngestItem[] }).items);
  }
  return items;
}

export interface AlertState {
  id: string;
  status: string;
  disposition: string | null;
  title: string;
}

export async function getAlert(request: APIRequestContext, key: string, id: string): Promise<AlertState> {
  const r = await request.get(`${API}/alerts/${id}`, { headers: { 'X-API-Key': key } });
  expect(r.status(), await r.text()).toBe(200);
  return (await r.json()) as AlertState;
}

/** Poll the alert (through a `read` API key) until its status is one of `statuses`. */
export async function waitForAlert(
  request: APIRequestContext,
  key: string,
  id: string,
  statuses: string[],
  timeoutMs = 120_000,
): Promise<AlertState> {
  const deadline = Date.now() + timeoutMs;
  let last: AlertState | null = null;
  while (Date.now() < deadline) {
    last = await getAlert(request, key, id);
    if (statuses.includes(last.status)) return last;
    await new Promise((r) => setTimeout(r, 1_000));
  }
  throw new Error(`alert ${id} did not reach ${statuses.join('|')} (last: ${last?.status})`);
}
