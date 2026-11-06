#!/usr/bin/env node
// Records the narrated product tour shown in the README (docs/media/tour.mp4 and tour.gif).
//
//   scripts/e2e_ui_stack.sh --stack-only            # start the demo stack (offline stand-in model)
//   TOUR_ENV_FILE=<stack.env printed above> node scripts/record_tour.mjs [out-dir]
//   scripts/make_tour_media.sh <out-dir>            # webm -> docs/media/tour.mp4 + tour.gif
//
// The tour signs in as the stack's bootstrap admin, sends the onboarding sample
// alerts, and walks the main pages. A caption bar explains each step. All data is
// synthetic, and the verdict texts come from the deterministic stand-in model, not
// from a real LLM. The admin password is read from the env file and never printed.
import { createRequire } from 'node:module';
import { mkdirSync, readFileSync, readdirSync, renameSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const require = createRequire(join(ROOT, 'src/lg_front/package.json'));
const { chromium } = require('@playwright/test');

const BASE_URL = process.env.TOUR_BASE_URL ?? 'http://localhost:13000';
const EMAIL = process.env.TOUR_ADMIN_EMAIL ?? 'admin@e2e.example.com';
const OUT = resolve(process.argv[2] ?? 'tour-out');
const SIZE = { width: 1440, height: 900 };

function adminPassword() {
  if (process.env.TOUR_ADMIN_PASSWORD) return process.env.TOUR_ADMIN_PASSWORD;
  const file = process.env.TOUR_ENV_FILE;
  if (!file) throw new Error('set TOUR_ENV_FILE to the stack env file (or TOUR_ADMIN_PASSWORD)');
  const line = readFileSync(file, 'utf8').split('\n').find((l) => l.startsWith('LG_SOTF_AUTH__BOOTSTRAP_ADMIN_PASSWORD='));
  if (!line) throw new Error('no LG_SOTF_AUTH__BOOTSTRAP_ADMIN_PASSWORD in the env file');
  return line.slice(line.indexOf('=') + 1);
}

const pause = (ms) => new Promise((r) => setTimeout(r, ms));

// Caption bar drawn on top of the app. Built with DOM APIs (no inline script or
// HTML strings), so the page's Content-Security-Policy stays untouched.
async function caption(page, title, text, ms = 4200) {
  await page.evaluate(
    ([t, b]) => {
      let bar = document.getElementById('tour-caption');
      if (!bar) {
        bar = document.createElement('div');
        bar.id = 'tour-caption';
        Object.assign(bar.style, {
          position: 'fixed', left: '50%', bottom: '28px', transform: 'translateX(-50%)', zIndex: '2147483647',
          maxWidth: '1100px', width: 'calc(100% - 120px)', padding: '16px 22px', borderRadius: '14px',
          background: 'rgba(8, 47, 73, 0.94)', border: '1px solid rgba(56, 189, 248, 0.7)',
          boxShadow: '0 10px 40px rgba(0,0,0,0.55)', color: '#f0f9ff',
          fontFamily: 'Inter, ui-sans-serif, system-ui, sans-serif', pointerEvents: 'none',
        });
        const h = document.createElement('div');
        h.id = 'tour-caption-title';
        Object.assign(h.style, { fontSize: '22px', fontWeight: '700', marginBottom: '4px', color: '#7dd3fc' });
        const p = document.createElement('div');
        p.id = 'tour-caption-text';
        Object.assign(p.style, { fontSize: '18px', lineHeight: '1.45' });
        bar.append(h, p);
        document.body.append(bar);
      }
      document.getElementById('tour-caption-title').textContent = t;
      document.getElementById('tour-caption-text').textContent = b;
    },
    [title, text],
  );
  await pause(ms);
}

async function clearCaption(page) {
  await page.evaluate(() => document.getElementById('tour-caption')?.remove());
}

async function nav(page, name) {
  await page.getByRole('navigation', { name: 'Main' }).getByRole('link', { name, exact: true }).click();
  await page.waitForLoadState('networkidle').catch(() => undefined);
  await pause(700);
}

// A step that cannot find what it looks for is skipped: the tour keeps going.
async function step(label, fn) {
  try {
    await fn();
  } catch (err) {
    console.error(`tour: skipped "${label}": ${String(err).split('\n')[0]}`);
  }
}

async function main() {
  mkdirSync(OUT, { recursive: true });
  const password = adminPassword();
  // TOUR_CHROMIUM: a Chromium binary, when Playwright's own download is unavailable for this OS.
  const browser = await chromium.launch(process.env.TOUR_CHROMIUM ? { executablePath: process.env.TOUR_CHROMIUM } : {});
  const context = await browser.newContext({
    baseURL: BASE_URL, viewport: SIZE, colorScheme: 'dark', recordVideo: { dir: OUT, size: SIZE },
  });
  const page = await context.newPage();
  page.setDefaultTimeout(15_000);

  await page.goto('/login');
  await caption(page, 'LG-SOTF: an AI-assisted SOC',
    'Alerts in, triage, correlation and analysis by AI agents, decisions by people. '
    + 'This tour uses synthetic alerts and an offline stand-in model.', 5200);
  await page.getByLabel('Email').fill(EMAIL);
  await page.getByLabel('Password').fill(password);
  await page.getByRole('button', { name: 'Sign in' }).click();
  await page.getByRole('heading', { name: 'Dashboard', level: 1 }).waitFor();

  await caption(page, 'Live dashboard',
    'Alerts, open escalations, queue depth, time to acknowledge and resolve, and LLM cost. '
    + 'It updates live over a WebSocket.', 4600);

  await step('send sample alerts', async () => {
    await nav(page, 'Getting started');
    await caption(page, 'Getting started',
      'A checklist for a new tenant: connect a source, send alerts, set the autonomy policy, add analysts.', 3800);
    const send = page.getByRole('button', { name: /^Send sample alerts/ }).first();
    await send.scrollIntoViewIfNeeded();
    await send.click();
    await caption(page, 'Sample alerts sent',
      'Each alert goes through the workflow: ingest, triage, correlation, analysis, then a decision '
      + '(close, escalate to a human, or plan a response).', 5200);
  });

  await step('alerts', async () => {
    await nav(page, 'Alerts');
    await pause(2500);
    await page.reload();
    await page.waitForLoadState('networkidle').catch(() => undefined);
    await caption(page, 'Alerts',
      'Every ingested alert with its severity, status and verdict. Filter by severity, status or text.', 4200);
    // Row 0 is the header row.
    await page.getByRole('grid', { name: 'Alerts' }).getByRole('row').nth(1).click();
    await page.getByRole('dialog').first().waitFor();
    await pause(900);
    await caption(page, 'One alert, end to end',
      'The verdict, the entities found (hosts, users, IPs) and the workflow timeline: '
      + 'what each agent did and why.', 5600);
    await page.keyboard.press('Escape');
    await pause(500);
  });

  await step('escalations', async () => {
    await nav(page, 'Escalations');
    await caption(page, 'Escalations',
      'What the AI cannot close safely goes to a person. Analysts claim an escalation, '
      + 'review the evidence and decide. Every decision is audited.', 5200);
  });

  await step('actions', async () => {
    await nav(page, 'Actions and approvals');
    await caption(page, 'Actions and approvals',
      'Proposed responses (block an IP, disable a user, isolate a host) wait for approval '
      + 'according to the tenant autonomy policy. Executed actions are verified and can be rolled back.', 5600);
  });

  await step('integrations', async () => {
    await nav(page, 'Integrations');
    await caption(page, 'Integrations',
      'Notifications (Slack, Teams, email, webhooks), ticketing, and direct response '
      + 'through Microsoft Defender and Entra.', 4200);
  });

  await step('settings', async () => {
    await nav(page, 'Tenant settings');
    await caption(page, 'Tenant settings',
      'Per-tenant routing thresholds, autonomy policy and the LLM provider, '
      + 'including self-hosted models for data that must stay on premises.', 4600);
  });

  await step('audit', async () => {
    await nav(page, 'Audit log');
    await caption(page, 'Audit log',
      'A hash-chained, per-tenant record of who did what. Each change commits together with its entry.', 4600);
  });

  await step('usage', async () => {
    await nav(page, 'LLM usage');
    await caption(page, 'LLM usage',
      'Tokens and cost per agent and model, so spend is visible per tenant.', 3800);
  });

  await step('back to dashboard', async () => {
    await nav(page, 'Dashboard');
    await caption(page, 'LG-SOTF',
      'Multi-tenant, self-hostable, human in the loop. See the README to run it with Docker Compose.', 5200);
  });
  await clearCaption(page);
  await pause(600);

  const video = page.video();
  await context.close();
  await browser.close();
  const src = await video.path();
  const dest = join(OUT, 'tour.webm');
  renameSync(src, dest);
  for (const f of readdirSync(OUT)) if (f.endsWith('.webm') && f !== 'tour.webm') console.error(`tour: extra video ${f}`);
  console.log(dest);
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
