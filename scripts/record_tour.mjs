#!/usr/bin/env node
// Records the narrated product tour shown in the README (docs/media/tour.mp4 and tour.gif).
//
//   scripts/e2e_ui_stack.sh --stack-only            # start the demo stack (offline stand-in model)
//   python3 scripts/demo/seed_demo.py --base-url http://127.0.0.1:18100 --credentials <file> --api-key-file <file>
//   TOUR_ENV_FILE=<stack.env printed above> node scripts/record_tour.mjs [out-dir]
//   scripts/make_tour_media.sh <out-dir>            # webm -> docs/media/tour.mp4 + tour.gif
//
// The tour needs alerts in the stack: seed the demo set first (second line), or use
// `scripts/e2e_ui_stack.sh --keep`, which leaves the suite's synthetic alerts in place.
//
// The tour signs in as the stack's bootstrap admin and walks console v2: the Overview, the work
// queue and a decision page, the Alerts list with one alert in its side panel and then on its
// full investigation page, Approvals, the command palette, Tenant settings and the Audit log, and
// ends on the Overview in the light theme. A caption bar explains each step. All data is
// synthetic. TOUR_MODEL_NOTE says which model wrote the verdict texts (default: the offline
// stand-in model). The admin password is read from the env file and never printed.
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
const MODEL_NOTE = process.env.TOUR_MODEL_NOTE ?? 'an offline stand-in model';

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
  // A link's name can go on with its count badge ("Approvals 5 waiting ...").
  const label = new RegExp(`^${name.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}(\\s|$)`);
  // The previous step's caption would otherwise sit on top of the next page.
  await clearCaption(page);
  await page.getByRole('navigation', { name: 'Main' }).getByRole('link', { name: label }).click();
  await page.waitForLoadState('networkidle').catch(() => undefined);
  await pause(700);
}

// The first-run callouts belong to a tenant that has not been set up; the tour shows one that has.
// They are hidden with a style, never removed: the app owns its DOM, and removing a node from
// under it breaks the next navigation.
async function hideFirstRun(page) {
  await page.evaluate(() => {
    if (window.__tourHider) return;
    const box = (label, marker) => {
      const hit = [...document.querySelectorAll('main button, main a')].find((e) => e.textContent.trim().startsWith(label));
      let el = hit;
      while (el && !el.textContent.includes(marker)) el = el.parentElement;
      while (el && el.parentElement && el.parentElement.tagName !== 'MAIN' && el.parentElement.innerText.trim() === el.innerText.trim()) el = el.parentElement;
      if (el && el.tagName !== 'MAIN' && el.style.display !== 'none') el.style.display = 'none';
    };
    // Re-applied for the whole visit: the Overview draws the callouts again each time it opens.
    window.__tourHider = setInterval(() => {
      box('Start setup', 'Finish setting up');
      box('Send sample alerts', 'Getting started:');
    }, 150);
  });
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
  await caption(page, 'LG-SOTF: a self-hosted AI SOC',
    'Alerts in; AI agents triage, correlate and analyse; people decide what is uncertain or dangerous. '
    + `This tour uses synthetic alerts, analysed by ${MODEL_NOTE}.`, 5200);
  await page.getByLabel('Email').fill(EMAIL);
  await page.getByLabel('Password').fill(password);
  await page.getByRole('button', { name: 'Sign in' }).click();
  await page.getByRole('heading', { name: 'Overview', level: 1 }).waitFor();
  await page.waitForLoadState('networkidle').catch(() => undefined);
  await hideFirstRun(page);

  await caption(page, 'Overview: your work first',
    'What you hold, the response actions you can approve, what nobody has claimed and the blind-audit samples '
    + 'waiting for a label. It updates live over a WebSocket.', 5400);
  await step('closed without a person', async () => {
    await page.mouse.move(900, 450);
    await page.mouse.wheel(0, 420);
    await pause(500);
    await caption(page, 'Closed without a person, and how that is checked',
      'The Overview accounts for every alert: how many were closed without a person, how many reached one, '
      + 'and what the blind audit and the safety net found. A figure that is not measured yet says so.', 6000);
    await page.mouse.wheel(0, -2000);
  });

  await step('queue', async () => {
    await nav(page, 'Queue');
    await caption(page, 'The work queue',
      'What needs a person, soonest deadline first, with a preview beside the list. '
      + 'J and K move, Space previews, C claims, Enter opens.', 5000);
    // The row's link is for assistive technology and is not drawn; the tour follows it directly.
    const links = page.locator('main a[href*="/escalations/"]');
    const pick = links.filter({ hasText: /S3 bucket|Impossible travel/ }).first();
    const href = await ((await pick.count()) ? pick : links.first()).getAttribute('href');
    await clearCaption(page);
    await page.goto(href);
    await hideFirstRun(page);
    await page.getByRole('heading', { name: 'Your decision' }).waitFor();
    await page.waitForLoadState('networkidle').catch(() => undefined);
    await caption(page, 'The decision page',
      'What the agents found, what points to malicious and what points to benign, next to the decision form. '
      + 'The verdict, the notes and the feedback on the triage are audited.', 5600);
  });

  await step('alerts', async () => {
    await nav(page, 'Alerts');
    await page.getByText(/^Awaiting approval/).first().click();
    await page.waitForLoadState('networkidle').catch(() => undefined);
    await caption(page, 'Alerts',
      'Every alert by where it stands: needs an analyst, awaiting approval, processing, failed, closed today.', 3800);
    // Row 0 is the header row. The last row is the most severe alert of the demo set.
    await page.getByRole('grid', { name: 'Alerts' }).getByRole('row').last().click();
    await page.getByRole('complementary').first().waitFor();
    await page.waitForLoadState('networkidle').catch(() => undefined);
    await pause(500);
    await caption(page, 'One alert, in a side panel',
      'The verdict in the model\'s words, the response it proposes and what the verdict is based on. '
      + 'The list stays in view.', 5000);
    await clearCaption(page);
    await page.getByRole('link', { name: 'Open full page' }).click();
    await page.waitForLoadState('networkidle').catch(() => undefined);
    await pause(600);
    await caption(page, 'The investigation view',
      'One page per alert: what the AI concluded, why it may not close this alert on its own, '
      + 'the entities and the alert as its source sent it.', 5600);
    await page.mouse.move(700, 500);
    await page.mouse.wheel(0, 520);
    await pause(500);
    await caption(page, 'Claims beside facts, and what is not established',
      'Each claim of the model sits beside the fact a tool returned. The page also says what was checked and '
      + 'found nothing, and what was not checked at all.', 6000);
    await page.mouse.wheel(0, -2000);
  });

  await step('approvals', async () => {
    await nav(page, 'Approvals');
    await caption(page, 'Approvals',
      'Proposed responses wait for a person, each with its target, blast radius, whether it can be rolled back '
      + 'and the guardrail result, checked again right now.', 5200);
  });

  await step('command palette', async () => {
    await clearCaption(page);
    await page.keyboard.press('Control+k');
    await pause(500);
    await page.keyboard.type('psexec', { delay: 90 });
    await pause(700);
    await caption(page, 'Search and commands',
      'Ctrl+K finds pages, alerts by title with their tenant, and commands. '
      + 'A command that changes something only opens the page where it is confirmed.', 4600);
    await page.keyboard.press('Escape');
    await pause(300);
  });

  await step('settings', async () => {
    await nav(page, 'Tenant settings');
    await caption(page, 'Tenant settings',
      'Per tenant: whether the AI may close alerts on its own, the autonomy policy for response actions and the '
      + 'language model, including a model you host yourself.', 4600);
  });

  await step('audit', async () => {
    await nav(page, 'Audit log');
    await caption(page, 'Audit log',
      'A hash-chained, per-tenant record of who did what. Each change commits together with its entry.', 4000);
  });

  await step('back to the overview, light theme', async () => {
    await nav(page, 'Overview');
    await hideFirstRun(page);
    await page.mouse.wheel(0, -2000);
    await pause(800);
    await page.getByRole('banner').getByRole('button', { name: /^Theme: / }).click();
    await caption(page, 'Dark, light or system theme',
      'LG-SOTF is multi-tenant and runs on your own infrastructure, with people deciding. '
      + 'See the README to run it with Docker Compose.', 5200);
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
