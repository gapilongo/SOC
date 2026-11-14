// Usage: node case-shots.cjs <node_modules with playwright-core> <console URL> <output dir> [png dir]
//
// Takes the case page of the running console (`npm run dev` in src/lg_front is enough: no backend is
// needed) in light and dark at 1440 and 390 px. The API is answered here with the prototype's case
// (console-v2.html, `#case`) as the backend assembles it: the read model is read from the frontend's
// test fixture (src/lg_front/src/test/caseReadModels.ts), which is generated from
// tests/fixtures/case.py. The clock is held at the scenario's 10:04:12, so the deadline reads as in
// the prototype. It also runs axe (WCAG 2.2 A and AA) on each and fails on sideways overflow, a page
// error or an API call this file does not answer. WebP files go to the output dir (case-<theme>-<width>.webp);
// pass a png dir to get PNG copies as well.
const path = require('path');
const fs = require('fs');
const modules = path.resolve(process.argv[2]);
const { chromium } = require(path.join(modules, 'playwright-core'));
const { AxeBuilder } = require(path.join(modules, '@axe-core/playwright'));
const base = process.argv[3].replace(/\/+$/, '');
const outDir = path.resolve(process.argv[4]);
const pngDir = process.argv[5] ? path.resolve(process.argv[5]) : null;

// The read model: the JSON between `export const OPEN_CASE: CaseOut = ` and the next export of the fixture.
const fixture = fs.readFileSync(path.join(__dirname, '../../../../src/lg_front/src/test/caseReadModels.ts'), 'utf8');
const start = fixture.indexOf('{', fixture.indexOf('export const OPEN_CASE'));
const CASE = JSON.parse(fixture.slice(start, fixture.indexOf('\n};\n', start) + 2));
const NOW = new Date(CASE.generated_at);

const INES = CASE.owner.user_id;
const USER = {
  id: INES, tenant_id: CASE.tenant_id, email: CASE.owner.email, role: 'analyst', is_platform_admin: false, is_active: true,
  created_at: '2026-01-01T00:00:00Z', updated_at: '2026-01-01T00:00:00Z',
};
const ME = { kind: 'user', tenant_id: CASE.tenant_id, home_tenant_id: CASE.tenant_id, auth_method: 'password', role: 'analyst', user_id: INES, email: USER.email, is_platform_admin: false, tenant_name: 'Northwind Logistics' };
const ESCALATION = {
  id: CASE.id, tenant_id: CASE.tenant_id, alert_id: CASE.alert_id, level: 'L2', status: CASE.status, reason: 'no automatic policy applies', priority: 8,
  summary: { title: CASE.title }, related_alert_ids: CASE.alerts.map((a) => a.id).filter((id) => id !== CASE.alert_id), version: CASE.version,
  created_at: CASE.opened_at, updated_at: CASE.opened_at, sla_deadline: CASE.sla_deadline, claimed_at: CASE.owner.since,
  assigned_to: INES, assigned_to_email: USER.email, alert_severity: 'high', approved_actions: [],
  entities_preview: null, routing: null, ai_reason_source: null,
};
const DASHBOARD = {
  window_hours: 24, since: new Date(NOW - 86_400_000).toISOString(), generated_at: NOW.toISOString(), alerts_total: 1284,
  by_status: {}, by_severity: {}, by_disposition: {}, open_escalations: 28, runs_by_status: {}, queue_depth: 2,
  handled_without_human: 1131, needed_human: 153, unassigned_escalations: 22, unassigned_breaching: 2, overdue_escalations: 3,
  next_sla_deadline: CASE.sla_deadline, open_escalations_by_severity: {}, pending_approvals_total: 13, pending_approvals_by_risk: {},
  pending_approvals: 13, my_claimed: 3,
};

function answer(method, pathname) {
  if (pathname === '/auth/refresh') return { access_token: 'test-only-access', token_type: 'bearer', expires_in: 3600, user: USER };
  if (pathname === '/auth/me') return ME;
  if (pathname === `/cases/${CASE.id}`) return CASE;
  if (pathname === `/escalations/${CASE.id}`) return ESCALATION;
  if (pathname === '/dashboard/summary') return DASHBOARD;
  if (pathname === '/onboarding/status') return { dismissed: true, complete: true, steps: [] };
  return undefined;
}

(async () => {
  fs.mkdirSync(outDir, { recursive: true });
  if (pngDir) fs.mkdirSync(pngDir, { recursive: true });
  const browser = await chromium.launch();
  const enc = await (await browser.newContext()).newPage();
  const problems = [];
  for (const width of [1440, 390]) {
    for (const theme of ['light', 'dark']) {
      const name = `case-${theme}-${width}`;
      const ctx = await browser.newContext({ viewport: { width, height: width === 1440 ? 900 : 844 }, colorScheme: theme, deviceScaleFactor: 1, timezoneId: 'UTC', locale: 'en-GB' });
      await ctx.addInitScript((t) => window.localStorage.setItem('lg-sotf.theme', t), theme);
      const page = await ctx.newPage();
      await page.clock.setFixedTime(NOW);
      page.on('pageerror', (e) => problems.push(`${name}: page error ${e.message}`));
      await page.routeWebSocket(/\/api\/v1\/ws/, (ws) => ws.send(JSON.stringify({ type: 'hello' })));
      await page.route(/\/api\/v1\//, (route) => {
        const url = new URL(route.request().url());
        const pathname = url.pathname.replace(/^.*\/api\/v1/, '');
        const body = answer(route.request().method(), pathname);
        if (body === undefined) {
          problems.push(`${name}: unanswered ${route.request().method()} ${pathname}`);
          return route.fulfill({ status: 404, contentType: 'application/json', body: JSON.stringify({ error: { code: 'not_found', message: 'Not found.', request_id: 'shots' } }) });
        }
        return route.fulfill({ status: 200, contentType: 'application/json', body: JSON.stringify(body) });
      });
      page.on('console', (m) => { if (m.type() === 'error') problems.push(`${name}: console ${m.text()}`); });
      await page.goto(`${base}/cases/${CASE.id}`);
      await page.getByRole('heading', { name: CASE.title, level: 1 }).waitFor().catch(async (e) => {
        console.error(problems.join('\n'));
        console.error((await page.evaluate(() => document.body.innerText)).slice(0, 400));
        throw e;
      });
      await page.getByRole('region', { name: 'Your decision' }).waitFor();
      await page.evaluate(() => document.fonts.ready);
      await page.waitForTimeout(400);
      // The marks the end-to-end step looks for (src/lg_front/e2e/triage.spec.ts), so a change here is seen there.
      const marks = {
        'the alerts': page.getByRole('region', { name: 'Alerts in this case' }),
        'the linked alerts': page.getByRole('region', { name: 'Linked by the safety net' }),
        'the response': page.getByRole('region', { name: 'Response' }),
        'the timeline': page.getByRole('region', { name: 'Timeline' }),
        'what the case touches': page.getByRole('region', { name: 'What the case touches' }),
      };
      for (const [what, mark] of Object.entries(marks)) if (!(await mark.isVisible().catch(() => false))) problems.push(`${name}: missing ${what}`);
      const rows = await page.locator('tr[data-alert]').count();
      if (rows !== CASE.alerts.length) problems.push(`${name}: ${rows} alert rows, expected ${CASE.alerts.length}`);
      const over = await page.evaluate(() => document.documentElement.scrollWidth - document.documentElement.clientWidth);
      if (over > 0) problems.push(`${name}: sideways overflow ${over}px`);
      const axe = await new AxeBuilder({ page }).withTags(['wcag2a', 'wcag2aa', 'wcag21a', 'wcag21aa', 'wcag22aa']).analyze();
      for (const v of axe.violations) problems.push(`${name}: axe ${v.impact} ${v.id} (${v.nodes.slice(0, 3).map((n) => n.target.join(' ')).join('; ')})`);
      // The decision bar stays at the bottom of the window: make the window as tall as the page, so the picture has it at its end.
      const height = await page.evaluate(() => document.documentElement.scrollHeight);
      await page.setViewportSize({ width, height });
      await page.waitForTimeout(200);
      const png = await page.screenshot({ fullPage: true, animations: 'disabled' });
      if (pngDir) fs.writeFileSync(path.join(pngDir, `${name}.png`), png);
      const webp = await enc.evaluate(async (b64) => {
        const img = new Image();
        img.src = 'data:image/png;base64,' + b64;
        await img.decode();
        const c = document.createElement('canvas');
        c.width = img.naturalWidth; c.height = img.naturalHeight;
        c.getContext('2d').drawImage(img, 0, 0);
        return c.toDataURL('image/webp', 0.6).split(',')[1];
      }, png.toString('base64'));
      fs.writeFileSync(path.join(outDir, `${name}.webp`), Buffer.from(webp, 'base64'));
      console.log(`${name}: ok`);
      await ctx.close();
    }
  }
  await browser.close();
  if (problems.length) {
    console.error(problems.join('\n'));
    process.exit(1);
  }
})();
