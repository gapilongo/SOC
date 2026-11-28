// Usage: node overview-shots.cjs <node_modules with playwright-core> <console URL> <output dir> <before|after> [png dir]
//
// Takes the Overview of the running console (`npm run dev` in src/lg_front is enough: no backend is
// needed) in light and dark at 1440 and 390 px, with the API answered here from one invented
// scenario, the same one as the prototype (console-v2.html, `#overview`), so the two can be laid
// side by side. It also runs axe (WCAG 2.2 A and AA) on each and fails on sideways overflow, a page
// error or an API call this file does not answer. WebP files go to the output dir; pass a png dir
// to get PNG copies as well.
const path = require('path');
const fs = require('fs');
const modules = path.resolve(process.argv[2]);
const { chromium } = require(path.join(modules, 'playwright-core'));
const { AxeBuilder } = require(path.join(modules, '@axe-core/playwright'));
const base = process.argv[3].replace(/\/+$/, '');
const outDir = path.resolve(process.argv[4]);
const label = process.argv[5] || 'after';
const pngDir = process.argv[6] ? path.resolve(process.argv[6]) : null;

const NOW = Date.now();
const inMinutes = (m) => new Date(NOW + m * 60_000).toISOString();
const USER = {
  id: 'u-ines', tenant_id: 'northwind', email: 'ines.moreau@northwind.example', role: 'admin', is_platform_admin: false, is_active: true,
  created_at: '2026-01-01T00:00:00Z', updated_at: '2026-01-01T00:00:00Z',
};
const ME = { kind: 'user', tenant_id: 'northwind', home_tenant_id: 'northwind', auth_method: 'password', role: 'admin', user_id: 'u-ines', email: USER.email, is_platform_admin: false, tenant_name: 'Northwind Logistics' };

const WINDOWS = { 24: [1284, 1131, 153], 168: [8412, 7390, 1022], 720: [35170, 31044, 4126] };
function dashboard(hours) {
  const [total, handled, needed] = WINDOWS[hours] || WINDOWS[24];
  return {
    window_hours: hours, since: inMinutes(-60 * hours), generated_at: new Date().toISOString(),
    alerts_total: total,
    by_status: { processing: 3, waiting_human: 24, waiting_approval: 4, closed: total - 32, failed: 1 },
    by_severity: { critical: 6, high: 148, medium: 512, low: 540, info: 78 },
    by_disposition: { malicious: 41, benign: total - 153 - 41, inconclusive: 112, undecided: 41 },
    mtta_s: 840, mttr_s: 372, acknowledged: 125, resolved: total - 32, open_escalations: 28,
    runs_by_status: { queued: 2, running: 3, waiting: 28 }, queue_depth: 2,
    llm_cost_usd: 18.42, llm_tokens: 6_184_300, llm_model: 'deep-model-example',
    handled_without_human: handled, needed_human: needed, handled_without_human_rate: handled / (handled + needed),
    // The split of the closes without a person (PRD-2.9a): the four kinds add up to `handled`.
    closed_without_human_by: { ai_evidence: Math.round(handled * 0.34), ai_audit: Math.round(handled * 0.52), suppression_rule: Math.round(handled * 0.1), cached_verdict: handled - Math.round(handled * 0.34) - Math.round(handled * 0.52) - Math.round(handled * 0.1), other: 0 },
    analyst_hours_saved: (handled * 15) / 60, minutes_per_alert: 15,
    unassigned_escalations: 22, unassigned_breaching: 2, overdue_escalations: 3, next_sla_deadline: inMinutes(4),
    open_escalations_by_severity: { critical: 2, high: 11, medium: 12, low: 3 },
    pending_approvals_total: 13, pending_approvals_by_risk: { high: 4, medium: 6, low: 3 }, pending_approvals: 13, my_claimed: 3,
  };
}

function escalation(n, title, severity, deadlineMin, owner, entities) {
  return {
    id: `esc-${n}`, tenant_id: 'northwind', alert_id: `alr-4821${n}`, level: n % 2 ? 'L2' : 'L1', status: owner ? 'claimed' : 'open', reason: 'needs_decision', priority: 1,
    summary: { title }, version: 1, created_at: inMinutes(-55), updated_at: inMinutes(-5), sla_deadline: inMinutes(deadlineMin),
    assigned_to: owner ? owner.id : null, assigned_to_email: owner ? owner.email : null, alert_severity: severity,
    entities_preview: { items: entities.map(([kind, value]) => ({ kind, value })), counts: Object.fromEntries(entities.map(([kind]) => [kind, 1])) },
    routing: null, ai_reason_source: null,
  };
}
const INES = { id: 'u-ines', email: USER.email };
const ESCALATIONS = [
  escalation(1, 'Password spray with one success against the VPN gateway', 'high', -12, null, [['user', 'p.lindqvist'], ['ip', '185.220.101.4']]),
  escalation(2, 'Mailbox rule forwards invoices to an outside address', 'medium', -3, null, [['user', 'a.keller']]),
  escalation(3, 'LSASS memory read on WS-FIN-0142', 'critical', 4, INES, [['host', 'WS-FIN-0142']]),
  escalation(4, 'Encoded PowerShell launched by Microsoft Word', 'high', 11, INES, [['host', 'WS-FIN-0142'], ['user', 'm.okafor']]),
  escalation(5, 'New service installed on a domain controller', 'high', 19, { id: 'u-2', email: 'n.haddad@northwind.example' }, [['host', 'DC-02']]),
];

const AUDIT = {
  from: new Date(NOW - 29 * 86_400_000).toISOString().slice(0, 10), to: new Date(NOW).toISOString().slice(0, 10), generated_at: new Date().toISOString(),
  estimate: {
    status: 'incomplete', complete: false, summary: '0.6% (stratified over 4 run(s); n=180; 95% CI 0.0% to 3.1%)', method: 'stratified', frame_size: 9870, estimated_frame: 9870,
    effective_n: 180, sampled: 200, labelled: 188, pending: 12, malicious: 1, benign: 179, unsure: 8, min_samples: 30,
    false_negative_rate: { rate: 0.0056, n: 180, ci_low: 0.0001, ci_high: 0.031 }, agreement_rate: { rate: 0.994, n: 180, ci_low: 0.969, ci_high: 0.999 },
    estimated_missed: 55, estimated_missed_low: 1, estimated_missed_high: 306, worst_case_rate: 0.105, worst_case_rate_high: 0.155, worst_case_missed: 1036, worst_case_missed_high: 1530,
  },
  strata: [], runs: [], uncovered: [], labels_by_organisation: [], notes: [],
};

function answer(method, pathname, query) {
  if (pathname === '/auth/refresh') return { access_token: 'test-only-access', token_type: 'bearer', expires_in: 3600, user: USER };
  if (pathname === '/auth/me') return ME;
  if (pathname === '/dashboard/summary') return dashboard(Number(query.get('window_hours') || 24));
  if (pathname === '/escalations') {
    const mine = query.get('assigned_to') === 'me';
    const none = query.get('assigned_to') === 'none';
    const rows = ESCALATIONS.filter((e) => (mine ? e.assigned_to === 'u-ines' : none ? e.assigned_to === null : true));
    return { items: rows.slice(0, Number(query.get('limit') || 50)), next_cursor: null };
  }
  if (pathname === '/blind-audit/items') return { items: Array.from({ length: 12 }, (_, i) => ({ id: `ba-${i}` })), next_cursor: null };
  if (pathname === '/reports/blind-audit') return AUDIT;
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
      const name = `overview-${label}-${theme}-${width}`;
      const ctx = await browser.newContext({ viewport: { width, height: width === 1440 ? 900 : 844 }, colorScheme: theme, deviceScaleFactor: 1 });
      await ctx.addInitScript((t) => window.localStorage.setItem('lg-sotf.theme', t), theme);
      const page = await ctx.newPage();
      page.on('pageerror', (e) => problems.push(`${name}: page error ${e.message}`));
      await page.routeWebSocket(/\/api\/v1\/ws/, (ws) => ws.send(JSON.stringify({ type: 'hello' })));
      await page.route(/\/api\/v1\//, (route) => {
        const url = new URL(route.request().url());
        const pathname = url.pathname.replace(/^.*\/api\/v1/, '');
        const body = answer(route.request().method(), pathname, url.searchParams);
        if (body === undefined) {
          problems.push(`${name}: unanswered ${route.request().method()} ${pathname}`);
          return route.fulfill({ status: 404, contentType: 'application/json', body: JSON.stringify({ error: { code: 'not_found', message: 'Not found.', request_id: 'shots' } }) });
        }
        return route.fulfill({ status: 200, contentType: 'application/json', body: JSON.stringify(body) });
      });
      page.on('console', (m) => { if (m.type() === 'error') problems.push(`${name}: console ${m.text()}`); });
      await page.goto(`${base}/`);
      await page.getByRole('heading', { name: 'Overview', level: 1 }).waitFor().catch(async (e) => {
        console.error(problems.join('\n'));
        console.error((await page.evaluate(() => document.body.innerText)).slice(0, 400));
        throw e;
      });
      await page.getByText(/^Loading/).first().waitFor({ state: 'detached' }).catch(() => undefined);
      await page.evaluate(() => document.fonts.ready);
      await page.waitForTimeout(400);
      if (label === 'after') {
        // The marks the end-to-end step looks for (src/lg_front/e2e/triage.spec.ts), so a change here is seen there.
        const needs = page.getByRole('region', { name: 'Needs you now' });
        const closed = page.getByRole('region', { name: 'Closed without a person' });
        const verified = page.getByRole('region', { name: "How the AI's closes are verified" });
        const marks = {
          ...Object.fromEntries(['Open my queue', 'Open approvals', 'Open the queue', 'Label them'].map((a) => [a, needs.getByRole('link', { name: a })])),
          'closes split by who closed them': closed.locator('tr[data-row="closed-by-ai_audit"]'),
          'blind audit': verified.getByRole('heading', { name: 'Blind audit, last 30 days' }),
          'next deadlines': page.getByRole('region', { name: 'Next deadlines' }),
          'platform health': page.getByRole('region', { name: 'Platform health' }),
        };
        if (width === 1440) marks['reached a person'] = closed.getByRole('row').filter({ hasText: 'Reached a person' });
        for (const [what, mark] of Object.entries(marks)) if (!(await mark.isVisible().catch(() => false))) problems.push(`${name}: missing ${what}`);
        if ((await verified.getByText('Not measured yet').count()) !== 2) problems.push(`${name}: expected two checks not measured yet`);
        if ((await page.getByTestId('overview-alerts-received').textContent()) !== '1,284') problems.push(`${name}: alerts received is not 1,284`);
      }
      const over = await page.evaluate(() => document.documentElement.scrollWidth - document.documentElement.clientWidth);
      if (over > 0) problems.push(`${name}: sideways overflow ${over}px`);
      const axe = await new AxeBuilder({ page }).withTags(['wcag2a', 'wcag2aa', 'wcag21a', 'wcag21aa', 'wcag22aa']).analyze();
      for (const v of axe.violations) problems.push(`${name}: axe ${v.impact} ${v.id} (${v.nodes.slice(0, 3).map((n) => n.target.join(' ')).join('; ')})`);
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
