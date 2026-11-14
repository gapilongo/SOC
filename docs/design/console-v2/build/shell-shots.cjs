// Screenshots of the built shell (PRD-2.12), for comparison with ../screens/shell-*.webp.
//
// Usage: node shell-shots.cjs <node_modules with @playwright/test> <base url of `npm run dev`> <output dir> <before|after>
//
// The API is answered by this script (no backend): a platform admin of an MSSP with six tenants, in the
// prototype's scenario. It checks each picture's page for sideways overflow and prints what it finds.
const path = require('path');
const fs = require('fs');
const [nm, base, outDir, label = 'after'] = process.argv.slice(2);
const { chromium } = require(path.join(path.resolve(nm), '@playwright/test'));

const NOW = Date.now();
const iso = (ms) => new Date(NOW + ms).toISOString();
const TENANTS = [
  ['brightwater', 'Brightwater SOC', 0],
  ['northwind-logistics', 'Northwind Logistics', 5],
  ['alpenglow-clinics', 'Alpenglow Clinics', 6],
  ['maritima-ferries', 'Maritima Ferries', 5],
  ['baltic-tool-die', 'Baltic Tool & Die', 4],
  ['helio-energy', 'Helio Energy Cooperative', 4],
  ['lindqvist-legal', 'Lindqvist Legal', 4],
];
const user = {
  id: 'u-ines',
  tenant_id: 'brightwater',
  email: 'ines.moreau@brightwater.example',
  role: 'admin',
  is_platform_admin: true,
  is_active: true,
  created_at: iso(-9e9),
  updated_at: iso(-9e9),
};
const tenantRow = ([id, name, open]) => ({
  id,
  name,
  status: 'active',
  created_at: iso(-9e9),
  updated_at: iso(-9e9),
  quotas: { max_alerts_per_day: null, max_sources: null, max_users: null },
  quota_usage: { max_alerts_per_day: { used: 0, limit: null }, max_sources: { used: 0, limit: null }, max_users: { used: 1, limit: null } },
  stats: { alerts_24h: 40, alerts_today: 12, last_ingest_at: iso(-6e4), open_escalations: open, overdue_escalations: 0, sla_breaches_24h: 0, llm_cost_mtd_usd: '12.40', llm_tokens_mtd: 1200000, users: 4, sources: 2 },
});
const dashboard = {
  window_hours: 24,
  since: iso(-864e5),
  generated_at: iso(0),
  alerts_total: 412,
  acknowledged: 31,
  resolved: 371,
  handled_without_human: 371,
  handled_without_human_rate: 0.9,
  needed_human: 41,
  analyst_hours_saved: 92.7,
  minutes_per_alert: 15,
  by_status: { new: 3, processing: 7, escalated: 28, closed: 374 },
  by_severity: { critical: 2, high: 24, medium: 141, low: 201, info: 44 },
  by_disposition: { benign: 300, false_positive: 61, true_positive: 10 },
  runs_by_status: { completed: 380, running: 7 },
  open_escalations: 28,
  open_escalations_by_severity: { critical: 2, high: 9, medium: 15, low: 2 },
  overdue_escalations: 0,
  unassigned_escalations: 22,
  unassigned_breaching: 2,
  my_claimed: 3,
  next_sla_deadline: iso(4 * 6e4 + 12e3),
  pending_approvals: 13,
  pending_approvals_total: 13,
  pending_approvals_by_risk: { low: 4, medium: 6, high: 3 },
  queue_depth: 7,
  mtta_s: 312,
  mttr_s: 1840,
  llm_cost_usd: '4.12',
  llm_tokens: 1840000,
  llm_model: 'synthetic',
};
const alert = (id, title, severity) => ({
  id,
  tenant_id: 'brightwater',
  title,
  severity,
  status: 'escalated',
  disposition: null,
  source_id: 'src-1',
  source_name: 'Wazuh manager',
  source_alert_id: id,
  occurred_at: iso(-20 * 6e4),
  ingested_at: iso(-19 * 6e4),
  updated_at: iso(-10 * 6e4),
  closed_at: null,
  entities_preview: [],
  case_key: null,
  category: null,
  confidence: null,
  fingerprint: id,
  priority: 2,
  summary: null,
  threat_score: null,
  assigned_to: null,
  hidden_for_blind_audit: false,
});
const ALERTS = [
  alert('a-48213', 'Encoded PowerShell launched by Microsoft Word on WS-FIN-0142', 'high'),
  alert('a-48219', 'LSASS memory read by rundll32 on WS-FIN-0142', 'critical'),
];
const source = (id, name, health, last_error) => ({
  id,
  tenant_id: 'brightwater',
  name,
  type: 'wazuh',
  enabled: true,
  health,
  last_error,
  consecutive_failures: last_error ? 6 : 0,
  last_polled_at: iso(-40 * 6e4),
  next_poll_at: iso(6e4),
  poll_interval_s: 60,
  cursor_watermark: null,
  has_secret: true,
  config: {},
  created_at: iso(-9e9),
  updated_at: iso(-9e9),
});

const escalation = (n, title, severity, minutes, mine) => ({
  id: `esc-${n}`,
  tenant_id: 'brightwater',
  alert_id: `a-4821${n}`,
  level: 'L1',
  status: mine ? 'claimed' : 'open',
  reason: 'needs_decision',
  priority: 1,
  summary: { title },
  version: 1,
  created_at: iso(-55 * 6e4),
  updated_at: iso(-5 * 6e4),
  sla_deadline: iso(minutes * 6e4),
  assigned_to: mine ? user.id : null,
  assigned_to_email: mine ? user.email : null,
  alert_severity: severity,
  entities_preview: { items: [{ kind: 'host', value: 'WS-FIN-0142' }], counts: { host: 1 } },
  routing: null,
  ai_reason_source: null,
});
const ESCALATIONS = [
  escalation(1, 'Password spray with one success against the VPN gateway', 'high', 9, false),
  escalation(3, 'LSASS memory read on WS-FIN-0142', 'critical', 4, true),
  escalation(4, 'Encoded PowerShell launched by Microsoft Word', 'high', 11, true),
];
const AUDIT = {
  from: iso(-29 * 864e5).slice(0, 10),
  to: iso(0).slice(0, 10),
  generated_at: iso(0),
  estimate: {
    status: 'incomplete',
    complete: false,
    summary: '0.6% (stratified over 4 run(s); n=180; 95% CI 0.0% to 3.1%)',
    method: 'stratified',
    frame_size: 9870,
    estimated_frame: 9870,
    effective_n: 180,
    sampled: 200,
    labelled: 188,
    pending: 12,
    malicious: 1,
    benign: 179,
    unsure: 8,
    min_samples: 30,
    false_negative_rate: { rate: 0.0056, n: 180, ci_low: 0.0001, ci_high: 0.031 },
    agreement_rate: { rate: 0.994, n: 180, ci_low: 0.969, ci_high: 0.999 },
    estimated_missed: 55,
    estimated_missed_low: 1,
    estimated_missed_high: 306,
    worst_case_rate: 0.105,
    worst_case_rate_high: 0.155,
    worst_case_missed: 1036,
    worst_case_missed_high: 1530,
  },
  strata: [],
  runs: [],
  uncovered: [],
  labels_by_organisation: [],
  notes: [],
};

function answer(method, url, tenantHeader) {
  const p = url.pathname.replace(/^\/api\/v1/, '');
  const tenant = TENANTS.find((t) => t[0] === (tenantHeader || 'brightwater')) || [tenantHeader, tenantHeader, 0];
  if (p === '/auth/refresh') return { access_token: 'shots', token_type: 'bearer', expires_in: 3600, user };
  if (p === '/auth/me') return { kind: 'user', tenant_id: tenant[0], home_tenant_id: 'brightwater', tenant_name: tenant[1], auth_method: 'password', role: 'admin', user_id: user.id, email: user.email, is_platform_admin: true };
  if (p === '/dashboard/summary') return dashboard;
  if (p === '/platform/tenants') return TENANTS.map(tenantRow);
  if (p === '/sources') return [source('src-1', 'Wazuh manager', 'failing', 'connection refused'), source('src-2', 'Microsoft Sentinel', 'healthy', null)];
  if (p === '/alerts') {
    const q = (url.searchParams.get('q') || '').toLowerCase();
    return { items: ALERTS.filter((a) => a.title.toLowerCase().includes(q)), next_cursor: null };
  }
  if (p === '/alerts/counts') return { by_status: {}, closed: 0 };
  if (p === '/onboarding/status') return { dismissed: label === 'after', complete: true, steps: [] };
  // The first-run setup is done in the after pictures, as in the prototype's scenario.
  if (p === '/onboarding/setup' && label === 'after') return { completed: true, tenant_id: 'brightwater', tenant_name: 'Brightwater SOC' };
  if (p === '/escalations') {
    const who = url.searchParams.get('assigned_to');
    return { items: ESCALATIONS.filter((e) => (who === 'me' ? e.assigned_to : who === 'none' ? !e.assigned_to : true)), next_cursor: null };
  }
  if (p === '/blind-audit/items') return { items: Array.from({ length: 12 }, (_, i) => ({ id: `ba-${i}` })), next_cursor: null };
  if (p === '/reports/blind-audit') return AUDIT;
  if (/^\/(actions|audit|pov\/runs)$/.test(p)) return { items: [], next_cursor: null };
  if (p === '/escalations/groups') return { groups: [] };
  return method === 'GET' ? [] : {};
}

async function open(browser, width, theme, route, brand) {
  const ctx = await browser.newContext({ viewport: { width, height: width === 1440 ? 900 : 844 }, colorScheme: theme, deviceScaleFactor: 1 });
  // Before PRD-2.12 the default theme was dark whatever the system said; since then it follows the system.
  if (label === 'before') await ctx.addInitScript((t) => window.localStorage.setItem('lg-sotf.theme', t), theme);
  const page = await ctx.newPage();
  const problems = [];
  page.on('pageerror', (e) => problems.push(`pageerror ${e.message}`));
  await page.routeWebSocket(/\/api\/v1\/ws/, (ws) => ws.send(JSON.stringify({ type: 'hello' })));
  if (brand) await page.route(/\/config\.js$/, (r) => r.fulfill({ contentType: 'text/javascript', body: `window.__LG_SOTF_CONFIG__ = ${JSON.stringify({ brand })};` }));
  await page.route(/\/api\/v1\//, (r) => {
    const req = r.request();
    return r.fulfill({ json: answer(req.method(), new URL(req.url()), req.headers()['x-tenant-id']) });
  });
  await page.goto(base + route);
  await page
    .getByRole('heading', { level: 1 })
    .first()
    .waitFor()
    .catch(async (e) => {
      console.error(problems.join('\n'), (await page.evaluate(() => document.body.innerText)).slice(0, 400));
      throw e;
    });
  await page.evaluate(() => document.fonts.ready);
  await page.waitForTimeout(400);
  return { ctx, page, problems };
}

(async () => {
  fs.mkdirSync(outDir, { recursive: true });
  const browser = await chromium.launch();
  const report = [];
  const save = async (page, name) => {
    const over = await page.evaluate(() => document.documentElement.scrollWidth - window.innerWidth);
    if (over > 0) report.push(`${name}: sideways overflow ${over}px`);
    await page.screenshot({ path: path.join(outDir, `${name}.png`), animations: 'disabled' });
  };
  for (const width of [1440, 390]) {
    for (const theme of ['light', 'dark']) {
      const { ctx, page, problems } = await open(browser, width, theme, '/');
      await save(page, `shell-${label}-${theme}-${width}`);
      if (label === 'after') {
        if (width === 390) {
          await page.getByRole('button', { name: 'Open the menu' }).click();
          await page.waitForTimeout(250);
          await save(page, `shell-after-menu-${theme}-390`);
          await page.keyboard.press('Escape');
        }
        if (theme === 'light') {
          await page.getByRole('button', { name: /^Search/ }).click();
          await page.getByRole('combobox').fill('ws-fin');
          await page.getByRole('option').first().waitFor();
          await page.waitForTimeout(500);
          await save(page, `shell-after-palette-light-${width}`);
          await page.keyboard.press('Escape');
          await page.getByRole('button', { name: /^Notifications/ }).click();
          await page.waitForTimeout(200);
          await save(page, `shell-after-notifications-light-${width}`);
          await page.keyboard.press('Escape');
          await page.getByRole('button', { name: /^Tenant/ }).click();
          await page.getByRole('option').first().waitFor();
          await save(page, `shell-after-scope-light-${width}`);
          await page.getByRole('option', { name: /Northwind Logistics/ }).click();
          await page.waitForURL(/\/s\/northwind-logistics/);
          await page.waitForTimeout(500);
          await save(page, `shell-after-tenant-light-${width}`);
          report.push(`${theme} ${width}: address after choosing a tenant: ${new URL(page.url()).pathname}`);
        }
      }
      report.push(...problems.map((p) => `${theme} ${width}: ${p}`));
      await ctx.close();
    }
  }
  if (label === 'after') {
    // An MSSP's brand: its name and one accent colour, set in the runtime configuration.
    for (const theme of ['light', 'dark']) {
      const { ctx, page, problems } = await open(browser, 1440, theme, '/', { name: 'Nordvakt Security', accent: '#0F766E' });
      await save(page, `shell-after-brand-${theme}-1440`);
      report.push(...problems.map((p) => `brand ${theme}: ${p}`));
      await ctx.close();
    }
  }
  await browser.close();
  console.log(report.length ? report.join('\n') : 'no overflow, no page error');
})();
