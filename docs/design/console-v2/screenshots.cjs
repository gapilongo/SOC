// Usage: node screenshots.cjs <node_modules dir with playwright-core> <html file> <output dir>
// Renders every screen in both themes at 1440 and 390 px, checks for page errors, outside requests and sideways overflow,
// and writes WebP files (encoded by the same browser, so no image tool is needed).
const path = require('path');
const fs = require('fs');
const { chromium } = require(path.join(process.argv[2], 'playwright-core'));
const file = 'file://' + path.resolve(process.argv[3]);
const outDir = path.resolve(process.argv[4]);
const screens = ['queue', 'investigation', 'case', 'approvals', 'overview', 'shell'];

(async () => {
  const browser = await chromium.launch();
  const enc = await (await browser.newContext()).newPage();
  async function save(page, name) {
    const png = (await page.screenshot()).toString('base64');
    const webp = await enc.evaluate(async (b64) => {
      const img = new Image();
      img.src = 'data:image/png;base64,' + b64;
      await img.decode();
      const c = document.createElement('canvas');
      c.width = img.naturalWidth; c.height = img.naturalHeight;
      c.getContext('2d').drawImage(img, 0, 0);
      return c.toDataURL('image/webp', 0.5).split(',')[1];
    }, png);
    fs.writeFileSync(path.join(outDir, name + '.webp'), Buffer.from(webp, 'base64'));
  }
  const problems = [];
  const watch = (page) => {
    page.on('pageerror', (e) => problems.push(`pageerror ${e.message}`));
    page.on('console', (m) => { if (m.type() === 'error') problems.push(`console ${m.text()}`); });
    page.on('request', (r) => { if (!/^(file|data):/.test(r.url())) problems.push(`external request ${r.url()}`); });
  };
  for (const width of [1440, 390]) {
    const base = width === 1440 ? 900 : 844;
    for (const theme of ['light', 'dark']) {
      const ctx = await browser.newContext({ viewport: { width, height: base }, colorScheme: theme, deviceScaleFactor: 1 });
      const page = await ctx.newPage();
      watch(page);
      for (const s of screens) {
        await page.goto(`${file}#${s}`);
        await page.evaluate((h) => { location.hash = h; }, s);
        await page.evaluate(() => document.fonts.ready);
        await page.waitForTimeout(150);
        const over = await page.evaluate(() => document.documentElement.scrollWidth - window.innerWidth);
        if (over > 0) problems.push(`${s} ${theme} ${width}: horizontal overflow ${over}px`);
        if (s === 'queue' && width === 1440 && theme === 'light') {
          for (const d of ['compact', 'dense']) {
            const n = await page.evaluate((dd) => {
              if (dd === 'dense') document.querySelector('button[data-density="dense"]').click();
              return [...document.querySelectorAll('#qbody tr')].filter((r) => { const b = r.getBoundingClientRect(); return b.top >= 0 && b.bottom <= window.innerHeight; }).length;
            }, d);
            console.log(`queue rows fully visible at 1440x900, ${d}: ${n}`);
          }
          await page.evaluate(() => document.querySelector('button[data-density="compact"]').click());
        }
        if (width === 1440 && theme === 'light' && (s === 'investigation' || s === 'queue')) await save(page, `${s}-first-screen-light-1440`);
        // a viewport as tall as the page, so sticky parts sit where a reader meets them at the end of the page
        const h = await page.evaluate(() => document.documentElement.scrollHeight);
        await page.setViewportSize({ width, height: Math.max(base, h) });
        await page.waitForTimeout(80);
        await save(page, `${s}-${theme}-${width}`);
        await page.setViewportSize({ width, height: base });
      }
      await ctx.close();
    }
  }
  // interaction states, light, 1440
  const ctx = await browser.newContext({ viewport: { width: 1440, height: 900 }, colorScheme: 'light' });
  const page = await ctx.newPage();
  watch(page);
  await page.goto(`${file}#queue`);
  await page.evaluate(() => document.fonts.ready);
  await page.keyboard.press('j'); await page.keyboard.press('j');
  const cur = await page.evaluate(() => document.querySelector('#qbody tr.cur .qt-title').textContent);
  if (!/Encoded PowerShell/.test(cur)) problems.push('J did not move the cursor to the third row: ' + cur);
  await page.keyboard.press('Control+k');
  await page.keyboard.type('ws-fin');
  await page.waitForTimeout(100);
  await save(page, 'palette-light-1440');
  await page.keyboard.press('Escape');
  for (let i = 0; i < 30; i++) await page.keyboard.press('j');
  await page.keyboard.press('k'); await page.keyboard.press('x');
  await page.waitForTimeout(100);
  await save(page, 'queue-bulk-light-1440');
  await page.keyboard.press('x'); await page.keyboard.press('Home'); await page.keyboard.press('j'); await page.keyboard.press('j');
  await page.keyboard.press('Enter');
  await page.waitForTimeout(100);
  if (!(await page.evaluate(() => location.hash === '#investigation'))) problems.push('Enter did not open the investigation');
  await page.keyboard.press('v');
  await page.waitForTimeout(100);
  await save(page, 'investigation-verdict-hidden-light-1440');
  await page.keyboard.press('v'); await page.keyboard.press('t');
  if (!(await page.evaluate(() => document.querySelector('.dock-v button').getAttribute('aria-pressed') === 'true'))) problems.push('T did not choose the verdict');
  await page.goto(`${file}#approvals`);
  await page.evaluate(() => { location.hash = 'approvals'; });
  await page.locator('[data-tenant="MAR"] .chk:not([disabled])').nth(0).check();
  await page.locator('[data-tenant="MAR"] .chk:not([disabled])').nth(1).check();
  await page.locator('[data-tenant="NWL"] [data-reject]').nth(1).click();
  await page.waitForTimeout(100);
  await page.setViewportSize({ width: 1440, height: await page.evaluate(() => document.documentElement.scrollHeight) });
  await page.waitForTimeout(80);
  await save(page, 'approvals-reason-light-1440');
  await ctx.close();
  await browser.close();
  console.log(problems.length ? 'PROBLEMS:\n' + [...new Set(problems)].join('\n') : 'no page errors, no external requests, no horizontal overflow, keyboard path works');
})();
