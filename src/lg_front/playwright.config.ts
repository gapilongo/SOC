/**
 * Playwright end-to-end suite for the web UI (e2e/). It drives a real
 * deployment: the production-like compose stack started by
 * scripts/e2e_ui_stack.sh, or any stack given by the variables below.
 *
 *   E2E_BASE_URL        UI origin, e.g. http://localhost:13000 (required)
 *   E2E_ADMIN_EMAIL     an admin of the tenant (required)
 *   E2E_ADMIN_PASSWORD  its password (required; never printed)
 *   E2E_SCREENSHOTS     directory for page screenshots (optional)
 *   E2E_CHROMIUM_PATH   Chromium executable (optional; default: Playwright's own,
 *                       see PLAYWRIGHT_BROWSERS_PATH)
 *
 * The suite creates its own users, API key and alerts, so it can run
 * against a stack that already holds data.
 */
import { defineConfig, devices } from '@playwright/test';

const baseURL = process.env.E2E_BASE_URL;
const executablePath = process.env.E2E_CHROMIUM_PATH || undefined;

export default defineConfig({
  testDir: './e2e',
  // One ordered scenario against shared server state.
  fullyParallel: false,
  workers: 1,
  retries: 0,
  forbidOnly: Boolean(process.env.CI),
  timeout: 240_000,
  expect: { timeout: 20_000 },
  reporter: process.env.CI ? [['list'], ['html', { open: 'never', outputFolder: 'playwright-report' }]] : [['list']],
  outputDir: 'test-results',
  use: {
    baseURL,
    trace: 'retain-on-failure',
    screenshot: 'only-on-failure',
    viewport: { width: 1440, height: 900 },
    colorScheme: 'dark',
    launchOptions: executablePath ? { executablePath } : {},
  },
  projects: [{ name: 'chromium', use: { ...devices['Desktop Chrome'], viewport: { width: 1440, height: 900 } } }],
});
