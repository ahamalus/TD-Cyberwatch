import { defineConfig, devices } from "@playwright/test";

/**
 * Browser tests against the real stack: e2e/stack.sh (API, worker, sample SFTP site) and the production
 * build served by `vite preview`, which proxies /api to the API like the nginx container does.
 */
export default defineConfig({
  testDir: "./e2e",
  timeout: 120_000,
  expect: { timeout: 15_000 },
  fullyParallel: false,
  workers: 1,
  retries: 0,
  reporter: process.env.CI ? [["list"], ["html", { open: "never" }]] : "list",
  use: {
    baseURL: "http://localhost:4173",
    trace: "off",
    actionTimeout: 15_000,
    screenshot: "only-on-failure",
    launchOptions: process.env.PW_CHROMIUM_PATH ? { executablePath: process.env.PW_CHROMIUM_PATH } : {},
  },
  projects: [{ name: "chromium", use: { ...devices["Desktop Chrome"] } }],
  webServer: [
    { command: "bash e2e/stack.sh", url: "http://127.0.0.1:8000/api/v1/health/live", timeout: 120_000, reuseExistingServer: !process.env.CI },
    { command: "npm run build && npx vite preview --port 4173 --strictPort", url: "http://localhost:4173", timeout: 180_000, reuseExistingServer: !process.env.CI },
  ],
});
