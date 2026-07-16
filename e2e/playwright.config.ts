import { defineConfig, devices } from '@playwright/test';

export default defineConfig({
  testDir: './specs',
  fullyParallel: true,
  forbidOnly: false,
  retries: 0,
  workers: 4,
  reporter: 'html',
  use: {
    trace: 'on-first-retry',
    video: 'on',
  },
  projects: [
    {
      name: 'chromium',
      use: { ...devices['Desktop Chrome'] },
    },
    {
      name: 'firefox',
      use: { ...devices['Desktop Firefox'] },
    },

    {
      name: 'webkit',
      use: { ...devices['Desktop Safari'] },
    },
    {
      name: 'Mobile Chrome',
      use: { ...devices['Pixel 5'] },
    },
    {
      name: 'Mobile Safari',
      use: { ...devices['iPhone 12'] },
    },
  ],
  webServer: {
    command: 'pnpm run up && pnpm run netcheck',
    url: 'http://tinyauth.127.0.0.1.sslip.io/api/healthz',
    reuseExistingServer: true,
    timeout: 5 * 60 * 1000,
    gracefulShutdown: {
      signal: 'SIGINT',
      timeout: 1000,
    },
  },
});
