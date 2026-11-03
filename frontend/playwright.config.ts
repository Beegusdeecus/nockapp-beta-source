import { defineConfig } from '@playwright/test';
export default defineConfig({
  testDir: './tests',
  fullyParallel: false,
  workers: 1,
  timeout: 30_000,
  outputDir: process.env.NOCKAPP_TEST_OUTPUT_DIR ?? 'test-results',
  use: { viewport: { width: 390, height: 844 }, trace: 'retain-on-failure' },
  reporter: [['list'], ['json', { outputFile: process.env.NOCKAPP_TEST_RECEIPT ?? `artifacts/test-${new Date().toISOString().replace(/[:.]/g, '-')}-${process.pid}.json` }]],
  webServer: { command: 'npm run dev -- --port 4173 --strictPort', url: 'http://127.0.0.1:4173/sidepanel.html', reuseExistingServer: false },
});
