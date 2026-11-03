import { existsSync } from 'node:fs';
import { resolve } from 'node:path';
import { spawnSync } from 'node:child_process';

const environment = { ...process.env };
// Optional, project-local Linux libraries support minimal development hosts.
// Ordinary machines use their installed Playwright system dependencies.
const localLibraries = resolve('.tools/browser-libs/usr/lib/x86_64-linux-gnu');
if (process.platform === 'linux' && existsSync(localLibraries)) {
  environment.LD_LIBRARY_PATH = [localLibraries, environment.LD_LIBRARY_PATH].filter(Boolean).join(':');
}
const result = spawnSync(process.execPath, [resolve('node_modules/@playwright/test/cli.js'), 'test', ...process.argv.slice(2)], { stdio: 'inherit', env: environment });
if (result.error) console.error(result.error.message);
process.exit(result.status ?? 1);
