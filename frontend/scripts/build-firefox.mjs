import { cp, readFile, rm, writeFile } from 'node:fs/promises';

// Reuse the built application; only browser wiring differs.
await rm('dist-firefox', { recursive: true, force: true });
await cp('dist', 'dist-firefox', { recursive: true });
const manifest = JSON.parse(await readFile('dist/manifest.json', 'utf8'));
delete manifest.minimum_chrome_version;
delete manifest.side_panel;
manifest.permissions = manifest.permissions.filter((name) => name !== 'sidePanel');
manifest.background = { scripts: ['background.js'], type: 'module' };
manifest.sidebar_action = { default_panel: 'sidepanel.html', default_title: 'NockApp' };
manifest.browser_specific_settings = { gecko: {
  id: 'nockapp@beegus.local', strict_min_version: '140.0',
  data_collection_permissions: { required: ['none'] },
} };
await writeFile('dist-firefox/manifest.json', JSON.stringify(manifest, null, 2) + '\n');
console.log('Firefox build prepared in dist-firefox.');
