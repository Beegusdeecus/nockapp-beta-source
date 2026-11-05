import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';
import { resolve } from 'node:path';

export default defineConfig({
  plugins: [react()],
  base: './',
  // The prototype never loads .env files, including during local builds.
  envDir: false,
  resolve: { alias: { events: resolve(import.meta.dirname, 'node_modules/events/events.js') } },
  build: {
    target: 'chrome116',
    rollupOptions: {
      input: { forum: resolve(import.meta.dirname, 'forum.html'), legacy: resolve(import.meta.dirname, 'legacy.html'), sidepanel: resolve(import.meta.dirname, 'sidepanel.html'), background: resolve(import.meta.dirname, 'src/background.ts'), xconnect: resolve(import.meta.dirname, 'x-connect.html'), publicpost: resolve(import.meta.dirname, 'public-post.html'), walletpost: resolve(import.meta.dirname, 'wallet-post.html'), publicwallet: resolve(import.meta.dirname, 'public-wallet.html'), publictickets: resolve(import.meta.dirname, 'public-tickets.html') },
      output: { entryFileNames: (chunk) => chunk.name === 'background' ? 'background.js' : 'assets/[name]-[hash].js' },
    },
  },
});
