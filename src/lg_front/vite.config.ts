/// <reference types="vitest/config" />
import react from '@vitejs/plugin-react';
import { defineConfig } from 'vite';

// The production bundle must run under a strict Content-Security-Policy
// (script-src 'self', style-src 'self'): no inline scripts or styles are
// emitted, and runtime settings come from /config.js (served by the
// container), never from build-time variables.
export default defineConfig({
  plugins: [react()],
  build: {
    outDir: 'dist',
    target: 'es2022',
    sourcemap: false,
    assetsInlineLimit: 0,
    cssCodeSplit: true,
    modulePreload: { polyfill: false },
    rollupOptions: {
      output: {
        manualChunks(id) {
          if (id.includes('node_modules')) {
            if (/[\\/](react|react-dom|scheduler|react-router|react-router-dom)[\\/]/.test(id)) return 'vendor-react';
            if (id.includes('@tanstack')) return 'vendor-query';
            return 'vendor';
          }
          return undefined;
        },
      },
    },
  },
  server: {
    port: 5173,
    strictPort: true,
    // `npm run dev` proxies the API to a local backend (lg-sotf api on :8000),
    // so the refresh cookie and the WebSocket are same-origin in development.
    proxy: {
      '/api': {
        target: process.env.LG_SOTF_DEV_API ?? 'http://127.0.0.1:8000',
        changeOrigin: false,
        ws: true,
      },
    },
  },
  test: {
    globals: true,
    environment: 'jsdom',
    setupFiles: ['./src/test/setup.ts'],
    css: false,
    restoreMocks: true,
    include: ['src/**/*.test.{ts,tsx}'],
    // Form tests type into jsdom; coverage instrumentation slows them on a busy runner.
    testTimeout: 15_000,
    // `npm run test:ci` measures coverage; scripts/coverage-floors.mjs then holds each area to
    // its floor in coverage-floors.json (a ratchet: floors only go up).
    coverage: {
      provider: 'v8',
      include: ['src/**/*.{ts,tsx}'],
      exclude: ['src/**/*.test.{ts,tsx}', 'src/test/**', 'src/**/*.d.ts'],
      reporter: ['text-summary', 'json-summary'],
      reportsDirectory: 'coverage',
    },
  },
});
