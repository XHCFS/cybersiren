import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';

// Vite config for the svc-10 analyst console SPA.
//
// In dev the SPA is served from http://localhost:5173 (the origin the svc-10
// backend CORS allow-list echoes back). The proxy below forwards same-origin
// relative calls (/api, /healthz) to the backend on :8088, so the app code can
// use relative paths and the browser never crosses an origin in dev. The proxy
// target is overridable via VITE_PROXY_TARGET for non-default backend ports.
const proxyTarget = process.env.VITE_PROXY_TARGET || 'http://localhost:8088';

export default defineConfig({
  plugins: [react()],
  server: {
    port: 5173,
    strictPort: true,
    proxy: {
      '/api': { target: proxyTarget, changeOrigin: true },
      '/healthz': { target: proxyTarget, changeOrigin: true },
    },
  },
  build: {
    outDir: 'dist',
    sourcemap: false,
  },
});
