import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';

// Same policy Caddy sends in production (deploy/caddy/Caddyfile), so `npm run preview`
// proves the built app works without inline scripts, eval or third-party origins.
const CSP = [
  "default-src 'self'",
  "script-src 'self'",
  "style-src 'self'",
  "img-src 'self' data: blob:",
  "connect-src 'self'",
  "font-src 'self'",
  "object-src 'none'",
  "base-uri 'none'",
  "form-action 'self'",
  "frame-ancestors 'none'",
].join('; ');

const proxy = {
  '/api': 'http://127.0.0.1:4000',
  '/authority': 'http://127.0.0.1:7000',
};

export default defineConfig({
  plugins: [react()],
  server: { port: 5173, proxy },
  preview: { port: 5173, proxy, headers: { 'Content-Security-Policy': CSP, 'X-Frame-Options': 'DENY' } },
  build: {
    target: 'es2022',
    sourcemap: false,
    chunkSizeWarningLimit: 900,
  },
});
