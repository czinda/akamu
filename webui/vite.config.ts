import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';

const AKAMU_SERVER_URL = process.env.AKAMU_SERVER_URL ?? 'https://localhost:443';

export default defineConfig({
  plugins: [react()],
  base: '/ui/',
  server: {
    port: 9000,
    proxy: {
      '/admin': {
        target: AKAMU_SERVER_URL,
        changeOrigin: true,
      },
      '/acme': {
        target: AKAMU_SERVER_URL,
        changeOrigin: true,
      },
    },
  },
  build: {
    outDir: 'dist',
  },
});
