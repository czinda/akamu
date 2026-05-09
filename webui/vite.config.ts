import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';

const AKAMU_ADMIN_URL = process.env.AKAMU_ADMIN_URL ?? 'https://localhost:8444';

export default defineConfig({
  plugins: [react()],
  base: '/ui/',
  server: {
    port: 9000,
    proxy: {
      '/api': {
        target: AKAMU_ADMIN_URL,
        changeOrigin: true,
        rewrite: (path) => path.replace(/^\/api/, ''),
      },
    },
  },
  build: {
    outDir: 'dist',
  },
});
