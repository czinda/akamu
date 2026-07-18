import { defineConfig, type Plugin } from 'vite';
import react from '@vitejs/plugin-react';

const AKAMU_SERVER_URL = process.env.AKAMU_SERVER_URL ?? 'https://localhost:443';

function fontDisplaySwap(): Plugin {
  return {
    name: 'font-display-swap',
    enforce: 'post',
    generateBundle(_, bundle) {
      for (const asset of Object.values(bundle)) {
        if (asset.type === 'asset' && typeof asset.source === 'string' && asset.fileName.endsWith('.css')) {
          asset.source = asset.source.replace(/font-display:\s*fallback/g, 'font-display:swap');
        }
      }
    },
  };
}

export default defineConfig({
  plugins: [react(), fontDisplaySwap()],
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
