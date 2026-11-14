import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';
import path from 'path';

// https://vitejs.dev/config/
export default defineConfig({
  plugins: [react()],
  resolve: {
    alias: {
      '@': path.resolve(__dirname, './src'),
    },
  },
  server: {
    port: 5173,
    proxy: {
      '/api': {
        target: 'http://127.0.0.1:8000',
        changeOrigin: true,
        ws: true,
        configure: (proxy) => {
          proxy.on('error', (_err, _req, res) => {
            if (res && 'writeHead' in res && !res.headersSent && !res.writableEnded) {
              res.writeHead(503, { 'Content-Type': 'application/json' });
              res.end(
                JSON.stringify({
                  detail:
                    'DRAIN-X backend service unavailable at http://127.0.0.1:8000. Ensure the FastAPI server is running (uvicorn app.main:app --port 8000).',
                })
              );
            }
          });
        },
      },
    },
  },
});
