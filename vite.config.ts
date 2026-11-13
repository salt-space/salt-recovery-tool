import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';

export default defineConfig({
  plugins: [react()],
  root: 'src/mainview',
  envDir: '../..',
  // Tauri dev: keep the terminal output from `tauri dev` visible.
  clearScreen: false,
  build: {
    outDir: '../../build/dist',
    emptyOutDir: true,
  },
  server: {
    port: 5173,
    strictPort: true,
    watch: { ignored: ['**/src-tauri/**', '**/target/**'] },
  },
  define: {
    'process.env': {},
    global: 'globalThis',
  },
});
