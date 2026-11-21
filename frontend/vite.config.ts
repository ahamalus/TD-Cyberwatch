import { defineConfig } from "vitest/config";
import react from "@vitejs/plugin-react";

export default defineConfig({
  plugins: [react()],
  server: {
    port: 5173,
    proxy: { "/api": { target: process.env.CW_API_URL ?? "http://localhost:8000", changeOrigin: false } },
  },
  preview: {
    proxy: { "/api": { target: process.env.CW_API_URL ?? "http://localhost:8000", changeOrigin: false } },
  },
  build: {
    sourcemap: false,
    chunkSizeWarningLimit: 600,
    rollupOptions: {
      output: {
        // Long-lived vendor chunks: they change rarely, so browsers keep them cached between releases.
        manualChunks(id) {
          if (!id.includes("node_modules")) return undefined;
          if (id.includes("@tabler/icons")) return "icons";
          if (id.includes("@mantine")) return "mantine";
          if (id.includes("@tanstack")) return "query";
          // Charts are only needed by dashboard pages: keep them out of the first load.
          if (/[\\/](recharts|d3-[a-z-]+|victory-vendor|lodash|react-smooth|recharts-scale|decimal\.js-light|eventemitter3|internmap|es-toolkit|immer|reselect|@reduxjs|redux|react-redux|use-sync-external-store)[\\/]/.test(id)) return "charts-vendor";
          return "vendor";
        },
      },
    },
  },
  test: { environment: "jsdom", globals: true, setupFiles: ["./src/test/setup.ts"], css: false, include: ["src/**/*.test.{ts,tsx}"] },
});
