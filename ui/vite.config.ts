import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

// The dev server proxies /v1 to the API so the browser makes same-origin
// requests and CORS never enters the picture during development.
export default defineConfig({
  plugins: [react()],
  server: {
    port: 5173,
    proxy: {
      "/v1": {
        target: process.env.VITE_API_URL ?? "http://localhost:8000",
        changeOrigin: true,
      },
    },
  },
  build: { outDir: "dist", sourcemap: true },
});
