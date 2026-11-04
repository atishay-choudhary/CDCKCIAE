import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

// The bundle is written into the Django app and served by Django at
// /assets/, so the backend needs no Node at run time.
export default defineConfig({
  plugins: [react()],
  base: "/assets/",
  build: {
    outDir: "../backend/core/frontend_dist",
    emptyOutDir: true,
    assetsDir: "",
  },
  server: {
    proxy: Object.fromEntries(
      ["crawl", "artifacts", "killchain", "graph", "risk-score", "evaluation", "reports", "tor"]
        .map((p) => [`/${p}`, "http://127.0.0.1:8000"])
    ),
  },
});
