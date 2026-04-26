import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";
import path from "path";
import tailwindcss from "@tailwindcss/vite";
import { visualizer } from "rollup-plugin-visualizer";

// https://vite.dev/config/
export default defineConfig({
  plugins: [react(), tailwindcss(), visualizer()],
  resolve: {
    alias: {
      "@": path.resolve(__dirname, "./src"),
    },
  },
  build: {
    rolldownOptions: {
      output: {
        codeSplitting: {
          groups: [
            {
              name: "ui",
              test: "@radix-ui|input-otp|tailwindcss|tailwind-merge|sonner|lucide-react",
            },
            {
              name: "i18n",
              test: "i18next|i18next-browser-languagedetector|i18next-resources-to-backend",
            },
            {
              name: "util",
              test: "zod|axios|react-hook-form",
            },
          ],
        },
      },
    },
  },
  server: {
    host: "0.0.0.0",
    proxy: {
      "/api": {
        target: "http://tinyauth-backend:3000/api",
        changeOrigin: true,
        rewrite: (path) => path.replace(/^\/api/, ""),
      },
      "/resources": {
        target: "http://tinyauth-backend:3000/resources",
        changeOrigin: true,
        rewrite: (path) => path.replace(/^\/resources/, ""),
      },
      "/.well-known": {
        target: "http://tinyauth-backend:3000/.well-known",
        changeOrigin: true,
        rewrite: (path) => path.replace(/^\/\.well-known/, ""),
      },
      "/robots.txt": {
        target: "http://tinyauth-backend:3000/robots.txt",
        changeOrigin: true,
        rewrite: (path) => path.replace(/^\/robots.txt/, ""),
      },
    },
    allowedHosts: true,
  },
});
