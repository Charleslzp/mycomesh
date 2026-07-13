import { defineConfig, loadEnv } from "vite";
import react from "@vitejs/plugin-react";

export default defineConfig(({ mode }) => {
  const env = loadEnv(mode, process.cwd(), "");
  return {
    plugins: [react()],
    server: {
      port: 5173,
      strictPort: true,
      proxy: {
        "/proxy-api": {
          target: env.MYCOMESH_DEV_PROXY_TARGET || "http://127.0.0.1:8100",
          changeOrigin: false,
          rewrite: (path) => path.replace(/^\/proxy-api/, ""),
        },
        "/bridge-api": {
          target: env.MYCOMESH_DEV_BRIDGE_TARGET || "http://127.0.0.1:9800",
          changeOrigin: false,
          rewrite: (path) => path.replace(/^\/bridge-api/, ""),
        },
      },
    },
    build: {
      sourcemap: true,
      target: "es2022",
      chunkSizeWarningLimit: 750,
    },
    test: {
      environment: "jsdom",
      setupFiles: "./src/test/setup.ts",
      include: ["src/**/*.test.{ts,tsx}"],
      css: true,
    },
  };
});
