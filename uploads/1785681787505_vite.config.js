import { defineConfig, loadEnv } from "vite";
import react from "@vitejs/plugin-react";

// https://vitejs.dev/config/
export default defineConfig(({ mode }) => {
  const env = loadEnv(mode, process.cwd(), "VITE_");
  const backendOrigin = (() => {
    const raw = env.VITE_BACKEND_API_BASE_URL || "";
    try {
      const u = new URL(raw);
      return u.origin;
    } catch {
      return "http://localhost:5000";
    }
  })();

  return {
    plugins: [react()],
    build: {
      outDir: "dist",
      assetsDir: "assets",
      copyPublicDir: true,
    },
    publicDir: "public",
    server: {
      port: 3000,
      host: true,
      strictPort: true,
      open: true,
      proxy: {
        "/api": {
          target: backendOrigin,
          changeOrigin: true,
          secure: false,
        },
        "/uploads": {
          target: backendOrigin,
          changeOrigin: true,
          secure: false,
        },
      },
    },
  };
});
