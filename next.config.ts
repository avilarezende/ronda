import type { NextConfig } from "next";

const pages = process.env.NEXT_PUBLIC_STATIC === "1";
const rawBase = process.env.BASE_PATH ?? "";
const basePath = rawBase && rawBase !== "/" ? rawBase.replace(/\/$/, "") : "";

const nextConfig: NextConfig = {
  allowedDevOrigins: ["127.0.0.1"],
  ...(pages
    ? {
        output: "export",
        images: { unoptimized: true },
        ...(basePath ? { basePath } : {}),
      }
    : {
        cacheComponents: true,
        partialPrefetching: true,
      }),
  turbopack: {
    rules: {
      "*.css": {
        loaders: ["@tailwindcss/turbopack"],
        as: "*.css",
      },
    },
  },
};

export default nextConfig;
