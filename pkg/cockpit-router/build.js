// Minimal esbuild bundler for the cockpit-router plugin.
// Produces a static dist/ suitable for /usr/share/cockpit/router/:
//   index.js (IIFE bundle: React + PatternFly), index.css, assets/*,
//   plus the copied manifest.json + index.html.
// The `cockpit` API is NOT bundled — it is provided at runtime as a global
// by ../base1/cockpit.js (loaded in index.html), so it is referenced directly.
import * as esbuild from "esbuild";
import { copyFileSync, mkdirSync, rmSync } from "node:fs";

const dev = process.env.NODE_ENV === "development";

rmSync("dist", { recursive: true, force: true });
mkdirSync("dist", { recursive: true });
copyFileSync("src/manifest.json", "dist/manifest.json");
copyFileSync("src/index.html", "dist/index.html");

await esbuild.build({
  entryPoints: ["src/index.tsx"],
  outfile: "dist/index.js",
  bundle: true,
  format: "iife",
  target: ["es2020"],
  jsx: "automatic",
  minify: !dev,
  sourcemap: dev,
  logLevel: "info",
  assetNames: "assets/[name]-[hash]",
  loader: {
    ".css": "css",
    ".woff": "file",
    ".woff2": "file",
    ".ttf": "file",
    ".eot": "file",
    ".svg": "file",
    ".png": "file",
    ".jpg": "file",
    ".gif": "file",
  },
});
