// esbuild bundler for the cockpit-router plugin.
//
// Produces a static dist/ for /usr/share/cockpit/router/. To match Cockpit's
// native look (theme, spacing, light/dark), imports resolve against Cockpit's
// own `pkg/lib` (vendored into ./pkg/lib by the Nix derivation): the `cockpit`
// global is provided at runtime by ../base1/cockpit.js, while `cockpit-dark-theme`,
// `patternfly/patternfly-6-cockpit.scss` and `page.scss` come from pkg/lib.
import fs from "node:fs";
import esbuild from "esbuild";
import { sassPlugin } from "esbuild-sass-plugin";

const dev = process.env.NODE_ENV === "development";
const nodePaths = ["pkg/lib"];
const outdir = "dist";

fs.rmSync(outdir, { recursive: true, force: true });
fs.mkdirSync(outdir, { recursive: true });

await esbuild.build({
  bundle: true,
  entryPoints: ["./src/index.tsx"],
  outdir,
  format: "iife",
  nodePaths,
  // Match the official Cockpit starter-kit: the Red Hat UI fonts are served by
  // Cockpit itself (../../static/fonts/…) so fonts/images are left external.
  // (PF6 component icons are inline SVG, so the legacy pficon webfont is unused.)
  external: ["*.woff", "*.woff2", "*.jpg", "*.svg", "../../assets*"],
  legalComments: "external",
  loader: { ".js": "jsx" },
  jsx: "automatic",
  minify: !dev,
  sourcemap: dev ? "linked" : false,
  target: ["es2020"],
  logLevel: "info",
  plugins: [
    {
      name: "copy-assets",
      setup(build) {
        // One HTML page per Cockpit menu entry (see src/manifest.json); each
        // loads the shared index.js bundle and selects its view via data-view.
        const htmlPages = ["hosts.html", "ips.html", "dns.html", "diagnostics.html"];
        build.onEnd((result) => {
          if (result.errors.length === 0) {
            fs.copyFileSync("./src/manifest.json", "./dist/manifest.json");
            for (const page of htmlPages) {
              fs.copyFileSync(`./src/${page}`, `./dist/${page}`);
            }
          }
        });
      },
    },
    sassPlugin({
      loadPaths: [...nodePaths, "node_modules"],
      quietDeps: true,
    }),
  ],
});
