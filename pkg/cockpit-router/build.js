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
import Ajv from "ajv";
import standaloneCode from "ajv/dist/standalone/index.js";

const dev = process.env.NODE_ENV === "development";
const nodePaths = ["pkg/lib"];
const outdir = "dist";

// ── Precompile the JSON Schema validator (Ajv standalone) ───────────────────
// Cockpit's default CSP (default-src 'self') forbids unsafe-eval, so Ajv's
// runtime compile() — which builds the validator with `new Function` — is blocked
// in the browser. Generate a plain-JS validator module from the schema at build
// time instead (no runtime codegen); src/schema.ts imports it. Regenerated every
// build, so the validator never drifts from router-settings.schema.json.
const schema = JSON.parse(fs.readFileSync("./src/router-settings.schema.json", "utf8"));
// Single source: the UT Capitole category set lives in ut-capitole.json (shared
// with the Cockpit UI). Inject its ids as the schema enum so an unknown category
// is rejected at validation time — without duplicating the list.
const utCapitole = JSON.parse(fs.readFileSync("./src/ut-capitole.json", "utf8"));
schema.definitions.utCapitoleCategory.enum = utCapitole.map((c) => c.id);
const ajv = new Ajv({ code: { source: true, esm: true }, allErrors: true, allowUnionTypes: true });
ajv.compile(schema); // compiles + registers the schema under its $id
fs.mkdirSync("./src/_generated", { recursive: true });
// Named export (import/no-default-export) keyed `validateRouterSettings`; the
// multi-export form references the schema by its registered $id.
fs.writeFileSync(
  "./src/_generated/validate-settings.js",
  standaloneCode(ajv, { validateRouterSettings: schema.$id }),
);

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
        const htmlPages = [
          "network.html",
          "hosts.html",
          "ips.html",
          "dns.html",
          "firewall.html",
          "diagnostics.html",
          "system.html",
        ];
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
