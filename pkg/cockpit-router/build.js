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
// router-settings.schema.json is GENERATED from the router.* NixOS options by
// nixos-install-helper (single source — regenerate with:
//   nix build .#packages.x86_64-linux.settingsSchema-router
//   && jq -S . result > src/router-settings.schema.json). It is a flat, inlined
// Draft-07 schema (no $ref/definitions, no $id).
const schema = JSON.parse(fs.readFileSync("./src/router-settings.schema.json", "utf8"));
// Ajv's standaloneCode keys exports by $id; the derived schema has none, so set
// a stable one here.
schema.$id =
  schema.$id || "https://github.com/Avunu/nixos-router/router-settings.schema.json";
// Single source for the UT Capitole categories: their ids live in
// ut-capitole.json (shared with the Cockpit UI). Inject them as the enum on the
// derived schema's category list so an unknown category is rejected at
// validation time — without duplicating the list.
const utCapitole = JSON.parse(fs.readFileSync("./src/ut-capitole.json", "utf8"));
const utEnum = utCapitole.map((c) => c.id);
const utItems =
  schema.properties?.dns?.properties?.adguard?.properties?.utCapitoleCategories?.items;
if (utItems) utItems.enum = utEnum;
// Back-compat: if a legacy definitions block is still present, fill it too.
if (schema.definitions?.utCapitoleCategory) schema.definitions.utCapitoleCategory.enum = utEnum;
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
          "threat-protection.html",
          "access-protection.html",
          "firewall.html",
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
