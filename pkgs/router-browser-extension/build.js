// Builds the nixos-router Block Page extension for both browser families.
//
//   dist/chrome/   dist/chrome.zip    Chrome, Edge, Brave (MV3 service worker)
//   dist/firefox/  dist/firefox.zip   Firefox (MV3 event page)
//
// One source tree; the targets differ only in their manifest.json and in the
// `__FIREFOX__` constant esbuild substitutes. Bundles are left unminified and
// without source maps, so what a store reviewer reads is the code that runs.
// The zips are deterministic — sorted entries, fixed timestamps — so the same
// source always produces byte-identical packages.
import fs from "node:fs";
import path from "node:path";
import zlib from "node:zlib";
import esbuild from "esbuild";

const pkg = JSON.parse(fs.readFileSync("./package.json", "utf8"));
const outdir = "dist";

const NAME = "nixos-router Block Page";
const DESCRIPTION =
  "Shows your nixos-router's block page instead of a certificate error when a secure site is blocked on your network.";
const HOMEPAGE = "https://avunu.github.io/nixos-router/docs/access-policies/browser-extension/";
const FIREFOX_ID = "nixos-router@avu.nu";
const ICON_SIZES = [16, 32, 48, 128];
const ICONS = Object.fromEntries(ICON_SIZES.map((size) => [size, `icons/icon-${size}.png`]));

// Chrome Web Store and AMO both cap the description at 132 characters.
if (DESCRIPTION.length > 132) {
  throw new Error(`manifest description is ${DESCRIPTION.length} characters; the limit is 132`);
}

function manifest(target) {
  const common = {
    manifest_version: 3,
    name: NAME,
    description: DESCRIPTION,
    version: pkg.version,
    homepage_url: HOMEPAGE,
    icons: ICONS,
    permissions: ["webNavigation", "storage"],
    // Granted per router from the options page, never at install.
    optional_host_permissions: ["https://*/*"],
    options_ui: { page: "options.html", open_in_tab: true },
    action: { default_title: NAME, default_icon: ICONS },
  };
  if (target === "firefox") {
    return {
      ...common,
      background: { scripts: ["background.js"] },
      browser_specific_settings: {
        gecko: {
          id: FIREFOX_ID,
          strict_min_version: "140.0",
          data_collection_permissions: { required: ["none"] },
        },
        // data_collection_permissions arrived in Firefox for Android 142.
        gecko_android: { strict_min_version: "142.0" },
      },
    };
  }
  return {
    ...common,
    minimum_chrome_version: "120",
    background: { service_worker: "background.js" },
    storage: { managed_schema: "managed-schema.json" },
  };
}

// ── Deterministic zip (stored/deflated entries, no extra fields) ───────────
// 1980-01-01 00:00:00, the earliest time a zip's MS-DOS timestamp can hold.
const DOS_TIME = 0;
const DOS_DATE = (1 << 5) | 1;
const UTF8_NAMES = 0x0800;

function listFiles(dir, prefix = "") {
  const out = [];
  for (const entry of fs.readdirSync(path.join(dir, prefix), { withFileTypes: true })) {
    const rel = prefix === "" ? entry.name : `${prefix}/${entry.name}`;
    if (entry.isDirectory()) {
      out.push(...listFiles(dir, rel));
    } else {
      out.push(rel);
    }
  }
  return out;
}

function zipDirectory(dir, zipPath) {
  const names = listFiles(dir).sort((a, b) => (a < b ? -1 : a > b ? 1 : 0));
  const records = [];
  const central = [];
  let offset = 0;
  for (const name of names) {
    const data = fs.readFileSync(path.join(dir, name));
    const deflated = zlib.deflateRawSync(data, { level: 9 });
    const method = deflated.length < data.length ? 8 : 0;
    const body = method === 8 ? deflated : data;
    const crc = zlib.crc32(data);
    const nameBytes = Buffer.from(name, "utf8");

    const local = Buffer.alloc(30);
    local.writeUInt32LE(0x04034b50, 0);
    local.writeUInt16LE(20, 4); // version needed to extract: 2.0
    local.writeUInt16LE(UTF8_NAMES, 6);
    local.writeUInt16LE(method, 8);
    local.writeUInt16LE(DOS_TIME, 10);
    local.writeUInt16LE(DOS_DATE, 12);
    local.writeUInt32LE(crc, 14);
    local.writeUInt32LE(body.length, 18);
    local.writeUInt32LE(data.length, 22);
    local.writeUInt16LE(nameBytes.length, 26);
    local.writeUInt16LE(0, 28); // extra field length
    records.push(local, nameBytes, body);

    const header = Buffer.alloc(46);
    header.writeUInt32LE(0x02014b50, 0);
    header.writeUInt16LE(20, 4); // version made by: MS-DOS, 2.0
    header.writeUInt16LE(20, 6);
    header.writeUInt16LE(UTF8_NAMES, 8);
    header.writeUInt16LE(method, 10);
    header.writeUInt16LE(DOS_TIME, 12);
    header.writeUInt16LE(DOS_DATE, 14);
    header.writeUInt32LE(crc, 16);
    header.writeUInt32LE(body.length, 20);
    header.writeUInt32LE(data.length, 24);
    header.writeUInt16LE(nameBytes.length, 28);
    // extra, comment, disk number, internal and external attributes: all zero
    header.writeUInt32LE(offset, 42);
    central.push(header, nameBytes);

    offset += local.length + nameBytes.length + body.length;
  }
  const directory = Buffer.concat(central);
  const end = Buffer.alloc(22);
  end.writeUInt32LE(0x06054b50, 0);
  end.writeUInt16LE(names.length, 8);
  end.writeUInt16LE(names.length, 10);
  end.writeUInt32LE(directory.length, 12);
  end.writeUInt32LE(offset, 16);
  fs.writeFileSync(zipPath, Buffer.concat([...records, directory, end]));
}

// ── Build ───────────────────────────────────────────────────────────────────
fs.rmSync(outdir, { recursive: true, force: true });

for (const target of ["chrome", "firefox"]) {
  const dir = path.join(outdir, target);
  await esbuild.build({
    bundle: true,
    entryPoints: { background: "./src/background.ts", options: "./src/options.ts" },
    outdir: dir,
    format: "iife",
    target: target === "firefox" ? ["firefox140"] : ["chrome120"],
    define: { __FIREFOX__: target === "firefox" ? "true" : "false" },
    minify: false,
    sourcemap: false,
    charset: "utf8",
    legalComments: "none",
    logLevel: "info",
  });

  fs.copyFileSync("./src/options.html", path.join(dir, "options.html"));
  fs.copyFileSync("./src/options.css", path.join(dir, "options.css"));
  fs.mkdirSync(path.join(dir, "icons"));
  for (const icon of Object.values(ICONS)) {
    fs.copyFileSync(`./${icon}`, path.join(dir, icon));
  }
  if (target === "chrome") {
    fs.copyFileSync("./src/managed-schema.json", path.join(dir, "managed-schema.json"));
  }
  fs.writeFileSync(
    path.join(dir, "manifest.json"),
    `${JSON.stringify(manifest(target), null, 2)}\n`,
  );

  zipDirectory(dir, path.join(outdir, `${target}.zip`));
  console.log(`${target}: ${dir}/ and ${outdir}/${target}.zip`);
}
