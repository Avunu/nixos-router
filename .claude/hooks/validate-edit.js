// PostToolUse validator — runs after Edit/Write/MultiEdit and ALERTS on any
// codebase-rule violation in the file that was just edited.
//
// NON-DESTRUCTIVE by design: it only READS the file (oxfmt --check, oxlint with
// no --fix). It never writes, never `git add`s, never reverts.
//
// On a violation it prints a report to stderr and exits 2, which surfaces the
// problem back into the session as feedback. The edit itself is left untouched.
//
// The lintable package lives in pkg/cockpit-router/, so the hook walks up from
// the edited file to the nearest dir containing .oxlintrc.json (the package
// root) and runs that package's locally-installed binaries with cwd set there
// (so .oxlintrc.json / tsconfig.json resolve). Files outside that package — or
// outside its `src/` (build.js is format-only) — are skipped, mirroring the
// package's own `format`/`lint` script scope.

const { execFileSync } = require("node:child_process");
const fs = require("node:fs");
const path = require("node:path");

let raw = "";
process.stdin.on("data", (chunk) => (raw += chunk));
process.stdin.on("end", () => {
  let input;
  try {
    input = JSON.parse(raw);
  } catch {
    process.exit(0); // no/invalid payload — nothing to validate
  }

  // Edit/Write/MultiEdit expose tool_input.file_path; NotebookEdit uses notebook_path.
  const file = input.tool_input?.file_path ?? input.tool_input?.notebook_path ?? "";
  if (!file || !/\.(ts|tsx|js|jsx|json|css|md)$/.test(file)) {
    process.exit(0);
  }
  const abs = path.resolve(file);

  // Find the package root: nearest ancestor dir with an .oxlintrc.json.
  let dir = path.dirname(abs);
  let pkgRoot = null;
  while (dir !== path.dirname(dir)) {
    if (fs.existsSync(path.join(dir, ".oxlintrc.json"))) {
      pkgRoot = dir;
      break;
    }
    dir = path.dirname(dir);
  }
  if (!pkgRoot) {
    process.exit(0); // not inside a linted package
  }

  // Only the package's checked scope: src/** (format + lint + typecheck) and
  // build.js (format only). Everything else (package.json, tsconfig, …) is skipped.
  const rel = path.relative(pkgRoot, abs);
  const inSrc = rel === "src" || rel.startsWith(`src${path.sep}`);
  const isBuildJs = rel === "build.js";
  if (!inSrc && !isBuildJs) {
    process.exit(0);
  }

  // Call the locally-installed binaries directly (fast; no npx re-resolution).
  const bin = (name) => path.join(pkgRoot, "node_modules", ".bin", name);
  if (!fs.existsSync(bin("oxlint")) || !fs.existsSync(bin("oxfmt"))) {
    process.exit(0); // deps not installed (e.g. fresh checkout) — skip silently
  }

  const check = (name, args) => {
    try {
      execFileSync(bin(name), args, { cwd: pkgRoot, stdio: ["ignore", "pipe", "pipe"] });
      return null; // exit 0 → clean
    } catch (error) {
      return `${error.stdout?.toString() ?? ""}${error.stderr?.toString() ?? ""}`.trim();
    }
  };

  const problems = [];

  // 1) Formatting drift — check only, never write.
  if (check("oxfmt", ["--check", rel]) !== null) {
    problems.push(`• Not formatted — run \`oxfmt ${rel}\` (or \`npm run format\`) in pkg/cockpit-router.`);
  }

  // 2) Lint violations — no --fix, just report. (src JS/TS only.)
  if (inSrc && /\.(ts|tsx|js|jsx)$/.test(file)) {
    const lint = check("oxlint", [rel]);
    if (lint) {
      problems.push(`• Lint violations:\n${lint}`);
    }
  }

  // 3) Type-aware lint errors — no --fix, just report. (src TS only.)
  if (inSrc && /\.(ts|tsx)$/.test(file)) {
    const typecheck = check("oxlint", ["--type-aware", "-c", ".oxlintrc.typecheck.json", rel]);
    if (typecheck) {
      problems.push(`• Type errors:\n${typecheck}`);
    }
  }

  if (problems.length > 0) {
    console.error(
      `⚠ Codebase-rule check failed for ${rel} (the edit was kept; please fix):\n\n${problems.join("\n\n")}`,
    );
    process.exit(2); // alert — non-destructive, the file is NOT reverted
  }
});
