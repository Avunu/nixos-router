// JSON settings store shared by the Settings tabs, the Firewall page, the System
// page, and the global changes tray.
//
// The router config the UI manages is a plain JSON file (router.cockpit.settingsFile,
// fed into the router module by the host flake). Cockpit reads/writes it directly —
// no Nix tooling in the read/write path. Two companion files come from the system:
//   • /etc/router/effective.json      — the *applied* effective values (module-emitted)
//   • /var/lib/cockpit-router/applied.json — snapshot the UI writes after each apply
// The applied snapshot is what the changes tray diffs against; effective drives
// default display and locked-field detection.

const cfg = (window.cockpitRouterConfig || {}) as {
  adguardPort?: number;
  macPrefixesPath?: string;
  hostName?: string;
  flakePath?: string;
  settingsFile?: string;
};

export const HOST = cfg.hostName || "";
export const FLAKE_PATH = cfg.flakePath || "/etc/nixos";
export const SETTINGS_FILE = cfg.settingsFile || "/etc/nixos/router-settings.json";
export const EFFECTIVE_FILE = "/etc/router/effective.json";
export const APPLIED_FILE = "/var/lib/cockpit-router/applied.json";

// `<flake>#<host>` — the rebuild target.
export const flakeHostRef = () => `${FLAKE_PATH}#${HOST}`;

export type Json = any;

export interface SettingsState {
  desired: Json; // editable JSON on disk (the saved state)
  effective: Json; // applied effective values (module-emitted)
  applied: Json; // snapshot written by the UI after the last apply
}

function readJson(path: string, superuser: "try" | "require" = "try"): Promise<Json> {
  return cockpit
    .file(path, { superuser })
    .read()
    .then((s: string | null) => (s && s.trim() ? JSON.parse(s) : {}))
    .catch(() => ({}));
}

export function loadState(): Promise<SettingsState> {
  return Promise.all([readJson(SETTINGS_FILE), readJson(EFFECTIVE_FILE), readJson(APPLIED_FILE)]).then(
    ([desired, effective, applied]) => ({ desired, effective, applied }),
  );
}

export function writeDesired(obj: Json): Promise<unknown> {
  return cockpit
    .file(SETTINGS_FILE, { superuser: "require" })
    .replace(JSON.stringify(obj, null, 2) + "\n")
    .then((r: unknown) => {
      window.dispatchEvent(new Event("router:changed"));
      return r;
    });
}

export function writeApplied(obj: Json): Promise<unknown> {
  return cockpit.file(APPLIED_FILE, { superuser: "require" }).replace(JSON.stringify(obj, null, 2) + "\n");
}

// ── small JSON path/equality helpers ────────────────────────────────────────
export function getPath(obj: Json, path: string): any {
  return path.split(".").reduce((o, k) => (o == null ? undefined : o[k]), obj);
}

export function setPath(obj: Json, path: string, value: any): Json {
  const keys = path.split(".");
  const clone = obj == null ? {} : JSON.parse(JSON.stringify(obj));
  let cur = clone;
  for (let i = 0; i < keys.length - 1; i++) {
    if (cur[keys[i]] == null || typeof cur[keys[i]] !== "object") cur[keys[i]] = {};
    cur = cur[keys[i]];
  }
  cur[keys[keys.length - 1]] = value;
  return clone;
}

export function deepEqual(a: any, b: any): boolean {
  if (a === b) return true;
  if (a == null || b == null) return a === b;
  if (typeof a !== typeof b) return false;
  if (Array.isArray(a) || Array.isArray(b)) {
    if (!Array.isArray(a) || !Array.isArray(b) || a.length !== b.length) return false;
    return a.every((x, i) => deepEqual(x, b[i]));
  }
  if (typeof a === "object") {
    const ka = Object.keys(a);
    const kb = Object.keys(b);
    if (ka.length !== kb.length) return false;
    return ka.every((k) => deepEqual(a[k], b[k]));
  }
  return false;
}

// A leaf is locked when the last-applied input set it but the effective config
// disagrees — i.e. something in Nix overrode the JSON value.
export function isLocked(state: SettingsState, path: string): boolean {
  const a = getPath(state.applied, path);
  if (a === undefined) return false;
  return !deepEqual(a, getPath(state.effective, path));
}

// Top-level keys that differ between the saved JSON and the last applied snapshot.
export function changedTopKeys(desired: Json, applied: Json): string[] {
  const keys = new Set([...Object.keys(desired || {}), ...Object.keys(applied || {})]);
  return [...keys].filter((k) => !deepEqual((desired || {})[k], (applied || {})[k]));
}
