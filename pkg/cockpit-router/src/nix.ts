// JSON settings store shared by the Settings tabs, the Firewall page, the System
// page, and the global changes tray.
//
// The router config the UI manages is a plain JSON file (router.cockpit.settingsFile,
// fed into the router module by the host flake). Cockpit reads/writes it directly —
// No Nix tooling in the read/write path. Two companion files come from the system:
//   • /etc/router/effective.json      — the *applied* effective values (module-emitted)
//   • /var/lib/cockpit-router/applied.json — snapshot the UI writes after each apply
// The applied snapshot is what the changes tray diffs against; effective drives
// Default display and locked-field detection.
import { validateSettings } from "./schema";

const cfg = (window.cockpitRouterConfig ?? {}) as {
  adguardPort?: number;
  macPrefixesPath?: string;
  hostName?: string;
  flakePath?: string;
  settingsFile?: string;
};

export const HOST = cfg.hostName ?? "";
export const FLAKE_PATH = cfg.flakePath ?? "/etc/nixos";
export const SETTINGS_FILE = cfg.settingsFile ?? "/etc/nixos/router-settings.json";
export const EFFECTIVE_FILE = "/etc/router/effective.json";
export const APPLIED_FILE = "/var/lib/cockpit-router/applied.json";

// `<flake>#<host>` — the rebuild target.
export const flakeHostRef = () => `${FLAKE_PATH}#${HOST}`;

export type Json = string | number | boolean | null | Json[] | { [key: string]: Json };
export type JsonObject = Record<string, Json>;

const isObject = (v: Json | undefined): v is JsonObject =>
  typeof v === "object" && v !== null && !Array.isArray(v);

// Normalize an unknown caught value to a message string.
export function errMsg(e: unknown): string {
  if (e instanceof Error) {
    return e.message;
  }
  if (typeof e === "object" && e !== null && "message" in e) {
    return String((e as { message: unknown }).message);
  }
  return String(e);
}

export interface SettingsState {
  desired: Json; // Editable JSON on disk (the saved state)
  effective: Json; // Applied effective values (module-emitted)
  applied: Json; // Snapshot written by the UI after the last apply
}

function readJson(path: string, superuser: "try" | "require" = "try"): Promise<Json> {
  return cockpit
    .file(path, { superuser })
    .read()
    .then((s: string | null): Json => (s && s.trim() ? (JSON.parse(s) as Json) : {}))
    .catch((): Json => ({}));
}

export function loadState(): Promise<SettingsState> {
  return Promise.all([
    readJson(SETTINGS_FILE),
    readJson(EFFECTIVE_FILE),
    readJson(APPLIED_FILE),
  ]).then(([desired, effective, applied]) => ({ desired, effective, applied }));
}

export function writeDesired(obj: Json): Promise<unknown> {
  // Validate against the schema before persisting, so an invalid config never
  // reaches disk (and therefore never reaches `nixos-rebuild`).
  const errors = validateSettings(obj);
  if (errors.length > 0) {
    return Promise.reject(
      new Error(`Configuration does not match the schema:\n${errors.join("\n")}`),
    );
  }
  return cockpit
    .file(SETTINGS_FILE, { superuser: "require" })
    .replace(`${JSON.stringify(obj, null, 2)}\n`)
    .then((r: unknown) => {
      window.dispatchEvent(new Event("router:changed"));
      return r;
    });
}

export function writeApplied(obj: Json): Promise<unknown> {
  return cockpit
    .file(APPLIED_FILE, { superuser: "require" })
    .replace(`${JSON.stringify(obj, null, 2)}\n`);
}

// ── small JSON path/equality helpers ────────────────────────────────────────
export function getPath(obj: Json, path: string): Json | undefined {
  let cur: Json | undefined = obj;
  for (const k of path.split(".")) {
    if (!isObject(cur)) {
      return undefined;
    }
    cur = cur[k];
  }
  return cur;
}

export function setPath(obj: Json, path: string, value: Json): Json {
  const keys = path.split(".");
  const clone: JsonObject = isObject(obj) ? structuredClone(obj) : {};
  let cur: JsonObject = clone;
  for (let i = 0; i < keys.length - 1; i++) {
    const k = keys[i]!;
    const next = cur[k];
    if (!isObject(next)) {
      cur[k] = {};
    }
    cur = cur[k] as JsonObject;
  }
  cur[keys.at(-1)!] = value;
  return clone;
}

export function deepEqual(a: Json | undefined, b: Json | undefined): boolean {
  if (a === b) {
    return true;
  }
  if (a === null || b === null || a === undefined || b === undefined) {
    return false;
  }
  if (Array.isArray(a) || Array.isArray(b)) {
    if (!Array.isArray(a) || !Array.isArray(b) || a.length !== b.length) {
      return false;
    }
    return a.every((x, i) => deepEqual(x, b[i]));
  }
  if (isObject(a) && isObject(b)) {
    const ka = Object.keys(a);
    const kb = Object.keys(b);
    if (ka.length !== kb.length) {
      return false;
    }
    return ka.every((k) => deepEqual(a[k], b[k]));
  }
  return false;
}

// A leaf is locked when the last-applied input set it but the effective config
// Disagrees — i.e. something in Nix overrode the JSON value.
export function isLocked(state: SettingsState, path: string): boolean {
  const a = getPath(state.applied, path);
  if (a === undefined) {
    return false;
  }
  return !deepEqual(a, getPath(state.effective, path));
}

// Top-level keys that differ between the saved JSON and the last applied snapshot.
export function changedTopKeys(desired: Json, applied: Json): string[] {
  const d = isObject(desired) ? desired : {};
  const a = isObject(applied) ? applied : {};
  const keys = new Set([...Object.keys(d), ...Object.keys(a)]);
  return [...keys].filter((k) => !deepEqual(d[k], a[k]));
}
