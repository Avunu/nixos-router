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
import type { Json, SettingsState } from "./settings-json";

// Re-exported so every existing `from "./nix"` import keeps working.
export type { Json, JsonObject, SettingsState } from "./settings-json";
export { changedTopKeys, deepEqual, getPath, isLocked, setPath } from "./settings-json";

const cfg = (window.cockpitRouterConfig ?? {}) as {
  technitiumPort?: number;
  technitiumTokenPath?: string;
  logdPort?: number;
  logdTokenPath?: string;
  directoryStatePath?: string;
  directoryStatusPath?: string;
  reportsDir?: string;
  macPrefixesPath?: string;
  hostName?: string;
  flakePath?: string;
  settingsFile?: string;
};

export const TECHNITIUM_PORT = cfg.technitiumPort ?? 5380;
export const TECHNITIUM_TOKEN_PATH =
  cfg.technitiumTokenPath ?? "/var/lib/cockpit-router/technitium-token";
export const LOGD_PORT = cfg.logdPort ?? 8067;
export const LOGD_TOKEN_PATH = cfg.logdTokenPath ?? "/var/lib/router-technitium/logd-query.token";
export const DIRECTORY_STATE_PATH =
  cfg.directoryStatePath ?? "/var/lib/router-directory/directory.json";
export const DIRECTORY_STATUS_PATH =
  cfg.directoryStatusPath ?? "/var/lib/router-directory/status.json";
export const REPORTS_DIR = cfg.reportsDir ?? "/var/lib/router-reports";

export const HOST = cfg.hostName ?? "";
export const FLAKE_PATH = cfg.flakePath ?? "/etc/nixos";
export const SETTINGS_FILE = cfg.settingsFile ?? "/etc/nixos/router-settings.json";
export const EFFECTIVE_FILE = "/etc/router/effective.json";
export const APPLIED_FILE = "/var/lib/cockpit-router/applied.json";

// `<flake>#<host>` — the rebuild target.
export const flakeHostRef = () => `${FLAKE_PATH}#${HOST}`;

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
