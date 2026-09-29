// The plugin's configuration (window.cockpitRouterConfig, written by the Nix
// module into config.js), the paths it works with, and small shared helpers.
//
// The router config the UI manages is a plain JSON file (router.cockpit.settingsFile,
// fed into the router module by the host flake). Cockpit reads and writes it
// directly — no Nix tooling in the read/write path (see router-state.ts). The
// system provides the rest, all read-only:
//   • /etc/router/effective.json         — the applied effective values (defaults
//     and Nix overrides included): form defaults and locked-field detection
//   • /etc/router/applied-settings.json  — the settings file the running
//     generation was built from: the baseline for unapplied changes
//   • /run/cockpit-router/rebuild.json   — router-rebuild's record of its
//     current or last run (see rebuild-status.ts)
import { superuser } from "superuser";
import { onSettledChange } from "./settings-read";
import type { Json } from "./settings-json";

// Re-exported so every existing `from "./nix"` import keeps working.
export type { Json, JsonObject, SettingsState } from "./settings-json";
export {
  canRevertTo,
  changedTopKeys,
  deepEqual,
  getPath,
  isLocked,
  rebaseEdits,
  setPath,
} from "./settings-json";

const cfg = (window.cockpitRouterConfig ?? {}) as {
  technitiumPort?: number;
  technitiumTokenPath?: string;
  logdPort?: number;
  logdTokenPath?: string;
  directoryStatePath?: string;
  directoryStatusPath?: string;
  reportsDir?: string;
  ddnsStatusPath?: string;
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
export const DDNS_STATUS_PATH = cfg.ddnsStatusPath ?? "/var/lib/router-ddns/status.json";

export const HOST = cfg.hostName ?? "";
export const SETTINGS_FILE = cfg.settingsFile ?? "/etc/nixos/router-settings.json";
export const EFFECTIVE_FILE = "/etc/router/effective.json";
export const APPLIED_SETTINGS_FILE = "/etc/router/applied-settings.json";
export const REBUILD_STATUS_FILE = "/run/cockpit-router/rebuild.json";

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

// A companion file, {} when it is missing or cannot be read.
function readJson(path: string): Promise<Json> {
  return cockpit
    .file(path, { superuser: "try" })
    .read()
    .then((s: string | null): Json => (s && s.trim() ? (JSON.parse(s) as Json) : {}))
    .catch((): Json => ({}));
}

// effective.json alone, for a view that only shows what is running.
export function loadEffective(): Promise<Json> {
  return readJson(EFFECTIVE_FILE);
}

// Call `cb` whenever Cockpit's administrative access is switched on or off, and
// return the unsubscribe. Every read here uses superuser: "try", so what a
// page can read depends on it, and Cockpit does not reload a page when it
// changes (superuser.reload_page_on_change would, but it throws away edits the
// admin has not saved; the store keeps them across a reload).
export function onAdminChange(cb: () => void): () => void {
  return onSettledChange(superuser, cb);
}
