// JSON settings store shared by the Settings tabs, the Firewall page, the System
// page, and the global changes tray.
//
// The router config the UI manages is a plain JSON file (router.cockpit.settingsFile,
// fed into the router module by the host flake). Cockpit reads/writes it directly —
// No Nix tooling in the read/write path. Two companion files come from the system:
//   • /etc/router/effective.json      — the *applied* effective values (module-emitted)
//   • /var/lib/cockpit-router/applied.json — snapshot the UI writes after each apply
// The applied snapshot is what the changes tray diffs against; effective drives
// Default display and locked-field detection. Only a UI apply writes the
// snapshot, so loadState falls back to the settings file whenever the running
// generation is newer than it — see appliedBaseline.
//
// The settings file is read strictly: a missing or empty file is {}, any other
// failure rejects loadState (see settings-read.ts), because every save builds
// on that read and replaces the whole file. The two companions stay lenient,
// {} when unreadable. Both are root-only (effective.json is 0600, applied.json
// sits in a 0700 directory), so a session that cannot read them has Limited
// access and cannot write the settings file either, and switching access on
// reloads everything (onAdminChange). The one write built on a companion is
// the tray's Revert, which copies the snapshot over the file; it is never
// offered for an empty snapshot (canRevertTo).
import { superuser } from "superuser";
import { validateSettings } from "./schema";
import { appliedBaseline, dropRetiredKeys } from "./settings-json";
import type { Json, SettingsState } from "./settings-json";
import {
  ADMIN_NEEDED,
  NOT_LOADED,
  isDenied,
  isLoaded,
  markLoaded,
  onSettledChange,
  readStrict,
} from "./settings-read";

// Re-exported so every existing `from "./nix"` import keeps working.
export type { Json, JsonObject, SettingsState } from "./settings-json";
export {
  appliedBaseline,
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
export const FLAKE_PATH = cfg.flakePath ?? "/etc/nixos";
export const SETTINGS_FILE = cfg.settingsFile ?? "/etc/nixos/router-settings.json";
export const EFFECTIVE_FILE = "/etc/router/effective.json";
export const APPLIED_FILE = "/var/lib/cockpit-router/applied.json";
export const CURRENT_SYSTEM = "/run/current-system";

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

// A companion file, {} when it is missing or cannot be read.
function readJson(path: string): Promise<Json> {
  return cockpit
    .file(path, { superuser: "try" })
    .read()
    .then((s: string | null): Json => (s && s.trim() ? (JSON.parse(s) as Json) : {}))
    .catch((): Json => ({}));
}

// Modification time in epoch seconds, or null when it cannot be read. `stat`
// does not follow symlinks, so /run/current-system reports when the generation
// was activated rather than its store path's 1970 timestamp.
function mtime(path: string): Promise<number | null> {
  return cockpit
    .spawn(["stat", "-c", "%Y", path], { err: "ignore" })
    .then((out: string): number | null => {
      const secs = Number(out.trim());
      return Number.isFinite(secs) ? secs : null;
    })
    .catch((): number | null => null);
}

export interface LoadedState extends SettingsState {
  // The snapshot on disk lagged the running system and `applied` above was
  // taken from the settings JSON instead (see appliedBaseline). The changes
  // tray persists the correction so it survives the next edit.
  snapshotStale: boolean;
}

// Rejects when the settings file cannot be read; the error says what to do.
export function loadState(): Promise<LoadedState> {
  return Promise.all([
    readStrict(SETTINGS_FILE, () => cockpit.file(SETTINGS_FILE, { superuser: "try" }).read()),
    readJson(EFFECTIVE_FILE),
    readJson(APPLIED_FILE),
    mtime(SETTINGS_FILE),
    mtime(CURRENT_SYSTEM),
  ]).then(([onDisk, effective, snapshotOnDisk, settingsAt, systemAt]) => {
    // Both sides, so a key only one of them still carries is never a change.
    const desired = dropRetiredKeys(onDisk);
    const snapshot = dropRetiredKeys(snapshotOnDisk);
    const { applied, stale } = appliedBaseline(desired, snapshot, settingsAt, systemAt);
    return markLoaded({ desired, effective, applied, snapshotStale: stale });
  });
}

// effective.json alone, for a view that only shows what is running.
export function loadEffective(): Promise<Json> {
  return readJson(EFFECTIVE_FILE);
}

// Call `cb` whenever Cockpit's administrative access is switched on or off, and
// return the unsubscribe. Every read here uses superuser: "try", so what a
// page can read depends on it, and Cockpit does not reload a page when it
// changes (superuser.reload_page_on_change would, but it throws away edits the
// admin has not saved; useSettings keeps them across a reload).
export function onAdminChange(cb: () => void): () => void {
  return onSettledChange(superuser, cb);
}

// Replace the settings file with `obj`. `base` is the loaded state `obj` was
// built from; nothing is written unless it came from a successful loadState,
// so a page that could not read the file can never save over it.
export function writeDesired(obj: Json, base: SettingsState | null | undefined): Promise<unknown> {
  if (!isLoaded(base)) {
    return Promise.reject(new Error(NOT_LOADED));
  }
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
    .then(
      (r: unknown) => {
        window.dispatchEvent(new Event("router:changed"));
        return r;
      },
      (e: unknown) => {
        throw isDenied(e) ? new Error(ADMIN_NEEDED, { cause: e }) : e;
      },
    );
}

export function writeApplied(obj: Json): Promise<unknown> {
  return cockpit
    .file(APPLIED_FILE, { superuser: "require" })
    .replace(`${JSON.stringify(obj, null, 2)}\n`);
}

// ── small JSON path/equality helpers ────────────────────────────────────────
