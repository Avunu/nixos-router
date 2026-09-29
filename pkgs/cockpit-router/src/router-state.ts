// The router's configuration state as this page sees it, kept in step with
// the files it comes from.
//
// Cockpit loads every menu entry in its own iframe, so nothing one page holds
// in memory reaches another. Every page instead follows the files themselves
// through the bridge (cockpit.file().watch), so a save on one page — or in
// another browser, or at a shell — reaches all of them, and so does a rebuild:
//   • the settings file, read strictly (see settings-read.ts): a missing or
//     empty file is {}, any other failure is an error the pages show instead
//     of a form, and nothing is ever saved over a file that was not read;
//   • /etc/router/effective.json and applied-settings.json, which activation
//     replaces one after the other: a change to either is taken a moment
//     later, together, so fields do not flash as locked in between;
//   • /run/cockpit-router/rebuild.json, router-rebuild's record of its runs.
// Saves go through the same watch handle with the tag it last delivered, so
// one built on a read that is no longer current is refused ("change-conflict")
// instead of overwriting what someone else saved, and the file keeps its mode
// and owner. Switching administrative access on or off reopens the watches,
// since it changes what can be read, and so does the page becoming visible
// again, in case a watch channel closed while it was hidden.
import { useSyncExternalStore } from "react";
import { validateSettings } from "./schema";
import { dropRetiredKeys } from "./settings-json";
import type { Json, SettingsState } from "./settings-json";
import {
  ADMIN_NEEDED,
  NOT_LOADED,
  isDenied,
  isLoaded,
  markLoaded,
  parseSettings,
} from "./settings-read";
import {
  APPLIED_SETTINGS_FILE,
  EFFECTIVE_FILE,
  REBUILD_STATUS_FILE,
  SETTINGS_FILE,
  errMsg,
  onAdminChange,
} from "./nix";
import { parseRebuildRecord } from "./rebuild-status";
import type { RebuildRecord } from "./rebuild-status";

export interface LoadedSettings extends SettingsState {
  tag: string; // the settings file's tag as read: a save must still match it
}

export interface RouterState {
  // The settings with their companions; null until first read and while the
  // settings file cannot be read (`error` says why).
  settings: LoadedSettings | null;
  error: string;
  // `settings.applied` is the running generation's settings. Without them
  // (applied-settings.json missing or unreadable) nothing can be said about
  // which saved changes are applied, and nothing is shown as locked.
  baselineKnown: boolean;
  rebuild: RebuildRecord | null;
}

export const CONFLICT =
  "The router settings were changed elsewhere while you were saving. Your unsaved edits are kept on top of the new version; review them and save again.";

// Raised by writeSettings when the file changed since it was read.
export class SettingsConflictError extends Error {
  public constructor() {
    super(CONFLICT);
    this.name = "SettingsConflictError";
  }
}

// How long activation's two /etc/router files get to settle.
const COMPANION_DELAY_MS = 250;

let state: RouterState = { settings: null, error: "", baselineKnown: false, rebuild: null };
const listeners = new Set<() => void>();

// The latest of each read; undefined until its watch first reports.
let settingsRead: { desired: Json; tag: string } | { error: string } | undefined;
let appliedRead: Json | null | undefined;
let effectiveRead: Json | undefined;
let composed = false;
let companionTimer: number | undefined;
let settingsFile: CockpitFile | null = null;
let closers: (() => void)[] = [];
let started = false;

function emit(next: RouterState) {
  state = next;
  for (const listener of listeners) {
    listener();
  }
}

function compose() {
  window.clearTimeout(companionTimer);
  companionTimer = undefined;
  if (settingsRead === undefined || appliedRead === undefined || effectiveRead === undefined) {
    return;
  }
  composed = true;
  if ("error" in settingsRead) {
    emit({ ...state, settings: null, error: settingsRead.error, baselineKnown: false });
    return;
  }
  const settings = markLoaded({
    desired: settingsRead.desired,
    effective: effectiveRead,
    applied: appliedRead ?? {},
    tag: settingsRead.tag,
  });
  emit({ ...state, settings, error: "", baselineKnown: appliedRead !== null });
}

// A companion changed: settle first, except for the very first read.
function companionChanged() {
  if (!composed) {
    compose();
    return;
  }
  window.clearTimeout(companionTimer);
  companionTimer = window.setTimeout(compose, COMPANION_DELAY_MS);
}

// A read-only companion's JSON, or null when it is missing, unreadable (both
// are root-only) or not JSON.
function lenientJson(content: string | null, error: CockpitError | null): Json | null {
  if (error || content === null || !content.trim()) {
    return null;
  }
  try {
    return JSON.parse(content) as Json;
  } catch {
    return null;
  }
}

function watch(
  path: string,
  callback: (content: string | null, tag: string | null, error: CockpitError | null) => void,
): CockpitFile {
  const file = cockpit.file(path, { superuser: "try" });
  const handle = file.watch(callback);
  closers.push(() => {
    handle.remove();
    file.close();
  });
  return file;
}

// (Re)open every watch. What was read before stays shown until the new
// watches report, so reopening never flashes an empty form.
function open() {
  for (const close of closers) {
    close();
  }
  closers = [];
  settingsFile = watch(SETTINGS_FILE, (content, tag, error) => {
    if (error) {
      settingsRead = {
        error: isDenied(error) ? ADMIN_NEEDED : `Could not read ${SETTINGS_FILE}: ${error.message}`,
      };
    } else {
      try {
        settingsRead = {
          desired: dropRetiredKeys(parseSettings(SETTINGS_FILE, content)),
          tag: tag ?? "-",
        };
      } catch (e) {
        settingsRead = { error: errMsg(e) };
      }
    }
    compose();
  });
  watch(APPLIED_SETTINGS_FILE, (content, _tag, error) => {
    appliedRead = lenientJson(content, error);
    companionChanged();
  });
  watch(EFFECTIVE_FILE, (content, _tag, error) => {
    effectiveRead = lenientJson(content, error) ?? {};
    companionChanged();
  });
  watch(REBUILD_STATUS_FILE, (content, _tag, error) => {
    emit({ ...state, rebuild: error ? null : parseRebuildRecord(content) });
  });
}

function ensureStarted() {
  if (started) {
    return;
  }
  started = true;
  open();
  onAdminChange(open);
  cockpit.addEventListener("visibilitychange", () => {
    if (!cockpit.hidden) {
      open();
    }
  });
}

export function subscribeRouterState(listener: () => void): () => void {
  ensureStarted();
  listeners.add(listener);
  return () => {
    listeners.delete(listener);
  };
}

export const getRouterState = (): RouterState => state;

export function useRouterState(): RouterState {
  return useSyncExternalStore(subscribeRouterState, getRouterState);
}

// Resolves once the settings have changed from what they are now, or after
// `ms` in any case.
export function settingsChanged(ms = 3000): Promise<void> {
  return new Promise((resolve) => {
    const before = state.settings;
    const done = () => {
      window.clearTimeout(timer);
      listeners.delete(check);
      resolve();
    };
    const check = () => {
      if (state.settings !== before) {
        done();
      }
    };
    const timer = window.setTimeout(done, ms);
    listeners.add(check);
  });
}

// Replace the settings file with `obj`. `base` is the state `obj` was built
// from: nothing is written unless it came from a successful read, and the
// bridge refuses the write (SettingsConflictError) once the file has changed since.
// Validated against the schema first, so an invalid config never reaches
// disk (and therefore never reaches a rebuild).
export async function writeSettings(obj: Json, base: LoadedSettings | null): Promise<void> {
  if (!base || !isLoaded(base) || !settingsFile) {
    throw new Error(NOT_LOADED);
  }
  const errors = validateSettings(obj);
  if (errors.length > 0) {
    throw new Error(`Configuration does not match the schema:\n${errors.join("\n")}`);
  }
  try {
    await settingsFile.replace(`${JSON.stringify(obj, null, 2)}\n`, base.tag);
  } catch (e) {
    const problem = typeof e === "object" && e !== null && "problem" in e ? e.problem : undefined;
    if (problem === "change-conflict") {
      throw new SettingsConflictError();
    }
    throw isDenied(e) ? new Error(ADMIN_NEEDED, { cause: e }) : e;
  }
}
