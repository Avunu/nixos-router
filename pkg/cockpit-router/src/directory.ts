// Readers for the directory-sync runtime state (read-only JSON files written by
// router-directory-sync) plus the manual "Sync now" trigger. The state files are
// root-owned; a Cockpit administrative session reads them via superuser "try".
import { DIRECTORY_STATE_PATH, DIRECTORY_STATUS_PATH } from "./nix";
import type { DirectoryState, DirectoryStatus } from "./types";

// Read + parse one of the state files; absent or invalid JSON → null (the UI
// treats both as "no directory data yet").
async function readJsonFile<T>(path: string): Promise<T | null> {
  try {
    const raw = await cockpit.file(path, { superuser: "try" }).read();
    if (!raw || !raw.trim()) {
      return null;
    }
    return JSON.parse(raw) as T;
  } catch {
    return null;
  }
}

export function loadDirectory(): Promise<DirectoryState | null> {
  return readJsonFile<DirectoryState>(DIRECTORY_STATE_PATH);
}

export function loadDirectoryStatus(): Promise<DirectoryStatus | null> {
  return readJsonFile<DirectoryStatus>(DIRECTORY_STATUS_PATH);
}

// Kick the oneshot sync unit; callers re-read state/status shortly afterwards.
export function syncNow(): Promise<void> {
  return cockpit
    .spawn(["systemctl", "start", "router-directory-sync.service"], { superuser: "require" })
    .then(() => {});
}
