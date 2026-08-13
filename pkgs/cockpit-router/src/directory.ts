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

// One read of both state files. Every screen offering a directory name field
// needs `unresolved` alongside the resolved users/groups, because SSSD is not
// enumerated: the picker is an autocomplete, not a closed list, and the only
// way to tell a valid new name from a typo is what the last sync could resolve.
export async function loadDirectoryAll(): Promise<{
  state: DirectoryState | null;
  status: DirectoryStatus | null;
}> {
  const [state, status] = await Promise.all([loadDirectory(), loadDirectoryStatus()]);
  return { state, status };
}

// Case-insensitive membership test for the unresolved list.
export function isUnresolved(status: DirectoryStatus | null, name: string): boolean {
  const n = name.trim().toLowerCase();
  return n !== "" && (status?.unresolved ?? []).some((u) => u.toLowerCase() === n);
}

// Kick the oneshot sync unit; callers re-read state/status shortly afterwards.
export function syncNow(): Promise<void> {
  return cockpit
    .spawn(["systemctl", "start", "router-directory-sync.service"], { superuser: "require" })
    .then(() => {});
}
