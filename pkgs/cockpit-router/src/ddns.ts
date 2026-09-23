// Dynamic DNS runtime: the router-ddns status file (read-only, written by the
// timer-driven oneshot) plus the manual "Update now" trigger and the helper
// that stores the Cloudflare API token as a root-owned file.
import { DDNS_STATUS_PATH } from "./nix";
import type { DdnsStatus } from "./types";

export const DEFAULT_TOKEN_FILE = "/etc/router/secrets/cloudflare-ddns.token";

// The unit runs as a DynamicUser, so its state lives under the 0700
// /var/lib/private; an administrative session reads it through superuser.
// Absent, unreadable or invalid → null ("no status yet").
export async function loadDdnsStatus(): Promise<DdnsStatus | null> {
  try {
    const raw = await cockpit.file(DDNS_STATUS_PATH, { superuser: "try" }).read();
    if (!raw || !raw.trim()) {
      return null;
    }
    return JSON.parse(raw) as DdnsStatus;
  } catch {
    return null;
  }
}

// Start the oneshot; it returns when the run finishes, so the caller can
// re-read the status straight away. A failed run rejects (non-zero exit), but
// the status file still says why.
export function updateNow(): Promise<void> {
  return cockpit
    .spawn(["systemctl", "start", "router-ddns.service"], { superuser: "require", err: "message" })
    .then(() => {});
}

// Write the token to `path` (mode 0600, directory 0700). The token travels on
// stdin, never on the command line, where any local user could read it from
// the process list.
export function saveToken(path: string, token: string): Promise<void> {
  return cockpit
    .spawn(
      ["sh", "-c", 'umask 077 && install -d -m700 "$(dirname "$1")" && cat > "$1"', "--", path],
      { superuser: "require", err: "message" },
    )
    .input(`${token.trim()}\n`)
    .then(() => {});
}
