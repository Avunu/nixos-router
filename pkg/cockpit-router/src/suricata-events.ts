// Suricata event source backed by a dedicated systemd-journald namespace.
//
// The suricata service runs with LogNamespace=suricata (see flake.nix), so its
// output — including the EVE "alert" stream it writes via syslog — lands in a
// dedicated journal queried with `journalctl --namespace suricata`. We read it
// with cockpit.spawn (Cockpit's journal.journalctl helper can't target a
// namespace) and parse each entry's MESSAGE back into `Ev`.
//   • followEvents() — preload recent + live-tail (the Events tab)
//   • fetchEvents()  — windowed history for Overview/Statistics aggregation
import { errMsg } from "./nix";

export interface Ev {
  timestamp: string;
  event_type: string;
  src_ip?: string;
  dest_ip?: string;
  src_port?: number;
  dest_port?: number;
  proto?: string;
  app_proto?: string;
  flow_id?: number;
  community_id?: string;
  alert?: {
    signature?: string;
    signature_id?: number;
    category?: string;
    severity?: number;
    action?: string; // "allowed" | "blocked"
    gid?: number;
    rev?: number;
  };
}

// journalctl args common to every query: the suricata namespace, JSON output.
const BASE = ["journalctl", "--namespace", "suricata", "-o", "json"];

// Default cap for a windowed history query — mirrors Cockpit's own Logs page
// (QUERY_COUNT = 5000) so a wide "All" range can't blow up the browser.
export const DEFAULT_CAP = 5000;

// Parse one EVE JSON record into an alert/drop event (or null). Defensive
// against any syslog framing by seeking the first '{'.
function parseEve(msg: string): Ev | null {
  const start = msg.indexOf("{");
  if (start === -1) {
    return null;
  }
  try {
    const o = JSON.parse(msg.slice(start)) as Ev;
    if (o && (o.event_type === "alert" || o.event_type === "drop")) {
      return o;
    }
    return null;
  } catch {
    return null;
  }
}

// Parse one `journalctl -o json` line: take its MESSAGE (the raw EVE record).
// Non-JSON suricata log lines in the same namespace parse to null and are
// skipped.
function parseLine(line: string): Ev | null {
  if (!line.trim()) {
    return null;
  }
  try {
    const rec = JSON.parse(line) as { MESSAGE?: unknown };
    return typeof rec.MESSAGE === "string" ? parseEve(rec.MESSAGE) : null;
  } catch {
    return null;
  }
}

export interface FollowHandle {
  stop: () => void;
}

// Preload the most recent `count` events, then live-tail new ones. `onBatch`
// fires with each batch of newly parsed events (oldest-first within the batch);
// callers typically prepend them to their list.
export function followEvents(
  count: number,
  onBatch: (evs: Ev[]) => void,
  onError?: (msg: string) => void,
): FollowHandle {
  let buf = "";
  const proc = cockpit.spawn([...BASE, "-n", String(count), "-f"], {
    superuser: "try",
    err: "message",
  });
  void proc.stream((data: string) => {
    buf += data;
    const lines = buf.split("\n");
    buf = lines.pop() ?? "";
    const evs: Ev[] = [];
    for (const line of lines) {
      const ev = parseLine(line);
      if (ev) {
        evs.push(ev);
      }
    }
    if (evs.length > 0) {
      onBatch(evs);
    }
  });
  proc.catch((e: unknown) => {
    const msg = errMsg(e);
    // close() rejects the promise with "cancelled" — that's our own stop().
    if (onError && !/cancelled/i.test(msg)) {
      onError(msg);
    }
  });
  return { stop: () => proc.close() };
}

export interface FetchResult {
  events: Ev[];
  capped: boolean; // true if the cap was hit (older events may be missing)
}

// Fetch alert/drop events in [since, until], oldest-first, capped at `cap`.
// `since`/`until` are journalctl time strings (see sinceDays). Omit `since` for
// the full retained window ("All").
export function fetchEvents(opts: {
  since?: string;
  until?: string;
  cap?: number;
}): Promise<FetchResult> {
  const cap = opts.cap ?? DEFAULT_CAP;
  const args = [...BASE, "--no-pager", "-n", String(cap)];
  if (opts.since) {
    args.push("--since", opts.since);
  }
  if (opts.until) {
    args.push("--until", opts.until);
  }
  return cockpit
    .spawn(args, { superuser: "try", err: "message" })
    .then((out: string) => {
      const events: Ev[] = [];
      for (const line of out.split("\n")) {
        const ev = parseLine(line);
        if (ev) {
          events.push(ev);
        }
      }
      return { events, capped: events.length >= cap };
    })
    .catch((e: unknown): FetchResult => {
      throw new Error(errMsg(e));
    });
}

// journalctl --since string for "N days ago", formatted in local time
// ("YYYY-MM-DD HH:MM:SS") which journalctl interprets in the system timezone.
export function sinceDays(days: number): string {
  const d = new Date(Date.now() - days * 86_400_000);
  const p = (n: number) => String(n).padStart(2, "0");
  return `${d.getFullYear()}-${p(d.getMonth() + 1)}-${p(d.getDate())} ${p(d.getHours())}:${p(d.getMinutes())}:${p(d.getSeconds())}`;
}

// Event severity → PatternFly Label color (sev 1 = high). Shared by the views.
export const sevColor = (s?: number): "red" | "orange" | "grey" =>
  s === 1 ? "red" : s === 2 ? "orange" : "grey";

export const sevLabel = (s?: number): string =>
  s === 1 ? "High" : s === 2 ? "Medium" : s === 3 ? "Low" : "Info";

// Whether an event resulted in the packet being blocked (drop event, or an
// alert whose action was "blocked" in IPS mode).
export const wasBlocked = (e: Ev): boolean =>
  e.event_type === "drop" || e.alert?.action === "blocked";
