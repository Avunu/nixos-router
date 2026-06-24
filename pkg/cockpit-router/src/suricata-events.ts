// Suricata event source backed by the systemd journal.
//
// Suricata's second EVE output (configured in flake.nix) writes alert + drop
// events to syslog under SYSLOG_IDENTIFIER=suricata, which journald captures.
// The full eve.json file (with dns/tls/http/flow) stays on disk for forensics;
// only these security events flow through the journal so it isn't flooded.
//
// We read them with Cockpit's vendored journal helper (pkg/lib/journal.js):
//   • followEvents() — preload recent + live-tail (the Events tab)
//   • fetchEvents()  — windowed history for Overview/Statistics aggregation
// Each journal entry's MESSAGE is the raw EVE JSON, parsed back into `Ev`.
import { journal } from "journal";
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

const MATCH = "SYSLOG_IDENTIFIER=suricata";

// Default cap for a windowed history query — mirrors Cockpit's own Logs page
// (QUERY_COUNT = 5000) so a wide "All" range can't blow up the browser.
export const DEFAULT_CAP = 5000;

// Parse a journal MESSAGE (the raw EVE JSON line) into an alert/drop event.
// Defensive against any syslog framing by seeking the first '{'.
function parseMessage(msg: unknown): Ev | null {
  if (typeof msg !== "string") {
    return null;
  }
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

function collect(entries: { MESSAGE?: string }[], into: Ev[]): void {
  for (const e of entries) {
    const ev = parseMessage(e.MESSAGE);
    if (ev) {
      into.push(ev);
    }
  }
}

export interface FollowHandle {
  stop: () => void;
}

// Preload the most recent `count` events, then live-tail new ones. `onBatch`
// fires with each batch of newly parsed events (newest appended); callers
// typically prepend them to their list.
export function followEvents(
  count: number,
  onBatch: (evs: Ev[]) => void,
  onError?: (msg: string) => void,
): FollowHandle {
  const p = journal.journalctl(MATCH, { count, follow: true });
  p.stream((entries) => {
    const evs: Ev[] = [];
    collect(entries, evs);
    if (evs.length > 0) {
      onBatch(evs);
    }
  });
  p.then(null, (ex: unknown) => {
    if (onError) {
      onError(errMsg(ex));
    }
  });
  return { stop: () => p.stop() };
}

export interface FetchResult {
  events: Ev[];
  capped: boolean; // true if the cap was hit (older events may be missing)
}

// Fetch all alert/drop events in [since, until], newest-last, capped at `cap`.
// `since`/`until` are journalctl time strings (see sinceDays). Omit `since` for
// the full retained window ("All").
export function fetchEvents(opts: {
  since?: string;
  until?: string;
  cap?: number;
}): Promise<FetchResult> {
  const cap = opts.cap ?? DEFAULT_CAP;
  return new Promise<FetchResult>((resolve, reject) => {
    const events: Ev[] = [];
    const p = journal.journalctl(MATCH, {
      follow: false,
      count: cap,
      ...(opts.since ? { since: opts.since } : {}),
      ...(opts.until ? { until: opts.until } : {}),
    });
    p.stream((entries) => collect(entries, events));
    p.then(
      () => resolve({ events, capped: events.length >= cap }),
      (ex: unknown) => reject(new Error(errMsg(ex))),
    );
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
