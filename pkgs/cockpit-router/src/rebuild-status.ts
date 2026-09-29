// What the router is doing about rebuilds, from two sources every frame can
// read even with Limited access: the systemd units' states (D-Bus) and the
// record router-rebuild keeps in /run/cockpit-router/rebuild.json.
//
// router-rebuild (modules/system.nix) runs every rebuild the admin asks for —
// from Cockpit or a shell — in the transient router-rebuild.service. A
// successful run's unit is gone as soon as it ends, so how a run ended comes
// from the record its ExecStopPost writes; a failed one stays loaded until
// someone dismisses it. The nightly upgrade and a switch started by hand run
// outside that unit and are only watched. Kept free of the `cockpit` global so
// `node --test` can import it.

export type RebuildOp = "apply" | "check" | "update" | "rollback";

export const REBUILD_OPS: readonly RebuildOp[] = ["apply", "check", "update", "rollback"];

export const isRebuildOp = (op: string): op is RebuildOp =>
  (REBUILD_OPS as readonly string[]).includes(op);

// /run/cockpit-router/rebuild.json. Written at the start of a run, completed
// by its ExecStopPost; the systemd fields are passed through as systemd
// names them ($SERVICE_RESULT, $EXIT_CODE, $EXIT_STATUS).
export interface RebuildRecord {
  op: string;
  invocation: string; // $INVOCATION_ID, hex: the run's journal match
  startedAt?: number; // epoch seconds
  systemBefore?: string; // /run/current-system when the run started
  finishedAt?: number;
  result?: string; // success | exit-code | signal | timeout | …
  exitCode?: string; // exited | killed | dumped
  exitStatus?: string; // a number, or a signal name for killed
  systemAfter?: string;
  note?: string; // "unchanged": update found nothing to rebuild
}

const str = (v: unknown): string | undefined => (typeof v === "string" ? v : undefined);
const num = (v: unknown): number | undefined =>
  typeof v === "number" && Number.isFinite(v) ? v : undefined;

// The record, or null when there is none or it is unreadable: the UI then
// knows nothing about past runs, which is never worth an error of its own.
export function parseRebuildRecord(text: string | null): RebuildRecord | null {
  if (!text?.trim()) {
    return null;
  }
  let raw: unknown;
  try {
    raw = JSON.parse(text);
  } catch {
    return null;
  }
  if (typeof raw !== "object" || raw === null) {
    return null;
  }
  const r = raw as Record<string, unknown>;
  const op = str(r["op"]);
  const invocation = str(r["invocation"]);
  if (op === undefined || invocation === undefined) {
    return null;
  }
  const record: RebuildRecord = { op, invocation };
  const optional = {
    startedAt: num(r["startedAt"]),
    systemBefore: str(r["systemBefore"]),
    finishedAt: num(r["finishedAt"]),
    result: str(r["result"]),
    exitCode: str(r["exitCode"]),
    exitStatus: str(r["exitStatus"]),
    systemAfter: str(r["systemAfter"]),
    note: str(r["note"]),
  };
  for (const [k, v] of Object.entries(optional)) {
    if (v !== undefined) {
      Object.assign(record, { [k]: v });
    }
  }
  return record;
}

export type Outcome =
  | "succeeded"
  | "unchanged" // update: the lock did not change, nothing was rebuilt
  | "cancelled"
  | "check-failed" // check: the configuration does not build
  | "switched-with-errors" // the new generation is running, but the switch reported failures
  | "failed";

const STOP_SIGNALS = new Set(["TERM", "INT", "HUP"]);

// How a finished run ended; null while it has not.
export function outcomeOf(r: RebuildRecord): Outcome | null {
  if (r.finishedAt === undefined || r.result === undefined) {
    return null;
  }
  // StopUnit SIGTERMs the main process (KillMode=mixed). systemd counts a
  // SIGTERM exit as clean, so the result may well say "success".
  if (r.exitCode === "killed" && STOP_SIGNALS.has(r.exitStatus ?? "")) {
    return "cancelled";
  }
  if (r.result === "success") {
    return r.note === "unchanged" ? "unchanged" : "succeeded";
  }
  if (r.op === "check") {
    return "check-failed";
  }
  if (r.systemBefore && r.systemAfter && r.systemBefore !== r.systemAfter) {
    return "switched-with-errors";
  }
  return "failed";
}

// Each unit's ActiveState ("" when unknown or never loaded).
export interface UnitStates {
  rebuild: string; // router-rebuild.service
  upgrade: string; // nixos-upgrade.service (the nightly upgrade)
  flakeUpdate: string; // flake-update.service (runs before it)
  switching: string; // nixos-rebuild-switch-to-configuration.service (any activation)
}

export type JobState =
  // Nothing running; `last` is the most recent finished run, if known.
  | { kind: "idle"; last: RebuildRecord | null }
  | {
      kind: "running";
      op: string; // "" until the run has written its record
      since: number | null; // epoch seconds
      invocation: string | null;
      activating: boolean; // switching to the new generation: too late to cancel
    }
  // A rebuild outside router-rebuild: the nightly upgrade, or a switch by hand.
  | { kind: "external"; what: "upgrade" | "switch" }
  // router-rebuild failed and nobody has dismissed it yet.
  | { kind: "failed"; record: RebuildRecord | null; outcome: Outcome };

const ACTIVE = new Set(["activating", "active", "deactivating", "reloading"]);
const isActive = (state: string) => ACTIVE.has(state);

export function deriveJob(units: UnitStates, record: RebuildRecord | null): JobState {
  const finished = record && outcomeOf(record) !== null ? record : null;
  if (isActive(units.rebuild)) {
    // Until this run writes its start, the record is the previous run's.
    const current = record && !finished ? record : null;
    return {
      kind: "running",
      op: current?.op ?? "",
      since: current?.startedAt ?? null,
      invocation: current?.invocation ?? null,
      activating: isActive(units.switching),
    };
  }
  if (units.rebuild === "failed") {
    const outcome = finished ? outcomeOf(finished)! : "failed";
    // A run stopped on purpose is history, not an alarm — even stopped from
    // a shell, which leaves the unit failed until reset.
    if (outcome !== "cancelled") {
      return { kind: "failed", record: finished, outcome };
    }
  }
  if (isActive(units.upgrade) || isActive(units.flakeUpdate)) {
    return { kind: "external", what: "upgrade" };
  }
  if (isActive(units.switching)) {
    return { kind: "external", what: "switch" };
  }
  return { kind: "idle", last: finished };
}

// Whether a new run may start now, and if not, why (for a disabled action's
// description). Mirrors router-rebuild's own refusal.
export function busyReason(job: JobState): "running" | "upgrade" | "switch" | null {
  if (job.kind === "running") {
    return "running";
  }
  if (job.kind === "external") {
    return job.what;
  }
  return null;
}
