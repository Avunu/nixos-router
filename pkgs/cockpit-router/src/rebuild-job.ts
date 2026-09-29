// Rebuilds as every page sees them, and the actions that start and stop them.
//
// router-rebuild (modules/system.nix) runs each rebuild in the transient
// router-rebuild.service, so it outlives the page, browser or SSH session
// that asked for it, and two never overlap. Every page watches that unit, the
// nightly upgrade and any activation through Cockpit's unprivileged systemd
// watcher (pkg/lib/service.js), plus router-rebuild's record, and derives one
// JobState from them (rebuild-status.ts) — the same in every page and
// browser, and readable with Limited access. Starting, cancelling and
// dismissing need administrative access. The rebuild's output is never shown
// here: it is in the journal, which Cockpit's Logs page follows (logUrl).
import { useEffect, useState, useSyncExternalStore } from "react";
import { proxy } from "service";
import { validateSettings } from "./schema";
import { NOT_LOADED } from "./settings-read";
import { getRouterState, subscribeRouterState } from "./router-state";
import { busyReason, deriveJob } from "./rebuild-status";
import type { JobState, Outcome, RebuildOp, UnitStates } from "./rebuild-status";
import { INITIAL_PROGRESS, progressOf } from "./rebuild-progress";
import type { RebuildProgress } from "./rebuild-progress";

export const REBUILD_UNIT = "router-rebuild.service";

const UNIT_NAMES: Record<keyof UnitStates, string> = {
  rebuild: REBUILD_UNIT,
  upgrade: "nixos-upgrade.service",
  flakeUpdate: "flake-update.service",
  switching: "nixos-rebuild-switch-to-configuration.service",
};

let units: UnitStates = { rebuild: "", upgrade: "", flakeUpdate: "", switching: "" };
let job: JobState = deriveJob(units, null);
let jobKey = JSON.stringify(job);
const listeners = new Set<() => void>();
let started = false;

function update() {
  const next = deriveJob(units, getRouterState().rebuild);
  const key = JSON.stringify(next);
  if (key !== jobKey) {
    job = next;
    jobKey = key;
    for (const listener of listeners) {
      listener();
    }
  }
}

function watchUnit(key: keyof UnitStates, name: string) {
  const unit = proxy(name);
  unit.addEventListener("changed", () => {
    units = { ...units, [key]: unit.unit?.ActiveState ?? "" };
    update();
  });
}

function ensureStarted() {
  if (started) {
    return;
  }
  started = true;
  for (const [key, name] of Object.entries(UNIT_NAMES) as [keyof UnitStates, string][]) {
    watchUnit(key, name);
  }
  subscribeRouterState(update);
}

export function subscribeRebuildJob(listener: () => void): () => void {
  ensureStarted();
  listeners.add(listener);
  return () => {
    listeners.delete(listener);
  };
}

export const getRebuildJob = (): JobState => job;

export function useRebuildJob(): JobState {
  return useSyncExternalStore(subscribeRebuildJob, getRebuildJob);
}

// Start `op` in router-rebuild.service. It returns once the unit is queued;
// the watchers take it from there. router-rebuild itself refuses (and says
// why) while another rebuild runs. Apply checks the saved settings against
// the schema first, as the build would, but minutes sooner.
export async function startRebuild(op: RebuildOp): Promise<void> {
  if (op === "apply") {
    const { settings, error } = getRouterState();
    if (!settings) {
      throw new Error(error || NOT_LOADED);
    }
    const errors = validateSettings(settings.desired);
    if (errors.length > 0) {
      throw new Error(`Configuration does not match the schema:\n${errors.join("\n")}`);
    }
  }
  await cockpit.spawn(["router-rebuild", "--no-block", op], {
    superuser: "require",
    err: "message",
  });
}

// SIGTERM to nixos-rebuild (router-rebuild uses KillMode=mixed). Only offered
// before activation: the switch runs in its own unit and is left to finish.
export async function cancelRebuild(): Promise<void> {
  await cockpit.spawn(["systemctl", "stop", "--no-block", REBUILD_UNIT], {
    superuser: "require",
    err: "message",
  });
}

// Clear a failed run for everyone; the record keeps it as the last run.
export async function dismissRebuild(): Promise<void> {
  await cockpit.spawn(["systemctl", "reset-failed", REBUILD_UNIT], {
    superuser: "require",
    err: "message",
  });
}

// Cockpit's Logs page on this rebuild's unit from when it started, following
// new lines as they come. Includes systemd's own lines about the unit, which
// an invocation match would leave out.
export function logUrl(since: number | null | undefined): string {
  const params = [`priority=debug`, `service=${REBUILD_UNIT}`];
  if (since) {
    const at = new Date(since * 1000);
    const pad = (n: number) => String(n).padStart(2, "0");
    params.push(
      `since=${at.getFullYear()}-${pad(at.getMonth() + 1)}-${pad(at.getDate())} ` +
        `${pad(at.getHours())}:${pad(at.getMinutes())}:${pad(at.getSeconds())}`,
    );
  }
  return `/system/logs#/?${params.map((p) => encodeURI(p)).join("&")}`;
}

// How far the running rebuild has got, from its journal as it is written;
// null until there is something to show (or without access to the journal).
// Follow only in a page that is shown: the others need the state, not this.
export function useRebuildProgress(invocation: string | null): RebuildProgress | null {
  const [followed, setFollowed] = useState<{
    invocation: string;
    progress: RebuildProgress;
  } | null>(null);
  useEffect(() => {
    if (!invocation) {
      return;
    }
    let progress = INITIAL_PROGRESS;
    let partial = "";
    const proc = cockpit.spawn(
      [
        "journalctl",
        "--follow",
        "--lines=all",
        "--output=cat",
        `_SYSTEMD_INVOCATION_ID=${invocation}`,
      ],
      { superuser: "try", err: "message", batch: 16_384, latency: 500 },
    );
    void proc.stream((data: string) => {
      const lines = (partial + data).split("\n");
      partial = lines.pop() ?? "";
      progress = progressOf(lines, progress);
      setFollowed({ invocation, progress });
    });
    // Closed on unmount; a journal this session cannot read just shows nothing.
    proc.catch(() => {});
    return () => proc.close();
  }, [invocation]);
  return followed && followed.invocation === invocation ? followed.progress : null;
}

// ── Wording shared by the save footer and the changes panel ─────────────────
const _ = cockpit.gettext;

// What a run is doing, as a status line: "Applying settings…".
export function runningLabel(op: string): string {
  const labels: Record<string, string> = {
    apply: _("Applying settings…"),
    check: _("Checking the configuration…"),
    update: _("Updating the system…"),
    rollback: _("Rolling back…"),
  };
  return labels[op] ?? _("Rebuilding…");
}

// How a finished run ended, as a status line.
export function outcomeLabel(outcome: Outcome): string {
  const labels: Record<Outcome, string> = {
    succeeded: _("Completed"),
    unchanged: _("Already up to date"),
    cancelled: _("Cancelled"),
    "check-failed": _("The configuration does not build"),
    "switched-with-errors": _("Switched, with errors"),
    failed: _("Failed"),
  };
  return labels[outcome];
}

// The name of an operation, for "Last run: Apply settings — Completed".
export function opLabel(op: string): string {
  const labels: Record<string, string> = {
    apply: _("Apply settings"),
    check: _("Check configuration"),
    update: _("Update system"),
    rollback: _("Roll back"),
  };
  return labels[op] ?? _("Rebuild");
}

// Why a new run cannot start now, for a disabled action's description; ""
// when one can.
export function busyLabel(state: JobState): string {
  const reason = busyReason(state);
  const labels = {
    running: _("A rebuild is already running"),
    upgrade: _("The nightly upgrade is running"),
    switch: _("A configuration switch is in progress"),
  };
  return reason ? labels[reason] : "";
}
