// Unit tests for reading rebuild state: the record router-rebuild keeps and
// the reducer that turns unit states plus that record into what the UI shows.
//
// The cases that matter are the ones that used to be invisible: a run that
// outlived the page that started it, a failure seen from another browser, and
// the nightly upgrade running while someone asks to apply.
import { test } from "node:test";
import assert from "node:assert/strict";

import { busyReason, deriveJob, outcomeOf, parseRebuildRecord } from "./rebuild-status.ts";
import type { RebuildRecord, UnitStates } from "./rebuild-status.ts";

const idleUnits: UnitStates = {
  rebuild: "",
  upgrade: "inactive",
  flakeUpdate: "inactive",
  switching: "",
};
const started: RebuildRecord = {
  op: "apply",
  invocation: "abc",
  startedAt: 100,
  systemBefore: "/nix/store/old-system",
};
const ended = (fields: Partial<RebuildRecord>): RebuildRecord => ({
  ...started,
  finishedAt: 200,
  systemAfter: "/nix/store/old-system",
  ...fields,
});

void test("parseRebuildRecord: lenient, and null for anything unusable", () => {
  assert.equal(parseRebuildRecord(null), null);
  assert.equal(parseRebuildRecord(""), null);
  assert.equal(parseRebuildRecord("{not json"), null);
  assert.equal(parseRebuildRecord('{"op":"apply"}'), null);
  assert.deepEqual(
    parseRebuildRecord('{"op":"apply","invocation":"abc","startedAt":100,"result":7}'),
    { op: "apply", invocation: "abc", startedAt: 100 },
  );
});

void test("outcomeOf: how a run ended", () => {
  assert.equal(outcomeOf(started), null);
  assert.equal(outcomeOf(ended({ result: "success" })), "succeeded");
  assert.equal(
    outcomeOf(ended({ op: "update", result: "success", note: "unchanged" })),
    "unchanged",
  );
  assert.equal(
    outcomeOf(ended({ result: "signal", exitCode: "killed", exitStatus: "TERM" })),
    "cancelled",
  );
  // systemd counts a SIGTERM exit as clean: a cancel is not a success.
  assert.equal(
    outcomeOf(ended({ result: "success", exitCode: "killed", exitStatus: "TERM" })),
    "cancelled",
  );
  assert.equal(
    outcomeOf(ended({ result: "signal", exitCode: "killed", exitStatus: "KILL" })),
    "failed",
  );
  assert.equal(
    outcomeOf(ended({ op: "check", result: "exit-code", exitStatus: "1" })),
    "check-failed",
  );
  assert.equal(outcomeOf(ended({ result: "exit-code", exitStatus: "1" })), "failed");
  assert.equal(
    outcomeOf(
      ended({ result: "exit-code", exitStatus: "4", systemAfter: "/nix/store/new-system" }),
    ),
    "switched-with-errors",
  );
});

void test("deriveJob: a running unit is a running job, whoever started it", () => {
  const job = deriveJob({ ...idleUnits, rebuild: "activating" }, started);
  assert.deepEqual(job, {
    kind: "running",
    op: "apply",
    since: 100,
    invocation: "abc",
    activating: false,
  });
  // Before the new run writes its start, the finished record is the last run's.
  assert.deepEqual(
    deriveJob({ ...idleUnits, rebuild: "activating" }, ended({ result: "success" })),
    {
      kind: "running",
      op: "",
      since: null,
      invocation: null,
      activating: false,
    },
  );
  // Too late to cancel once the switch is under way.
  const switching = deriveJob(
    { ...idleUnits, rebuild: "activating", switching: "active" },
    started,
  );
  assert.equal(switching.kind === "running" && switching.activating, true);
});

void test("deriveJob: a failed unit is an alarm until dismissed, except a cancel", () => {
  const failed = ended({ result: "exit-code", exitStatus: "1" });
  assert.deepEqual(deriveJob({ ...idleUnits, rebuild: "failed" }, failed), {
    kind: "failed",
    record: failed,
    outcome: "failed",
  });
  // Dismissed (reset-failed): the unit is gone and the run is history.
  assert.deepEqual(deriveJob(idleUnits, failed), { kind: "idle", last: failed });
  const cancelled = ended({ result: "signal", exitCode: "killed", exitStatus: "TERM" });
  assert.deepEqual(deriveJob({ ...idleUnits, rebuild: "failed" }, cancelled), {
    kind: "idle",
    last: cancelled,
  });
});

void test("deriveJob: the nightly upgrade and a hand-run switch block a new run", () => {
  const upgrading = deriveJob({ ...idleUnits, upgrade: "activating" }, null);
  assert.deepEqual(upgrading, { kind: "external", what: "upgrade" });
  assert.equal(busyReason(upgrading), "upgrade");
  assert.equal(busyReason(deriveJob({ ...idleUnits, flakeUpdate: "activating" }, null)), "upgrade");
  assert.equal(busyReason(deriveJob({ ...idleUnits, switching: "active" }, null)), "switch");
  assert.equal(busyReason(deriveJob(idleUnits, null)), null);
});
