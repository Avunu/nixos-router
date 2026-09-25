// Unit tests for the scheduled-report rules (report-schedules.ts).
//
// Their contract is agreement with modules/reporting.nix: a schedule the
// Reports page lets through must pass the module's types on rebuild. The page
// once named new schedules "Report 1", which the name pattern refuses, so every
// fresh schedule failed the apply until someone renamed it.
//
// Run with `npm test`.
import { test } from "node:test";
import assert from "node:assert/strict";

import { nextScheduleName, scheduleNameError, timeError } from "./report-schedules.ts";
import type { ReportSchedule } from "./types.ts";

void test("nextScheduleName: new names pass the module's name pattern", () => {
  assert.equal(nextScheduleName([]), "report-1");
  assert.equal(scheduleNameError(nextScheduleName([]), []), null);
  assert.equal(nextScheduleName([{ name: "weekly" }]), "report-2");
});

void test("nextScheduleName: skips names already in use", () => {
  // report-1 was removed, report-2 is still there: the next is report-3.
  assert.equal(nextScheduleName([{ name: "report-2" }]), "report-3");
  const taken = [{ name: "report-2" }, { name: "report-3" }, { name: "report-4" }];
  const next = nextScheduleName(taken);
  assert.equal(next, "report-5");
  assert.equal(
    scheduleNameError(
      next,
      taken.map((sc) => sc.name),
    ),
    null,
  );
});

void test("scheduleNameError: mirrors strMatching [A-Za-z0-9_-]+", () => {
  for (const ok of ["weekly-summary", "Daily_2", "a", "R-1"]) {
    assert.equal(scheduleNameError(ok, []), null, ok);
  }
  assert.equal(scheduleNameError("", []), "empty");
  for (const bad of ["Report 1", " weekly", "weekly ", "week.ly", "wöchentlich", "a/b"]) {
    assert.equal(scheduleNameError(bad, []), "pattern", bad);
  }
});

void test("scheduleNameError: names are unique", () => {
  assert.equal(scheduleNameError("weekly", ["daily", "weekly"]), "duplicate");
  // The module compares exactly, so a different case is another name.
  assert.equal(scheduleNameError("Weekly", ["weekly"]), null);
});

void test("timeError: mirrors strMatching [0-2][0-9]:[0-5][0-9]", () => {
  for (const ok of ["00:00", "08:00", "07:30", "23:59"]) {
    assert.equal(timeError(ok), null, ok);
  }
  // A schedule without a time takes the module default (06:00).
  const untimed: ReportSchedule = { name: "weekly" };
  assert.equal(timeError(untimed.time), null);
  for (const bad of ["", "8:00", "08:0", "08:60", "30:00", "0800", "08:00 ", "08:00:00"]) {
    assert.equal(timeError(bad), "format", bad);
  }
});
