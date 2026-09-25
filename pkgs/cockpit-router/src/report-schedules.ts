// Scheduled-report rules that need no browser: the default name for a new
// schedule, and the checks modules/reporting.nix applies to a schedule on
// rebuild. The committed schema drops `types.strMatching` patterns, so Ajv
// lets a bad name or time through and only the rebuild would catch it.
//
// Checks return a code rather than a sentence, so this module stays free of
// `cockpit` (node --test runs it); reports.tsx turns them into translated text.
//
// Imports carry their .ts extension: node --test resolves them as plain ESM.
import type { ReportSchedule } from "./types.ts";

// reporting.nix types `name` as strMatching "[A-Za-z0-9_-]+": it becomes the
// router-report-<name> unit and the generated file names. Names are unique.
const NAME_RE = /^[A-Za-z0-9_-]+$/;

// reporting.nix types `time` as strMatching "[0-2][0-9]:[0-5][0-9]". Kept
// identical to it, so hours 24-29 pass here as they do there.
const TIME_RE = /^[0-2]\d:[0-5]\d$/;

export type ScheduleNameIssue = "empty" | "pattern" | "duplicate";

// `report-<n>`, counting on from the number of schedules and skipping any name
// already in use.
export function nextScheduleName(schedules: Pick<ReportSchedule, "name">[]): string {
  const names = new Set(schedules.map((sc) => sc.name));
  let i = schedules.length + 1;
  while (names.has(`report-${i}`)) {
    i += 1;
  }
  return `report-${i}`;
}

// The card saves the name exactly as typed, so it is checked untrimmed.
export function scheduleNameError(
  name: string,
  otherNames: readonly string[],
): ScheduleNameIssue | null {
  if (name === "") {
    return "empty";
  }
  if (!NAME_RE.test(name)) {
    return "pattern";
  }
  if (otherNames.includes(name)) {
    return "duplicate";
  }
  return null;
}

// An absent time takes the module default; a present one must match.
export function timeError(time: string | undefined): "format" | null {
  return time === undefined || TIME_RE.test(time) ? null : "format";
}
