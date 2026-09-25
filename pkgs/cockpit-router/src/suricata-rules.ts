// A light lint for the Threat Protection → Settings "Extra local rules" box.
//
// It is no rule parser: Suricata itself checks the rules when the router is
// rebuilt (the `suricata -T` system check in modules/threat-protection.nix),
// and a rule it rejects fails the apply, unless router.suricata.checkRulesAtBuild
// turns that check off (see rulesTestedAtBuild). This catches the common slips
// before that, while typing: a line that is not a rule, a missing `sid`, a SID
// used twice or one of the built-in rules' SIDs.
//
// It reads the text the way Suricata's rule loader does: a line whose first
// character is `#` is a comment, and so is one starting with a space or tab
// (which surprises people, hence a warning); a trailing `\` joins the next
// line onto the rule. Issues carry a code rather than a sentence, so this
// module stays free of `cockpit` (node --test runs it); suricata.tsx turns
// them into translated text.

import { getPath } from "./settings-json.ts";
import type { Json } from "./settings-json.ts";

// The built-in rules (localSuricataRules in modules/threat-protection.nix)
// use 1000001–1000007, 1000010 and 1000011; the range between stays reserved.
export const BUILTIN_SID_MIN = 1_000_001;
export const BUILTIN_SID_MAX = 1_000_011;

// Suricata 8's rule actions, except firewall mode's `accept`.
export const RULE_ACTIONS = [
  "alert",
  "drop",
  "pass",
  "reject",
  "rejectsrc",
  "rejectdst",
  "rejectboth",
  "config",
];

export type RuleIssueCode =
  | "indented"
  | "noAction"
  | "noClosingParen"
  | "noSid"
  | "dupSid"
  | "builtinSid";

export interface RuleIssue {
  level: "error" | "warning";
  code: RuleIssueCode;
  // 1-based line in the text where the rule starts.
  line: number;
  sid?: number;
  // For dupSid: the line that already uses the SID.
  firstLine?: number;
}

interface Rule {
  line: number;
  text: string;
}

// Logical rules with the line each starts on, comments and blanks dropped.
// Indented lines are reported, not returned: Suricata never loads them.
function splitRules(text: string, issues: RuleIssue[]): Rule[] {
  const rules: Rule[] = [];
  let pending: Rule | null = null;
  const lines = text.split(/\r?\n/);
  for (const [i, raw] of lines.entries()) {
    if (pending) {
      pending.text += raw.trimEnd();
    } else if (raw.trim() === "" || raw.startsWith("#")) {
      continue;
    } else if (/^[ \t]/.test(raw)) {
      if (!raw.trim().startsWith("#")) {
        issues.push({ level: "warning", code: "indented", line: i + 1 });
      }
      continue;
    } else {
      pending = { line: i + 1, text: raw.trimEnd() };
    }
    if (pending.text.endsWith("\\")) {
      pending.text = pending.text.slice(0, -1);
    } else {
      rules.push(pending);
      pending = null;
    }
  }
  if (pending) {
    rules.push(pending);
  }
  return rules;
}

const sidOf = (rule: string): number | null => {
  const m = /[(;]\s*sid\s*:\s*(\d+)\s*[;)]/.exec(rule);
  return m?.[1] === undefined ? null : Number(m[1]);
};

export function lintExtraRules(text: string): RuleIssue[] {
  const issues: RuleIssue[] = [];
  const seen = new Map<number, number>();
  for (const { line, text: rule } of splitRules(text, issues)) {
    const action = rule.split(/\s/, 1)[0]?.toLowerCase() ?? "";
    if (!RULE_ACTIONS.includes(action)) {
      issues.push({ level: "error", code: "noAction", line });
      continue;
    }
    if (!rule.endsWith(")")) {
      issues.push({ level: "error", code: "noClosingParen", line });
    }
    const sid = sidOf(rule);
    if (sid === null) {
      issues.push({ level: "error", code: "noSid", line });
      continue;
    }
    if (sid >= BUILTIN_SID_MIN && sid <= BUILTIN_SID_MAX) {
      issues.push({ level: "error", code: "builtinSid", line, sid });
    }
    const firstLine = seen.get(sid);
    if (firstLine === undefined) {
      seen.set(sid, line);
    } else {
      issues.push({ level: "error", code: "dupSid", line, sid, firstLine });
    }
  }
  return issues.toSorted((a, b) => a.line - b.line);
}

// Whether applying runs that `suricata -T` check on the local rules. Its switch,
// router.suricata.checkRulesAtBuild, is Nix-only (hidden from the schema) but
// still reaches effective.json with the rest of router.suricata. Missing, as
// when effective.json can't be read and loads as `{}`, means on: the default.
export const rulesTestedAtBuild = (effective: Json): boolean =>
  getPath(effective, "suricata.checkRulesAtBuild") !== false;
