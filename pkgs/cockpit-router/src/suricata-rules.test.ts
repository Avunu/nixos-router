// Unit tests for the extra-rules lint (suricata-rules.ts).
//
// The lint is a courtesy ahead of the `suricata -T` system check that fails a
// rebuild on a broken rule: it should flag what Suricata would reject or skip,
// and stay quiet on anything Suricata loads.
//
// Run with `npm test`.
import { test } from "node:test";
import assert from "node:assert/strict";

import { lintExtraRules } from "./suricata-rules.ts";

const RDP = `alert tcp $HOME_NET any -> $EXTERNAL_NET 3389 (msg:"LOCAL outbound RDP"; flow:to_server; flags:S; sid:1000100; rev:1;)`;

const codes = (text: string) => lintExtraRules(text).map((it) => `${it.line}:${it.code}`);

void test("valid rules, comments and blank lines pass", () => {
  assert.deepEqual(codes(""), []);
  assert.deepEqual(
    codes(
      [
        "# local additions",
        RDP,
        "",
        `drop icmp any any -> any any (msg:"x"; sid: 1000101 ; rev:1;)`,
        `Pass tcp any any -> any any (msg:"y"; sid:1000102;)`,
        `rejectboth tcp any any -> any any (msg:"z"; sid:1000103;)`,
        "",
      ].join("\n"),
    ),
    [],
  );
});

void test("a trailing backslash continues the rule onto the next line", () => {
  assert.deepEqual(
    codes(
      [
        `alert tcp any any -> any 22 (msg:"ssh"; \\`,
        `    flow:to_server; sid:1000104; rev:1;)`,
        `alert tcp any any -> any 23 (msg:"telnet"; sid:1000105;)`,
      ].join("\n"),
    ),
    [],
  );
});

void test("a line that isn't a rule is an error", () => {
  const issues = lintExtraRules(
    ["hello world", `alrt tcp any any -> any any (sid:1000106;)`].join("\n"),
  );
  assert.deepEqual(
    issues.map((it) => [it.line, it.level, it.code]),
    [
      [1, "error", "noAction"],
      [2, "error", "noAction"],
    ],
  );
});

void test("a rule must end with ) and carry a numeric sid", () => {
  assert.deepEqual(codes(`alert tcp any any -> any any (msg:"cut off"; sid:1000107;`), [
    "1:noClosingParen",
  ]);
  assert.deepEqual(codes(`alert tcp any any -> any any (msg:"no sid"; rev:1;)`), ["1:noSid"]);
  assert.deepEqual(codes(`alert tcp any any -> any any (msg:"x"; sid:abc;)`), ["1:noSid"]);
  // `sid:` inside the message is not the option.
  assert.deepEqual(codes(`alert tcp any any -> any any (msg:"sid:1000108;"; rev:1;)`), ["1:noSid"]);
});

void test("duplicate SIDs point back at the first use", () => {
  const issues = lintExtraRules([RDP, "", RDP.replace("RDP", "RDP again")].join("\n"));
  assert.equal(issues.length, 1);
  assert.deepEqual(issues[0], {
    level: "error",
    code: "dupSid",
    line: 3,
    sid: 1_000_100,
    firstLine: 1,
  });
});

void test("the built-in rules' SID range is reserved", () => {
  for (const sid of [1_000_001, 1_000_008, 1_000_011]) {
    assert.deepEqual(codes(`alert ip any any -> any any (msg:"x"; sid:${sid};)`), ["1:builtinSid"]);
  }
  for (const sid of [1_000_000, 1_000_012]) {
    assert.deepEqual(codes(`alert ip any any -> any any (msg:"x"; sid:${sid};)`), []);
  }
});

void test("an indented rule is a warning, since Suricata skips it", () => {
  const issues = lintExtraRules(
    [RDP, `  alert ip any any -> any any (msg:"x"; sid:1000109;)`, "\t# note"].join("\n"),
  );
  assert.deepEqual(
    issues.map((it) => [it.line, it.level, it.code]),
    [[2, "warning", "indented"]],
  );
});

void test("issues come back in line order", () => {
  assert.deepEqual(
    codes(["  indented", "junk", `alert ip any any -> any any (msg:"x"; sid:1000001;)`].join("\n")),
    ["1:indented", "2:noAction", "3:builtinSid"],
  );
});
