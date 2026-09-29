// Unit tests for the section map and the change list's formatting.
//
// The coverage test is the one that matters: a settings key without an entry
// would still be listed, but under its raw name and on the wrong page.
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";

import {
  SECTION_KEYS,
  formatPath,
  formatValue,
  sectionHref,
  sectionOf,
  summarizeChanges,
} from "./sections.ts";

const schema = JSON.parse(
  readFileSync(new URL("router-settings.schema.json", import.meta.url), "utf8"),
) as { properties: Record<string, unknown> };

void test("every top-level settings key has a section", () => {
  const missing = Object.keys(schema.properties).filter((k) => !SECTION_KEYS.includes(k));
  assert.deepEqual(missing, [], "add these to SECTIONS in sections.ts");
  const stale = SECTION_KEYS.filter((k) => !(k in schema.properties));
  assert.deepEqual(stale, [], "these are no longer settings keys");
});

void test("sectionHref: the page, and the tab when there is one", () => {
  assert.equal(sectionHref(sectionOf("hosts")), "/router/hosts#/?tab=devices");
  assert.equal(sectionHref(sectionOf("dns")), "/router/dns");
  // An unknown key still lands somewhere sensible.
  assert.deepEqual(sectionOf("futureThing"), {
    key: "futureThing",
    label: "futureThing",
    page: "system",
  });
});

void test("summarizeChanges: only changed sections, by label", () => {
  const applied = {
    hostName: "r1",
    hosts: [{ name: "nas", ip: "10.0.0.2" }],
    upnp: { enable: false },
  };
  const desired = {
    hostName: "r1",
    hosts: [{ name: "nas", ip: "10.0.0.3" }],
    upnp: { enable: true },
  };
  const summary = summarizeChanges(applied, desired);
  assert.deepEqual(
    summary.map((s) => [s.section.label, s.changes.length]),
    [
      ["Hosts", 1],
      ["UPnP", 1],
    ],
  );
  assert.equal(formatPath(summary[0]!.changes[0]!.path), "“nas” › ip");
  assert.deepEqual(summarizeChanges(applied, applied), []);
});

void test("formatPath and formatValue read as one line", () => {
  assert.equal(
    formatPath(["dns", "technitium", "upstreamServers", 1]),
    "technitium › upstreamServers › #2",
  );
  assert.equal(formatPath(["hostName"]), "");
  assert.equal(formatValue(), "—");
  assert.equal(formatValue([]), "[]");
  assert.equal(formatValue(["a", "b"]), "[2]");
  assert.equal(formatValue({ name: "nas", ip: "x" }), "“nas”");
  assert.equal(formatValue({ ip: "x" }), "{…}");
  assert.equal(formatValue(true), "true");
  assert.equal(formatValue("x".repeat(80)).length, 60);
});
