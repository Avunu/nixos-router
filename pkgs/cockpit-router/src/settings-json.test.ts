// Unit tests for the pure settings-JSON helpers.
//
// isLocked earns most of the attention here. It decides whether a form field is
// editable, and when it was wrong it did not fail loudly — it silently greyed
// out the entire Access Policies page while the data underneath was correct.
// The cases below encode the distinction it gets wrong most easily: Nix ADDING
// a default the settings JSON omitted (not a lock) versus Nix CHANGING or
// DROPPING something the JSON set (a lock).
//
// Run with `npm test` (node --test strips the types; no runner dependency).
import { test } from "node:test";
import assert from "node:assert/strict";

import type { Json, SettingsState } from "./settings-json.ts";
import { changedTopKeys, deepEqual, getPath, isLocked, setPath } from "./settings-json.ts";

const state = (effective: Json, applied: Json): SettingsState => ({
  desired: applied,
  effective,
  applied,
});

// A migrated Access Policies section, trimmed to the shape that matters: the
// settings JSON omits the list-valued fields, and the module defaults them.
const appliedPolicies: Json = {
  defaultPolicy: "Base",
  policies: [
    {
      name: "Base",
      responseType: "blockingAddress",
      standardFilters: ["adaway", "adguard_ads"],
      allowDomains: ["apple.com"],
    },
  ],
  blockPage: { enable: true, contactEmail: "mail@example.org" },
};

const effectivePolicies: Json = {
  defaultPolicy: "Base",
  policies: [
    {
      name: "Base",
      responseType: "blockingAddress",
      standardFilters: ["adaway", "adguard_ads"],
      allowDomains: ["apple.com"],
      // Defaults the module fills in; the JSON never mentions them.
      allowListUrls: [],
      allowRegex: [],
      blockListUrls: [],
      blockRegex: [],
      blockingAddresses: ["0.0.0.0", "::"],
      regexBlockListUrls: [],
    },
  ],
  blockPage: {
    enable: true,
    contactEmail: "mail@example.org",
    heading: "Access blocked",
    message: "This site is blocked.",
    title: "Blocked",
  },
};

void test("isLocked: module defaults the JSON omits are not an override", () => {
  assert.equal(
    isLocked(
      state({ accessPolicies: effectivePolicies }, { accessPolicies: appliedPolicies }),
      "accessPolicies",
    ),
    false,
  );
});

void test("isLocked: a value the JSON never set is not locked", () => {
  assert.equal(isLocked(state({ a: 1 }, {}), "a"), false);
});

void test("isLocked: Nix changing a value the JSON set is locked", () => {
  const overridden = structuredClone(effectivePolicies) as {
    policies: { responseType: string }[];
  };
  overridden.policies[0]!.responseType = "nxdomain";
  assert.equal(
    isLocked(
      state({ accessPolicies: overridden as Json }, { accessPolicies: appliedPolicies }),
      "accessPolicies",
    ),
    true,
  );
});

void test("isLocked: Nix dropping a key the JSON set is locked", () => {
  const trimmed = structuredClone(effectivePolicies) as {
    policies: Record<string, unknown>[];
  };
  delete trimmed.policies[0]!.allowDomains;
  assert.equal(
    isLocked(
      state({ accessPolicies: trimmed as Json }, { accessPolicies: appliedPolicies }),
      "accessPolicies",
    ),
    true,
  );
});

void test("isLocked: Nix adding a whole policy is locked", () => {
  const extra = structuredClone(effectivePolicies) as { policies: unknown[] };
  extra.policies.push({ name: "NixOnly" });
  assert.equal(
    isLocked(
      state({ accessPolicies: extra as Json }, { accessPolicies: appliedPolicies }),
      "accessPolicies",
    ),
    true,
  );
});

void test("isLocked: a shortened list is locked, not treated as a subset", () => {
  const shortened = structuredClone(effectivePolicies) as {
    policies: { standardFilters: string[] }[];
  };
  shortened.policies[0]!.standardFilters = ["adaway"];
  assert.equal(
    isLocked(
      state({ accessPolicies: shortened as Json }, { accessPolicies: appliedPolicies }),
      "accessPolicies",
    ),
    true,
  );
});

void test("isLocked: leaf paths behave the same as before", () => {
  const s = state({ lan: { address: "10.0.0.1" } }, { lan: { address: "10.0.0.1" } });
  assert.equal(isLocked(s, "lan.address"), false);
  assert.equal(
    isLocked(
      state({ lan: { address: "10.9.9.9" } }, { lan: { address: "10.0.0.1" } }),
      "lan.address",
    ),
    true,
  );
});

void test("getPath / setPath round-trip through nested objects", () => {
  const obj: Json = { a: { b: { c: 1 } } };
  assert.equal(getPath(obj, "a.b.c"), 1);
  assert.ok(getPath(obj, "a.b.missing") === undefined);
  assert.equal(getPath(setPath(obj, "a.b.c", 2), "a.b.c"), 2);
  // setPath must not mutate its input — the changes tray diffs against it.
  assert.equal(getPath(obj, "a.b.c"), 1);
});

void test("deepEqual distinguishes key count, order-independence, and array length", () => {
  assert.equal(deepEqual({ a: 1, b: 2 }, { b: 2, a: 1 }), true);
  assert.equal(deepEqual({ a: 1 }, { a: 1, b: 2 }), false);
  assert.equal(deepEqual([1, 2], [1, 2, 3]), false);
  assert.equal(deepEqual(null, 0), false);
});

void test("changedTopKeys reports only sections that differ", () => {
  assert.deepEqual(changedTopKeys({ a: 1, b: 2 }, { a: 1, b: 3 }), ["b"]);
  assert.deepEqual(changedTopKeys({ a: 1 }, { a: 1 }), []);
  // A key present on one side only is a change.
  assert.deepEqual(changedTopKeys({ a: 1, c: 1 }, { a: 1 }), ["c"]);
});
