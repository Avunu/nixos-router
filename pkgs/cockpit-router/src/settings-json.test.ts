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
import {
  canRevertTo,
  changedTopKeys,
  deepEqual,
  diffLeaves,
  dropRetiredKeys,
  getPath,
  isLocked,
  patchWithEdits,
  rebaseEdits,
  setPath,
} from "./settings-json.ts";

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
  // setPath must not mutate its input — the changes panel diffs against it.
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

// rebaseEdits keeps an open form in step with the file: without it, a page
// left open across a revert of the saved changes wrote its stale copy
// straight back, undoing the revert on the next save.
void test("rebaseEdits: an untouched form takes the file as it now is", () => {
  const pending = new Map<string, Json>();
  const disk: Json = { upnp: { enable: false }, hostName: "r1" };
  assert.deepEqual(rebaseEdits(disk, pending), disk);
});

void test("rebaseEdits: unsaved edits survive a change made elsewhere", () => {
  const pending = new Map<string, Json>([["upnp.enable", true]]);
  const reverted: Json = { upnp: { enable: false }, hostName: "reverted" };
  assert.deepEqual(rebaseEdits(reverted, pending), {
    upnp: { enable: true },
    hostName: "reverted",
  });
  assert.equal(pending.size, 1, "still unsaved, still pending");
});

void test("rebaseEdits: an edit the file already carries counts as saved", () => {
  const pending = new Map<string, Json>([["hostName", "r2"]]);
  rebaseEdits({ hostName: "r2" }, pending); // this form's own save landed
  assert.equal(pending.size, 0);
  // …so the tray reverting it afterwards is not undone by the form.
  assert.deepEqual(rebaseEdits({ hostName: "r1" }, pending), { hostName: "r1" });
});

void test("rebaseEdits: a later parent edit wins over an earlier child edit", () => {
  const pending = new Map<string, Json>([
    ["ddns.ttl", 300],
    ["ddns", { enable: true, ttl: 60 }],
  ]);
  assert.deepEqual(rebaseEdits({ ddns: { enable: false } }, pending), {
    ddns: { enable: true, ttl: 60 },
  });
});

void test("rebaseEdits: clearing a value the file never set is nothing to re-apply", () => {
  const pending = new Map<string, Json>([["ddns.cloudflare.apiTokenFile", null]]);
  assert.deepEqual(rebaseEdits({ ddns: {} }, pending), { ddns: {} });
  assert.equal(pending.size, 0);
});

// A router installed before the settings loader keeps the seeded
// "listenPort": 53 on disk. The schema no longer allows it, so without this
// every save there fails validation.
void test("dropRetiredKeys: drops the retired DNS listen port and nothing else", () => {
  const onDisk: Json = {
    hostName: "r1",
    dns: { technitium: { enable: true, listenPort: 53, webPort: 5380 }, overrides: [] },
  };
  const before = structuredClone(onDisk);
  const current = dropRetiredKeys(onDisk);
  assert.deepEqual(current, {
    hostName: "r1",
    dns: { technitium: { enable: true, webPort: 5380 }, overrides: [] },
  });
  assert.deepEqual(onDisk, before, "the input is not modified");
  assert.deepEqual(dropRetiredKeys(current), current, "a second pass changes nothing");
});

void test("dropRetiredKeys: settings without the key come back as they are", () => {
  for (const obj of [
    { hostName: "r1" },
    { dns: { technitium: { enable: false } } },
    { dns: null },
    {},
  ] as Json[]) {
    assert.equal(dropRetiredKeys(obj), obj);
  }
});

// The store drops the key from the file as it reads it, and the running
// generation's settings never carry it (the loader's migration dropped it):
// a key only one side still holds must not be offered as a change.
void test("dropRetiredKeys: a key only one side still carries is not a change", () => {
  const saved: Json = { dns: { technitium: { enable: true } } };
  const snapshot: Json = { dns: { technitium: { enable: true, listenPort: 53 } } };
  assert.deepEqual(changedTopKeys(saved, snapshot), ["dns"], "compared as read");
  assert.deepEqual(changedTopKeys(dropRetiredKeys(saved), dropRetiredKeys(snapshot)), []);
});

// "Discard saved changes" copies the running generation's settings over the
// file. Without them (a generation that predates applied-settings.json, or a
// session that cannot read it) that baseline is {}, and offering the discard
// would offer to wipe every setting.
void test("canRevertTo: never to an empty baseline", () => {
  assert.equal(canRevertTo({}), false);
  assert.equal(canRevertTo(null), false);
  assert.equal(canRevertTo([]), false);
  assert.equal(canRevertTo({ hostName: "r1" }), true);
});

// patchWithEdits exists for the two writes made beside a form: approving an
// exception and adding a rule from an event. Written to the file alone, the
// change was hidden by the form's own pending edit of the same section and
// then saved away with it.
const addDomain = (settings: Json): Json => {
  const list = getPath(settings, "accessPolicies.allow");
  const allow = Array.isArray(list) ? list : [];
  return allow.includes("example.org")
    ? settings
    : setPath(settings, "accessPolicies.allow", [...allow, "example.org"]);
};

void test("patchWithEdits: the change reaches the file and the pending edit", () => {
  const disk: Json = { accessPolicies: { allow: ["a.test"], mode: "strict" } };
  const pending = new Map<string, Json>([["accessPolicies", { allow: ["a.test"], mode: "open" }]]);
  const patched = patchWithEdits(disk, pending, addDomain);
  assert.deepEqual(patched.disk, {
    accessPolicies: { allow: ["a.test", "example.org"], mode: "strict" },
  });
  // Saving the form later keeps both its own edit and the approval.
  assert.deepEqual(rebaseEdits(patched.disk, patched.pending), {
    accessPolicies: { allow: ["a.test", "example.org"], mode: "open" },
  });
});

void test("patchWithEdits: unrelated edits are left alone", () => {
  const disk: Json = { accessPolicies: { allow: [] }, hostName: "r1" };
  const pending = new Map<string, Json>([["hostName", "r2"]]);
  const patched = patchWithEdits(disk, pending, addDomain);
  assert.deepEqual([...patched.pending], [["hostName", "r2"]]);
  assert.deepEqual(getPath(patched.disk, "accessPolicies.allow"), ["example.org"]);
});

void test("diffLeaves: objects by key, down to the changed leaf", () => {
  assert.deepEqual(diffLeaves({ a: { b: 1, c: 2 } }, { a: { b: 1, c: 3 } }), [
    { path: ["a", "c"], before: 2, after: 3 },
  ]);
  assert.deepEqual(diffLeaves({ a: 1 }, { a: 1, b: true }), [
    { path: ["b"], before: undefined, after: true },
  ]);
  assert.deepEqual(diffLeaves({ a: 1, b: 2 }, { a: 1 }), [
    { path: ["b"], before: 2, after: undefined },
  ]);
  assert.deepEqual(diffLeaves({ a: [1] }, { a: [1] }), []);
});

void test("diffLeaves: named entries by name, whatever their order", () => {
  const nas = { name: "nas", ip: "10.0.0.2" };
  const tv = { name: "tv", ip: "10.0.0.3" };
  assert.deepEqual(
    diffLeaves(
      { hosts: [nas, tv] },
      { hosts: [{ ...tv, ip: "10.0.0.9" }, nas, { name: "cam", ip: "10.0.0.4" }] },
    ),
    [
      { path: ["hosts", { name: "tv" }, "ip"], before: "10.0.0.3", after: "10.0.0.9" },
      {
        path: ["hosts", { name: "cam" }],
        before: undefined,
        after: { name: "cam", ip: "10.0.0.4" },
      },
    ],
  );
  assert.deepEqual(diffLeaves({ hosts: [nas, tv] }, { hosts: [nas] }), [
    { path: ["hosts", { name: "tv" }], before: tv, after: undefined },
  ]);
});

void test("diffLeaves: other lists by position when the length holds, else whole", () => {
  assert.deepEqual(diffLeaves({ dns: ["1.1.1.1", "9.9.9.9"] }, { dns: ["1.1.1.1", "8.8.8.8"] }), [
    { path: ["dns", 1], before: "9.9.9.9", after: "8.8.8.8" },
  ]);
  assert.deepEqual(diffLeaves({ dns: ["1.1.1.1"] }, { dns: ["1.1.1.1", "8.8.8.8"] }), [
    { path: ["dns"], before: ["1.1.1.1"], after: ["1.1.1.1", "8.8.8.8"] },
  ]);
  // Duplicate names are not names.
  const dup = [
    { name: "x", v: 1 },
    { name: "x", v: 2 },
  ];
  assert.deepEqual(diffLeaves({ l: dup }, { l: [dup[0]!, { name: "x", v: 3 }] }), [
    { path: ["l", 1, "v"], before: 2, after: 3 },
  ]);
});
