// Unit tests for reading the settings file strictly (settings-read.ts).
//
// The failure these pin down was silent: a read that failed (the file is
// root-only and the session had Limited access) came back as {}, the forms
// showed defaults, and the next Save replaced the whole file with just the
// edited fields. So the cases below keep "no file" and "empty file" apart from
// "could not read it", and check that only a real read can be saved over.
//
// Run with `npm test`.
import { test } from "node:test";
import assert from "node:assert/strict";

import type { SuperuserLike } from "./settings-read.ts";
import {
  ADMIN_NEEDED,
  isDenied,
  isLoaded,
  markLoaded,
  onSettledChange,
  parseSettings,
  readStrict,
} from "./settings-read.ts";

const PATH = "/etc/nixos/router-settings.json";

// What cockpit.file().read() rejects with: a BasicError, which is not an Error.
const bridgeError = (problem: string, message = "Not permitted to perform this action.") => ({
  problem,
  message,
});

void test("parseSettings: a missing or blank file is an empty object", () => {
  assert.deepEqual(parseSettings(PATH, null), {});
  assert.deepEqual(parseSettings(PATH, ""), {});
  assert.deepEqual(parseSettings(PATH, "  \n"), {});
});

void test("parseSettings: a JSON object comes back as it is", () => {
  assert.deepEqual(parseSettings(PATH, '{"hostName":"r1","lan":{"address":"10.0.0.1"}}\n'), {
    hostName: "r1",
    lan: { address: "10.0.0.1" },
  });
});

void test("parseSettings: broken JSON is an error, not an empty file", () => {
  assert.throws(
    () => parseSettings(PATH, '{"hostName": '),
    (e: Error) => {
      assert.match(e.message, /router-settings\.json is not valid JSON/);
      return true;
    },
  );
});

void test("parseSettings: JSON that is not an object is an error", () => {
  for (const text of ["[]", "null", '"r1"', "42"]) {
    assert.throws(() => parseSettings(PATH, text), /does not hold a JSON object/, text);
  }
});

void test("readStrict: a missing file (read resolves null) is an empty object", async () => {
  assert.deepEqual(await readStrict(PATH, () => Promise.resolve(null)), {});
});

void test("readStrict: a permission error rejects and asks for administrative access", async () => {
  for (const problem of ["access-denied", "not-authorized"]) {
    const cause = bridgeError(problem);
    await assert.rejects(
      readStrict(PATH, () => Promise.reject(cause)),
      (e: Error) => {
        assert.equal(e.message, ADMIN_NEEDED);
        assert.equal(e.cause, cause);
        return true;
      },
      problem,
    );
  }
});

void test("readStrict: any other read error rejects with the path and the reason", async () => {
  await assert.rejects(
    readStrict(PATH, () => Promise.reject(bridgeError("internal-error", "Input/output error"))),
    { message: `Could not read ${PATH}: Input/output error` },
  );
});

void test("readStrict: unreadable JSON rejects", async () => {
  await assert.rejects(
    readStrict(PATH, () => Promise.resolve("{")),
    /is not valid JSON/,
  );
});

void test("isDenied: only the bridge's permission problems", () => {
  assert.ok(isDenied(bridgeError("access-denied")));
  assert.ok(isDenied(bridgeError("not-authorized")));
  assert.ok(!isDenied(bridgeError("not-found")));
  assert.ok(!isDenied(new Error("access-denied")));
  assert.ok(!isDenied(null));
});

void test("isLoaded: only a state loadState marked can be saved over", () => {
  const state = { desired: { hostName: "r1" }, effective: {}, applied: {} };
  assert.ok(!isLoaded(state), "not marked yet");
  assert.ok(!isLoaded(null), "a failed read leaves no state");
  assert.equal(markLoaded(state), state);
  assert.ok(isLoaded(state));
  assert.ok(!isLoaded({ ...state }), "a copy is not a read");
});

// A stand-in for Cockpit's superuser object, driven the way pkg/lib/superuser.js
// drives it: `allowed` is set first, then "changed" fires.
const fakeSuperuser = (allowed: boolean | null) => {
  const handlers = new Set<() => void>();
  const su: SuperuserLike & { set: (v: boolean | null) => void; listeners: () => number } = {
    allowed,
    addEventListener: (_type, h) => handlers.add(h),
    removeEventListener: (_type, h) => handlers.delete(h),
    set(v) {
      su.allowed = v;
      for (const h of handlers) {
        h();
      }
    },
    listeners: () => handlers.size,
  };
  return su;
};

void test("onSettledChange: reloads when access settles, not while it switches", () => {
  const su = fakeSuperuser(null);
  let calls = 0;
  const off = onSettledChange(su, () => {
    calls += 1;
  });
  su.set(false); // the session settled in Limited access
  assert.equal(calls, 1);
  su.set(null); // "Limited access" clicked: the superuser bridge is starting
  assert.equal(calls, 1, "nothing can be read differently yet");
  su.set(true); // administrative access granted
  assert.equal(calls, 2);
  su.set(false); // and dropped again
  assert.equal(calls, 3);
  off();
  assert.equal(su.listeners(), 0);
  su.set(true);
  assert.equal(calls, 3, "unsubscribed");
});
