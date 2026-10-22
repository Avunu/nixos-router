// Unit tests for the router list: policy + user entries, normalized and merged.
import { test } from "node:test";
import assert from "node:assert/strict";

import { affectsRouters, loadRouters, mergeRouters, RouterCache, routerList } from "./config.ts";
import type { ReadableArea, RouterEntry } from "./config.ts";

const GW = "https://blocked.gw.example.com:8068";
const OFFICE = "https://blocked.office.example.org:9443";

function area(value: unknown): ReadableArea {
  return { get: async () => ({ routers: value }) };
}

/** An area with nothing stored: get() answers without the key. */
const empty: ReadableArea = { get: async () => ({}) };

const refusing: ReadableArea = {
  get: async () => {
    throw new Error("Managed storage manifest not found");
  },
};

void test("routerList normalizes, de-duplicates and drops what is not an address", () => {
  assert.deepEqual(
    routerList([
      "blocked.gw.example.com",
      "https://blocked.gw.example.com:8068/",
      "BLOCKED.GW.EXAMPLE.COM:8068",
      "http://blocked.insecure.example.com",
      "192.168.1.1",
      42,
      null,
      "blocked.office.example.org:9443",
    ]),
    [GW, OFFICE],
  );
  for (const value of [undefined, null, "blocked.gw.example.com", { routers: [] }, 7]) {
    assert.deepEqual(routerList(value), [], JSON.stringify(value));
  }
});

void test("mergeRouters lists policy first, and an address in both only as managed", () => {
  assert.deepEqual(mergeRouters(["blocked.gw.example.com"], [OFFICE, GW]), [
    { origin: GW, managed: true },
    { origin: OFFICE, managed: false },
  ]);
  assert.deepEqual(mergeRouters(undefined, [GW]), [{ origin: GW, managed: false }]);
  assert.deepEqual(mergeRouters("junk", null), []);
});

void test("loadRouters treats a refusing or absent managed area as no policy", async () => {
  assert.deepEqual(await loadRouters({ managed: refusing, sync: area([GW]) }), [
    { origin: GW, managed: false },
  ]);
  assert.deepEqual(await loadRouters({ sync: area([GW]) }), [{ origin: GW, managed: false }]);
  assert.deepEqual(await loadRouters({ managed: area([OFFICE]), sync: empty }), [
    { origin: OFFICE, managed: true },
  ]);
  assert.deepEqual(await loadRouters({ managed: refusing, sync: refusing }), []);
});

void test("only router-list changes in managed or sync storage invalidate", () => {
  assert.equal(affectsRouters({ routers: {} }, "sync"), true);
  assert.equal(affectsRouters({ routers: {} }, "managed"), true);
  assert.equal(affectsRouters({ routers: {} }, "local"), false);
  assert.equal(affectsRouters({ routers: {} }, "session"), false);
  assert.equal(affectsRouters({ other: {} }, "sync"), false);
});

void test("RouterCache loads once, reloads after invalidate, and forgets a failed load", async () => {
  let loads = 0;
  let fail = false;
  const entries: RouterEntry[] = [{ origin: GW, managed: false }];
  const cache = new RouterCache(async () => {
    loads += 1;
    if (fail) {
      throw new Error("storage unavailable");
    }
    return entries;
  });

  const [first, second] = await Promise.all([cache.get(), cache.get()]);
  assert.deepEqual(first, entries);
  assert.deepEqual(second, entries);
  assert.equal(loads, 1);

  cache.invalidate();
  fail = true;
  assert.deepEqual(await cache.get(), []);
  fail = false;
  assert.deepEqual(await cache.get(), entries);
  assert.equal(loads, 3);
});
