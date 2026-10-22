// Unit tests for the onErrorOccurred decision — every reason the extension
// leaves a tab alone, and the exact redirect it makes otherwise.
import { test } from "node:test";
import assert from "node:assert/strict";

import { handleNavigationError, isTopLevel } from "./redirect.ts";
import type { NavigationErrorDetails, RedirectDeps, TabUpdate } from "./redirect.ts";
import type { RouterEntry } from "./config.ts";
import type { Verdict } from "./portal.ts";

const GW = "https://blocked.gw.example.com:8068";
const OFFICE = "https://blocked.office.example.org:8068";
const TAB = 7;

interface World {
  routers: RouterEntry[];
  granted: Set<string>;
  /** origin → answer (a function, so a test can hold or change it). */
  answers: Map<string, (host: string) => Promise<Verdict | null>>;
  navigations: number;
  lastCommitted: string | undefined;
  checks: [string, string][];
  updates: [number, TabUpdate][];
  cleared: number;
  /** Runs while the router is being asked, to simulate the user acting. */
  duringCheck: () => void;
}

function world(overrides: Partial<World> = {}): { world: World; deps: RedirectDeps } {
  const state: World = {
    routers: [{ origin: GW, managed: false }],
    granted: new Set([GW, OFFICE]),
    answers: new Map([[GW, async () => ({ blocked: true, reason: "Ads" })]]),
    navigations: 1,
    lastCommitted: undefined,
    checks: [],
    updates: [],
    cleared: 0,
    duringCheck: () => {},
    ...overrides,
  };
  const deps: RedirectDeps = {
    routers: async () => state.routers,
    hasPermission: async (origin) => state.granted.has(origin),
    check: async (origin, host) => {
      state.checks.push([origin, host]);
      state.duringCheck();
      const answer = state.answers.get(origin);
      return answer === undefined ? null : answer(host);
    },
    navigationCount: () => state.navigations,
    lastCommitted: async () => state.lastCommitted,
    clearLastCommitted: async () => {
      state.cleared += 1;
      state.lastCommitted = undefined;
    },
    updateTab: async (tabId, update) => {
      state.updates.push([tabId, update]);
    },
  };
  return { world: state, deps };
}

function failure(overrides: Partial<NavigationErrorDetails> = {}): NavigationErrorDetails {
  return {
    tabId: TAB,
    frameId: 0,
    url: "https://ads.example.com/banner",
    error: "net::ERR_CERT_AUTHORITY_INVALID",
    frameType: "outermost_frame",
    documentLifecycle: "active",
    ...overrides,
  };
}

const BLOCK_PAGE = `${GW}/portal/blocked?host=ads.example.com`;

void test("Chrome: a blocked host is sent to the router's block page", async () => {
  const { world: w, deps } = world();
  const outcome = await handleNavigationError(failure(), deps, false);
  assert.deepEqual(outcome, { action: "redirect", update: { url: BLOCK_PAGE } });
  assert.deepEqual(w.updates, [[TAB, { url: BLOCK_PAGE }]]);
  assert.equal("loadReplace" in (w.updates[0]?.[1] ?? {}), false);
});

void test("Firefox: the redirect replaces the error page's history entry", async () => {
  const { world: w, deps } = world();
  const details = failure({
    error: "Error code 2153390067",
    frameType: undefined,
    documentLifecycle: undefined,
  });
  const outcome = await handleNavigationError(details, deps, true);
  assert.deepEqual(outcome, {
    action: "redirect",
    update: { url: BLOCK_PAGE, loadReplace: true },
  });
  assert.deepEqual(w.updates, [[TAB, { url: BLOCK_PAGE, loadReplace: true }]]);
});

void test("only the normalized hostname reaches the router and the block page URL", async () => {
  const { world: w, deps } = world();
  await handleNavigationError(
    failure({ url: "https://Ads.Example.COM.:8443/track?id=secret#frag" }),
    deps,
    false,
  );
  assert.deepEqual(w.checks, [[GW, "ads.example.com"]]);
  assert.deepEqual(w.updates, [[TAB, { url: BLOCK_PAGE }]]);

  const idn = world();
  await handleNavigationError(failure({ url: "https://bücher.example/" }), idn.deps, false);
  assert.deepEqual(idn.world.updates, [
    [TAB, { url: `${GW}/portal/blocked?host=xn--bcher-kva.example` }],
  ]);
});

void test("subframes, prerenders and back/forward-cache restores are ignored", async () => {
  for (const details of [
    failure({ frameId: 3 }),
    failure({ frameType: "sub_frame" }),
    failure({ frameType: "fenced_frame" }),
    failure({ documentLifecycle: "prerender" }),
    failure({ documentLifecycle: "cached" }),
    failure({ documentLifecycle: "pending_deletion" }),
  ]) {
    const { world: w, deps } = world();
    assert.deepEqual(await handleNavigationError(details, deps, false), {
      action: "skip",
      reason: "not-top-level",
    });
    assert.deepEqual(w.checks, []);
    assert.deepEqual(w.updates, []);
  }
  assert.equal(isTopLevel({ tabId: 1, frameId: 0, url: "https://a.example/" }), true);
});

void test("URLs the router cannot have blocked by name are never sent", async () => {
  for (const url of [
    "https://192.168.1.1/",
    "https://[fd00::1]/",
    "https://intranet/",
    "chrome-error://chromewebdata/",
    "about:certerror?e=nssBadCert",
    "ftp://files.example.com/",
  ]) {
    const { world: w, deps } = world();
    assert.deepEqual(await handleNavigationError(failure({ url }), deps, false), {
      action: "skip",
      reason: "not-checkable",
    });
    assert.deepEqual(w.checks, [], url);
  }
});

void test("errors a block cannot cause are never sent", async () => {
  for (const error of ["net::ERR_ABORTED", "net::ERR_NAME_NOT_RESOLVED", "Error code 2152398850"]) {
    const { world: w, deps } = world();
    assert.deepEqual(await handleNavigationError(failure({ error }), deps, false), {
      action: "skip",
      reason: "error-kind",
    });
    assert.deepEqual(w.checks, [], error);
  }
});

void test("a portal failing to load is never redirected to itself", async () => {
  const { world: w, deps } = world();
  const outcome = await handleNavigationError(failure({ url: BLOCK_PAGE }), deps, false);
  assert.deepEqual(outcome, { action: "skip", reason: "portal" });
  assert.deepEqual(w.checks, []);
});

void test("routers without granted access are not asked", async () => {
  const { world: w, deps } = world({ granted: new Set() });
  assert.deepEqual(await handleNavigationError(failure(), deps, false), {
    action: "skip",
    reason: "not-blocked",
  });
  assert.deepEqual(w.checks, []);
});

void test("not blocked, or no router answering, leaves the tab alone", async () => {
  for (const answer of [
    async () => ({ blocked: false, reason: null }),
    async () => null,
    async () => {
      throw new Error("boom");
    },
  ]) {
    const { world: w, deps } = world({ answers: new Map([[GW, answer]]) });
    assert.deepEqual(await handleNavigationError(failure(), deps, false), {
      action: "skip",
      reason: "not-blocked",
    });
    assert.deepEqual(w.updates, []);
  }
  const none = world({ routers: [] });
  assert.deepEqual(await handleNavigationError(failure(), none.deps, false), {
    action: "skip",
    reason: "not-blocked",
  });
});

void test("the first router to say blocked wins, without waiting for a silent one", async () => {
  const { world: w, deps } = world({
    routers: [
      { origin: GW, managed: true },
      { origin: OFFICE, managed: false },
    ],
    answers: new Map([
      // The home router is out of reach and never answers.
      [GW, () => new Promise<never>(() => {})],
      [OFFICE, async () => ({ blocked: true, reason: null })],
    ]),
  });
  const outcome = await handleNavigationError(failure(), deps, false);
  assert.deepEqual(outcome, {
    action: "redirect",
    update: { url: `${OFFICE}/portal/blocked?host=ads.example.com` },
  });
  assert.equal(w.checks.length, 2);
});

void test("a navigation started while the router was asked cancels the redirect", async () => {
  const setup = world();
  setup.world.duringCheck = () => {
    setup.world.navigations += 1;
  };
  assert.deepEqual(await handleNavigationError(failure(), setup.deps, false), {
    action: "skip",
    reason: "navigated",
  });
  assert.deepEqual(setup.world.updates, []);
});

void test("Back from the block page is let through once, then redirects again", async () => {
  const { world: w, deps } = world({ lastCommitted: BLOCK_PAGE });
  assert.deepEqual(await handleNavigationError(failure(), deps, false), {
    action: "skip",
    reason: "back",
  });
  assert.equal(w.cleared, 1);
  assert.deepEqual(w.updates, []);

  // A deliberate retry (reload, retyping the address) is redirected as usual.
  const retry = await handleNavigationError(failure(), deps, false);
  assert.equal(retry.action, "redirect");
  assert.equal(w.updates.length, 1);
});

void test("the back guard matches only that router's block page for that host", async () => {
  for (const lastCommitted of [
    `${GW}/portal/blocked?host=other.example.com`,
    `${OFFICE}/portal/blocked?host=ads.example.com`,
    "https://ads.example.com/portal/blocked?host=ads.example.com",
    "https://news.example.com/",
  ]) {
    const { world: w, deps } = world({ lastCommitted });
    const outcome = await handleNavigationError(failure(), deps, false);
    assert.equal(outcome.action, "redirect", lastCommitted);
    assert.equal(w.cleared, 0, lastCommitted);
  }
});
