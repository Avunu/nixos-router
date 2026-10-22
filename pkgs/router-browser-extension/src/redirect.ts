// What to do about a failed navigation — the whole of the extension's
// behaviour, kept free of browser APIs so every branch is unit-tested.
//
// The tab is redirected only when all of these hold:
//   • it is a top-level navigation in the visible page (not a subframe, not a
//     prerender, not a back/forward-cache restore);
//   • the URL is http(s) with a hostname the router could have blocked;
//   • the error is one a router block produces (errors.ts);
//   • it is not a router portal itself failing;
//   • a configured router the user has granted access to says the host is
//     blocked for this device;
//   • the user has not navigated elsewhere while the router was asked;
//   • the user did not just come Back from that very block page.
// The destination is always `<configured portal origin>/portal/blocked`: the
// extension never downgrades to http, never proceeds past a certificate error,
// and never navigates anywhere a router's owner did not configure.

import { shouldCheck } from "./errors.ts";
import { checkableHost } from "./host.ts";
import type { RouterEntry } from "./config.ts";
import { blockPageUrl, isBlockPageFor } from "./portal.ts";
import type { Verdict } from "./portal.ts";

/** The fields of webNavigation.onErrorOccurred both browsers provide, plus Chrome's extras. */
export interface NavigationErrorDetails {
  readonly tabId: number;
  readonly frameId: number;
  readonly url: string;
  readonly error?: string | undefined;
  /** Chrome only. */
  readonly frameType?: string | undefined;
  /** Chrome only. */
  readonly documentLifecycle?: string | undefined;
}

export interface TabUpdate {
  readonly url: string;
  /** Firefox only: replace the error page's history entry rather than add one. */
  readonly loadReplace?: boolean;
}

export interface RedirectDeps {
  readonly routers: () => Promise<readonly RouterEntry[]>;
  readonly hasPermission: (origin: string) => Promise<boolean>;
  readonly check: (origin: string, host: string) => Promise<Verdict | null>;
  /** Top-level navigations the tab has started (onBeforeNavigate, frame 0). */
  readonly navigationCount: (tabId: number) => number;
  /** The tab's last committed top-level URL, if it was a block page. */
  readonly lastCommitted: (tabId: number) => Promise<string | undefined>;
  readonly clearLastCommitted: (tabId: number) => Promise<void>;
  readonly updateTab: (tabId: number, update: TabUpdate) => Promise<void>;
}

export type SkipReason =
  | "not-top-level"
  | "not-checkable"
  | "error-kind"
  | "portal"
  | "not-blocked"
  | "navigated"
  | "back";

export type Outcome =
  | { readonly action: "skip"; readonly reason: SkipReason }
  | { readonly action: "redirect"; readonly update: TabUpdate };

/**
 * frame 0 of the visible page. Chrome's frameType/documentLifecycle filter out
 * prerendered pages and back/forward-cache restores; Firefox has neither field
 * (and neither kind of navigation reports an error there).
 */
export function isTopLevel(details: NavigationErrorDetails): boolean {
  return (
    details.frameId === 0 &&
    (details.frameType === undefined || details.frameType === "outermost_frame") &&
    (details.documentLifecycle === undefined || details.documentLifecycle === "active")
  );
}

function sameOrigin(url: string, origins: readonly string[]): boolean {
  try {
    return origins.includes(new URL(url).origin);
  } catch {
    return false;
  }
}

/**
 * The first router — in answer order, all asked in parallel — that says
 * `host` is blocked, or null. A router without granted access is not asked,
 * and one that fails simply does not count.
 */
async function blockingRouter(
  routers: readonly RouterEntry[],
  host: string,
  deps: RedirectDeps,
): Promise<string | null> {
  const probes = routers.map(async ({ origin }) => {
    const granted = await deps.hasPermission(origin).catch(() => false);
    const verdict = granted ? await deps.check(origin, host).catch(() => null) : null;
    if (verdict?.blocked !== true) {
      throw new Error("not blocked here");
    }
    return origin;
  });
  try {
    return await Promise.any(probes);
  } catch {
    return null;
  }
}

/**
 * Decides, and when the answer is to redirect, navigates the tab. `firefox`
 * is the build's __FIREFOX__, passed in so both variants are tested.
 */
export async function handleNavigationError(
  details: NavigationErrorDetails,
  deps: RedirectDeps,
  firefox: boolean,
): Promise<Outcome> {
  if (!isTopLevel(details)) {
    return { action: "skip", reason: "not-top-level" };
  }
  const host = checkableHost(details.url);
  if (host === null) {
    return { action: "skip", reason: "not-checkable" };
  }
  if (!shouldCheck(details.error)) {
    return { action: "skip", reason: "error-kind" };
  }
  const { tabId } = details;
  const started = deps.navigationCount(tabId);
  const routers = await deps.routers();
  const portals = routers.map((router) => router.origin);
  if (sameOrigin(details.url, portals)) {
    return { action: "skip", reason: "portal" };
  }
  const origin = await blockingRouter(routers, host, deps);
  if (origin === null) {
    return { action: "skip", reason: "not-blocked" };
  }
  if (deps.navigationCount(tabId) !== started) {
    return { action: "skip", reason: "navigated" };
  }
  // Back from the block page lands on the blocked URL again, which fails again.
  // Redirecting once more would trap the user, so the first failure after
  // leaving the block page is let through — once: the guard is cleared, and a
  // deliberate retry (reload, typing the address) redirects as usual.
  const last = await deps.lastCommitted(tabId).catch(() => null);
  if (typeof last === "string" && isBlockPageFor(last, origin, host)) {
    await deps.clearLastCommitted(tabId);
    return { action: "skip", reason: "back" };
  }
  const url = blockPageUrl(origin, host);
  const update: TabUpdate = firefox ? { url, loadReplace: true } : { url };
  await deps.updateTab(tabId, update);
  return { action: "redirect", update };
}
