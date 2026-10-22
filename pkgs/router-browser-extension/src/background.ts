// Background context: Chrome's service worker, Firefox's event page.
//
// Every listener is registered synchronously at the top level: either browser
// may stop this context whenever it is idle and restart it for the next event,
// and only listeners registered during that first synchronous run receive it.
// For the same reason nothing here that must outlive a restart is kept in a
// module variable except caches: the back-button guard lives in
// storage.session (memory-only, cleared when the browser quits).
//
// Nothing is logged. The only place a hostname ever goes is the configured
// router's /portal/check, over HTTPS.

import { api } from "./api.ts";
import { affectsRouters, loadRouters, RouterCache } from "./config.ts";
import { permissionPattern } from "./host.ts";
import { looksLikeBlockPage, PortalClient } from "./portal.ts";
import { handleNavigationError } from "./redirect.ts";
import type { RedirectDeps } from "./redirect.ts";

/** Top-level navigations each tab has started, to notice one that superseded a check. */
const navigationCounts = new Map<number, number>();

const portal = new PortalClient({ fetch: (url, init) => fetch(url, init), now: () => Date.now() });
const routers = new RouterCache(() => loadRouters(api.storage));

const lastCommittedKey = (tabId: number) => `lastCommitted:${tabId}`;

function hasPermission(origin: string): Promise<boolean> {
  return api.permissions.contains({ origins: [permissionPattern(origin)] });
}

const deps: RedirectDeps = {
  routers: () => routers.get(),
  hasPermission,
  check: (origin, host) => portal.checkHost(origin, host),
  navigationCount: (tabId) => navigationCounts.get(tabId) ?? 0,
  lastCommitted: async (tabId) => {
    const key = lastCommittedKey(tabId);
    const items = await api.storage.session.get(key);
    const value = items[key];
    return typeof value === "string" ? value : undefined;
  },
  clearLastCommitted: (tabId) => api.storage.session.remove(lastCommittedKey(tabId)),
  updateTab: async (tabId, update) => {
    // `loadReplace` is Firefox's; Chrome's typings do not know it.
    await api.tabs.update(tabId, update);
  },
};

api.webNavigation.onBeforeNavigate.addListener((details) => {
  if (details.frameId === 0) {
    navigationCounts.set(details.tabId, (navigationCounts.get(details.tabId) ?? 0) + 1);
  }
});

// The back-button guard needs to know whether the page a failure replaced was
// the block page. Only a block-page URL is remembered — any other commit just
// clears the entry — so no browsing history is kept.
api.webNavigation.onCommitted.addListener((details) => {
  if (details.frameId !== 0 || details.documentLifecycle === "prerender") {
    return;
  }
  const key = lastCommittedKey(details.tabId);
  const write = looksLikeBlockPage(details.url)
    ? api.storage.session.set({ [key]: details.url })
    : api.storage.session.remove(key);
  void write.catch(() => {});
});

api.webNavigation.onErrorOccurred.addListener((details) => {
  // Everything that can fail here is benign: the tab closed, the router went
  // away, the context is shutting down. The page stays as the browser left it.
  void handleNavigationError(details, deps, __FIREFOX__).catch(() => {});
});

api.tabs.onRemoved.addListener((tabId) => {
  navigationCounts.delete(tabId);
  void api.storage.session.remove(lastCommittedKey(tabId)).catch(() => {});
});

api.storage.onChanged.addListener((changes, areaName) => {
  if (affectsRouters(changes, areaName)) {
    routers.invalidate();
    portal.reset();
  }
});

api.runtime.onInstalled.addListener((details) => {
  if (details.reason !== "install") {
    return;
  }
  // A router set by policy is useless until the user grants access to it, and
  // only the options page can ask (permission prompts need a click).
  void (async () => {
    const configured = await routers.get();
    const managed = configured.filter((router) => router.managed);
    const granted = await Promise.all(managed.map((router) => hasPermission(router.origin)));
    if (granted.includes(false)) {
      await api.runtime.openOptionsPage();
    }
  })().catch(() => {});
});

api.action.onClicked.addListener(() => {
  void api.runtime.openOptionsPage().catch(() => {});
});
