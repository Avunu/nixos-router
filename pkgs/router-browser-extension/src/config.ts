// The configured routers: the union of what an administrator set by policy
// (storage.managed — read-only here) and what the user added on the options
// page (storage.sync). Both hold `routers`, a list of portal addresses; every
// entry is normalized to its canonical origin, invalid ones are dropped, and a
// router listed in both places counts once, as managed.
//
// Chrome reads the managed list from policy through managed-schema.json
// (3rdparty.extensions.<id>.routers); Firefox from policies.json
// (3rdparty.Extensions["nixos-router@avu.nu"].routers). Where there is no
// policy, Firefox rejects storage.managed.get() outright — that is an empty
// list, not an error.

import { normalizePortalOrigin } from "./host.ts";

export const ROUTERS_KEY = "routers";

export interface RouterEntry {
  readonly origin: string;
  /** Set by policy: shown as such, and not removable on the options page. */
  readonly managed: boolean;
}

/** The part of a storage area this module reads. */
export interface ReadableArea {
  readonly get: (keys: string) => Promise<Record<string, unknown>>;
}

export interface RouterStorage {
  readonly managed?: ReadableArea | undefined;
  readonly sync: ReadableArea;
}

/** Canonical, de-duplicated origins from a stored `routers` value of any shape. */
export function routerList(value: unknown): string[] {
  if (!Array.isArray(value)) {
    return [];
  }
  const origins: string[] = [];
  for (const item of value as unknown[]) {
    const origin = typeof item === "string" ? normalizePortalOrigin(item) : null;
    if (origin !== null && !origins.includes(origin)) {
      origins.push(origin);
    }
  }
  return origins;
}

/** Managed routers first, then the user's own that policy does not already list. */
export function mergeRouters(managed: unknown, synced: unknown): RouterEntry[] {
  const fromPolicy = routerList(managed);
  const fromUser = routerList(synced).filter((origin) => !fromPolicy.includes(origin));
  return [
    ...fromPolicy.map((origin) => ({ origin, managed: true })),
    ...fromUser.map((origin) => ({ origin, managed: false })),
  ];
}

/** An area's `routers` value, or undefined when the area is missing or refuses. */
export async function readRouters(area: ReadableArea | undefined): Promise<unknown> {
  if (area === undefined) {
    return undefined;
  }
  try {
    const items = await area.get(ROUTERS_KEY);
    return items[ROUTERS_KEY];
  } catch {
    return undefined;
  }
}

export async function loadRouters(storage: RouterStorage): Promise<RouterEntry[]> {
  const [managed, synced] = await Promise.all([
    readRouters(storage.managed),
    readRouters(storage.sync),
  ]);
  return mergeRouters(managed, synced);
}

/** Whether a storage.onChanged event touches the router list. */
export function affectsRouters(changes: Record<string, unknown>, areaName: string): boolean {
  return (areaName === "managed" || areaName === "sync") && ROUTERS_KEY in changes;
}

/**
 * The background's view of the list: loaded once, reused until storage says it
 * changed. Holding the promise (not the value) lets concurrent navigation
 * errors share one load.
 */
export class RouterCache {
  readonly #load: () => Promise<RouterEntry[]>;
  #pending: Promise<RouterEntry[]> | null = null;

  public constructor(load: () => Promise<RouterEntry[]>) {
    this.#load = load;
  }

  public get(): Promise<RouterEntry[]> {
    if (this.#pending === null) {
      const pending = this.#load().catch((): RouterEntry[] => {
        // A failed load is not remembered: the next error tries again.
        if (this.#pending === pending) {
          this.#pending = null;
        }
        return [];
      });
      this.#pending = pending;
    }
    return this.#pending;
  }

  public invalidate(): void {
    this.#pending = null;
  }
}
