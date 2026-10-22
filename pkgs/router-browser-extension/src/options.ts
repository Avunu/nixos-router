// The options page: the list of routers, their status, and pairing a new one.
//
// Permission prompts only appear from inside a user gesture, so in every click
// or submit handler `permissions.request` is the first extension call, made
// before anything is awaited.

import { api } from "./api.ts";
import { affectsRouters, loadRouters, routerList, ROUTERS_KEY } from "./config.ts";
import type { RouterEntry } from "./config.ts";
import { displayAddress, normalizePortalOrigin, permissionPattern } from "./host.ts";
import { PortalClient } from "./portal.ts";
import type { InfoResult } from "./portal.ts";

type Tone = "ok" | "warn" | "error" | "pending";

const portal = new PortalClient({ fetch: (url, init) => fetch(url, init), now: () => Date.now() });

const list = document.querySelector<HTMLUListElement>("#routers")!;
const empty = document.querySelector<HTMLElement>("#no-routers")!;
const form = document.querySelector<HTMLFormElement>("#add-form")!;
const input = document.querySelector<HTMLInputElement>("#address")!;
const addButton = document.querySelector<HTMLButtonElement>("#add-button")!;
const addStatus = document.querySelector<HTMLElement>("#add-status")!;

function setStatus(target: HTMLElement, tone: Tone, text: string): void {
  target.dataset.tone = tone;
  target.textContent = text;
}

function element<K extends keyof HTMLElementTagNameMap>(
  tag: K,
  className: string,
  text?: string,
): HTMLElementTagNameMap[K] {
  const node = document.createElement(tag);
  node.className = className;
  if (text !== undefined) {
    node.textContent = text;
  }
  return node;
}

function problemText(result: Exclude<InfoResult, { ok: true }>, origin: string): string {
  switch (result.problem) {
    case "unreachable": {
      return `Couldn't reach ${displayAddress(origin)} over HTTPS. Check the address, and that you're on the router's network.`;
    }
    case "not-portal": {
      return "That server isn't a nixos-router portal.";
    }
    case "http": {
      return `The router answered with an error (HTTP ${result.status}). Try again in a minute.`;
    }
    default: {
      return "Something went wrong.";
    }
  }
}

function listStatusText(result: Exclude<InfoResult, { ok: true }>, origin: string): string {
  return result.problem === "unreachable"
    ? "Not reachable — you may not be on this router's network."
    : problemText(result, origin);
}

function hasPermission(origin: string): Promise<boolean> {
  return api.permissions.contains({ origins: [permissionPattern(origin)] });
}

/**
 * Gives back a host permission no configured router still needs. Two portals
 * on the same name share one (patterns carry no port).
 */
async function dropUnusedPermission(origin: string): Promise<void> {
  const pattern = permissionPattern(origin);
  const routers = await loadRouters(api.storage);
  if (!routers.some((router) => permissionPattern(router.origin) === pattern)) {
    await api.permissions.remove({ origins: [pattern] });
  }
}

async function removeRouter(origin: string): Promise<void> {
  const items = await api.storage.sync.get(ROUTERS_KEY);
  const next = routerList(items[ROUTERS_KEY]).filter((stored) => stored !== origin);
  await api.storage.sync.set({ [ROUTERS_KEY]: next });
  await dropUnusedPermission(origin);
}

async function showStatus(router: RouterEntry, status: HTMLElement, actions: HTMLElement) {
  const address = displayAddress(router.origin);
  setStatus(status, "pending", "Checking…");
  if (!(await hasPermission(router.origin))) {
    setStatus(
      status,
      "warn",
      "Access not granted — this router can't be asked about blocked sites.",
    );
    const allow = element("button", "", "Allow access");
    allow.type = "button";
    allow.setAttribute("aria-label", `Allow access to ${address}`);
    allow.addEventListener("click", () => {
      // permissions.onAdded re-renders the list once access is granted.
      void api.permissions
        .request({ origins: [permissionPattern(router.origin)] })
        .catch(() => false);
    });
    actions.prepend(allow);
    return;
  }
  const result = await portal.getInfo(router.origin);
  if (result.ok) {
    setStatus(status, "ok", `Connected — ${result.info.name ?? address}`);
  } else {
    setStatus(
      status,
      result.problem === "unreachable" ? "warn" : "error",
      listStatusText(result, router.origin),
    );
  }
}

function routerItem(router: RouterEntry): HTMLLIElement {
  const address = displayAddress(router.origin);
  const item = element("li", "router");
  const title = element("p", "router-address", address);
  const status = element("p", "status router-status");
  const actions = element("div", "router-actions");
  if (router.managed) {
    title.append(element("span", "badge", "Set by your administrator"));
  } else {
    const remove = element("button", "secondary", "Remove");
    remove.type = "button";
    remove.setAttribute("aria-label", `Remove ${address}`);
    remove.addEventListener("click", () => {
      remove.disabled = true;
      void removeRouter(router.origin).catch(() => {
        remove.disabled = false;
        setStatus(status, "error", "Couldn't remove this router. Try again.");
      });
    });
    actions.append(remove);
  }
  item.append(title, status, actions);
  void showStatus(router, status, actions).catch(() => {
    setStatus(status, "error", "Couldn't check this router.");
  });
  return item;
}

let renderToken = 0;

async function render(): Promise<void> {
  renderToken += 1;
  const token = renderToken;
  const routers = await loadRouters(api.storage);
  if (token !== renderToken) {
    return;
  }
  empty.hidden = routers.length > 0;
  list.replaceChildren(...routers.map((router) => routerItem(router)));
}

async function addRouter(origin: string, granted: Promise<boolean>): Promise<void> {
  addButton.disabled = true;
  setStatus(addStatus, "pending", `Contacting ${displayAddress(origin)}…`);
  try {
    if (!(await granted.catch(() => false))) {
      setStatus(addStatus, "error", "Access wasn't granted, so the router wasn't added.");
      return;
    }
    const result = await portal.getInfo(origin);
    if (!result.ok) {
      await dropUnusedPermission(origin);
      setStatus(addStatus, "error", problemText(result, origin));
      return;
    }
    const items = await api.storage.sync.get(ROUTERS_KEY);
    const current = routerList(items[ROUTERS_KEY]);
    if (!current.includes(origin)) {
      await api.storage.sync.set({ [ROUTERS_KEY]: [...current, origin] });
    }
    input.value = "";
    setStatus(addStatus, "ok", `Added ${result.info.name ?? displayAddress(origin)}.`);
  } catch {
    setStatus(addStatus, "error", "Couldn't save the router. Try again.");
  } finally {
    addButton.disabled = false;
  }
}

form.addEventListener("submit", (event) => {
  event.preventDefault();
  const origin = normalizePortalOrigin(input.value);
  if (origin === null) {
    input.setAttribute("aria-invalid", "true");
    setStatus(
      addStatus,
      "error",
      "Enter the router's block page address over HTTPS, like blocked.gw.example.com:8068 (not an IP address).",
    );
    input.focus();
    return;
  }
  input.removeAttribute("aria-invalid");
  // Synchronously, inside the submit's user gesture — nothing awaited before it.
  const granted = api.permissions.request({ origins: [permissionPattern(origin)] });
  void addRouter(origin, granted);
});

api.storage.onChanged.addListener((changes, areaName) => {
  if (affectsRouters(changes, areaName)) {
    void render();
  }
});
api.permissions.onAdded.addListener(() => {
  void render();
});
api.permissions.onRemoved.addListener(() => {
  void render();
});

void render();
