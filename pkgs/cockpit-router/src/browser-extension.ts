// The browser extension's side of the Block page tab: whether the router
// serves the HTTPS portal the extension talks to, the address to pair it
// with, and managed-policy snippets for deploying it to many browsers.
//
// The portal exists while router.fqdn is set and the block page is on
// (modules/cockpit-cert.nix, wantPortal), at blocked.<fqdn> on router-logd's
// tlsPort. Everything here reads the APPLIED settings: the portal only exists
// once they are.
import { getPath } from "./settings-json.ts";
import type { Json } from "./settings-json.ts";

// The certificate's name under /var/lib/acme and in its acme-* units.
export const PORTAL_CERT = "router-portal";
export const DEFAULT_PORTAL_PORT = 8068;
export const DOCS_URL =
  "https://avunu.github.io/nixos-router/docs/access-policies/browser-extension/";

// The extension's ids: Firefox's is chosen in its manifest (gecko.id); the
// Chrome Web Store assigns Chrome's on the first upload, and until it is
// filled in here no Chrome snippet is offered.
export const EXTENSION_IDS: { firefox: string; chrome: string | null } = {
  firefox: "nixos-router@avu.nu",
  chrome: null,
};

export type PortalState =
  | { state: "ready"; name: string; port: number; origin: string; address: string }
  | { state: "needsName" }
  | { state: "needsBlockPage" }
  | { state: "needsDns" };

export function portalState(applied: Json): PortalState {
  if (getPath(applied, "dns.technitium.enable") === false) {
    return { state: "needsDns" };
  }
  if (getPath(applied, "accessPolicies.blockPage.enable") !== true) {
    return { state: "needsBlockPage" };
  }
  const fqdn = getPath(applied, "fqdn");
  if (typeof fqdn !== "string" || fqdn.trim() === "") {
    return { state: "needsName" };
  }
  const rawPort = getPath(applied, "reporting.logd.tlsPort");
  const port = typeof rawPort === "number" ? rawPort : DEFAULT_PORTAL_PORT;
  const name = `blocked.${fqdn.trim().toLowerCase()}`;
  return {
    state: "ready",
    name,
    port,
    origin: `https://${name}:${port}`,
    address: `${name}:${port}`,
  };
}

const pretty = (obj: unknown) => JSON.stringify(obj, null, 2);

// policies.json (/etc/firefox/policies/policies.json on Linux): the router
// list the extension reads through storage.managed.
export function firefoxPolicy(origin: string): string {
  return pretty({
    policies: { "3rdparty": { Extensions: { [EXTENSION_IDS.firefox]: { routers: [origin] } } } },
  });
}

// A Chrome/Edge managed policy file (/etc/opt/chrome/policies/managed/ on
// Linux; the same keys under 3rdparty\extensions\<id>\policy on Windows).
export function chromePolicy(origin: string, id: string): string {
  return pretty({ "3rdparty": { extensions: { [id]: { routers: [origin] } } } });
}
