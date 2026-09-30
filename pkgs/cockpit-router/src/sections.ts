// Where each top-level settings key is edited, and how a change to it reads.
//
// The changes panel (System → Operations) and the System page's sidebar
// status name the saved-but-unapplied sections and link to the page and tab
// that edit them. Kept free of the `cockpit` global, like settings-json.ts, so
// `node --test` can import it; sections.test.ts checks every key the settings
// schema allows has an entry here, so a new option cannot go unlisted.
import { changedTopKeys, diffLeaves } from "./settings-json.ts";
import type { Json, LeafChange, PathSegment } from "./settings-json.ts";

export interface Section {
  key: string;
  label: string;
  page: string; // manifest menu key, e.g. "hosts" (→ /router/hosts)
  tab?: string; // SubNav tab id on that page
}

type Place = Omit<Section, "key">;

// Labels are English here and translated where they are shown (cockpit.gettext
// needs the global, which this module must not touch).
const SECTIONS: Record<string, Place> = {
  accessPolicies: { label: "Access policies", page: "access-policies", tab: "policies" },
  acme: { label: "Certificates", page: "ingress", tab: "proxy" },
  adminUser: { label: "Admin user", page: "system", tab: "settings" },
  bootMode: { label: "Boot mode", page: "system", tab: "settings" },
  cloudflareTunnel: { label: "Cloudflare Tunnel", page: "ingress", tab: "tunnel" },
  ddns: { label: "Dynamic DNS", page: "network", tab: "ddns" },
  directory: { label: "Directory", page: "users", tab: "settings" },
  diskDevice: { label: "Disk", page: "system", tab: "settings" },
  dns: { label: "DNS", page: "dns" },
  fqdn: { label: "Domain name", page: "system", tab: "settings" },
  guest: { label: "Guest network", page: "network", tab: "guest" },
  hostGroups: { label: "Host groups", page: "hosts", tab: "groups" },
  hostName: { label: "Host name", page: "system", tab: "settings" },
  hosts: { label: "Hosts", page: "hosts", tab: "devices" },
  lan: { label: "LAN", page: "network", tab: "lan" },
  portForwards: { label: "Port forwards", page: "ingress", tab: "forwards" },
  reporting: { label: "Reports", page: "reports", tab: "schedules" },
  reverseProxy: { label: "Reverse proxy", page: "ingress", tab: "proxy" },
  stateVersion: { label: "State version", page: "system", tab: "settings" },
  suricata: { label: "Threat protection", page: "threat-protection" },
  timeZone: { label: "Time zone", page: "system", tab: "settings" },
  trunkInterfaces: { label: "Trunk interfaces", page: "network", tab: "interfaces" },
  upnp: { label: "UPnP", page: "firewall", tab: "upnp" },
  wan: { label: "WAN", page: "network", tab: "wan" },
  wireguard: { label: "WireGuard", page: "network", tab: "wireguard" },
  wireless: { label: "Wireless", page: "wireless" },
};

export const SECTION_KEYS = Object.keys(SECTIONS);

// A key the map does not know (one newer than this plugin) still shows, on
// the System page.
export function sectionOf(key: string): Section {
  return { key, ...(SECTIONS[key] ?? { label: key, page: "system" }) };
}

// The Cockpit path of the page (and tab) that edits the section.
export function sectionHref(section: Section): string {
  return `/router/${section.page}${section.tab ? `#/?tab=${section.tab}` : ""}`;
}

export interface SectionChanges {
  section: Section;
  changes: LeafChange[];
}

// Saved-but-unapplied changes, grouped by section and sorted by label.
export function summarizeChanges(applied: Json, desired: Json): SectionChanges[] {
  return changedTopKeys(desired, applied)
    .map((key) => {
      const before =
        typeof applied === "object" && applied && !Array.isArray(applied)
          ? applied[key]
          : undefined;
      const after =
        typeof desired === "object" && desired && !Array.isArray(desired)
          ? desired[key]
          : undefined;
      return { section: sectionOf(key), changes: diffLeaves(before, after, [key]) };
    })
    .toSorted((a, b) => a.section.label.localeCompare(b.section.label));
}

const segmentText = (seg: PathSegment): string =>
  typeof seg === "string" ? seg : typeof seg === "number" ? `#${seg + 1}` : `“${seg.name}”`;

// A change's path below its section, e.g. `“tv” › staticIp` for
// hosts[name=tv].staticIp; "" when the whole section changed.
export function formatPath(path: PathSegment[]): string {
  return path
    .slice(1)
    .map((seg) => segmentText(seg))
    .join(" › ");
}

// A value as the change list shows it: short, one line.
export function formatValue(value?: Json): string {
  if (value === undefined) {
    return "—";
  }
  if (Array.isArray(value)) {
    return value.length === 0 ? "[]" : `[${value.length}]`;
  }
  if (value !== null && typeof value === "object") {
    const { name } = value;
    return typeof name === "string" ? `“${name}”` : "{…}";
  }
  const text = typeof value === "string" ? value : JSON.stringify(value);
  return text.length > 60 ? `${text.slice(0, 59)}…` : text;
}
