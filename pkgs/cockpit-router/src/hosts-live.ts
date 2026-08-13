// Pure live-discovery helpers shared by the Hosts & Groups page and the IPS
// views: neighbor-table loading (`ip -j neigh`) consolidated per MAC, OUI
// vendor lookup (nmap's prefix database), Avahi hostname resolution and the
// streaming nmap port-scan parser. No React here — just cockpit calls.

interface Neigh {
  dst: string;
  lladdr?: string;
  dev: string;
  state?: string[];
}

// One physical device, consolidated from every neighbor entry sharing its MAC
// (a node typically has several addresses: IPv4 + link-local/global IPv6).
export interface LiveHost {
  mac: string;
  ips: string[];
  devs: string[];
  states: string[];
  vendor?: string;
  name?: string;
}

export const isIPv4 = (ip: string) => /^\d{1,3}(\.\d{1,3}){3}$/.test(ip);

// IPv4 before IPv6, numeric within each family.
export const ipCompare = (a: string, b: string) => {
  const av = isIPv4(a);
  if (av !== isIPv4(b)) {
    return av ? -1 : 1;
  }
  return a.localeCompare(b, undefined, { numeric: true });
};

// ── MAC vendor lookup (nmap's OUI prefix database, read once) ───────────────
let ouiMapPromise: Promise<Map<string, string>> | null = null;
export function loadOuiMap(): Promise<Map<string, string>> {
  if (ouiMapPromise) {
    return ouiMapPromise;
  }
  const path = window.cockpitRouterConfig?.macPrefixesPath;
  if (!path) {
    ouiMapPromise = Promise.resolve(new Map());
    return ouiMapPromise;
  }
  ouiMapPromise = cockpit
    .file(path)
    .read()
    .then((data: string | null) => {
      const m = new Map<string, string>();
      for (const line of (data || "").split("\n")) {
        if (!line || line[0] === "#") {
          continue;
        }
        const sp = line.indexOf(" ");
        if (sp !== 6) {
          continue;
        } // "<6 hex> <vendor>"
        m.set(line.slice(0, 6).toUpperCase(), line.slice(7).trim());
      }
      return m;
    })
    .catch(() => new Map<string, string>());
  return ouiMapPromise;
}

export const vendorFor = (mac: string | undefined, oui: Map<string, string>) => {
  if (!mac) {
    return "";
  }
  const hex = mac.replaceAll(":", "").toUpperCase();
  return hex.length >= 6 ? oui.get(hex.slice(0, 6)) || "" : "";
};

// ── Hostname resolution via Avahi/mDNS (one batch call) ─────────────────────
export function resolveNames(ips: string[]): Promise<Record<string, string>> {
  return new Promise((resolve) => {
    if (ips.length === 0) {
      resolve({});
      return;
    }
    let out = "";
    const proc = cockpit.spawn(["avahi-resolve", "-a", ...ips], { err: "ignore" });
    void proc.stream((d: string) => {
      out += d;
    });
    const done = () => {
      const map: Record<string, string> = {};
      for (const line of out.split("\n")) {
        const tab = line.indexOf("\t");
        if (tab > 0) {
          const ip = line.slice(0, tab).trim();
          const name = line
            .slice(tab + 1)
            .trim()
            .replace(/\.$/, "");
          if (ip && name) {
            map[ip] = name;
          }
        }
      }
      resolve(map);
    };
    proc.then(done).catch(done);
  });
}

// ── Neighbor loading (one row per MAC) ──────────────────────────────────────
// Read the kernel neighbor tables and collapse the entries into one LiveHost
// per MAC (FAILED entries dropped). Grouping is keyed by the upper-cased MAC,
// but the first-seen casing is kept for display. Vendors come from the OUI map.
export function loadNeighbors(): Promise<LiveHost[]> {
  return Promise.all([cockpit.spawn(["ip", "-j", "neigh"], { err: "message" }), loadOuiMap()]).then(
    ([out, oui]) => {
      const parsed = JSON.parse(out || "[]") as Neigh[];
      const rows = parsed.filter((n) => n.lladdr && !(n.state || []).includes("FAILED"));
      rows.sort((a, b) => a.dst.localeCompare(b.dst, undefined, { numeric: true }));
      const byMac = new Map<string, LiveHost>();
      for (const r of rows) {
        if (!r.lladdr) {
          continue;
        }
        const key = r.lladdr.toUpperCase();
        let node = byMac.get(key);
        if (!node) {
          node = { mac: r.lladdr, ips: [], devs: [], states: [] };
          const vendor = vendorFor(r.lladdr, oui);
          if (vendor) {
            node.vendor = vendor;
          }
          byMac.set(key, node);
        }
        if (!node.ips.includes(r.dst)) {
          node.ips.push(r.dst);
        }
        if (r.dev && !node.devs.includes(r.dev)) {
          node.devs.push(r.dev);
        }
        for (const s of r.state || []) {
          if (!node.states.includes(s)) {
            node.states.push(s);
          }
        }
      }
      const list = [...byMac.values()];
      for (const n of list) {
        n.ips.sort(ipCompare);
      }
      list.sort((a, b) => ipCompare(a.ips[0] ?? "", b.ips[0] ?? ""));
      return list;
    },
  );
}

// ── Port scan (nmap, streaming grepable output) ─────────────────────────────
// Scan the given IPv4 targets' top ports; `onUpdate` receives per-IP open-port
// lists as output lines arrive (an empty array means "scanned, none open").
// Returns the process handle so callers can await completion or close it.
export function scanOpenPorts(
  targets: string[],
  onUpdate: (updates: Record<string, number[]>) => void,
): CockpitProcess {
  let buf = "";
  const proc = cockpit.spawn(
    ["nmap", "-T4", "--top-ports", "100", "--open", "-oG", "-", ...targets],
    { superuser: "require", err: "message" },
  );
  void proc.stream((chunk: string) => {
    buf += chunk;
    const lines = buf.split("\n");
    buf = lines.pop() || "";
    const updates: Record<string, number[]> = {};
    for (const line of lines) {
      const m = line.match(/^Host:\s+(\d{1,3}(?:\.\d{1,3}){3})\b.*?\bPorts:\s+([^\t]+)/);
      if (m) {
        const ip = m[1] ?? "";
        const spec = m[2] ?? "";
        updates[ip] = spec
          .split(", ")
          .map((p) => p.split("/"))
          .filter((f) => f[1] === "open")
          .map((f) => Number(f[0]))
          .filter((n) => !Number.isNaN(n));
      }
    }
    if (Object.keys(updates).length > 0) {
      onUpdate(updates);
    }
  });
  return proc;
}
