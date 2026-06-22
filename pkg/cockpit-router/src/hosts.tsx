import { useEffect, useState, useCallback, useRef } from "react";
import {
  Toolbar,
  ToolbarContent,
  ToolbarItem,
  SearchInput,
  Button,
  Spinner,
  Alert,
  EmptyState,
  EmptyStateBody,
  Label,
  LabelGroup,
  Stack,
  StackItem,
} from "@patternfly/react-core";
import { Table, Thead, Tbody, Tr, Th, Td, OuterScrollContainer, InnerScrollContainer } from "@patternfly/react-table";

const _ = cockpit.gettext;

interface Neigh {
  dst: string;
  lladdr?: string;
  dev: string;
  state?: string[];
}

const isIPv4 = (ip: string) => /^\d{1,3}(\.\d{1,3}){3}$/.test(ip);

// ── MAC vendor lookup (nmap's OUI prefix database, read once) ───────────────
let ouiMapPromise: Promise<Map<string, string>> | null = null;
function loadOuiMap(): Promise<Map<string, string>> {
  if (ouiMapPromise) return ouiMapPromise;
  const path = window.cockpitRouterConfig?.macPrefixesPath;
  if (!path) {
    ouiMapPromise = Promise.resolve(new Map());
    return ouiMapPromise;
  }
  ouiMapPromise = cockpit
    .file(path)
    .read()
    .then((data: string) => {
      const m = new Map<string, string>();
      for (const line of (data || "").split("\n")) {
        if (!line || line[0] === "#") continue;
        const sp = line.indexOf(" ");
        if (sp !== 6) continue; // "<6 hex> <vendor>"
        m.set(line.slice(0, 6).toUpperCase(), line.slice(7).trim());
      }
      return m;
    })
    .catch(() => new Map<string, string>());
  return ouiMapPromise;
}

const vendorFor = (mac: string | undefined, oui: Map<string, string>) => {
  if (!mac) return "";
  const hex = mac.replace(/:/g, "").toUpperCase();
  return hex.length >= 6 ? oui.get(hex.slice(0, 6)) || "" : "";
};

// ── Hostname resolution via Avahi/mDNS (one batch call) ─────────────────────
function resolveNames(ips: string[]): Promise<Record<string, string>> {
  return new Promise((resolve) => {
    if (!ips.length) {
      resolve({});
      return;
    }
    let out = "";
    const proc = cockpit.spawn(["avahi-resolve", "-a", ...ips], { err: "ignore" });
    proc.stream((d: string) => {
      out += d;
    });
    const done = () => {
      const map: Record<string, string> = {};
      for (const line of out.split("\n")) {
        const tab = line.indexOf("\t");
        if (tab > 0) {
          const ip = line.slice(0, tab).trim();
          const name = line.slice(tab + 1).trim().replace(/\.$/, "");
          if (ip && name) map[ip] = name;
        }
      }
      resolve(map);
    };
    proc.then(done).catch(done);
  });
}

export const Hosts = () => {
  const [rows, setRows] = useState<Neigh[]>([]);
  const [names, setNames] = useState<Record<string, string>>({});
  const [oui, setOui] = useState<Map<string, string>>(new Map());
  const [ports, setPorts] = useState<Record<string, number[]>>({});
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [filter, setFilter] = useState("");
  const [scanning, setScanning] = useState(false);
  const [scanError, setScanError] = useState("");
  const [isStuck, setIsStuck] = useState(false);
  const scanProc = useRef<any>(null);

  useEffect(() => {
    loadOuiMap().then(setOui);
  }, []);

  const load = useCallback(() => {
    setError("");
    cockpit
      .spawn(["ip", "-j", "neigh"], { err: "message" })
      .then((out: string) => {
        const parsed: Neigh[] = JSON.parse(out || "[]");
        const hosts = parsed.filter(
          (n) => n.lladdr && !(n.state || []).includes("FAILED"),
        );
        hosts.sort((a, b) => a.dst.localeCompare(b.dst, undefined, { numeric: true }));
        setRows(hosts);
        setLoading(false);
        // Enrich with hostnames asynchronously (don't block the table).
        resolveNames(hosts.map((h) => h.dst)).then((m) =>
          setNames((prev) => ({ ...prev, ...m })),
        );
      })
      .catch((e: any) => {
        setError(e.message || String(e));
        setLoading(false);
      });
  }, []);

  useEffect(() => {
    load();
    const timer = setInterval(load, 15000);
    return () => clearInterval(timer);
  }, [load]);

  const scanPorts = useCallback(() => {
    const targets = rows.map((r) => r.dst).filter(isIPv4);
    if (!targets.length) return;
    setScanError("");
    setScanning(true);
    let buf = "";
    const proc = cockpit.spawn(
      ["nmap", "-T4", "--top-ports", "100", "--open", "-oG", "-", ...targets],
      { superuser: "require", err: "message" },
    );
    scanProc.current = proc;
    proc.stream((chunk: string) => {
      buf += chunk;
      const lines = buf.split("\n");
      buf = lines.pop() || "";
      const updates: Record<string, number[]> = {};
      for (const line of lines) {
        const m = line.match(/^Host:\s+(\d{1,3}(?:\.\d{1,3}){3})\b.*?\bPorts:\s+([^\t]+)/);
        if (m) {
          updates[m[1]] = m[2]
            .split(", ")
            .map((p) => p.split("/"))
            .filter((f) => f[1] === "open")
            .map((f) => Number(f[0]))
            .filter((n) => !Number.isNaN(n));
        }
      }
      if (Object.keys(updates).length) setPorts((prev) => ({ ...prev, ...updates }));
    })
      .then(() => setScanning(false))
      .catch((e: any) => {
        setScanError(e.message || String(e));
        setScanning(false);
      });
  }, [rows]);

  const shown = rows.filter(
    (r) =>
      !filter ||
      [r.dst, r.lladdr, r.dev, names[r.dst], vendorFor(r.lladdr, oui)]
        .join(" ")
        .toLowerCase()
        .includes(filter.toLowerCase()),
  );

  if (loading) return <Spinner />;

  return (
    <Stack hasGutter className="ct-router-stack">
      <StackItem>
        <Toolbar>
          <ToolbarContent>
            <ToolbarItem>
              <SearchInput
                placeholder={_("Filter by IP, host, MAC, vendor")}
                value={filter}
                onChange={(_e, v) => setFilter(v)}
                onClear={() => setFilter("")}
              />
            </ToolbarItem>
            <ToolbarItem>
              <Button variant="secondary" onClick={load} isDisabled={scanning}>
                {_("Refresh")}
              </Button>
            </ToolbarItem>
            <ToolbarItem>
              <Button
                variant="secondary"
                onClick={scanPorts}
                isDisabled={scanning}
                icon={scanning ? <Spinner size="sm" /> : undefined}
              >
                {scanning ? _("Scanning ports…") : _("Scan ports")}
              </Button>
            </ToolbarItem>
          </ToolbarContent>
        </Toolbar>
      </StackItem>
      {error && (
        <StackItem>
          <Alert variant="danger" title={error} isInline />
        </StackItem>
      )}
      {scanError && (
        <StackItem>
          <Alert variant="warning" title={_("Port scan failed")} isInline>
            {scanError}
          </Alert>
        </StackItem>
      )}
      <StackItem isFilled className="ct-table-scroll">
        {shown.length === 0 ? (
          <EmptyState>
            <EmptyStateBody>{_("No connected hosts found.")}</EmptyStateBody>
          </EmptyState>
        ) : (
          <OuterScrollContainer>
            <InnerScrollContainer onScroll={(e) => setIsStuck(e.currentTarget.scrollTop > 0)}>
              <Table
                variant="compact"
                aria-label={_("Connected hosts")}
                isStickyHeaderBase
                isStickyHeaderStuck={isStuck}
              >
                <Thead>
                  <Tr>
                    <Th>{_("IP address")}</Th>
                    <Th>{_("Hostname")}</Th>
                    <Th>{_("Vendor")}</Th>
                    <Th>{_("MAC address")}</Th>
                    <Th>{_("Interface")}</Th>
                    <Th>{_("State")}</Th>
                    <Th>{_("Open ports")}</Th>
                  </Tr>
                </Thead>
                <Tbody>
                  {shown.map((r, i) => {
                    const open = ports[r.dst];
                    return (
                      <Tr key={i}>
                        <Td>{r.dst}</Td>
                        <Td>{names[r.dst] || "—"}</Td>
                        <Td>{vendorFor(r.lladdr, oui) || "—"}</Td>
                        <Td>{r.lladdr || "—"}</Td>
                        <Td>{r.dev}</Td>
                        <Td>{(r.state || []).join(", ")}</Td>
                        <Td>
                          {open && open.length > 0 ? (
                            <LabelGroup numLabels={8}>
                              {open.map((p) => (
                                <Label key={p} isCompact color="blue">
                                  {p}
                                </Label>
                              ))}
                            </LabelGroup>
                          ) : open ? (
                            _("none")
                          ) : (
                            "—"
                          )}
                        </Td>
                      </Tr>
                    );
                  })}
                </Tbody>
              </Table>
            </InnerScrollContainer>
          </OuterScrollContainer>
        )}
      </StackItem>
    </Stack>
  );
};
