import { useEffect, useState, useCallback, useRef, useMemo } from "react";
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
  Tabs,
  Tab,
  TabTitleText,
  Form,
  FormGroup,
  TextInput,
  ActionGroup,
} from "@patternfly/react-core";
import { Table, Thead, Tbody, Tr, Th, Td, OuterScrollContainer, InnerScrollContainer } from "@patternfly/react-table";
import { readOption, writeOption } from "./nix";
import { PendingBanner, useLoader, useSaver, SaverStatus, Loading } from "./settings";

const _ = cockpit.gettext;

interface Neigh {
  dst: string;
  lladdr?: string;
  dev: string;
  state?: string[];
}

// One physical device, consolidated from every neighbor entry sharing its MAC
// (a node typically has several addresses: IPv4 + link-local/global IPv6).
interface HostNode {
  mac: string;
  ips: string[];
  devs: string[];
  states: string[];
}

const isIPv4 = (ip: string) => /^\d{1,3}(\.\d{1,3}){3}$/.test(ip);

// IPv4 before IPv6, numeric within each family.
const ipCompare = (a: string, b: string) => {
  const av = isIPv4(a);
  if (av !== isIPv4(b)) return av ? -1 : 1;
  return a.localeCompare(b, undefined, { numeric: true });
};

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

const HostsTable = () => {
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

  // Collapse the neighbor entries into one row per MAC. Grouping is keyed by the
  // upper-cased MAC, but the first-seen casing is kept for display.
  const nodes: HostNode[] = useMemo(() => {
    const byMac = new Map<string, HostNode>();
    for (const r of rows) {
      if (!r.lladdr) continue;
      const key = r.lladdr.toUpperCase();
      let node = byMac.get(key);
      if (!node) {
        node = { mac: r.lladdr, ips: [], devs: [], states: [] };
        byMac.set(key, node);
      }
      if (!node.ips.includes(r.dst)) node.ips.push(r.dst);
      if (r.dev && !node.devs.includes(r.dev)) node.devs.push(r.dev);
      for (const s of r.state || []) if (!node.states.includes(s)) node.states.push(s);
    }
    const list = [...byMac.values()];
    for (const n of list) n.ips.sort(ipCompare);
    list.sort((a, b) => ipCompare(a.ips[0], b.ips[0]));
    return list;
  }, [rows]);

  // Hostnames resolve per IP; a node shows the distinct names across its IPs.
  const nodeName = (n: HostNode) =>
    [...new Set(n.ips.map((ip) => names[ip]).filter(Boolean))].join(", ");

  // Open ports are scanned per IP; report the union, distinguishing "scanned,
  // none open" (empty array) from "not scanned yet" (undefined).
  const nodePorts = (n: HostNode): number[] | undefined => {
    const set = new Set<number>();
    let scanned = false;
    for (const ip of n.ips) {
      const p = ports[ip];
      if (p) {
        scanned = true;
        for (const x of p) set.add(x);
      }
    }
    return scanned ? [...set].sort((a, b) => a - b) : undefined;
  };

  const shown = nodes.filter(
    (n) =>
      !filter ||
      [...n.ips, n.mac, ...n.devs, nodeName(n), vendorFor(n.mac, oui)]
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
                  {shown.map((n) => {
                    const open = nodePorts(n);
                    return (
                      <Tr key={n.mac}>
                        <Td>
                          {n.ips.map((ip) => (
                            <div key={ip}>{ip}</div>
                          ))}
                        </Td>
                        <Td>{nodeName(n) || "—"}</Td>
                        <Td>{vendorFor(n.mac, oui) || "—"}</Td>
                        <Td>{n.mac}</Td>
                        <Td>{n.devs.join(", ")}</Td>
                        <Td>{n.states.join(", ")}</Td>
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

interface DhcpForm {
  domain: string;
  poolOffset: number;
  poolSize: number;
  leaseTime: string;
}

const HostsSettings = () => {
  const { value, setValue, loading, error } = useLoader<DhcpForm>(async () => {
    const [domain, dhcp] = await Promise.all([
      readOption<string>("lan.domain"),
      readOption<any>("lan.dhcp"),
    ]);
    return {
      domain: domain || "",
      poolOffset: dhcp?.poolOffset ?? 100,
      poolSize: dhcp?.poolSize ?? 150,
      leaseTime: dhcp?.leaseTime || "24h",
    };
  }, { domain: "", poolOffset: 100, poolSize: 150, leaseTime: "24h" });
  const { saving, status, run } = useSaver();
  const set = (patch: Partial<DhcpForm>) => setValue((v) => ({ ...v, ...patch }));

  if (loading) return <Loading />;
  if (error) return <Alert variant="danger" isInline title={_("Could not load settings")}>{error}</Alert>;

  const save = () =>
    run(async () => {
      await writeOption("lan.domain", value.domain);
      await writeOption("lan.dhcp.poolOffset", value.poolOffset);
      await writeOption("lan.dhcp.poolSize", value.poolSize);
      await writeOption("lan.dhcp.leaseTime", value.leaseTime);
    });

  return (
    <Stack hasGutter className="ct-router-stack">
      <StackItem isFilled style={{ overflowY: "auto" }}>
        <PendingBanner />
        <Form isHorizontal onSubmit={(e) => e.preventDefault()}>
          <FormGroup label={_("LAN domain")} fieldId="lanDomain">
            <TextInput
              id="lanDomain"
              value={value.domain}
              onChange={(_e, v) => set({ domain: v })}
            />
          </FormGroup>
          <FormGroup
            label={_("DHCP pool offset")}
            fieldId="poolOffset"
            labelHelp={_("First host address in the DHCP pool, counted from the network address")}
          >
            <TextInput
              id="poolOffset"
              type="number"
              value={value.poolOffset}
              onChange={(_e, v) => set({ poolOffset: Number(v) || 0 })}
            />
          </FormGroup>
          <FormGroup label={_("DHCP pool size")} fieldId="poolSize">
            <TextInput
              id="poolSize"
              type="number"
              value={value.poolSize}
              onChange={(_e, v) => set({ poolSize: Number(v) || 0 })}
            />
          </FormGroup>
          <FormGroup
            label={_("DHCP lease time")}
            fieldId="leaseTime"
            labelHelp={_("e.g. 12h, 30d")}
          >
            <TextInput
              id="leaseTime"
              value={value.leaseTime}
              onChange={(_e, v) => set({ leaseTime: v })}
            />
          </FormGroup>
          <SaverStatus status={status} />
          <ActionGroup>
            <Button variant="primary" onClick={save} isLoading={saving} isDisabled={saving}>
              {_("Save")}
            </Button>
          </ActionGroup>
        </Form>
      </StackItem>
    </Stack>
  );
};

export const Hosts = () => {
  const [tab, setTab] = useState<number | string>(0);
  return (
    <Stack className="ct-router-stack">
      <StackItem>
        <Tabs activeKey={tab} onSelect={(_e, k) => setTab(k)} isBox aria-label={_("Hosts")}>
          <Tab eventKey={0} title={<TabTitleText>{_("Connected hosts")}</TabTitleText>} />
          <Tab eventKey={1} title={<TabTitleText>{_("DHCP settings")}</TabTitleText>} />
        </Tabs>
      </StackItem>
      <StackItem isFilled className="ct-table-scroll">
        {tab === 0 ? <HostsTable /> : <HostsSettings />}
      </StackItem>
    </Stack>
  );
};
