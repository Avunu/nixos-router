// Hosts — the persistent device registry (settings `hosts` and
// `hostGroups`) merged with live neighbor discovery (hosts-live.ts).
//
// Devices tab: one table keyed by lowercase MAC that overlays the registry on
// the live neighbor list. Adopting a device records it in the registry; giving
// it a static IP creates a DHCP reservation, which device-tier access policies
// require (the IP→device mapping must be stable). Groups tab: named device
// groups that access policies can target, with referential integrity into
// hosts[].group on rename/delete.
import { useEffect, useState, useCallback, useMemo } from "react";
import type { Ref } from "react";
import { errMsg } from "./nix";
import type { Json } from "./nix";
import {
  ActionGroup,
  Alert,
  Button,
  Card,
  CardBody,
  CardTitle,
  EmptyState,
  EmptyStateBody,
  Form,
  FormGroup,
  FormSelect,
  FormSelectOption,
  HelperText,
  HelperTextItem,
  Icon,
  Label,
  MenuToggle,
  SearchInput,
  Select,
  SelectList,
  SelectOption,
  Split,
  SplitItem,
  Stack,
  StackItem,
  Switch,
  TextArea,
  TextInput,
  TextInputGroup,
  TextInputGroupMain,
  TextInputGroupUtilities,
  Toolbar,
  ToolbarContent,
  ToolbarItem,
  Tooltip,
} from "@patternfly/react-core";
import type { MenuToggleElement } from "@patternfly/react-core";
import { ExclamationTriangleIcon, TimesIcon } from "@patternfly/react-icons";
import {
  Table,
  Thead,
  Tbody,
  Tr,
  Th,
  Td,
  OuterScrollContainer,
  InnerScrollContainer,
} from "@patternfly/react-table";
import { useSettings, Loading, SubNav, SaveBar, hint, TabbedPage } from "./settings";
import { loadNeighbors, resolveNames, loadOuiMap, vendorFor, isIPv4 } from "./hosts-live";
import type { LiveHost } from "./hosts-live";
import { suggestStaticIp, cidrContains, ipToInt } from "./ip-math";
import type { NetworkShape } from "./ip-math";
import { loadDirectoryAll } from "./directory";
import type { RouterHost, HostGroup, DirectoryUser } from "./types";

const _ = cockpit.gettext;

type S = ReturnType<typeof useSettings>;

// ── shared helpers ──────────────────────────────────────────────────────────
interface NetShapes {
  lan: NetworkShape;
  guest: NetworkShape | null;
}

const readShapes = (s: S): NetShapes => ({
  lan: {
    networkAddress: s.valueOf("lan.networkAddress", ""),
    prefixLength: s.valueOf("lan.prefixLength", 24),
    gateway: s.valueOf("lan.address", ""),
    poolOffset: s.valueOf("lan.dhcp.poolOffset", 100),
    poolSize: s.valueOf("lan.dhcp.poolSize", 150),
  },
  guest: s.valueOf("guest.enable", false)
    ? {
        networkAddress: s.valueOf("guest.networkAddress", ""),
        prefixLength: s.valueOf("guest.prefixLength", 24),
        gateway: s.valueOf("guest.address", ""),
        poolOffset: s.valueOf("guest.dhcp.poolOffset", 100),
        poolSize: s.valueOf("guest.dhcp.poolSize", 150),
      }
    : null,
});

const shapeCidr = (shape: NetworkShape) => `${shape.networkAddress}/${shape.prefixLength}`;

interface IpIssue {
  level: "error" | "warning";
  msg: string;
}

// Static-IP validation: errors block the save, the in-pool case is only a
// warning (the reservation still works; the address is carved out of the pool).
function checkStaticIp(ip: string, shape: NetworkShape | null, taken: string[]): IpIssue | null {
  if (!ip) {
    return null;
  }
  if (!shape) {
    return { level: "error", msg: _("This network is not enabled.") };
  }
  if (ipToInt(ip) === null) {
    return { level: "error", msg: _("Not a valid IPv4 address.") };
  }
  if (!cidrContains(shapeCidr(shape), ip)) {
    return {
      level: "error",
      msg: cockpit.format(_("Outside the subnet ($0)."), shapeCidr(shape)),
    };
  }
  if (ip === shape.gateway) {
    return { level: "error", msg: _("This is the router's own address.") };
  }
  if (taken.includes(ip)) {
    return { level: "error", msg: _("Already reserved for another device.") };
  }
  const base = ipToInt(shape.networkAddress);
  const val = ipToInt(ip);
  if (base !== null && val !== null) {
    const poolStart = base + shape.poolOffset;
    if (val >= poolStart && val < poolStart + shape.poolSize) {
      return {
        level: "warning",
        msg: _("Inside the dynamic pool — will be excluded from dynamic assignment."),
      };
    }
  }
  return null;
}

// Directory state + status from the sync-state files. `users` holds only the
// identities already referenced and resolved (SSSD is never enumerated), so it
// is an autocomplete source rather than a closed list; `unresolved` is what
// distinguishes a name that has not been looked up yet from a typo.
function useDirectory(): { users: DirectoryUser[]; unresolved: string[] } {
  const [dir, setDir] = useState<{ users: DirectoryUser[]; unresolved: string[] }>({
    users: [],
    unresolved: [],
  });
  useEffect(() => {
    void loadDirectoryAll()
      .then(({ state, status }) =>
        setDir({
          users: Array.isArray(state?.users) ? state.users : [],
          unresolved: Array.isArray(status?.unresolved) ? status.unresolved : [],
        }),
      )
      .catch(() => {});
  }, []);
  return dir;
}

const userLabel = (u: DirectoryUser) => (u.name && u.name !== u.id ? `${u.name} (${u.id})` : u.id);

// ── user picker ─────────────────────────────────────────────────────────────
// FREE TEXT with autocomplete, deliberately not a closed list. SSSD is not
// enumerated, so `users` only ever holds identities that some device or policy
// ALREADY references and the last sync resolved — the first device assigned to
// a new person types a name that is in neither array. The typed value is the
// stored value; the list is a convenience, and `unresolved` is what turns a
// typo into a visible warning instead of silent non-enforcement.
const UserTypeahead = ({
  users,
  unresolved,
  value,
  onChange,
}: {
  users: DirectoryUser[];
  unresolved: string[];
  value: string;
  onChange: (v: string) => void;
}) => {
  const [isOpen, setIsOpen] = useState(false);
  const q = value.trim().toLowerCase();
  const shown = q
    ? users.filter((u) => `${u.id} ${u.name} ${u.email}`.toLowerCase().includes(q))
    : users;

  const resolved = users.some((u) => u.id.toLowerCase() === q || u.email.toLowerCase() === q);
  const isBad = q !== "" && unresolved.some((n) => n.toLowerCase() === q);

  const toggle = (toggleRef: Ref<MenuToggleElement>) => (
    <MenuToggle
      ref={toggleRef}
      variant="typeahead"
      aria-label={_("User")}
      onClick={() => setIsOpen((o) => !o)}
      isExpanded={isOpen}
      isFullWidth
      status={isBad ? "warning" : undefined}
    >
      <TextInputGroup isPlain>
        <TextInputGroupMain
          value={value}
          onClick={() => setIsOpen(true)}
          onChange={(_e, v) => {
            onChange(v);
            setIsOpen(true);
          }}
          autoComplete="off"
          placeholder={_("directory login name, e.g. jdoe")}
          role="combobox"
          isExpanded={isOpen}
          aria-controls="host-user-listbox"
          aria-label={_("User")}
        />
        <TextInputGroupUtilities>
          {value ? (
            <Button
              variant="plain"
              onClick={() => onChange("")}
              aria-label={_("Clear user")}
              icon={<TimesIcon />}
            />
          ) : null}
        </TextInputGroupUtilities>
      </TextInputGroup>
    </MenuToggle>
  );

  return (
    <>
      <Select
        isOpen={isOpen}
        selected={value}
        variant="typeahead"
        onSelect={(_e, v) => {
          onChange(String(v ?? ""));
          setIsOpen(false);
        }}
        onOpenChange={setIsOpen}
        toggle={toggle}
      >
        <SelectList id="host-user-listbox">
          {shown.length === 0 ? (
            <SelectOption isDisabled value="">
              {_("No already-resolved user matches — type the login name anyway")}
            </SelectOption>
          ) : (
            shown.map((u) => (
              <SelectOption key={u.id} value={u.id} isSelected={u.id === value}>
                {userLabel(u)}
              </SelectOption>
            ))
          )}
        </SelectList>
      </Select>
      {q !== "" && !resolved && (
        <HelperText>
          {isBad ? (
            <HelperTextItem variant="warning">
              {cockpit.format(
                _(
                  "The last directory sync could not resolve '$0'. Check the spelling against the domain — this device will not get a user-tier policy.",
                ),
                value.trim(),
              )}
            </HelperTextItem>
          ) : (
            <HelperTextItem variant="indeterminate">
              {_("Not looked up yet — it will be resolved on the next directory sync.")}
            </HelperTextItem>
          )}
        </HelperText>
      )}
    </>
  );
};

// ── adopt / edit form (detail card, no modal) ───────────────────────────────
interface DeviceDraft {
  mac: string; // lowercase
  isNew: boolean;
  name: string;
  network: "lan" | "guest";
  staticIp: string;
  group: string;
  user: string;
  notes: string;
}

const DeviceEditor = ({
  init,
  live,
  shapes,
  groups,
  users,
  unresolved,
  taken,
  onSave,
  onCancel,
}: {
  init: DeviceDraft;
  live: LiveHost | null;
  shapes: NetShapes;
  groups: HostGroup[];
  users: DirectoryUser[];
  unresolved: string[];
  taken: string[];
  onSave: (h: RouterHost) => void;
  onCancel: () => void;
}) => {
  const [name, setName] = useState(init.name);
  const [network, setNetwork] = useState<"lan" | "guest">(init.network);
  const [staticIp, setStaticIp] = useState(init.staticIp);
  const [group, setGroup] = useState(init.group);
  const [user, setUser] = useState(init.user);
  const [notes, setNotes] = useState(init.notes);
  const [suggestMsg, setSuggestMsg] = useState("");

  const shape = network === "guest" ? shapes.guest : shapes.lan;
  const issue = checkStaticIp(staticIp.trim(), shape, taken);

  const suggest = () => {
    setSuggestMsg("");
    if (!shape) {
      return;
    }
    const liveV4 = (live?.ips ?? []).filter((ip) => isIPv4(ip));
    const current = liveV4.find((ip) => cidrContains(shapeCidr(shape), ip)) ?? liveV4[0];
    const suggestion = suggestStaticIp(shape, current, taken);
    if (suggestion) {
      setStaticIp(suggestion);
    } else {
      setSuggestMsg(_("No free address available in the reserved range."));
    }
  };

  const commit = () =>
    onSave({
      mac: init.mac,
      name: name.trim(),
      network,
      staticIp: staticIp.trim() || null,
      group: group || null,
      user: user.trim() || null,
      ...(notes.trim() ? { notes: notes.trim() } : {}),
    });

  return (
    <Card isCompact>
      <CardTitle>
        <Split hasGutter>
          <SplitItem isFilled>
            {cockpit.format(init.isNew ? _("Adopt device $0") : _("Edit device $0"), init.mac)}
          </SplitItem>
          <SplitItem>
            <Button variant="link" isInline onClick={onCancel}>
              {_("Close")}
            </Button>
          </SplitItem>
        </Split>
      </CardTitle>
      <CardBody>
        <Form isHorizontal onSubmit={(e) => e.preventDefault()}>
          <FormGroup label={_("Name")} fieldId="devName" isRequired>
            <TextInput
              id="devName"
              value={name}
              onChange={(_e, v) => setName(v)}
              aria-label={_("Name")}
            />
          </FormGroup>
          <FormGroup label={_("Network")} fieldId="devNetwork">
            <FormSelect
              id="devNetwork"
              value={network}
              onChange={(_e, v) => setNetwork(v === "guest" ? "guest" : "lan")}
              aria-label={_("Network")}
            >
              <FormSelectOption value="lan" label={_("LAN")} />
              {shapes.guest && <FormSelectOption value="guest" label={_("Guest")} />}
            </FormSelect>
          </FormGroup>
          <FormGroup
            label={_("Static IP")}
            fieldId="devIp"
            labelHelp={hint(
              _(
                "DHCP reservation for this device. Required for device-tier access policies; leave empty for a dynamic lease.",
              ),
            )}
          >
            <Split hasGutter>
              <SplitItem isFilled>
                <TextInput
                  id="devIp"
                  value={staticIp}
                  placeholder={_("dynamic")}
                  validated={issue ? issue.level : "default"}
                  onChange={(_e, v) => {
                    setStaticIp(v);
                    setSuggestMsg("");
                  }}
                  aria-label={_("Static IP")}
                />
              </SplitItem>
              <SplitItem>
                <Button variant="secondary" onClick={suggest}>
                  {_("Suggest")}
                </Button>
              </SplitItem>
            </Split>
            {(issue || suggestMsg) && (
              <HelperText>
                {issue && <HelperTextItem variant={issue.level}>{issue.msg}</HelperTextItem>}
                {suggestMsg && <HelperTextItem variant="warning">{suggestMsg}</HelperTextItem>}
              </HelperText>
            )}
          </FormGroup>
          <FormGroup label={_("Group")} fieldId="devGroup">
            <FormSelect
              id="devGroup"
              value={group}
              onChange={(_e, v) => setGroup(v)}
              aria-label={_("Group")}
            >
              <FormSelectOption value="" label={_("— none —")} />
              {groups.map((g) => (
                <FormSelectOption key={g.name} value={g.name} label={g.name} />
              ))}
            </FormSelect>
          </FormGroup>
          <FormGroup
            label={_("User")}
            fieldId="devUser"
            labelHelp={hint(
              _(
                "The directory login name, exactly as `id <name>` resolves it on the router. Free text: the directory is never enumerated, so a person nobody has referenced yet will not autocomplete.",
              ),
            )}
          >
            <UserTypeahead users={users} unresolved={unresolved} value={user} onChange={setUser} />
          </FormGroup>
          <FormGroup label={_("Notes")} fieldId="devNotes">
            <TextArea
              id="devNotes"
              value={notes}
              rows={3}
              resizeOrientation="vertical"
              onChange={(_e, v) => setNotes(v)}
              aria-label={_("Notes")}
            />
          </FormGroup>
          {(group || user.trim()) && !staticIp.trim() && (
            <Alert
              variant="warning"
              isInline
              isPlain
              title={_("No static IP — device-tier policies cannot apply")}
            />
          )}
          <ActionGroup>
            <Button
              variant="primary"
              onClick={commit}
              isDisabled={!name.trim() || issue?.level === "error"}
            >
              {init.isNew ? _("Adopt") : _("Update")}
            </Button>
            <Button variant="link" onClick={onCancel}>
              {_("Cancel")}
            </Button>
          </ActionGroup>
        </Form>
      </CardBody>
    </Card>
  );
};

// ── Devices tab ─────────────────────────────────────────────────────────────
interface DeviceRow {
  mac: string; // lowercase
  reg: RouterHost | null;
  live: LiveHost | null;
}

const DevicesTab = ({ s }: { s: S }) => {
  const hosts = s.valueOf<RouterHost[]>("hosts", []);
  const groups = s.valueOf<HostGroup[]>("hostGroups", []);
  const shapes = readShapes(s);
  const { users, unresolved } = useDirectory();

  const [neighbors, setNeighbors] = useState<LiveHost[]>([]);
  const [names, setNames] = useState<Record<string, string>>({});
  const [oui, setOui] = useState<Map<string, string>>(new Map());
  const [liveError, setLiveError] = useState("");
  const [filter, setFilter] = useState("");
  const [showUnregistered, setShowUnregistered] = useState(true);
  const [editing, setEditing] = useState<DeviceDraft | null>(null);
  const [confirmRemove, setConfirmRemove] = useState<string | null>(null);
  const [isStuck, setIsStuck] = useState(false);

  useEffect(() => {
    void loadOuiMap().then(setOui);
  }, []);

  const loadLive = useCallback(() => {
    setLiveError("");
    loadNeighbors()
      .then((list) => {
        setNeighbors(list);
        // Enrich with hostnames asynchronously (don't block the table).
        void resolveNames(list.flatMap((n) => n.ips)).then((m) =>
          setNames((prev) => ({ ...prev, ...m })),
        );
      })
      .catch((e: unknown) => setLiveError(errMsg(e)));
  }, []);

  useEffect(() => {
    loadLive();
    const timer = setInterval(loadLive, 15_000);
    return () => clearInterval(timer);
  }, [loadLive]);

  // Hostnames resolve per IP; a node shows the distinct names across its IPs.
  const liveName = (n: LiveHost) =>
    [...new Set(n.ips.map((ip) => names[ip]).filter(Boolean))].join(", ");

  // Registry entries overlaid with live neighbors, keyed by lowercase MAC.
  const rows: DeviceRow[] = useMemo(() => {
    const byMac = new Map<string, DeviceRow>();
    for (const h of hosts) {
      const mac = h.mac.toLowerCase();
      byMac.set(mac, { mac, reg: h, live: null });
    }
    for (const n of neighbors) {
      const mac = n.mac.toLowerCase();
      const row = byMac.get(mac);
      if (row) {
        row.live = n;
      } else {
        byMac.set(mac, { mac, reg: null, live: n });
      }
    }
    const list = [...byMac.values()];
    list.sort((a, b) => {
      const ipA = a.reg?.staticIp ?? a.live?.ips[0] ?? "";
      const ipB = b.reg?.staticIp ?? b.live?.ips[0] ?? "";
      if (Boolean(ipA) !== Boolean(ipB)) {
        return ipA ? -1 : 1;
      }
      const c = ipA.localeCompare(ipB, undefined, { numeric: true });
      return c !== 0 ? c : a.mac.localeCompare(b.mac);
    });
    return list;
  }, [hosts, neighbors]);

  const userDisplay = (val: string) => {
    const v = val.toLowerCase();
    const u = users.find((x) => x.id.toLowerCase() === v || x.email.toLowerCase() === v);
    return u?.name || val;
  };

  const shown = rows.filter((row) => {
    if (!showUnregistered && !row.reg) {
      return false;
    }
    if (!filter) {
      return true;
    }
    const hay = [
      row.mac,
      row.reg?.name ?? "",
      row.reg?.staticIp ?? "",
      row.reg?.group ?? "",
      row.reg?.user ?? "",
      row.reg?.user ? userDisplay(row.reg.user) : "",
      row.live?.vendor ?? vendorFor(row.mac, oui),
      row.live ? liveName(row.live) : "",
      ...(row.live?.ips ?? []),
    ]
      .join(" ")
      .toLowerCase();
    return hay.includes(filter.toLowerCase());
  });

  // Static IPs of every OTHER registered device (conflict set for validation).
  const takenIps = (mac: string) =>
    hosts
      .filter((h) => h.mac.toLowerCase() !== mac)
      .map((h) => h.staticIp)
      .filter(Boolean) as string[];

  const openAdopt = (row: DeviceRow) => {
    const liveV4 = (row.live?.ips ?? []).filter((ip) => isIPv4(ip));
    const inGuest = shapes.guest
      ? liveV4.some((ip) => cidrContains(shapeCidr(shapes.guest!), ip))
      : false;
    const network: "lan" | "guest" = inGuest ? "guest" : "lan";
    const shape = network === "guest" ? shapes.guest : shapes.lan;
    const current = shape
      ? (liveV4.find((ip) => cidrContains(shapeCidr(shape), ip)) ?? liveV4[0])
      : undefined;
    const suggestion = shape ? suggestStaticIp(shape, current, takenIps(row.mac)) : null;
    setConfirmRemove(null);
    setEditing({
      mac: row.mac,
      isNew: true,
      name: row.live ? liveName(row.live) : "",
      network,
      staticIp: suggestion ?? "",
      group: "",
      user: "",
      notes: "",
    });
  };

  const openEdit = (row: DeviceRow) => {
    if (!row.reg) {
      return;
    }
    setConfirmRemove(null);
    setEditing({
      mac: row.mac,
      isNew: false,
      name: row.reg.name,
      network: row.reg.network === "guest" ? "guest" : "lan",
      staticIp: row.reg.staticIp ?? "",
      group: row.reg.group ?? "",
      user: row.reg.user ?? "",
      notes: row.reg.notes ?? "",
    });
  };

  const commitDevice = (h: RouterHost) => {
    const idx = hosts.findIndex((x) => x.mac.toLowerCase() === h.mac.toLowerCase());
    const next = idx === -1 ? [...hosts, h] : hosts.map((x, i) => (i === idx ? h : x));
    s.setLeaf("hosts", next as unknown as Json);
    setEditing(null);
  };

  const removeDevice = (mac: string) => {
    s.setLeaf("hosts", hosts.filter((h) => h.mac.toLowerCase() !== mac) as unknown as Json);
    setConfirmRemove(null);
    if (editing?.mac === mac) {
      setEditing(null);
    }
  };

  const liveByMac = new Map(neighbors.map((n) => [n.mac.toLowerCase(), n]));

  return (
    <Stack hasGutter className="ct-router-stack">
      <StackItem>
        <Toolbar>
          <ToolbarContent>
            <ToolbarItem>
              <SearchInput
                placeholder={_("Filter by name, IP, MAC, vendor, group, user")}
                value={filter}
                onChange={(_e, v) => setFilter(v)}
                onClear={() => setFilter("")}
              />
            </ToolbarItem>
            <ToolbarItem>
              <Button variant="secondary" onClick={loadLive}>
                {_("Refresh")}
              </Button>
            </ToolbarItem>
            <ToolbarItem>
              <Switch
                id="show-unregistered"
                label={_("Show unregistered")}
                isChecked={showUnregistered}
                onChange={(_e, c) => setShowUnregistered(c)}
                aria-label={_("Show unregistered")}
              />
            </ToolbarItem>
          </ToolbarContent>
        </Toolbar>
      </StackItem>
      {liveError && (
        <StackItem>
          <Alert variant="warning" title={_("Could not read live neighbors")} isInline>
            {liveError}
          </Alert>
        </StackItem>
      )}
      {editing && (
        <StackItem>
          <DeviceEditor
            key={`${editing.mac}-${editing.isNew ? "adopt" : "edit"}`}
            init={editing}
            live={liveByMac.get(editing.mac) ?? null}
            shapes={shapes}
            groups={groups}
            users={users}
            unresolved={unresolved}
            taken={takenIps(editing.mac)}
            onSave={commitDevice}
            onCancel={() => setEditing(null)}
          />
        </StackItem>
      )}
      <StackItem isFilled className="ct-table-scroll">
        {shown.length === 0 ? (
          <EmptyState>
            <EmptyStateBody>
              {rows.length === 0 ? _("No devices found.") : _("No devices match the filter.")}
            </EmptyStateBody>
          </EmptyState>
        ) : (
          <OuterScrollContainer>
            <InnerScrollContainer onScroll={(e) => setIsStuck(e.currentTarget.scrollTop > 0)}>
              <Table
                variant="compact"
                aria-label={_("Devices")}
                isStickyHeaderBase
                isStickyHeaderStuck={isStuck}
              >
                <Thead>
                  <Tr>
                    <Th>{_("Status")}</Th>
                    <Th>{_("Name")}</Th>
                    <Th>{_("IP(s)")}</Th>
                    <Th>{_("Vendor")}</Th>
                    <Th>{_("Group")}</Th>
                    <Th>{_("User")}</Th>
                    <Th>{_("MAC address")}</Th>
                    <Th screenReaderText={_("Actions")} />
                  </Tr>
                </Thead>
                <Tbody>
                  {shown.map((row) => {
                    const discovered = row.live ? liveName(row.live) : "";
                    const needsStatic = Boolean(
                      row.reg && (row.reg.group || row.reg.user) && !row.reg.staticIp,
                    );
                    return (
                      <Tr key={row.mac}>
                        <Td>
                          {row.live ? (
                            row.reg ? (
                              <Label color="green" isCompact>
                                {_("online")}
                              </Label>
                            ) : (
                              <Label color="yellow" isCompact>
                                {_("new")}
                              </Label>
                            )
                          ) : (
                            <Label color="grey" isCompact>
                              {_("offline")}
                            </Label>
                          )}
                        </Td>
                        <Td>{row.reg ? row.reg.name : discovered ? <i>{discovered}</i> : "—"}</Td>
                        <Td>
                          {row.reg?.staticIp && (
                            <div>
                              <strong>{row.reg.staticIp}</strong>
                            </div>
                          )}
                          {(row.live?.ips ?? [])
                            .filter((ip) => ip !== row.reg?.staticIp)
                            .map((ip) => (
                              <div key={ip}>{ip}</div>
                            ))}
                          {needsStatic && (
                            <Tooltip
                              content={_("No static IP — device-tier policies cannot apply")}
                            >
                              <Icon status="warning">
                                <ExclamationTriangleIcon />
                              </Icon>
                            </Tooltip>
                          )}
                          {!row.reg?.staticIp &&
                            (row.live?.ips ?? []).length === 0 &&
                            !needsStatic &&
                            "—"}
                        </Td>
                        <Td>{row.live?.vendor || vendorFor(row.mac, oui) || "—"}</Td>
                        <Td>{row.reg?.group ?? "—"}</Td>
                        <Td>{row.reg?.user ? userDisplay(row.reg.user) : "—"}</Td>
                        <Td>{row.mac}</Td>
                        <Td>
                          {confirmRemove === row.mac ? (
                            <>
                              <Button
                                variant="link"
                                isInline
                                isDanger
                                onClick={() => removeDevice(row.mac)}
                              >
                                {_("Confirm remove")}
                              </Button>{" "}
                              <Button
                                variant="link"
                                isInline
                                onClick={() => setConfirmRemove(null)}
                              >
                                {_("Cancel")}
                              </Button>
                            </>
                          ) : row.reg ? (
                            <>
                              <Button variant="link" isInline onClick={() => openEdit(row)}>
                                {_("Edit")}
                              </Button>{" "}
                              <Button
                                variant="link"
                                isInline
                                isDanger
                                onClick={() => setConfirmRemove(row.mac)}
                              >
                                {_("Remove")}
                              </Button>
                            </>
                          ) : (
                            <Button variant="link" isInline onClick={() => openAdopt(row)}>
                              {_("Adopt")}
                            </Button>
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
      <StackItem>
        <SaveBar saving={s.saving} status={s.status} onSave={s.save} onSaveApply={s.saveAndApply} />
      </StackItem>
    </Stack>
  );
};

// ── Groups tab ──────────────────────────────────────────────────────────────
const GroupsTab = ({ s }: { s: S }) => {
  const groups = s.valueOf<HostGroup[]>("hostGroups", []);
  const hosts = s.valueOf<RouterHost[]>("hosts", []);
  const [newName, setNewName] = useState("");
  const [newDesc, setNewDesc] = useState("");
  const [renaming, setRenaming] = useState<{ from: string; value: string } | null>(null);
  const [confirmDelete, setConfirmDelete] = useState<string | null>(null);

  const setGroups = (g: HostGroup[]) => s.setLeaf("hostGroups", g as unknown as Json);
  const memberCount = (name: string) => hosts.filter((h) => h.group === name).length;
  const nameTaken = (name: string, except?: string) =>
    groups.some((g) => g.name !== except && g.name.toLowerCase() === name.toLowerCase());

  const addGroup = () => {
    const n = newName.trim();
    if (!n || nameTaken(n)) {
      return;
    }
    setGroups([...groups, { name: n, ...(newDesc.trim() ? { description: newDesc.trim() } : {}) }]);
    setNewName("");
    setNewDesc("");
  };

  // Renames keep referential integrity: member hosts follow in the same edit.
  const commitRename = () => {
    if (!renaming) {
      return;
    }
    const to = renaming.value.trim();
    const { from } = renaming;
    if (!to || (to !== from && nameTaken(to, from))) {
      return;
    }
    if (to !== from) {
      setGroups(groups.map((g) => (g.name === from ? { ...g, name: to } : g)));
      s.setLeaf(
        "hosts",
        hosts.map((h) => (h.group === from ? { ...h, group: to } : h)) as unknown as Json,
      );
    }
    setRenaming(null);
  };

  const setDescription = (name: string, description: string) =>
    setGroups(groups.map((g) => (g.name === name ? { ...g, description } : g)));

  // Deleting clears the group ref from member hosts in the same save.
  const clearGroupRef = (h: RouterHost): RouterHost => ({ ...h, group: null });
  const removeGroup = (name: string) => {
    setGroups(groups.filter((g) => g.name !== name));
    if (memberCount(name) > 0) {
      s.setLeaf(
        "hosts",
        hosts.map((h) => (h.group === name ? clearGroupRef(h) : h)) as unknown as Json,
      );
    }
    setConfirmDelete(null);
  };

  const renameInvalid = renaming
    ? !renaming.value.trim() ||
      (renaming.value.trim() !== renaming.from && nameTaken(renaming.value.trim(), renaming.from))
    : false;
  const addInvalid = Boolean(newName.trim()) && nameTaken(newName.trim());

  return (
    <Stack hasGutter className="ct-router-stack">
      <StackItem>
        <Split hasGutter>
          <SplitItem>
            <TextInput
              value={newName}
              placeholder={_("Group name")}
              onChange={(_e, v) => setNewName(v)}
              validated={addInvalid ? "error" : "default"}
              onKeyDown={(e) => {
                if (e.key === "Enter") {
                  e.preventDefault();
                  addGroup();
                }
              }}
              aria-label={_("Group name")}
            />
          </SplitItem>
          <SplitItem isFilled>
            <TextInput
              value={newDesc}
              placeholder={_("Description (optional)")}
              onChange={(_e, v) => setNewDesc(v)}
              aria-label={_("Description")}
            />
          </SplitItem>
          <SplitItem>
            <Button
              variant="secondary"
              onClick={addGroup}
              isDisabled={!newName.trim() || addInvalid}
            >
              {_("Add group")}
            </Button>
          </SplitItem>
        </Split>
        {addInvalid && (
          <HelperText>
            <HelperTextItem variant="error">{_("A group with this name exists.")}</HelperTextItem>
          </HelperText>
        )}
      </StackItem>
      <StackItem isFilled style={{ overflowY: "auto" }}>
        {groups.length === 0 ? (
          <EmptyState>
            <EmptyStateBody>
              {_("No device groups yet. Groups let access policies target sets of devices.")}
            </EmptyStateBody>
          </EmptyState>
        ) : (
          <Table variant="compact" aria-label={_("Device groups")}>
            <Thead>
              <Tr>
                <Th>{_("Name")}</Th>
                <Th>{_("Description")}</Th>
                <Th>{_("Members")}</Th>
                <Th screenReaderText={_("Actions")} />
              </Tr>
            </Thead>
            <Tbody>
              {groups.map((g) => {
                const members = memberCount(g.name);
                return (
                  <Tr key={g.name}>
                    <Td>
                      {renaming?.from === g.name ? (
                        <>
                          <Split hasGutter>
                            <SplitItem isFilled>
                              <TextInput
                                value={renaming.value}
                                onChange={(_e, v) => setRenaming({ from: g.name, value: v })}
                                validated={renameInvalid ? "error" : "default"}
                                onKeyDown={(e) => {
                                  if (e.key === "Enter") {
                                    e.preventDefault();
                                    commitRename();
                                  }
                                }}
                                aria-label={_("New group name")}
                              />
                            </SplitItem>
                            <SplitItem>
                              <Button
                                variant="link"
                                isInline
                                onClick={commitRename}
                                isDisabled={renameInvalid}
                              >
                                {_("Save")}
                              </Button>{" "}
                              <Button variant="link" isInline onClick={() => setRenaming(null)}>
                                {_("Cancel")}
                              </Button>
                            </SplitItem>
                          </Split>
                          {renameInvalid && (
                            <HelperText>
                              <HelperTextItem variant="error">
                                {_("Group names must be unique and non-empty.")}
                              </HelperTextItem>
                            </HelperText>
                          )}
                        </>
                      ) : (
                        g.name
                      )}
                    </Td>
                    <Td>
                      <TextInput
                        value={g.description ?? ""}
                        placeholder={_("Description")}
                        onChange={(_e, v) => setDescription(g.name, v)}
                        aria-label={cockpit.format(_("Description for $0"), g.name)}
                      />
                    </Td>
                    <Td>
                      {members > 0 ? (
                        <Label color="blue" isCompact>
                          {members}
                        </Label>
                      ) : (
                        <Label color="grey" isCompact>
                          0
                        </Label>
                      )}
                    </Td>
                    <Td>
                      {confirmDelete === g.name ? (
                        <>
                          {members > 0 && (
                            <span className="pf-v6-u-color-200" style={{ marginRight: "0.5rem" }}>
                              {cockpit.format(
                                _("$0 member device(s) will lose this group."),
                                members,
                              )}
                            </span>
                          )}
                          <Button
                            variant="link"
                            isInline
                            isDanger
                            onClick={() => removeGroup(g.name)}
                          >
                            {_("Confirm delete")}
                          </Button>{" "}
                          <Button variant="link" isInline onClick={() => setConfirmDelete(null)}>
                            {_("Cancel")}
                          </Button>
                        </>
                      ) : (
                        <>
                          <Button
                            variant="link"
                            isInline
                            onClick={() => setRenaming({ from: g.name, value: g.name })}
                          >
                            {_("Rename")}
                          </Button>{" "}
                          <Button
                            variant="link"
                            isInline
                            isDanger
                            onClick={() => setConfirmDelete(g.name)}
                          >
                            {_("Delete")}
                          </Button>
                        </>
                      )}
                    </Td>
                  </Tr>
                );
              })}
            </Tbody>
          </Table>
        )}
      </StackItem>
      <StackItem>
        <SaveBar saving={s.saving} status={s.status} onSave={s.save} onSaveApply={s.saveAndApply} />
      </StackItem>
    </Stack>
  );
};

// ── page shell ──────────────────────────────────────────────────────────────
export const Hosts = () => {
  const s = useSettings();
  const [tab, setTab] = useState("devices");

  return (
    <TabbedPage
      subnav={
        <SubNav
          active={tab}
          onSelect={setTab}
          items={[
            { id: "devices", label: _("Devices") },
            { id: "groups", label: _("Groups") },
          ]}
        />
      }
    >
      {!s.ready && !s.error ? (
        <Loading />
      ) : s.error ? (
        <Alert variant="danger" isInline title={_("Could not load settings")}>
          {s.error}
        </Alert>
      ) : (
        <>
          {tab === "devices" && <DevicesTab s={s} />}
          {tab === "groups" && <GroupsTab s={s} />}
        </>
      )}
    </TabbedPage>
  );
};
