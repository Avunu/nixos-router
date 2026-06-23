import { useState } from "react";
import { errMsg } from "./nix";
import {
  Stack,
  StackItem,
  Form,
  FormGroup,
  FormSelect,
  FormSelectOption,
  TextInput,
  Switch,
  Checkbox,
  Button,
  Alert,
  Card,
  CardTitle,
  CardBody,
  Split,
  SplitItem,
  ActionGroup,
  EmptyState,
  EmptyStateBody,
  Label,
  ClipboardCopy,
  FormSection,
} from "@patternfly/react-core";
import { Table, Thead, Tbody, Tr, Th, Td } from "@patternfly/react-table";
import { useSettings, Loading, SubNav, SaveBar, ListEditor, hint } from "./settings";
import { useInterfaces, validateNetwork } from "./interfaces";
import type { Nic, NetView } from "./interfaces";

const _ = cockpit.gettext;

type S = ReturnType<typeof useSettings>;

// Resolved interface/VLAN view from leaf reads (avoids partial-desired shadowing).
const netView = (s: S): NetView => ({
  trunkInterfaces: s.valueOf("trunkInterfaces", []),
  wan: { interface: s.valueOf("wan.interface", null), vlan: s.valueOf("wan.vlan", null) },
  lan: {
    interfaces: s.valueOf("lan.interfaces", []),
    vlan: s.valueOf("lan.vlan", null),
    taggedInterfaces: s.valueOf("lan.taggedInterfaces", []),
  },
  guest: {
    enable: Boolean(s.valueOf("guest.enable", false)),
    interfaces: s.valueOf("guest.interfaces", []),
    vlan: s.valueOf("guest.vlan", null),
    taggedInterfaces: s.valueOf("guest.taggedInterfaces", []),
  },
});

// Nullable VLAN id input (empty = untagged/null).
const VlanInput = ({
  value,
  onChange,
  isDisabled,
}: {
  value: number | null;
  onChange: (v: number | null) => void;
  isDisabled?: boolean;
}) => (
  <TextInput
    type="number"
    aria-label={_("VLAN id")}
    value={value ?? ""}
    isDisabled={isDisabled}
    placeholder={_("untagged")}
    onChange={(_e, v) => onChange(v === "" ? null : Number(v))}
  />
);

// Checkbox group selecting which NICs carry a network's VLAN tag.
const NicCheckboxes = ({
  nics,
  selected,
  onChange,
  isDisabled,
  idPrefix,
}: {
  nics: string[];
  selected: string[];
  onChange: (v: string[]) => void;
  isDisabled?: boolean;
  idPrefix: string;
}) =>
  nics.length === 0 ? (
    <span className="pf-v6-u-color-200">{_("No interfaces detected.")}</span>
  ) : (
    <Split hasGutter>
      {nics.map((n) => (
        <SplitItem key={n}>
          <Checkbox
            id={`${idPrefix}-${n}`}
            label={n}
            isChecked={selected.includes(n)}
            isDisabled={isDisabled}
            onChange={(_e, c) => onChange(c ? [...selected, n] : selected.filter((x) => x !== n))}
          />
        </SplitItem>
      ))}
    </Split>
  );

// ── Interfaces tab: untagged owner + trunk per physical NIC ──────────────────
const InterfacesTab = ({ s, nics, net }: { s: S; nics: Nic[]; net: NetView }) => {
  const locked =
    s.lockedOf("wan.interface") ||
    s.lockedOf("lan.interfaces") ||
    s.lockedOf("guest.interfaces") ||
    s.lockedOf("trunkInterfaces");

  // Rows: detected NICs plus any configured names not currently present.
  const configured = [
    net.wan.interface,
    ...net.lan.interfaces,
    ...net.guest.interfaces,
    ...net.trunkInterfaces,
  ].filter(Boolean) as string[];
  const names = [...new Set([...nics.map((n) => n.name), ...configured])].toSorted((a, b) =>
    a.localeCompare(b, undefined, { numeric: true }),
  );
  const nicByName = new Map(nics.map((n) => [n.name, n]));

  const ownerOf = (name: string): string =>
    net.wan.interface === name
      ? "wan"
      : net.lan.interfaces.includes(name)
        ? "lan"
        : net.guest.interfaces.includes(name)
          ? "guest"
          : "none";

  const setOwner = (name: string, owner: string) => {
    s.setLeaf("wan.interface", net.wan.interface === name ? null : net.wan.interface);
    s.setLeaf(
      "lan.interfaces",
      net.lan.interfaces.filter((x) => x !== name),
    );
    s.setLeaf(
      "guest.interfaces",
      net.guest.interfaces.filter((x) => x !== name),
    );
    if (owner === "wan") {
      s.setLeaf("wan.interface", name);
    }
    if (owner === "lan") {
      s.setLeaf("lan.interfaces", [...net.lan.interfaces.filter((x) => x !== name), name]);
    }
    if (owner === "guest") {
      s.setLeaf("guest.interfaces", [...net.guest.interfaces.filter((x) => x !== name), name]);
    }
  };

  const toggleTrunk = (name: string, on: boolean) =>
    s.setLeaf(
      "trunkInterfaces",
      on ? [...net.trunkInterfaces, name] : net.trunkInterfaces.filter((x) => x !== name),
    );

  return (
    <Stack hasGutter>
      <StackItem>
        <Alert
          variant="warning"
          isInline
          title={_(
            "Reassigning interfaces can disconnect you. Use “Save” to stage changes, then Apply when ready.",
          )}
        />
      </StackItem>
      {locked && (
        <StackItem>
          <Alert
            variant="info"
            isInline
            title={_("Interface assignment is locked in the Nix configuration.")}
          />
        </StackItem>
      )}
      <StackItem>
        <Table variant="compact" aria-label={_("Interfaces")}>
          <Thead>
            <Tr>
              <Th>{_("Interface")}</Th>
              <Th>{_("Status")}</Th>
              <Th>{_("Untagged network")}</Th>
              <Th>{_("Trunk (VLAN tags)")}</Th>
            </Tr>
          </Thead>
          <Tbody>
            {names.map((name) => {
              const nic = nicByName.get(name);
              return (
                <Tr key={name}>
                  <Td>{name}</Td>
                  <Td>
                    {!nic ? (
                      <Label color="grey" isCompact>
                        {_("not detected")}
                      </Label>
                    ) : nic.carrier ? (
                      <Label color="green" isCompact>
                        {_("up")}
                      </Label>
                    ) : nic.up ? (
                      <Label color="orange" isCompact>
                        {_("no carrier")}
                      </Label>
                    ) : (
                      <Label color="grey" isCompact>
                        {_("down")}
                      </Label>
                    )}
                  </Td>
                  <Td>
                    <FormSelect
                      value={ownerOf(name)}
                      aria-label={_("Untagged network")}
                      isDisabled={locked}
                      onChange={(_e, v) => setOwner(name, v)}
                    >
                      <FormSelectOption value="none" label={_("— none —")} />
                      <FormSelectOption value="wan" label={_("WAN")} />
                      <FormSelectOption value="lan" label={_("LAN")} />
                      <FormSelectOption value="guest" label={_("Guest")} />
                    </FormSelect>
                  </Td>
                  <Td>
                    <Checkbox
                      id={`trunk-${name}`}
                      label={_("Trunk")}
                      isChecked={net.trunkInterfaces.includes(name)}
                      isDisabled={locked}
                      onChange={(_e, c) => toggleTrunk(name, c)}
                    />
                  </Td>
                </Tr>
              );
            })}
          </Tbody>
        </Table>
      </StackItem>
    </Stack>
  );
};

// ── WAN tab ─────────────────────────────────────────────────────────────────
const WanTab = ({ s, net }: { s: S; net: NetView }) => (
  <Form isHorizontal onSubmit={(e) => e.preventDefault()}>
    <FormGroup label={_("Untagged interface")} fieldId="wanIf">
      <TextInput
        id="wanIf"
        value={net.wan.interface || _("(none — assign on the Interfaces tab)")}
        isDisabled
      />
    </FormGroup>
    <FormGroup
      label={_("VLAN id")}
      fieldId="wanVlan"
      labelHelp={hint(
        _("Tagged WAN uplink; the tag rides on trunk ports. Leave empty for an untagged uplink."),
      )}
    >
      <VlanInput
        value={net.wan.vlan}
        isDisabled={s.lockedOf("wan.vlan")}
        onChange={(v) => s.setLeaf("wan.vlan", v)}
      />
    </FormGroup>
  </Form>
);

// ── LAN tab ─────────────────────────────────────────────────────────────────
const LanTab = ({ s, nics, net }: { s: S; nics: Nic[]; net: NetView }) => (
  <Form isHorizontal onSubmit={(e) => e.preventDefault()}>
    <FormSection title={_("Addressing")} titleElement="h2">
      <FormGroup label={_("Gateway address")} fieldId="lanAddr">
        <TextInput
          id="lanAddr"
          value={s.valueOf("lan.address", "")}
          isDisabled={s.lockedOf("lan.address")}
          placeholder="10.0.0.1"
          onChange={(_e, v) => s.setLeaf("lan.address", v)}
        />
      </FormGroup>
      <FormGroup label={_("Network address")} fieldId="lanNet">
        <TextInput
          id="lanNet"
          value={s.valueOf("lan.networkAddress", "")}
          isDisabled={s.lockedOf("lan.networkAddress")}
          placeholder="10.0.0.0"
          onChange={(_e, v) => s.setLeaf("lan.networkAddress", v)}
        />
      </FormGroup>
      <FormGroup label={_("Prefix length")} fieldId="lanPrefix">
        <TextInput
          id="lanPrefix"
          type="number"
          value={s.valueOf("lan.prefixLength", 24)}
          isDisabled={s.lockedOf("lan.prefixLength")}
          onChange={(_e, v) => s.setLeaf("lan.prefixLength", Number(v) || 0)}
        />
      </FormGroup>
      <FormGroup label={_("Local domain")} fieldId="lanDomain">
        <TextInput
          id="lanDomain"
          value={s.valueOf("lan.domain", "lan")}
          isDisabled={s.lockedOf("lan.domain")}
          onChange={(_e, v) => s.setLeaf("lan.domain", v)}
        />
      </FormGroup>
    </FormSection>

    <FormSection title={_("VLAN")} titleElement="h2">
      <FormGroup
        label={_("VLAN id")}
        fieldId="lanVlan"
        labelHelp={hint(
          _(
            "Tag carried on trunk ports plus the tagged interfaces below. Leave empty for untagged.",
          ),
        )}
      >
        <VlanInput
          value={net.lan.vlan}
          isDisabled={s.lockedOf("lan.vlan")}
          onChange={(v) => s.setLeaf("lan.vlan", v)}
        />
      </FormGroup>
      <FormGroup
        label={_("Tagged on interfaces")}
        fieldId="lanTagged"
        labelHelp={hint(_("Ports carrying the LAN VLAN tag in addition to trunk ports."))}
      >
        <NicCheckboxes
          idPrefix="lan-tag"
          nics={nics.map((n) => n.name)}
          selected={net.lan.taggedInterfaces}
          isDisabled={s.lockedOf("lan.taggedInterfaces") || net.lan.vlan == null}
          onChange={(v) => s.setLeaf("lan.taggedInterfaces", v)}
        />
      </FormGroup>
    </FormSection>

    <FormSection title={_("DHCP")} titleElement="h2">
      <FormGroup
        label={_("Pool offset")}
        fieldId="lanPoolOffset"
        labelHelp={hint(_("First host address in the pool, from the network base."))}
      >
        <TextInput
          id="lanPoolOffset"
          type="number"
          value={s.valueOf("lan.dhcp.poolOffset", 100)}
          isDisabled={s.lockedOf("lan.dhcp.poolOffset")}
          onChange={(_e, v) => s.setLeaf("lan.dhcp.poolOffset", Number(v) || 0)}
        />
      </FormGroup>
      <FormGroup label={_("Pool size")} fieldId="lanPoolSize">
        <TextInput
          id="lanPoolSize"
          type="number"
          value={s.valueOf("lan.dhcp.poolSize", 151)}
          isDisabled={s.lockedOf("lan.dhcp.poolSize")}
          onChange={(_e, v) => s.setLeaf("lan.dhcp.poolSize", Number(v) || 0)}
        />
      </FormGroup>
      <FormGroup label={_("Lease time")} fieldId="lanLease" labelHelp={hint(_("e.g. 12h, 30d"))}>
        <TextInput
          id="lanLease"
          value={s.valueOf("lan.dhcp.leaseTime", "24h")}
          isDisabled={s.lockedOf("lan.dhcp.leaseTime")}
          onChange={(_e, v) => s.setLeaf("lan.dhcp.leaseTime", v)}
        />
      </FormGroup>
    </FormSection>
  </Form>
);

// ── Guest tab ───────────────────────────────────────────────────────────────
const GuestTab = ({ s, nics, net }: { s: S; nics: Nic[]; net: NetView }) => {
  const on = net.guest.enable;
  return (
    <Form isHorizontal onSubmit={(e) => e.preventDefault()}>
      <FormGroup
        label={_("Enable guest network")}
        fieldId="guestEnable"
        labelHelp={hint(_("Isolated network with no access to LAN."))}
      >
        <Switch
          id="guestEnable"
          isChecked={on}
          isDisabled={s.lockedOf("guest.enable")}
          onChange={(_e, c) => s.setLeaf("guest.enable", c)}
          aria-label={_("Enable guest network")}
        />
      </FormGroup>
      {on && (
        <>
          <FormSection title={_("Addressing")} titleElement="h2">
            <FormGroup label={_("Gateway address")} fieldId="gAddr">
              <TextInput
                id="gAddr"
                value={s.valueOf("guest.address", "192.168.20.1")}
                isDisabled={s.lockedOf("guest.address")}
                onChange={(_e, v) => s.setLeaf("guest.address", v)}
              />
            </FormGroup>
            <FormGroup label={_("Network address")} fieldId="gNet">
              <TextInput
                id="gNet"
                value={s.valueOf("guest.networkAddress", "192.168.20.0")}
                isDisabled={s.lockedOf("guest.networkAddress")}
                onChange={(_e, v) => s.setLeaf("guest.networkAddress", v)}
              />
            </FormGroup>
            <FormGroup label={_("Prefix length")} fieldId="gPrefix">
              <TextInput
                id="gPrefix"
                type="number"
                value={s.valueOf("guest.prefixLength", 24)}
                isDisabled={s.lockedOf("guest.prefixLength")}
                onChange={(_e, v) => s.setLeaf("guest.prefixLength", Number(v) || 0)}
              />
            </FormGroup>
          </FormSection>
          <FormSection title={_("VLAN")} titleElement="h2">
            <FormGroup label={_("VLAN id")} fieldId="gVlan">
              <VlanInput
                value={net.guest.vlan}
                isDisabled={s.lockedOf("guest.vlan")}
                onChange={(v) => s.setLeaf("guest.vlan", v)}
              />
            </FormGroup>
            <FormGroup label={_("Tagged on interfaces")} fieldId="gTagged">
              <NicCheckboxes
                idPrefix="guest-tag"
                nics={nics.map((n) => n.name)}
                selected={net.guest.taggedInterfaces}
                isDisabled={s.lockedOf("guest.taggedInterfaces") || net.guest.vlan == null}
                onChange={(v) => s.setLeaf("guest.taggedInterfaces", v)}
              />
            </FormGroup>
          </FormSection>
          <FormSection title={_("DHCP")} titleElement="h2">
            <FormGroup label={_("Pool offset")} fieldId="gPoolOffset">
              <TextInput
                id="gPoolOffset"
                type="number"
                value={s.valueOf("guest.dhcp.poolOffset", 100)}
                isDisabled={s.lockedOf("guest.dhcp.poolOffset")}
                onChange={(_e, v) => s.setLeaf("guest.dhcp.poolOffset", Number(v) || 0)}
              />
            </FormGroup>
            <FormGroup label={_("Pool size")} fieldId="gPoolSize">
              <TextInput
                id="gPoolSize"
                type="number"
                value={s.valueOf("guest.dhcp.poolSize", 151)}
                isDisabled={s.lockedOf("guest.dhcp.poolSize")}
                onChange={(_e, v) => s.setLeaf("guest.dhcp.poolSize", Number(v) || 0)}
              />
            </FormGroup>
            <FormGroup label={_("Lease time")} fieldId="gLease">
              <TextInput
                id="gLease"
                value={s.valueOf("guest.dhcp.leaseTime", "1h")}
                isDisabled={s.lockedOf("guest.dhcp.leaseTime")}
                onChange={(_e, v) => s.setLeaf("guest.dhcp.leaseTime", v)}
              />
            </FormGroup>
          </FormSection>
        </>
      )}
    </Form>
  );
};

// ── WireGuard tab ───────────────────────────────────────────────────────────
type Peer = {
  publicKey: string;
  endpoint: string | null;
  allowedIPs: string[];
  persistentKeepalive: number;
};
type Tunnel = {
  address: string;
  listenPort: number;
  privateKeyFile: string;
  routes: string[];
  peers: Peer[];
};
const EMPTY_PEER: Peer = { publicKey: "", endpoint: null, allowedIPs: [], persistentKeepalive: 25 };

const WireGuardTab = ({ s }: { s: S }) => {
  const tunnels: Record<string, Tunnel> = s.valueOf<Record<string, Tunnel>>("wireguard", {});
  const locked = s.lockedOf("wireguard");
  const names = Object.keys(tunnels);
  const [selected, setSelected] = useState<string | null>(names[0] ?? null);
  const [newName, setNewName] = useState("");
  const [pubKey, setPubKey] = useState("");
  const [keyMsg, setKeyMsg] = useState("");

  const setTunnels = (t: Record<string, Tunnel>) => s.setLeaf("wireguard", t);
  const sel = selected && tunnels[selected] ? tunnels[selected] : null;

  const addTunnel = () => {
    const n = newName.trim();
    if (!n || tunnels[n]) {
      return;
    }
    const created: Tunnel = {
      address: "",
      listenPort: 51_820,
      privateKeyFile: `/etc/wireguard/${n}.key`,
      routes: [],
      peers: [],
    };
    setTunnels({ ...tunnels, [n]: created });
    setSelected(n);
    setNewName("");
  };
  const removeTunnel = (n: string) => {
    const t = Object.fromEntries(Object.entries(tunnels).filter(([k]) => k !== n));
    setTunnels(t);
    if (selected === n) {
      setSelected(Object.keys(t)[0] ?? null);
    }
  };
  const patch = (p: Partial<Tunnel>) => {
    if (!selected) {
      return;
    }
    const cur = tunnels[selected];
    if (!cur) {
      return;
    }
    const updated: Tunnel = { ...cur, ...p };
    setTunnels({ ...tunnels, [selected]: updated });
  };
  const setPeer = (i: number, p: Peer) =>
    sel && patch({ peers: sel.peers.map((x, j) => (j === i ? p : x)) });
  const addPeer = () => sel && patch({ peers: [...sel.peers, { ...EMPTY_PEER }] });
  const removePeer = (i: number) => sel && patch({ peers: sel.peers.filter((_x, j) => j !== i) });

  const genKey = () => {
    if (!sel) {
      return;
    }
    setKeyMsg("");
    setPubKey("");
    const f = sel.privateKeyFile;
    cockpit
      .spawn(
        [
          "sh",
          "-c",
          `install -d -m700 "$(dirname "$1")" && umask 077 && wg genkey | tee "$1" | wg pubkey`,
          "--",
          f,
        ],
        {
          superuser: "require",
          err: "message",
        },
      )
      .then((out: string) => setPubKey(out.trim()))
      .catch((e: unknown) => setKeyMsg(errMsg(e)));
  };

  return (
    <Stack hasGutter>
      {locked && (
        <StackItem>
          <Alert
            variant="info"
            isInline
            title={_("WireGuard is locked in the Nix configuration.")}
          />
        </StackItem>
      )}
      <StackItem>
        <Split hasGutter>
          <SplitItem>
            <FormSelect
              value={selected ?? ""}
              aria-label={_("Tunnel")}
              onChange={(_e, v) => setSelected(v || null)}
              style={{ minWidth: "12rem" }}
            >
              <FormSelectOption
                value=""
                label={names.length > 0 ? _("— select tunnel —") : _("no tunnels")}
                isDisabled
              />
              {names.map((n) => (
                <FormSelectOption key={n} value={n} label={n} />
              ))}
            </FormSelect>
          </SplitItem>
          <SplitItem isFilled />
          <SplitItem>
            <TextInput
              value={newName}
              aria-label={_("New tunnel name")}
              placeholder={_("wg0")}
              isDisabled={locked}
              onChange={(_e, v) => setNewName(v)}
              style={{ width: "8rem" }}
            />
          </SplitItem>
          <SplitItem>
            <Button variant="secondary" onClick={addTunnel} isDisabled={locked || !newName.trim()}>
              {_("Add tunnel")}
            </Button>
          </SplitItem>
        </Split>
      </StackItem>

      {sel && selected && (
        <StackItem>
          <Card isCompact>
            <CardTitle>
              <Split>
                <SplitItem isFilled>{selected}</SplitItem>
                <SplitItem>
                  <Button
                    variant="link"
                    isDanger
                    isInline
                    isDisabled={locked}
                    onClick={() => removeTunnel(selected)}
                  >
                    {_("Delete tunnel")}
                  </Button>
                </SplitItem>
              </Split>
            </CardTitle>
            <CardBody>
              <Form isHorizontal onSubmit={(e) => e.preventDefault()}>
                <FormGroup label={_("Address (CIDR)")} fieldId="wgAddr" isRequired>
                  <TextInput
                    id="wgAddr"
                    value={sel.address}
                    isDisabled={locked}
                    placeholder="10.100.0.1/24"
                    onChange={(_e, v) => patch({ address: v })}
                  />
                </FormGroup>
                <FormGroup label={_("Listen port")} fieldId="wgPort">
                  <TextInput
                    id="wgPort"
                    type="number"
                    value={sel.listenPort}
                    isDisabled={locked}
                    onChange={(_e, v) => patch({ listenPort: Number(v) || 0 })}
                  />
                </FormGroup>
                <FormGroup
                  label={_("Private key file")}
                  fieldId="wgKey"
                  labelHelp={hint(
                    _("Path to the private key on the router (never in the Nix store)."),
                  )}
                >
                  <Split hasGutter>
                    <SplitItem isFilled>
                      <TextInput
                        id="wgKey"
                        value={sel.privateKeyFile}
                        isDisabled={locked}
                        onChange={(_e, v) => patch({ privateKeyFile: v })}
                      />
                    </SplitItem>
                    <SplitItem>
                      <Button
                        variant="secondary"
                        onClick={genKey}
                        isDisabled={locked || !sel.privateKeyFile}
                      >
                        {_("Generate keypair")}
                      </Button>
                    </SplitItem>
                  </Split>
                </FormGroup>
                {pubKey && (
                  <FormGroup label={_("Public key (share with peers)")} fieldId="wgPub">
                    <ClipboardCopy isReadOnly hoverTip={_("Copy")} clickTip={_("Copied")}>
                      {pubKey}
                    </ClipboardCopy>
                  </FormGroup>
                )}
                {keyMsg && (
                  <Alert variant="danger" isInline title={_("Key generation failed")}>
                    {keyMsg}
                  </Alert>
                )}
                <FormGroup
                  label={_("Routes")}
                  fieldId="wgRoutes"
                  labelHelp={hint(_("Extra destinations routed through this tunnel."))}
                >
                  <ListEditor
                    value={sel.routes}
                    isDisabled={locked}
                    onChange={(v) => patch({ routes: v })}
                    placeholder="10.20.0.0/24"
                  />
                </FormGroup>
              </Form>

              <FormSection title={_("Peers")} titleElement="h2">
                {sel.peers.length === 0 ? (
                  <EmptyState>
                    <EmptyStateBody>{_("No peers.")}</EmptyStateBody>
                  </EmptyState>
                ) : (
                  sel.peers.map((p, i) => (
                    <Card key={i} isCompact style={{ marginBlockEnd: "0.5rem" }}>
                      <CardBody>
                        <Form isHorizontal onSubmit={(e) => e.preventDefault()}>
                          <FormGroup label={_("Public key")} fieldId={`pk-${i}`} isRequired>
                            <TextInput
                              id={`pk-${i}`}
                              value={p.publicKey}
                              isDisabled={locked}
                              onChange={(_e, v) => setPeer(i, { ...p, publicKey: v })}
                            />
                          </FormGroup>
                          <FormGroup
                            label={_("Endpoint (optional)")}
                            fieldId={`ep-${i}`}
                            labelHelp={hint(_("host:port; leave empty for inbound-only peers."))}
                          >
                            <TextInput
                              id={`ep-${i}`}
                              value={p.endpoint || ""}
                              isDisabled={locked}
                              placeholder="vpn.example.com:51820"
                              onChange={(_e, v) => setPeer(i, { ...p, endpoint: v.trim() || null })}
                            />
                          </FormGroup>
                          <FormGroup label={_("Allowed IPs")} fieldId={`aip-${i}`} isRequired>
                            <ListEditor
                              value={p.allowedIPs}
                              isDisabled={locked}
                              onChange={(v) => setPeer(i, { ...p, allowedIPs: v })}
                              placeholder="10.100.0.2/32"
                            />
                          </FormGroup>
                          <FormGroup label={_("Persistent keepalive (s)")} fieldId={`ka-${i}`}>
                            <TextInput
                              id={`ka-${i}`}
                              type="number"
                              value={p.persistentKeepalive}
                              isDisabled={locked}
                              onChange={(_e, v) =>
                                setPeer(i, { ...p, persistentKeepalive: Number(v) || 0 })
                              }
                            />
                          </FormGroup>
                          <ActionGroup>
                            <Button
                              variant="link"
                              isDanger
                              isInline
                              isDisabled={locked}
                              onClick={() => removePeer(i)}
                            >
                              {_("Remove peer")}
                            </Button>
                          </ActionGroup>
                        </Form>
                      </CardBody>
                    </Card>
                  ))
                )}
                <Button variant="secondary" onClick={addPeer} isDisabled={locked}>
                  {_("Add peer")}
                </Button>
              </FormSection>
            </CardBody>
          </Card>
        </StackItem>
      )}
    </Stack>
  );
};

// ── Network page ────────────────────────────────────────────────────────────
export const Network = () => {
  const s = useSettings();
  const { nics } = useInterfaces();
  const [tab, setTab] = useState("interfaces");

  if (!s.ready && !s.error) {
    return <Loading />;
  }
  if (s.error) {
    return (
      <Alert variant="danger" isInline title={_("Could not load settings")}>
        {s.error}
      </Alert>
    );
  }

  const net = netView(s);
  const errors = validateNetwork(net);

  return (
    <Stack className="ct-router-stack">
      <StackItem>
        <SubNav
          active={tab}
          onSelect={setTab}
          items={[
            { id: "interfaces", label: _("Interfaces") },
            { id: "wan", label: _("WAN") },
            { id: "lan", label: _("LAN") },
            { id: "guest", label: _("Guest") },
            { id: "wireguard", label: _("WireGuard") },
          ]}
        />
      </StackItem>
      <StackItem isFilled style={{ overflowY: "auto" }}>
        {tab === "interfaces" && <InterfacesTab s={s} nics={nics} net={net} />}
        {tab === "wan" && <WanTab s={s} net={net} />}
        {tab === "lan" && <LanTab s={s} nics={nics} net={net} />}
        {tab === "guest" && <GuestTab s={s} nics={nics} net={net} />}
        {tab === "wireguard" && <WireGuardTab s={s} />}
      </StackItem>
      <StackItem>
        {errors.length > 0 && (
          <Alert
            variant="danger"
            isInline
            title={_("Network configuration is invalid")}
            style={{ marginBlockEnd: "0.5rem" }}
          >
            <ul>
              {errors.map((e, i) => (
                <li key={i}>{e}</li>
              ))}
            </ul>
          </Alert>
        )}
        <SaveBar
          saving={s.saving}
          status={s.status}
          onSave={s.save}
          onSaveApply={s.saveAndApply}
          applyDisabled={errors.length > 0}
        />
      </StackItem>
    </Stack>
  );
};
