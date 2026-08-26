// ── DNS page ────────────────────────────────────────────────────────────────
// Split-horizon DNS (router.dns.overrides / forwardZones) plus the resolver
// settings that had no UI at all before this page existed
// (dns.technitium.upstreamServers, safeSearch, blockDoHProviders).
//
// The two tables follow the port-forward editor in firewall.tsx: a compact
// table over the settings-JSON array plus one draft Card for add/edit, so an
// admin never hand-writes JSON for a record.
import { useState } from "react";
import {
  Button,
  Alert,
  Stack,
  StackItem,
  Form,
  FormGroup,
  FormSelect,
  FormSelectOption,
  TextInput,
  Switch,
  ActionGroup,
  Card,
  CardTitle,
  CardBody,
  EmptyState,
  EmptyStateBody,
  Split,
  SplitItem,
} from "@patternfly/react-core";
import { Table, Thead, Tbody, Tr, Th, Td } from "@patternfly/react-table";
import { useSettings, Loading, SubNav, SaveBar, ListEditor, hint, TabbedPage } from "./settings";
import type { Json } from "./nix";
import type { DnsForwardZone, DnsOverride, DnsRecordType } from "./types";

const _ = cockpit.gettext;

const RECORD_TYPES: DnsRecordType[] = ["A", "AAAA", "CNAME", "ANAME", "TXT", "SRV"];
const PROTOCOLS = ["Udp", "Tcp", "Tls", "Https", "Quic"] as const;

const EMPTY_OVERRIDE: DnsOverride = { name: "", type: "A", value: "", ttl: 300, notes: "" };
const EMPTY_ZONE: DnsForwardZone = {
  zone: "",
  forwarders: [],
  protocol: "Udp",
  dnssecValidation: false,
  notes: "",
};

// What the "Value" field means depends on the record type; the placeholder is
// the only affordance a table row has to explain it.
const VALUE_HINTS: Record<DnsRecordType, string> = {
  A: "10.48.4.20",
  AAAA: "fd00::20",
  CNAME: "nas.example.com",
  ANAME: "nas.example.com",
  TXT: _("free-form text"),
  SRV: "10 5 5060 sip.example.com",
};

// ── Overrides ───────────────────────────────────────────────────────────────
const Overrides = () => {
  const s = useSettings();
  const rows = s.valueOf<DnsOverride[]>("dns.overrides", []);
  const locked = s.lockedOf("dns.overrides");

  const [draft, setDraft] = useState<DnsOverride | null>(null);
  const [editIndex, setEditIndex] = useState<number | null>(null);

  if (!s.ready && !s.error) {
    return <Loading />;
  }
  if (s.error) {
    return (
      <Alert variant="danger" isInline title={_("Could not load DNS overrides")}>
        {s.error}
      </Alert>
    );
  }

  const setRows = (r: DnsOverride[]) => s.setLeaf("dns.overrides", r as unknown as Json);
  const cancel = () => {
    setDraft(null);
    setEditIndex(null);
  };
  const commit = () => {
    if (!draft) {
      return;
    }
    const row: DnsOverride = {
      ...draft,
      name: draft.name.trim().toLowerCase().replace(/\.$/, ""),
      value: draft.value.trim(),
    };
    setRows(editIndex === null ? [...rows, row] : rows.map((r, i) => (i === editIndex ? row : r)));
    cancel();
  };
  const draftType = draft?.type ?? "A";
  const draftValid = Boolean(draft && draft.name.trim() && draft.value.trim());

  return (
    <Stack hasGutter className="ct-router-stack">
      <StackItem isFilled style={{ overflowY: "auto" }}>
        <Stack hasGutter>
          <StackItem>
            <Alert
              variant="info"
              isInline
              title={_("These answers are served to LAN, guest and VPN clients only.")}
            >
              {_(
                "The router serves each overridden domain as a conditional-forwarder zone, so names " +
                  "under it that are not listed here still resolve from the public upstream.",
              )}
            </Alert>
          </StackItem>
          {locked && (
            <StackItem>
              <Alert
                variant="info"
                isInline
                title={_("DNS overrides are locked in the Nix configuration.")}
              />
            </StackItem>
          )}
          <StackItem>
            <Split>
              <SplitItem isFilled />
              <SplitItem>
                <Button
                  variant="secondary"
                  onClick={() => {
                    setDraft({ ...EMPTY_OVERRIDE });
                    setEditIndex(null);
                  }}
                  isDisabled={Boolean(draft) || locked}
                >
                  {_("Add override")}
                </Button>
              </SplitItem>
            </Split>
          </StackItem>

          <StackItem>
            {rows.length === 0 ? (
              <EmptyState>
                <EmptyStateBody>{_("No DNS overrides configured.")}</EmptyStateBody>
              </EmptyState>
            ) : (
              <Table variant="compact" aria-label={_("DNS overrides")}>
                <Thead>
                  <Tr>
                    <Th>{_("Name")}</Th>
                    <Th>{_("Type")}</Th>
                    <Th>{_("Value")}</Th>
                    <Th>{_("TTL")}</Th>
                    <Th>{_("Notes")}</Th>
                    <Th screenReaderText={_("Actions")} />
                  </Tr>
                </Thead>
                <Tbody>
                  {rows.map((r, i) => (
                    <Tr key={i}>
                      <Td>{r.name}</Td>
                      <Td>{r.type ?? "A"}</Td>
                      <Td>{r.value}</Td>
                      <Td>{r.ttl ?? 300}</Td>
                      <Td>{r.notes || "—"}</Td>
                      <Td isActionCell>
                        <Button
                          variant="link"
                          isInline
                          onClick={() => {
                            setDraft({ ...EMPTY_OVERRIDE, ...r });
                            setEditIndex(i);
                          }}
                          isDisabled={locked}
                        >
                          {_("Edit")}
                        </Button>{" "}
                        <Button
                          variant="link"
                          isInline
                          isDanger
                          onClick={() => setRows(rows.filter((_r, idx) => idx !== i))}
                          isDisabled={locked}
                        >
                          {_("Delete")}
                        </Button>
                      </Td>
                    </Tr>
                  ))}
                </Tbody>
              </Table>
            )}
          </StackItem>

          {draft && (
            <StackItem>
              <Card isCompact>
                <CardTitle>{editIndex === null ? _("Add override") : _("Edit override")}</CardTitle>
                <CardBody>
                  <Form isHorizontal onSubmit={(e) => e.preventDefault()}>
                    <FormGroup label={_("Name")} fieldId="dnsName" isRequired>
                      <TextInput
                        id="dnsName"
                        value={draft.name}
                        placeholder="nas.example.com"
                        onChange={(_e, v) => setDraft({ ...draft, name: v })}
                      />
                    </FormGroup>
                    <FormGroup
                      label={_("Type")}
                      fieldId="dnsType"
                      labelHelp={hint(
                        _(
                          "A CNAME is illegal at the top of a zone, so an alias that owns its own " +
                            "name must use ANAME — the router resolves the target and answers with " +
                            "its addresses.",
                        ),
                      )}
                    >
                      <FormSelect
                        id="dnsType"
                        value={draftType}
                        onChange={(_e, v) => setDraft({ ...draft, type: v as DnsRecordType })}
                      >
                        {RECORD_TYPES.map((t) => (
                          <FormSelectOption key={t} value={t} label={t} />
                        ))}
                      </FormSelect>
                    </FormGroup>
                    <FormGroup label={_("Value")} fieldId="dnsValue" isRequired>
                      <TextInput
                        id="dnsValue"
                        value={draft.value}
                        placeholder={VALUE_HINTS[draftType]}
                        onChange={(_e, v) => setDraft({ ...draft, value: v })}
                      />
                    </FormGroup>
                    <FormGroup label={_("TTL (seconds)")} fieldId="dnsTtl">
                      <TextInput
                        id="dnsTtl"
                        type="number"
                        value={String(draft.ttl ?? 300)}
                        onChange={(_e, v) => setDraft({ ...draft, ttl: Number(v) || 300 })}
                      />
                    </FormGroup>
                    <FormGroup label={_("Notes")} fieldId="dnsNotes">
                      <TextInput
                        id="dnsNotes"
                        value={draft.notes ?? ""}
                        onChange={(_e, v) => setDraft({ ...draft, notes: v })}
                      />
                    </FormGroup>
                    <ActionGroup>
                      <Button variant="secondary" onClick={commit} isDisabled={!draftValid}>
                        {editIndex === null ? _("Add") : _("Update")}
                      </Button>
                      <Button variant="link" onClick={cancel}>
                        {_("Cancel")}
                      </Button>
                    </ActionGroup>
                  </Form>
                </CardBody>
              </Card>
            </StackItem>
          )}

          <StackItem>
            <SaveBar
              saving={s.saving}
              status={s.status}
              onSave={s.save}
              onSaveApply={s.saveAndApply}
            />
          </StackItem>
        </Stack>
      </StackItem>
    </Stack>
  );
};

// ── Conditional forward zones ───────────────────────────────────────────────
const ForwardZones = () => {
  const s = useSettings();
  const rows = s.valueOf<DnsForwardZone[]>("dns.forwardZones", []);
  const locked = s.lockedOf("dns.forwardZones");

  const [draft, setDraft] = useState<DnsForwardZone | null>(null);
  const [editIndex, setEditIndex] = useState<number | null>(null);

  if (!s.ready && !s.error) {
    return <Loading />;
  }
  if (s.error) {
    return (
      <Alert variant="danger" isInline title={_("Could not load forward zones")}>
        {s.error}
      </Alert>
    );
  }

  const setRows = (r: DnsForwardZone[]) => s.setLeaf("dns.forwardZones", r as unknown as Json);
  const cancel = () => {
    setDraft(null);
    setEditIndex(null);
  };
  const commit = () => {
    if (!draft) {
      return;
    }
    const row: DnsForwardZone = {
      ...draft,
      zone: draft.zone.trim().toLowerCase().replace(/\.$/, ""),
    };
    setRows(editIndex === null ? [...rows, row] : rows.map((r, i) => (i === editIndex ? row : r)));
    cancel();
  };
  const draftValid = Boolean(draft && draft.zone.trim() && draft.forwarders.length > 0);

  return (
    <Stack hasGutter className="ct-router-stack">
      <StackItem isFilled style={{ overflowY: "auto" }}>
        <Stack hasGutter>
          <StackItem>
            <Alert
              variant="info"
              isInline
              title={_("A forward zone hands the whole domain to another server.")}
            >
              {_(
                "Use this for an internal DNS server that is authoritative for a domain — an " +
                  "Active Directory controller, for example. Every name under the domain is asked " +
                  "of it, so an override for one of those names would never be consulted.",
              )}
            </Alert>
          </StackItem>
          {locked && (
            <StackItem>
              <Alert
                variant="info"
                isInline
                title={_("Forward zones are locked in the Nix configuration.")}
              />
            </StackItem>
          )}
          <StackItem>
            <Split>
              <SplitItem isFilled />
              <SplitItem>
                <Button
                  variant="secondary"
                  onClick={() => {
                    setDraft({ ...EMPTY_ZONE, forwarders: [] });
                    setEditIndex(null);
                  }}
                  isDisabled={Boolean(draft) || locked}
                >
                  {_("Add forward zone")}
                </Button>
              </SplitItem>
            </Split>
          </StackItem>

          <StackItem>
            {rows.length === 0 ? (
              <EmptyState>
                <EmptyStateBody>{_("No forward zones configured.")}</EmptyStateBody>
              </EmptyState>
            ) : (
              <Table variant="compact" aria-label={_("Forward zones")}>
                <Thead>
                  <Tr>
                    <Th>{_("Zone")}</Th>
                    <Th>{_("Forwarders")}</Th>
                    <Th>{_("Protocol")}</Th>
                    <Th>{_("DNSSEC")}</Th>
                    <Th>{_("Notes")}</Th>
                    <Th screenReaderText={_("Actions")} />
                  </Tr>
                </Thead>
                <Tbody>
                  {rows.map((r, i) => (
                    <Tr key={i}>
                      <Td>{r.zone}</Td>
                      <Td>{r.forwarders.join(", ")}</Td>
                      <Td>{r.protocol ?? "Udp"}</Td>
                      <Td>{r.dnssecValidation ? _("on") : _("off")}</Td>
                      <Td>{r.notes || "—"}</Td>
                      <Td isActionCell>
                        <Button
                          variant="link"
                          isInline
                          onClick={() => {
                            setDraft({ ...EMPTY_ZONE, ...r });
                            setEditIndex(i);
                          }}
                          isDisabled={locked}
                        >
                          {_("Edit")}
                        </Button>{" "}
                        <Button
                          variant="link"
                          isInline
                          isDanger
                          onClick={() => setRows(rows.filter((_r, idx) => idx !== i))}
                          isDisabled={locked}
                        >
                          {_("Delete")}
                        </Button>
                      </Td>
                    </Tr>
                  ))}
                </Tbody>
              </Table>
            )}
          </StackItem>

          {draft && (
            <StackItem>
              <Card isCompact>
                <CardTitle>
                  {editIndex === null ? _("Add forward zone") : _("Edit forward zone")}
                </CardTitle>
                <CardBody>
                  <Form isHorizontal onSubmit={(e) => e.preventDefault()}>
                    <FormGroup label={_("Zone")} fieldId="fzZone" isRequired>
                      <TextInput
                        id="fzZone"
                        value={draft.zone}
                        placeholder="corp.example.com"
                        onChange={(_e, v) => setDraft({ ...draft, zone: v })}
                      />
                    </FormGroup>
                    <FormGroup
                      label={_("Forwarders")}
                      fieldId="fzServers"
                      isRequired
                      labelHelp={hint(
                        _("An address, address:port, or a DoH/DoT URL. Queried in order."),
                      )}
                    >
                      <ListEditor
                        value={draft.forwarders}
                        onChange={(v) => setDraft({ ...draft, forwarders: v })}
                        placeholder="10.48.4.5"
                      />
                    </FormGroup>
                    <FormGroup label={_("Protocol")} fieldId="fzProto">
                      <FormSelect
                        id="fzProto"
                        value={draft.protocol ?? "Udp"}
                        onChange={(_e, v) =>
                          setDraft({ ...draft, protocol: v as DnsForwardZone["protocol"] })
                        }
                      >
                        {PROTOCOLS.map((p) => (
                          <FormSelectOption key={p} value={p} label={p} />
                        ))}
                      </FormSelect>
                    </FormGroup>
                    <FormGroup label={_("Validate DNSSEC")} fieldId="fzDnssec">
                      <Switch
                        id="fzDnssec"
                        isChecked={Boolean(draft.dnssecValidation)}
                        onChange={(_e, v) => setDraft({ ...draft, dnssecValidation: v })}
                      />
                    </FormGroup>
                    <FormGroup label={_("Notes")} fieldId="fzNotes">
                      <TextInput
                        id="fzNotes"
                        value={draft.notes ?? ""}
                        onChange={(_e, v) => setDraft({ ...draft, notes: v })}
                      />
                    </FormGroup>
                    <ActionGroup>
                      <Button variant="secondary" onClick={commit} isDisabled={!draftValid}>
                        {editIndex === null ? _("Add") : _("Update")}
                      </Button>
                      <Button variant="link" onClick={cancel}>
                        {_("Cancel")}
                      </Button>
                    </ActionGroup>
                  </Form>
                </CardBody>
              </Card>
            </StackItem>
          )}

          <StackItem>
            <SaveBar
              saving={s.saving}
              status={s.status}
              onSave={s.save}
              onSaveApply={s.saveAndApply}
            />
          </StackItem>
        </Stack>
      </StackItem>
    </Stack>
  );
};

// ── Resolver ────────────────────────────────────────────────────────────────
const Resolver = () => {
  const s = useSettings();

  if (!s.ready && !s.error) {
    return <Loading />;
  }
  if (s.error) {
    return (
      <Alert variant="danger" isInline title={_("Could not load resolver settings")}>
        {s.error}
      </Alert>
    );
  }

  return (
    <Stack hasGutter className="ct-router-stack">
      <StackItem isFilled style={{ overflowY: "auto" }}>
        <Form isHorizontal onSubmit={(e) => e.preventDefault()}>
          <FormGroup
            label={_("Upstream resolvers")}
            fieldId="dnsUpstreams"
            labelHelp={hint(
              _("DNS-over-HTTPS endpoints. Also used as the fall-through for override zones."),
            )}
          >
            <ListEditor
              value={s.valueOf<string[]>("dns.technitium.upstreamServers", [])}
              onChange={(v) => s.setLeaf("dns.technitium.upstreamServers", v)}
              isDisabled={s.lockedOf("dns.technitium.upstreamServers")}
              placeholder="https://dns.cloudflare.com/dns-query"
            />
          </FormGroup>
          <FormGroup
            label={_("Publish static hosts")}
            fieldId="dnsRegisterHosts"
            labelHelp={hint(
              _(
                "Give every device with a DHCP reservation a name under the LAN domain, plus a " +
                  "reverse lookup. Device names are lowercased into DNS labels.",
              ),
            )}
          >
            <Switch
              id="dnsRegisterHosts"
              isChecked={s.valueOf<boolean>("dns.registerStaticHosts", true)}
              isDisabled={s.lockedOf("dns.registerStaticHosts")}
              onChange={(_e, v) => s.setLeaf("dns.registerStaticHosts", v)}
            />
          </FormGroup>
          <FormGroup label={_("Enforce SafeSearch")} fieldId="dnsSafeSearch">
            <Switch
              id="dnsSafeSearch"
              isChecked={s.valueOf<boolean>("dns.technitium.safeSearch", false)}
              isDisabled={s.lockedOf("dns.technitium.safeSearch")}
              onChange={(_e, v) => s.setLeaf("dns.technitium.safeSearch", v)}
            />
          </FormGroup>
          <FormGroup
            label={_("Block public DoH resolvers")}
            fieldId="dnsBlockDoH"
            labelHelp={hint(
              _("Stops clients bypassing filtering by speaking DNS-over-HTTPS themselves."),
            )}
          >
            <Switch
              id="dnsBlockDoH"
              isChecked={s.valueOf<boolean>("dns.technitium.blockDoHProviders", true)}
              isDisabled={s.lockedOf("dns.technitium.blockDoHProviders")}
              onChange={(_e, v) => s.setLeaf("dns.technitium.blockDoHProviders", v)}
            />
          </FormGroup>
        </Form>
      </StackItem>
      <StackItem>
        <SaveBar saving={s.saving} status={s.status} onSave={s.save} onSaveApply={s.saveAndApply} />
      </StackItem>
    </Stack>
  );
};

export const Dns = () => {
  const [tab, setTab] = useState("overrides");
  return (
    <TabbedPage
      subnav={
        <SubNav
          active={tab}
          onSelect={setTab}
          items={[
            { id: "overrides", label: _("Overrides") },
            { id: "forward", label: _("Forward zones") },
            { id: "resolver", label: _("Resolver") },
          ]}
        />
      }
    >
      {tab === "overrides" && <Overrides />}
      {tab === "forward" && <ForwardZones />}
      {tab === "resolver" && <Resolver />}
    </TabbedPage>
  );
};
