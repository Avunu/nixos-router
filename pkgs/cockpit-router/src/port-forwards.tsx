// Ingress → Port forwards: static port forwards (router.portForwards). Moved
// here from the Firewall page, next to the reverse proxy and tunnel that
// publish services by name.
import { useState } from "react";
import type { Json } from "./nix";
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
  ActionGroup,
  Card,
  CardTitle,
  CardBody,
  EmptyState,
  EmptyStateBody,
  Split,
  SplitItem,
  HelperText,
  HelperTextItem,
  Label,
} from "@patternfly/react-core";
import { Table, Thead, Tbody, Tr, Th, Td } from "@patternfly/react-table";
import { useSettings, Loading, SaveBar, hint, ListEditor } from "./settings";
import { isPrefix } from "./ip-math";
import { normalizeForward } from "./forwards";
import { claimsWebPorts } from "./ingress";
import { hostDetail } from "./ingress-widgets";
import type { PortForward, RouterHost } from "./types";

const _ = cockpit.gettext;

// ── Static port forwards ────────────────────────────────────────────────────
// Each forward names a registered host (router.hosts). IPv4 is DNAT'd to the
// host's static IP; IPv6 is a pinhole to the host's own global address, found
// by its IPv6 suffix since the delegated prefix is dynamic. The checks below
// mirror modules/firewall.nix's assertions, so a rebuild never fails on
// something this form let through.
type Family = "both" | "ipv4" | "ipv6";

interface Draft {
  name: string;
  protocol: "tcp" | "udp";
  host: string;
  family: Family;
  sources: string[];
}

const EMPTY_DRAFT: Draft = { name: "", protocol: "tcp", host: "", family: "both", sources: [] };

const FAMILIES: Family[] = ["both", "ipv4", "ipv6"];
const familyLabel = (f: Family) =>
  f === "ipv4" ? _("IPv4 only") : f === "ipv6" ? _("IPv6 only") : _("IPv4 + IPv6");

const parsePorts = (s: string): number[] =>
  s
    .split(/[\s,]+/)
    .map((p) => Number(p.trim()))
    .filter((n) => Number.isInteger(n) && n > 0 && n <= 65_535);

const wantsV4 = (f: Family) => f !== "ipv6";
const wantsV6 = (f: Family) => f !== "ipv4";
const isV6Source = (p: string) => p.includes(":");

interface Issue {
  level: "error" | "warning";
  msg: string;
}

function checkForward(
  d: Draft,
  ports: number[],
  host: RouterHost | undefined,
  others: PortForward[],
  proxyEnabled: boolean,
): Issue[] {
  const issues: Issue[] = [];
  if (!d.host) {
    issues.push({ level: "error", msg: _("Choose the host to forward to.") });
  } else if (!host) {
    issues.push({
      level: "error",
      msg: cockpit.format(_("Host '$0' is not registered."), d.host),
    });
  }
  if (ports.length === 0) {
    issues.push({ level: "error", msg: _("Enter at least one port (1-65535).") });
  }
  if (host && wantsV4(d.family) && !host.staticIp) {
    issues.push({
      level: "error",
      msg: cockpit.format(
        _(
          "$0 has no static IP to forward IPv4 to — reserve one on the Hosts page, or forward IPv6 only.",
        ),
        host.name,
      ),
    });
  }
  if (host && wantsV6(d.family) && !host.ipv6Suffix) {
    issues.push({
      level: "error",
      msg: cockpit.format(
        _(
          "$0 has no IPv6 suffix to open a pinhole for — set one on the Hosts page, or forward IPv4 only.",
        ),
        host.name,
      ),
    });
  }
  const bad = d.sources.filter((p) => !isPrefix(p));
  if (bad.length > 0) {
    issues.push({
      level: "error",
      msg: cockpit.format(_("Not an IPv4 or IPv6 address or prefix: $0"), bad.join(", ")),
    });
  }
  if (d.sources.length > 0 && wantsV6(d.family) && !d.sources.some((p) => isV6Source(p))) {
    issues.push({
      level: "warning",
      msg: _("All sources are IPv4, so the IPv6 side of this forward stays closed."),
    });
  }
  if (d.sources.length > 0 && wantsV4(d.family) && d.sources.every((p) => isV6Source(p))) {
    issues.push({
      level: "warning",
      msg: _("All sources are IPv6, so nothing is forwarded over IPv4."),
    });
  }
  if (proxyEnabled && claimsWebPorts({ ...d, ports })) {
    issues.push({
      level: "error",
      msg: _(
        "tcp 80/443 over IPv4 belong to the reverse proxy — add a Reverse proxy route for the host instead, or forward IPv6 only.",
      ),
    });
  }
  if (wantsV4(d.family) && d.sources.length === 0) {
    const clash = ports.filter((p) =>
      others.some(
        (o) =>
          wantsV4(o.family ?? "both") &&
          (o.sources ?? []).length === 0 &&
          (o.protocol ?? "tcp") === d.protocol &&
          o.ports.includes(p),
      ),
    );
    if (clash.length > 0) {
      issues.push({
        level: "error",
        msg: cockpit.format(
          _("Another unrestricted IPv4 forward already claims $0 $1."),
          d.protocol,
          clash.join(", "),
        ),
      });
    }
  }
  return issues;
}

export const PortForwards = () => {
  const s = useSettings();
  const stored = s.valueOf<PortForward[]>("portForwards", []);
  const hosts = s.valueOf<RouterHost[]>("hosts", []);
  const locked = s.lockedOf("portForwards");
  const proxyEnabled = Boolean(s.valueOf("reverseProxy.enable", false));

  // The row currently being edited/added, plus the raw ports text being typed.
  const [draft, setDraft] = useState<Draft | null>(null);
  const [editIndex, setEditIndex] = useState<number | null>(null);
  const [portsText, setPortsText] = useState("");

  if (!s.ready && !s.error) {
    return <Loading />;
  }
  if (s.error) {
    return (
      <Alert variant="danger" isInline title={_("Could not load port forwards")}>
        {s.error}
      </Alert>
    );
  }

  const hostByName = new Map(hosts.map((h) => [h.name, h]));
  const rows = stored.map((r) => normalizeForward(r));
  const setRows = (r: PortForward[]) => s.setLeaf("portForwards", r as unknown as Json);

  const beginAdd = () => {
    setDraft({ ...EMPTY_DRAFT });
    setEditIndex(null);
    setPortsText("");
  };
  const beginEdit = (i: number) => {
    const r = rows[i];
    if (!r) {
      return;
    }
    setDraft({
      name: r.name ?? "",
      protocol: r.protocol ?? "tcp",
      host: r.host,
      family: r.family ?? "both",
      sources: r.sources ?? [],
    });
    setEditIndex(i);
    setPortsText(r.ports.join(", "));
  };
  const cancel = () => {
    setDraft(null);
    setEditIndex(null);
    setPortsText("");
  };
  const remove = (i: number) => setRows(rows.filter((_r, idx) => idx !== i));

  const ports = parsePorts(portsText);
  const issues = draft
    ? checkForward(
        draft,
        ports,
        hostByName.get(draft.host),
        rows.filter((_r, i) => i !== editIndex),
        proxyEnabled,
      )
    : [];

  const commit = () => {
    if (!draft) {
      return;
    }
    const row = normalizeForward({ ...draft, name: draft.name.trim(), ports });
    setRows(editIndex === null ? [...rows, row] : rows.map((r, i) => (i === editIndex ? row : r)));
    cancel();
  };

  return (
    <Stack hasGutter className="ct-router-stack">
      <StackItem isFilled style={{ overflowY: "auto" }}>
        <Stack hasGutter>
          {locked && (
            <StackItem>
              <Alert
                variant="info"
                isInline
                title={_("Port forwards are locked in the Nix configuration.")}
              />
            </StackItem>
          )}
          <StackItem>
            <Split>
              <SplitItem isFilled />
              <SplitItem>
                <Button
                  variant="secondary"
                  onClick={beginAdd}
                  isDisabled={Boolean(draft) || locked || hosts.length === 0}
                >
                  {_("Add port forward")}
                </Button>
              </SplitItem>
            </Split>
          </StackItem>

          <StackItem>
            {rows.length === 0 ? (
              <EmptyState>
                <EmptyStateBody>
                  {hosts.length === 0
                    ? _("No port forwards configured. Register the device on the Hosts page first.")
                    : _("No port forwards configured.")}
                </EmptyStateBody>
              </EmptyState>
            ) : (
              <Table variant="compact" aria-label={_("Port forwards")}>
                <Thead>
                  <Tr>
                    <Th>{_("Name")}</Th>
                    <Th>{_("Protocol")}</Th>
                    <Th>{_("Host")}</Th>
                    <Th>{_("Family")}</Th>
                    <Th>{_("Ports")}</Th>
                    <Th>{_("Sources")}</Th>
                    <Th screenReaderText={_("Actions")} />
                  </Tr>
                </Thead>
                <Tbody>
                  {rows.map((r, i) => {
                    const host = hostByName.get(r.host);
                    return (
                      <Tr key={i}>
                        <Td>{r.name || "—"}</Td>
                        <Td>{r.protocol}</Td>
                        <Td>
                          <div>{r.host}</div>
                          <small>
                            {host ? (
                              hostDetail(host)
                            ) : (
                              <Label color="red" isCompact>
                                {_("unknown host")}
                              </Label>
                            )}
                          </small>
                        </Td>
                        <Td>{familyLabel(r.family ?? "both")}</Td>
                        <Td>{r.ports.join(", ")}</Td>
                        <Td>{(r.sources ?? []).join(", ") || _("any")}</Td>
                        <Td isActionCell>
                          <Button
                            variant="link"
                            isInline
                            onClick={() => beginEdit(i)}
                            isDisabled={locked}
                          >
                            {_("Edit")}
                          </Button>{" "}
                          <Button
                            variant="link"
                            isInline
                            isDanger
                            onClick={() => remove(i)}
                            isDisabled={locked}
                          >
                            {_("Delete")}
                          </Button>
                        </Td>
                      </Tr>
                    );
                  })}
                </Tbody>
              </Table>
            )}
          </StackItem>

          {draft && (
            <StackItem>
              <Card isCompact>
                <CardTitle>
                  {editIndex === null ? _("Add port forward") : _("Edit port forward")}
                </CardTitle>
                <CardBody>
                  <Form isHorizontal onSubmit={(e) => e.preventDefault()}>
                    <FormGroup label={_("Name")} fieldId="pfName">
                      <TextInput
                        id="pfName"
                        value={draft.name}
                        onChange={(_e, v) => setDraft({ ...draft, name: v })}
                      />
                    </FormGroup>
                    <FormGroup label={_("Host")} fieldId="pfHost" isRequired>
                      <FormSelect
                        id="pfHost"
                        value={draft.host}
                        onChange={(_e, v) => setDraft({ ...draft, host: v })}
                      >
                        <FormSelectOption value="" label={_("— choose a host —")} isPlaceholder />
                        {hosts.map((h) => (
                          <FormSelectOption
                            key={h.mac}
                            value={h.name}
                            label={`${h.name} (${hostDetail(h)})`}
                          />
                        ))}
                      </FormSelect>
                    </FormGroup>
                    <FormGroup label={_("Protocol")} fieldId="pfProto">
                      <FormSelect
                        id="pfProto"
                        value={draft.protocol}
                        onChange={(_e, v) => setDraft({ ...draft, protocol: v as "tcp" | "udp" })}
                      >
                        <FormSelectOption value="tcp" label="tcp" />
                        <FormSelectOption value="udp" label="udp" />
                      </FormSelect>
                    </FormGroup>
                    <FormGroup
                      label={_("Family")}
                      fieldId="pfFamily"
                      labelHelp={hint(
                        _(
                          "IPv4 is forwarded from the router's public address to the host's static IP. IPv6 needs no forwarding address: the host's own IPv6 address is opened on these ports.",
                        ),
                      )}
                    >
                      <FormSelect
                        id="pfFamily"
                        value={draft.family}
                        onChange={(_e, v) => setDraft({ ...draft, family: v as Family })}
                      >
                        {FAMILIES.map((f) => (
                          <FormSelectOption key={f} value={f} label={familyLabel(f)} />
                        ))}
                      </FormSelect>
                    </FormGroup>
                    <FormGroup
                      label={_("Ports")}
                      fieldId="pfPorts"
                      isRequired
                      labelHelp={hint(_("Comma or space separated"))}
                    >
                      <TextInput
                        id="pfPorts"
                        value={portsText}
                        placeholder="80, 443"
                        onChange={(_e, v) => setPortsText(v)}
                      />
                    </FormGroup>
                    <FormGroup
                      label={_("Sources (optional)")}
                      fieldId="pfSrc"
                      labelHelp={hint(
                        _(
                          "Restrict the forward to these WAN addresses or prefixes, IPv4 and IPv6 mixed (e.g. 203.0.113.0/24, 2001:db8::/48). Empty allows any source.",
                        ),
                      )}
                    >
                      <ListEditor
                        value={draft.sources}
                        placeholder={_("any")}
                        onChange={(v) => setDraft({ ...draft, sources: v })}
                      />
                    </FormGroup>
                    {issues.length > 0 && (
                      <HelperText>
                        {issues.map((it) => (
                          <HelperTextItem key={it.msg} variant={it.level}>
                            {it.msg}
                          </HelperTextItem>
                        ))}
                      </HelperText>
                    )}
                    <ActionGroup>
                      <Button
                        variant="secondary"
                        onClick={commit}
                        isDisabled={issues.some((it) => it.level === "error")}
                      >
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
