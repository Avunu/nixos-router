import { useEffect, useState, useCallback } from "react";
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
  TextArea,
  Switch,
  ActionGroup,
  Card,
  CardTitle,
  CardBody,
  EmptyState,
  EmptyStateBody,
  Spinner,
  CodeBlock,
  CodeBlockCode,
  Split,
  SplitItem,
} from "@patternfly/react-core";
import { Table, Thead, Tbody, Tr, Th, Td } from "@patternfly/react-table";
import { readOption, writeOption } from "./nix";
import { PendingBanner, useLoader, useSaver, SaverStatus, Loading, SubNav } from "./settings";

const _ = cockpit.gettext;

// ── Static port forwards (DNAT) ─────────────────────────────────────────────
interface PortForward {
  name: string;
  protocol: "tcp" | "udp";
  destination: string;
  ports: number[];
  source: string | null;
}

const EMPTY_PF: PortForward = { name: "", protocol: "tcp", destination: "", ports: [], source: null };

const parsePorts = (s: string): number[] =>
  s
    .split(/[\s,]+/)
    .map((p) => Number(p.trim()))
    .filter((n) => Number.isInteger(n) && n > 0 && n <= 65535);

const PortForwards = () => {
  const { value, setValue, loading, error } = useLoader<PortForward[]>(
    () => readOption<PortForward[]>("portForwards"),
    [],
  );
  const { saving, status, run } = useSaver();

  // The row currently being edited/added, plus the raw ports text being typed.
  const [draft, setDraft] = useState<PortForward | null>(null);
  const [editIndex, setEditIndex] = useState<number | null>(null);
  const [portsText, setPortsText] = useState("");

  if (loading) return <Loading />;
  if (error) return <Alert variant="danger" isInline title={_("Could not load port forwards")}>{error}</Alert>;

  const persist = (rows: PortForward[]) =>
    run(async () => {
      await writeOption("portForwards", rows);
      setValue(rows);
    });

  const beginAdd = () => {
    setDraft({ ...EMPTY_PF });
    setEditIndex(null);
    setPortsText("");
  };
  const beginEdit = (i: number) => {
    setDraft({ ...value[i] });
    setEditIndex(i);
    setPortsText(value[i].ports.join(", "));
  };
  const cancel = () => {
    setDraft(null);
    setEditIndex(null);
    setPortsText("");
  };
  const remove = (i: number) => persist(value.filter((_r, idx) => idx !== i));

  const commit = () => {
    if (!draft) return;
    const row: PortForward = {
      ...draft,
      ports: parsePorts(portsText),
      source: draft.source && draft.source.trim() ? draft.source.trim() : null,
    };
    const rows = editIndex === null ? [...value, row] : value.map((r, i) => (i === editIndex ? row : r));
    persist(rows);
    cancel();
  };

  const draftValid = draft && draft.destination.trim() && parsePorts(portsText).length > 0;

  return (
    <Stack hasGutter className="ct-router-stack">
      <StackItem isFilled style={{ overflowY: "auto" }}>
        <PendingBanner />
        <SaverStatus status={status} />
        <Stack hasGutter>
          <StackItem>
            <Split>
              <SplitItem isFilled />
              <SplitItem>
                <Button variant="primary" onClick={beginAdd} isDisabled={!!draft}>
                  {_("Add port forward")}
                </Button>
              </SplitItem>
            </Split>
          </StackItem>

          <StackItem>
            {value.length === 0 ? (
              <EmptyState>
                <EmptyStateBody>{_("No port forwards configured.")}</EmptyStateBody>
              </EmptyState>
            ) : (
              <Table variant="compact" aria-label={_("Port forwards")}>
                <Thead>
                  <Tr>
                    <Th>{_("Name")}</Th>
                    <Th>{_("Protocol")}</Th>
                    <Th>{_("Destination")}</Th>
                    <Th>{_("Ports")}</Th>
                    <Th>{_("Source")}</Th>
                    <Th screenReaderText={_("Actions")} />
                  </Tr>
                </Thead>
                <Tbody>
                  {value.map((r, i) => (
                    <Tr key={i}>
                      <Td>{r.name || "—"}</Td>
                      <Td>{r.protocol}</Td>
                      <Td>{r.destination}</Td>
                      <Td>{r.ports.join(", ")}</Td>
                      <Td>{r.source || _("any")}</Td>
                      <Td isActionCell>
                        <Button variant="link" isInline onClick={() => beginEdit(i)} isDisabled={saving}>
                          {_("Edit")}
                        </Button>{" "}
                        <Button variant="link" isInline isDanger onClick={() => remove(i)} isDisabled={saving}>
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
                <CardTitle>{editIndex === null ? _("Add port forward") : _("Edit port forward")}</CardTitle>
                <CardBody>
                  <Form isHorizontal onSubmit={(e) => e.preventDefault()}>
                    <FormGroup label={_("Name")} fieldId="pfName">
                      <TextInput
                        id="pfName"
                        value={draft.name}
                        onChange={(_e, v) => setDraft({ ...draft, name: v })}
                      />
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
                    <FormGroup label={_("Destination IPv4")} fieldId="pfDest" isRequired>
                      <TextInput
                        id="pfDest"
                        value={draft.destination}
                        placeholder="10.48.4.2"
                        onChange={(_e, v) => setDraft({ ...draft, destination: v })}
                      />
                    </FormGroup>
                    <FormGroup label={_("Ports")} fieldId="pfPorts" isRequired labelHelp={_("Comma or space separated")}>
                      <TextInput
                        id="pfPorts"
                        value={portsText}
                        placeholder="80, 443"
                        onChange={(_e, v) => setPortsText(v)}
                      />
                    </FormGroup>
                    <FormGroup label={_("Source prefix (optional)")} fieldId="pfSrc" labelHelp={_("Restrict to a WAN source, e.g. 203.0.113.0/24")}>
                      <TextInput
                        id="pfSrc"
                        value={draft.source || ""}
                        placeholder={_("any")}
                        onChange={(_e, v) => setDraft({ ...draft, source: v })}
                      />
                    </FormGroup>
                    <ActionGroup>
                      <Button variant="primary" onClick={commit} isDisabled={!draftValid || saving} isLoading={saving}>
                        {_("Save")}
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
        </Stack>
      </StackItem>
    </Stack>
  );
};

// ── UPnP-IGD / NAT-PMP (miniupnpd) ──────────────────────────────────────────
interface UpnpForm {
  enable: boolean;
  extraConfig: string;
}

const UpnpSettings = () => {
  const { value, setValue, loading, error } = useLoader<UpnpForm>(
    async () => {
      const u = await readOption<any>("upnp");
      return { enable: !!u.enable, extraConfig: u.extraConfig || "" };
    },
    { enable: false, extraConfig: "" },
  );
  const { saving, status, run } = useSaver();

  if (loading) return <Loading />;
  if (error) return <Alert variant="danger" isInline title={_("Could not load UPnP settings")}>{error}</Alert>;

  const save = () =>
    run(async () => {
      await writeOption("upnp.enable", value.enable);
      await writeOption("upnp.extraConfig", value.extraConfig);
    });

  return (
    <Stack hasGutter className="ct-router-stack">
      <StackItem isFilled style={{ overflowY: "auto" }}>
        <PendingBanner />
        <Alert
          variant="info"
          isInline
          title={_("UPnP lets LAN devices open inbound ports automatically, with no authentication. Enable only when needed; it is never offered to the guest network.")}
          style={{ marginBlockEnd: "1rem" }}
        />
        <Form onSubmit={(e) => e.preventDefault()}>
          <FormGroup label={_("Enable UPnP / NAT-PMP")} fieldId="upnpEnable">
            <Switch
              id="upnpEnable"
              isChecked={value.enable}
              onChange={(_e, c) => setValue((v) => ({ ...v, enable: c }))}
              aria-label={_("Enable UPnP / NAT-PMP")}
            />
          </FormGroup>
          <FormGroup
            label={_("Extra miniupnpd.conf")}
            fieldId="upnpExtra"
            labelHelp={_("Appended after the hardened defaults")}
          >
            <TextArea
              id="upnpExtra"
              value={value.extraConfig}
              onChange={(_e, v) => setValue((s) => ({ ...s, extraConfig: v }))}
              rows={6}
              resizeOrientation="vertical"
              aria-label={_("Extra miniupnpd.conf")}
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

// ── Live nftables ruleset (read-only) ───────────────────────────────────────
const ActiveRules = () => {
  const [text, setText] = useState("");
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");

  const load = useCallback(() => {
    setLoading(true);
    setError("");
    cockpit
      .spawn(["nft", "list", "ruleset"], { superuser: "require", err: "message" })
      .then((out: string) => {
        setText(out || "");
        setLoading(false);
      })
      .catch((e: any) => {
        setError(e.message || String(e));
        setLoading(false);
      });
  }, []);

  useEffect(() => {
    load();
  }, [load]);

  return (
    <Stack hasGutter className="ct-router-stack">
      <StackItem>
        <Split>
          <SplitItem isFilled />
          <SplitItem>
            <Button variant="secondary" onClick={load} isDisabled={loading}>
              {_("Refresh")}
            </Button>
          </SplitItem>
        </Split>
      </StackItem>
      {error && (
        <StackItem>
          <Alert variant="danger" isInline title={_("Could not read the ruleset")}>{error}</Alert>
        </StackItem>
      )}
      <StackItem isFilled style={{ overflow: "auto", minBlockSize: 0 }}>
        {loading ? (
          <Spinner />
        ) : (
          <CodeBlock>
            <CodeBlockCode>{text}</CodeBlockCode>
          </CodeBlock>
        )}
      </StackItem>
    </Stack>
  );
};

export const Firewall = () => {
  const [tab, setTab] = useState("forwards");
  return (
    <Stack className="ct-router-stack">
      <StackItem>
        <SubNav
          active={tab}
          onSelect={setTab}
          items={[
            { id: "forwards", label: _("Port forwards") },
            { id: "upnp", label: _("UPnP") },
            { id: "rules", label: _("Active rules") },
          ]}
        />
      </StackItem>
      <StackItem isFilled className="ct-table-scroll">
        {tab === "forwards" && <PortForwards />}
        {tab === "upnp" && <UpnpSettings />}
        {tab === "rules" && <ActiveRules />}
      </StackItem>
    </Stack>
  );
};
