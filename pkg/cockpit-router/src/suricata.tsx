import { useEffect, useState, useCallback } from "react";
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
  Stack,
  StackItem,
  Tabs,
  Tab,
  TabTitleText,
  Form,
  FormGroup,
  Switch,
  TextArea,
  ActionGroup,
} from "@patternfly/react-core";
import { Table, Thead, Tbody, Tr, Th, Td, OuterScrollContainer, InnerScrollContainer } from "@patternfly/react-table";
import { readOption, writeOption } from "./nix";
import { PendingBanner, useLoader, useSaver, SaverStatus, Loading } from "./settings";

const _ = cockpit.gettext;
const EVE = "/var/log/suricata/eve.json";
const SCAN = 1000; // lines to tail

interface Ev {
  timestamp: string;
  event_type: string;
  src_ip?: string;
  dest_ip?: string;
  proto?: string;
  alert?: { signature?: string; severity?: number; category?: string };
}

const sevColor = (s?: number) =>
  s === 1 ? "red" : s === 2 ? "orange" : "grey";

const SuricataLog = () => {
  const [rows, setRows] = useState<Ev[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [filter, setFilter] = useState("");
  const [isStuck, setIsStuck] = useState(false);

  const load = useCallback(() => {
    setError("");
    cockpit
      .spawn(["tail", "-n", String(SCAN), EVE], {
        superuser: "require",
        err: "message",
      })
      .then((out: string) => {
        const evs: Ev[] = [];
        for (const line of (out || "").split("\n")) {
          if (!line.trim()) continue;
          try {
            const o = JSON.parse(line);
            if (o.event_type === "alert" || o.event_type === "drop") evs.push(o);
          } catch {
            /* skip partial/non-JSON lines */
          }
        }
        setRows(evs.reverse()); // newest first
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

  const shown = rows.filter(
    (r) =>
      !filter ||
      [r.src_ip, r.dest_ip, r.proto, r.event_type, r.alert?.signature, r.alert?.category]
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
                placeholder={_("Filter by IP, signature, category")}
                value={filter}
                onChange={(_e, v) => setFilter(v)}
                onClear={() => setFilter("")}
              />
            </ToolbarItem>
            <ToolbarItem>
              <Button variant="secondary" onClick={load}>
                {_("Refresh")}
              </Button>
            </ToolbarItem>
          </ToolbarContent>
        </Toolbar>
      </StackItem>
      {error && (
        <StackItem>
          <Alert variant="danger" title={_("Could not read Suricata events")} isInline>{error}</Alert>
        </StackItem>
      )}
      <StackItem isFilled className="ct-table-scroll">
        {shown.length === 0 ? (
          <EmptyState>
            <EmptyStateBody>{_("No alerts or drops in the recent log.")}</EmptyStateBody>
          </EmptyState>
        ) : (
          <OuterScrollContainer>
            <InnerScrollContainer onScroll={(e) => setIsStuck(e.currentTarget.scrollTop > 0)}>
              <Table
                variant="compact"
                aria-label={_("Suricata events")}
                isStickyHeaderBase
                isStickyHeaderStuck={isStuck}
              >
                <Thead>
                  <Tr>
                    <Th>{_("Time")}</Th>
                    <Th>{_("Type")}</Th>
                    <Th>{_("Source")}</Th>
                    <Th>{_("Destination")}</Th>
                    <Th>{_("Proto")}</Th>
                    <Th>{_("Signature")}</Th>
                  </Tr>
                </Thead>
                <Tbody>
                  {shown.map((r, i) => (
                    <Tr key={i}>
                      <Td>{r.timestamp}</Td>
                      <Td>
                        <Label color={r.event_type === "drop" ? "red" : sevColor(r.alert?.severity)} isCompact>
                          {r.event_type}
                        </Label>
                      </Td>
                      <Td>{r.src_ip || "—"}</Td>
                      <Td>{r.dest_ip || "—"}</Td>
                      <Td>{r.proto || "—"}</Td>
                      <Td>{r.alert?.signature || "—"}</Td>
                    </Tr>
                  ))}
                </Tbody>
              </Table>
            </InnerScrollContainer>
          </OuterScrollContainer>
        )}
      </StackItem>
    </Stack>
  );
};

interface IPSForm {
  enable: boolean;
  extraRules: string;
}

const SuricataSettings = () => {
  const { value, setValue, loading, error } = useLoader<IPSForm>(
    async () => ({
      enable: !!(await readOption<boolean>("suricata.enable")),
      extraRules: (await readOption<string>("suricata.extraRules")) || "",
    }),
    { enable: false, extraRules: "" },
  );
  const { saving, status, run } = useSaver();

  if (loading) return <Loading />;
  if (error) return <Alert variant="danger" isInline title={_("Could not load settings")}>{error}</Alert>;

  const save = () =>
    run(async () => {
      await writeOption("suricata.enable", value.enable);
      await writeOption("suricata.extraRules", value.extraRules);
    });

  return (
    <Stack hasGutter className="ct-router-stack">
      <StackItem isFilled style={{ overflowY: "auto" }}>
        <PendingBanner />
        <Form onSubmit={(e) => e.preventDefault()}>
          <FormGroup label={_("Enable Suricata IPS")} fieldId="ipsEnable">
            <Switch
              id="ipsEnable"
              isChecked={value.enable}
              onChange={(_e, c) => setValue((v) => ({ ...v, enable: c }))}
              aria-label={_("Enable Suricata IPS")}
            />
          </FormGroup>
          <FormGroup
            label={_("Extra local rules")}
            fieldId="extraRules"
            labelHelp={_("Custom Suricata rules, one per line")}
          >
            <TextArea
              id="extraRules"
              value={value.extraRules}
              onChange={(_e, v) => setValue((s) => ({ ...s, extraRules: v }))}
              rows={10}
              resizeOrientation="vertical"
              aria-label={_("Extra local rules")}
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

export const Suricata = () => {
  const [tab, setTab] = useState<number | string>(0);
  return (
    <Stack className="ct-router-stack">
      <StackItem>
        <Tabs activeKey={tab} onSelect={(_e, k) => setTab(k)} isBox aria-label={_("IPS")}>
          <Tab eventKey={0} title={<TabTitleText>{_("Events")}</TabTitleText>} />
          <Tab eventKey={1} title={<TabTitleText>{_("Settings")}</TabTitleText>} />
        </Tabs>
      </StackItem>
      <StackItem isFilled className="ct-table-scroll">
        {tab === 0 ? <SuricataLog /> : <SuricataSettings />}
      </StackItem>
    </Stack>
  );
};
