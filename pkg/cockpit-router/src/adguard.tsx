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
  Card,
  CardBody,
  DescriptionList,
  DescriptionListGroup,
  DescriptionListTerm,
  DescriptionListDescription,
  Label,
  Stack,
  StackItem,
  Tabs,
  Tab,
  TabTitleText,
  Form,
  FormGroup,
  FormSection,
  Switch,
  TextInput,
  ActionGroup,
} from "@patternfly/react-core";
import { Table, Thead, Tbody, Tr, Th, Td, OuterScrollContainer, InnerScrollContainer } from "@patternfly/react-table";
import { readOption, writeOption } from "./nix";
import { PendingBanner, ListEditor, useLoader, useSaver, SaverStatus, Loading } from "./settings";

const _ = cockpit.gettext;
const PORT = (window.cockpitRouterConfig && window.cockpitRouterConfig.adguardPort) || 3000;

const api = () => cockpit.http({ address: "127.0.0.1", port: PORT });

interface Entry {
  time: string;
  client: string;
  question?: { name?: string; host?: string; type?: string };
  reason?: string;
  status?: string;
}

interface Stats {
  num_dns_queries?: number;
  num_blocked_filtering?: number;
  num_replaced_safebrowsing?: number;
  num_replaced_safesearch?: number;
  avg_processing_time?: number;
}

const blocked = (e: Entry) => /Filtered|Blocked|ParentalBlocked|Safe/i.test(e.reason || "");

// ── Query log + live stats (the original DNS view) ──────────────────────────
const AdGuardLog = () => {
  const [rows, setRows] = useState<Entry[]>([]);
  const [stats, setStats] = useState<Stats>({});
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [filter, setFilter] = useState("");
  const [isStuck, setIsStuck] = useState(false);

  const load = useCallback(() => {
    setError("");
    Promise.all([
      api().get("/control/querylog", { limit: 200, search: filter || undefined }),
      api().get("/control/stats"),
    ])
      .then(([ql, st]: [string, string]) => {
        setRows((JSON.parse(ql).data as Entry[]) || []);
        setStats(JSON.parse(st) as Stats);
        setLoading(false);
      })
      .catch((e: any) => {
        setError(e.message || String(e));
        setLoading(false);
      });
  }, [filter]);

  useEffect(() => {
    load();
  }, [load]);

  if (loading) return <Spinner />;

  return (
    <Stack hasGutter className="ct-router-stack">
      <StackItem>
        <Card isCompact>
          <CardBody>
            <DescriptionList isHorizontal isCompact isFluid>
              <DescriptionListGroup>
                <DescriptionListTerm>{_("Queries")}</DescriptionListTerm>
                <DescriptionListDescription>{stats.num_dns_queries ?? "—"}</DescriptionListDescription>
              </DescriptionListGroup>
              <DescriptionListGroup>
                <DescriptionListTerm>{_("Blocked")}</DescriptionListTerm>
                <DescriptionListDescription>{stats.num_blocked_filtering ?? "—"}</DescriptionListDescription>
              </DescriptionListGroup>
              <DescriptionListGroup>
                <DescriptionListTerm>{_("Safe browsing")}</DescriptionListTerm>
                <DescriptionListDescription>{stats.num_replaced_safebrowsing ?? "—"}</DescriptionListDescription>
              </DescriptionListGroup>
              <DescriptionListGroup>
                <DescriptionListTerm>{_("Avg. processing")}</DescriptionListTerm>
                <DescriptionListDescription>
                  {stats.avg_processing_time != null
                    ? `${(stats.avg_processing_time * 1000).toFixed(1)} ms`
                    : "—"}
                </DescriptionListDescription>
              </DescriptionListGroup>
            </DescriptionList>
          </CardBody>
        </Card>
      </StackItem>
      <StackItem>
        <Toolbar>
          <ToolbarContent>
            <ToolbarItem>
              <SearchInput
                placeholder={_("Search domain or client")}
                value={filter}
                onChange={(_e, v) => setFilter(v)}
                onSearch={() => load()}
                onClear={() => {
                  setFilter("");
                }}
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
          <Alert variant="danger" title={_("Could not reach AdGuard Home")} isInline>{error}</Alert>
        </StackItem>
      )}
      <StackItem isFilled className="ct-table-scroll">
        {rows.length === 0 ? (
          <EmptyState>
            <EmptyStateBody>{_("No queries in the log.")}</EmptyStateBody>
          </EmptyState>
        ) : (
          <OuterScrollContainer>
            <InnerScrollContainer onScroll={(e) => setIsStuck(e.currentTarget.scrollTop > 0)}>
              <Table
                variant="compact"
                aria-label={_("AdGuard query log")}
                isStickyHeaderBase
                isStickyHeaderStuck={isStuck}
              >
                <Thead>
                  <Tr>
                    <Th>{_("Time")}</Th>
                    <Th>{_("Client")}</Th>
                    <Th>{_("Domain")}</Th>
                    <Th>{_("Result")}</Th>
                  </Tr>
                </Thead>
                <Tbody>
                  {rows.map((e, i) => (
                    <Tr key={i}>
                      <Td>{e.time}</Td>
                      <Td>{e.client}</Td>
                      <Td>{e.question?.name || e.question?.host || "—"}</Td>
                      <Td>
                        <Label color={blocked(e) ? "red" : "green"} isCompact>
                          {e.reason || "—"}
                        </Label>
                      </Td>
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

// ── Settings: filtering, DNS upstreams, allow/block lists ───────────────────
const FILTER_LABELS: Record<string, string> = {
  adaway: "AdAway hosts list",
  adguard_ads: "AdGuard Base (ads & trackers)",
  adguard_anti_malware: "Dandelion Sprout Anti-Malware",
  adguard_malware: "AdGuard Malware",
  adguard_hacked_sites: "Big List of Hacked Malware Sites",
  adguard_phishing: "AdGuard Phishing URL Blocklist",
  phishtank_openphish: "Phishing Army (PhishTank + OpenPhish)",
  steven_black: "Steven Black unified hosts",
  yoyo_adservers: "Peter Lowe's ad/tracker list",
};

interface AGForm {
  safeSearch: boolean;
  standardFilters: Record<string, boolean>;
  utCapitoleCategories: string[];
  allowList: string[];
  blockList: string[];
  extraUserRules: string[];
  webPort: number;
  listenPort: number;
  upstreamServers: string[];
  bootstrapServers: string[];
}

const EMPTY_AG: AGForm = {
  safeSearch: false,
  standardFilters: {},
  utCapitoleCategories: [],
  allowList: [],
  blockList: [],
  extraUserRules: [],
  webPort: 3000,
  listenPort: 53,
  upstreamServers: [],
  bootstrapServers: [],
};

const AdGuardSettings = () => {
  const { value, setValue, loading, error } = useLoader<AGForm>(async () => {
    const [ag, up, boot] = await Promise.all([
      readOption<any>("dns.adguard"),
      readOption<string[]>("dns.upstreamServers"),
      readOption<string[]>("dns.bootstrapServers"),
    ]);
    return {
      safeSearch: !!ag.safeSearch,
      standardFilters: ag.standardFilters || {},
      utCapitoleCategories: ag.utCapitoleCategories || [],
      allowList: ag.allowList || [],
      blockList: ag.blockList || [],
      extraUserRules: ag.extraUserRules || [],
      webPort: ag.webPort ?? 3000,
      listenPort: ag.listenPort ?? 53,
      upstreamServers: up || [],
      bootstrapServers: boot || [],
    };
  }, EMPTY_AG);

  const { saving, status, run } = useSaver();
  const set = (patch: Partial<AGForm>) => setValue((v) => ({ ...v, ...patch }));

  if (loading) return <Loading />;
  if (error) return <Alert variant="danger" isInline title={_("Could not load settings")}>{error}</Alert>;

  const save = () =>
    run(async () => {
      await writeOption("dns.adguard.safeSearch", value.safeSearch);
      await writeOption("dns.adguard.standardFilters", value.standardFilters);
      await writeOption("dns.adguard.utCapitoleCategories", value.utCapitoleCategories);
      await writeOption("dns.adguard.allowList", value.allowList);
      await writeOption("dns.adguard.blockList", value.blockList);
      await writeOption("dns.adguard.extraUserRules", value.extraUserRules);
      await writeOption("dns.adguard.webPort", value.webPort);
      await writeOption("dns.adguard.listenPort", value.listenPort);
      await writeOption("dns.upstreamServers", value.upstreamServers);
      await writeOption("dns.bootstrapServers", value.bootstrapServers);
    });

  return (
    <Stack hasGutter className="ct-router-stack">
      <StackItem isFilled style={{ overflowY: "auto" }}>
        <PendingBanner />
        <Form isHorizontal onSubmit={(e) => e.preventDefault()}>
          <FormSection title={_("Protection")} titleElement="h2">
            <FormGroup label={_("Enforce SafeSearch")} fieldId="safeSearch">
              <Switch
                id="safeSearch"
                isChecked={value.safeSearch}
                onChange={(_e, c) => set({ safeSearch: c })}
                aria-label={_("Enforce SafeSearch")}
              />
            </FormGroup>
          </FormSection>

          <FormSection title={_("Standard filter lists")} titleElement="h2">
            {Object.keys(FILTER_LABELS).map((key) => (
              <FormGroup label={_(FILTER_LABELS[key])} fieldId={key} key={key}>
                <Switch
                  id={key}
                  isChecked={!!value.standardFilters[key]}
                  onChange={(_e, c) =>
                    set({ standardFilters: { ...value.standardFilters, [key]: c } })
                  }
                  aria-label={_(FILTER_LABELS[key])}
                />
              </FormGroup>
            ))}
          </FormSection>

          <FormSection title={_("Block & allow lists")} titleElement="h2">
            <FormGroup
              label={_("UT Capitole categories")}
              fieldId="utc"
              labelHelp={_("Category names from dsi.ut-capitole.fr/blacklists")}
            >
              <ListEditor
                value={value.utCapitoleCategories}
                onChange={(v) => set({ utCapitoleCategories: v })}
                placeholder={_("e.g. gambling")}
              />
            </FormGroup>
            <FormGroup label={_("Allow list (domains)")} fieldId="allow">
              <ListEditor
                value={value.allowList}
                onChange={(v) => set({ allowList: v })}
                placeholder={_("e.g. example.com")}
              />
            </FormGroup>
            <FormGroup label={_("Block list (domains)")} fieldId="block">
              <ListEditor
                value={value.blockList}
                onChange={(v) => set({ blockList: v })}
                placeholder={_("e.g. ads.example.com")}
              />
            </FormGroup>
            <FormGroup label={_("Extra user rules")} fieldId="rules">
              <ListEditor
                value={value.extraUserRules}
                onChange={(v) => set({ extraUserRules: v })}
                placeholder={_("AdGuard rule syntax")}
              />
            </FormGroup>
          </FormSection>

          <FormSection title={_("Upstream DNS")} titleElement="h2">
            <FormGroup label={_("Upstream servers")} fieldId="upstream">
              <ListEditor
                value={value.upstreamServers}
                onChange={(v) => set({ upstreamServers: v })}
                placeholder={_("https://dns.example/dns-query")}
              />
            </FormGroup>
            <FormGroup label={_("Bootstrap servers")} fieldId="bootstrap">
              <ListEditor
                value={value.bootstrapServers}
                onChange={(v) => set({ bootstrapServers: v })}
                placeholder={_("1.1.1.1")}
              />
            </FormGroup>
          </FormSection>

          <FormSection title={_("Ports")} titleElement="h2">
            <FormGroup label={_("DNS listen port")} fieldId="listenPort">
              <TextInput
                id="listenPort"
                type="number"
                value={value.listenPort}
                onChange={(_e, v) => set({ listenPort: Number(v) || 0 })}
              />
            </FormGroup>
            <FormGroup label={_("Web UI port")} fieldId="webPort">
              <TextInput
                id="webPort"
                type="number"
                value={value.webPort}
                onChange={(_e, v) => set({ webPort: Number(v) || 0 })}
              />
            </FormGroup>
          </FormSection>

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

export const AdGuard = () => {
  const [tab, setTab] = useState<number | string>(0);
  return (
    <Stack className="ct-router-stack">
      <StackItem>
        <Tabs activeKey={tab} onSelect={(_e, k) => setTab(k)} isBox aria-label={_("DNS")}>
          <Tab eventKey={0} title={<TabTitleText>{_("Query log")}</TabTitleText>} />
          <Tab eventKey={1} title={<TabTitleText>{_("Settings")}</TabTitleText>} />
        </Tabs>
      </StackItem>
      <StackItem isFilled className="ct-table-scroll">
        {tab === 0 ? <AdGuardLog /> : <AdGuardSettings />}
      </StackItem>
    </Stack>
  );
};
