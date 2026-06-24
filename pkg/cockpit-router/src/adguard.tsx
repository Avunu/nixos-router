import { useEffect, useState, useCallback } from "react";
import { errMsg } from "./nix";
import utCapitoleCategories from "./ut-capitole.json";
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
  Split,
  SplitItem,
  Gallery,
  Form,
  FormGroup,
  FormSection,
  Switch,
  TextInput,
} from "@patternfly/react-core";
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
import { useSettings, ListEditor, Loading, SubNav, SaveBar, hint, TabbedPage } from "./settings";
import { AdGuardOverview } from "./adguard-overview";

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
        setRows((JSON.parse(ql) as { data?: Entry[] }).data ?? []);
        setStats(JSON.parse(st) as Stats);
        setLoading(false);
      })
      .catch((e: unknown) => {
        setError(errMsg(e));
        setLoading(false);
      });
  }, [filter]);

  useEffect(() => {
    load();
  }, [load]);

  if (loading) {
    return <Spinner />;
  }

  return (
    <Stack hasGutter className="ct-router-stack">
      <StackItem>
        <Card isCompact>
          <CardBody>
            <DescriptionList isHorizontal isCompact isFluid>
              <DescriptionListGroup>
                <DescriptionListTerm>{_("Queries")}</DescriptionListTerm>
                <DescriptionListDescription>
                  {stats.num_dns_queries ?? "—"}
                </DescriptionListDescription>
              </DescriptionListGroup>
              <DescriptionListGroup>
                <DescriptionListTerm>{_("Blocked")}</DescriptionListTerm>
                <DescriptionListDescription>
                  {stats.num_blocked_filtering ?? "—"}
                </DescriptionListDescription>
              </DescriptionListGroup>
              <DescriptionListGroup>
                <DescriptionListTerm>{_("Safe browsing")}</DescriptionListTerm>
                <DescriptionListDescription>
                  {stats.num_replaced_safebrowsing ?? "—"}
                </DescriptionListDescription>
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
          <Alert variant="danger" title={_("Could not reach AdGuard Home")} isInline>
            {error}
          </Alert>
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

// Editor for custom AdGuard filter-list objects ({ enabled, name, url, id }).
type Filter = { enabled?: boolean; name?: string; url?: string; id?: number };

const ExtraFiltersEditor = ({
  value,
  onChange,
  isDisabled,
}: {
  value: Filter[];
  onChange: (v: Filter[]) => void;
  isDisabled?: boolean;
}) => {
  const set = (i: number, patch: Partial<Filter>) =>
    onChange(value.map((f, j) => (j === i ? { ...f, ...patch } : f)));
  const add = () => {
    const nextId = Math.max(100, ...value.map((f) => Number(f.id) || 0)) + 1;
    onChange([...value, { enabled: true, name: "", url: "", id: nextId }]);
  };
  const remove = (i: number) => onChange(value.filter((_f, j) => j !== i));
  return (
    <>
      {value.map((f, i) => (
        <Split hasGutter key={i} style={{ marginBlockEnd: "0.5rem", alignItems: "center" }}>
          <SplitItem>
            <Switch
              aria-label={_("Enabled")}
              isChecked={Boolean(f.enabled)}
              isDisabled={isDisabled}
              onChange={(_e, c) => set(i, { enabled: c })}
            />
          </SplitItem>
          <SplitItem>
            <TextInput
              aria-label={_("Name")}
              placeholder={_("Name")}
              value={f.name || ""}
              isDisabled={isDisabled}
              onChange={(_e, v) => set(i, { name: v })}
            />
          </SplitItem>
          <SplitItem isFilled>
            <TextInput
              aria-label={_("URL")}
              placeholder="https://…"
              value={f.url || ""}
              isDisabled={isDisabled}
              onChange={(_e, v) => set(i, { url: v })}
            />
          </SplitItem>
          <SplitItem>
            <Button
              variant="link"
              isDanger
              isInline
              isDisabled={isDisabled}
              onClick={() => remove(i)}
            >
              {_("Remove")}
            </Button>
          </SplitItem>
        </Split>
      ))}
      <Button variant="secondary" onClick={add} isDisabled={isDisabled}>
        {_("Add filter list")}
      </Button>
    </>
  );
};

// Toggle-switch selector for UT Capitole blacklist categories. The list (id +
// official description) lives in ut-capitole.json — the single source also used at
// build time to inject the schema's allowed-values enum.
const UtCapitoleSelector = ({
  value,
  onChange,
  isDisabled,
}: {
  value: string[];
  onChange: (v: string[]) => void;
  isDisabled?: boolean;
}) => {
  const selected = new Set(value);
  return (
    <Gallery hasGutter minWidths={{ default: "320px" }}>
      {utCapitoleCategories.map((c) => (
        <div key={c.id}>
          <Switch
            id={`utc-${c.id}`}
            label={c.id}
            isChecked={selected.has(c.id)}
            isDisabled={isDisabled}
            onChange={(_e, on) => onChange(on ? [...value, c.id] : value.filter((x) => x !== c.id))}
          />
          <div
            className="pf-v6-u-color-200"
            style={{ fontSize: "0.85rem", marginBlockStart: "0.125rem" }}
          >
            {c.description}
          </div>
        </div>
      ))}
    </Gallery>
  );
};

const AdGuardSettings = () => {
  const s = useSettings();
  const filters: Record<string, boolean> = s.valueOf("dns.adguard.standardFilters", {});
  const filtersLocked = s.lockedOf("dns.adguard.standardFilters");

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

  return (
    <Stack hasGutter className="ct-router-stack">
      <StackItem isFilled style={{ overflowY: "auto" }}>
        <Form isHorizontal onSubmit={(e) => e.preventDefault()}>
          <FormSection title={_("Protection")} titleElement="h2">
            <FormGroup label={_("Enforce SafeSearch")} fieldId="safeSearch">
              <Switch
                id="safeSearch"
                isChecked={Boolean(s.valueOf("dns.adguard.safeSearch", false))}
                isDisabled={s.lockedOf("dns.adguard.safeSearch")}
                onChange={(_e, c) => s.setLeaf("dns.adguard.safeSearch", c)}
                aria-label={_("Enforce SafeSearch")}
              />
            </FormGroup>
          </FormSection>

          <FormSection title={_("Standard filter lists")} titleElement="h2">
            {Object.keys(FILTER_LABELS).map((key) => (
              <FormGroup label={_(FILTER_LABELS[key] ?? key)} fieldId={key} key={key}>
                <Switch
                  id={key}
                  isChecked={Boolean(filters[key])}
                  isDisabled={filtersLocked}
                  onChange={(_e, c) =>
                    s.setLeaf("dns.adguard.standardFilters", { ...filters, [key]: c })
                  }
                  aria-label={_(FILTER_LABELS[key] ?? key)}
                />
              </FormGroup>
            ))}
          </FormSection>

          <FormSection title={_("Block & allow lists")} titleElement="h2">
            <FormGroup
              label={_("UT Capitole categories")}
              fieldId="utc"
              labelHelp={hint(_("Category names from dsi.ut-capitole.fr/blacklists"))}
            >
              <UtCapitoleSelector
                value={s.valueOf("dns.adguard.utCapitoleCategories", [])}
                isDisabled={s.lockedOf("dns.adguard.utCapitoleCategories")}
                onChange={(v) => s.setLeaf("dns.adguard.utCapitoleCategories", v)}
              />
            </FormGroup>
            <FormGroup label={_("Allow list (domains)")} fieldId="allow">
              <ListEditor
                value={s.valueOf("dns.adguard.allowList", [])}
                isDisabled={s.lockedOf("dns.adguard.allowList")}
                onChange={(v) => s.setLeaf("dns.adguard.allowList", v)}
                placeholder={_("e.g. example.com")}
              />
            </FormGroup>
            <FormGroup label={_("Block list (domains)")} fieldId="block">
              <ListEditor
                value={s.valueOf("dns.adguard.blockList", [])}
                isDisabled={s.lockedOf("dns.adguard.blockList")}
                onChange={(v) => s.setLeaf("dns.adguard.blockList", v)}
                placeholder={_("e.g. ads.example.com")}
              />
            </FormGroup>
            <FormGroup label={_("Extra user rules")} fieldId="rules">
              <ListEditor
                value={s.valueOf("dns.adguard.extraUserRules", [])}
                isDisabled={s.lockedOf("dns.adguard.extraUserRules")}
                onChange={(v) => s.setLeaf("dns.adguard.extraUserRules", v)}
                placeholder={_("AdGuard rule syntax")}
              />
            </FormGroup>
          </FormSection>

          <FormSection title={_("Custom filter lists")} titleElement="h2">
            <ExtraFiltersEditor
              value={s.valueOf("dns.adguard.extraFilters", [])}
              isDisabled={s.lockedOf("dns.adguard.extraFilters")}
              onChange={(v) => s.setLeaf("dns.adguard.extraFilters", v)}
            />
          </FormSection>

          <FormSection title={_("Upstream DNS")} titleElement="h2">
            <FormGroup label={_("Upstream servers")} fieldId="upstream">
              <ListEditor
                value={s.valueOf("dns.upstreamServers", [])}
                isDisabled={s.lockedOf("dns.upstreamServers")}
                onChange={(v) => s.setLeaf("dns.upstreamServers", v)}
                placeholder={_("https://dns.example/dns-query")}
              />
            </FormGroup>
            <FormGroup label={_("Bootstrap servers")} fieldId="bootstrap">
              <ListEditor
                value={s.valueOf("dns.bootstrapServers", [])}
                isDisabled={s.lockedOf("dns.bootstrapServers")}
                onChange={(v) => s.setLeaf("dns.bootstrapServers", v)}
                placeholder={_("1.1.1.1")}
              />
            </FormGroup>
          </FormSection>

          <FormSection title={_("Ports")} titleElement="h2">
            <FormGroup label={_("DNS listen port")} fieldId="listenPort">
              <TextInput
                id="listenPort"
                type="number"
                value={s.valueOf("dns.adguard.listenPort", 53)}
                isDisabled={s.lockedOf("dns.adguard.listenPort")}
                onChange={(_e, v) => s.setLeaf("dns.adguard.listenPort", Number(v) || 0)}
              />
            </FormGroup>
            <FormGroup label={_("Web UI port")} fieldId="webPort">
              <TextInput
                id="webPort"
                type="number"
                value={s.valueOf("dns.adguard.webPort", 3000)}
                isDisabled={s.lockedOf("dns.adguard.webPort")}
                onChange={(_e, v) => s.setLeaf("dns.adguard.webPort", Number(v) || 0)}
              />
            </FormGroup>
          </FormSection>

          <SaveBar
            saving={s.saving}
            status={s.status}
            onSave={s.save}
            onSaveApply={s.saveAndApply}
          />
        </Form>
      </StackItem>
    </Stack>
  );
};

export const AdGuard = () => {
  const [tab, setTab] = useState("overview");
  return (
    <TabbedPage
      subnav={
        <SubNav
          active={tab}
          onSelect={setTab}
          items={[
            { id: "overview", label: _("Overview") },
            { id: "log", label: _("Query log") },
            { id: "settings", label: _("Settings") },
          ]}
        />
      }
    >
      {tab === "overview" ? (
        <AdGuardOverview />
      ) : tab === "log" ? (
        <AdGuardLog />
      ) : (
        <AdGuardSettings />
      )}
    </TabbedPage>
  );
};
