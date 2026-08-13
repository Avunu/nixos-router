// Reports page — engine-level dashboard stats (Technitium), the enriched query
// log served by router-logd (device/group/policy attribution done at ingest),
// and the scheduled-PDF-report settings + generated-report downloads.
import { useCallback, useEffect, useMemo, useState } from "react";
import {
  Alert,
  Button,
  Card,
  CardBody,
  CardTitle,
  Checkbox,
  EmptyState,
  EmptyStateBody,
  Form,
  FormGroup,
  FormSection,
  FormSelect,
  FormSelectOption,
  Gallery,
  Label,
  NumberInput,
  Pagination,
  Split,
  SplitItem,
  Stack,
  StackItem,
  Switch,
  TextInput,
  ToggleGroup,
  ToggleGroupItem,
  Toolbar,
  ToolbarContent,
  ToolbarItem,
} from "@patternfly/react-core";
import { Table, Tbody, Td, Th, Thead, Tr } from "@patternfly/react-table";
import { REPORTS_DIR, errMsg } from "./nix";
import type { Json } from "./nix";
import { ListEditor, Loading, SaveBar, SubNav, TabbedPage, hint, useSettings } from "./settings";
import { statsGet, statsGetTop } from "./technitium";
import { logsCsv, logsQuery, statsTop } from "./logd";
import type { LogFilters } from "./logd";
import { QueriesChart, RankCard } from "./widgets";
import type {
  HostGroup,
  LogPage,
  ReportSchedule,
  RouterHost,
  StatsRange,
  TechnitiumDashboard,
  TechnitiumTopEntry,
  TopEntry,
} from "./types";

const _ = cockpit.gettext;

type Settings = ReturnType<typeof useSettings>;

const REFRESH_MS = 10_000;
const PAGE_SIZE = 50;

const RANGES: { id: StatsRange; label: string; ms: number }[] = [
  { id: "LastHour", label: _("Last hour"), ms: 3_600_000 },
  { id: "LastDay", label: _("Last day"), ms: 86_400_000 },
  { id: "LastWeek", label: _("Last week"), ms: 604_800_000 },
  { id: "LastMonth", label: _("Last month"), ms: 2_592_000_000 },
];

const pct = (part: number, whole: number): string =>
  whole > 0 ? `${((part / whole) * 100).toFixed(1)}%` : "—";

// Client-side file download via a temporary object URL + anchor click.
function downloadBlob(name: string, blob: Blob): void {
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = name;
  document.body.append(a);
  a.click();
  a.remove();
  setTimeout(() => URL.revokeObjectURL(url), 60_000);
}

// Bounded integer input used by the settings form.
const IntInput = ({
  id,
  value,
  min = 0,
  onChange,
}: {
  id: string;
  value: number;
  min?: number;
  onChange: (v: number) => void;
}) => (
  <NumberInput
    id={id}
    value={value}
    min={min}
    inputAriaLabel={id}
    onMinus={() => onChange(Math.max(min, value - 1))}
    onPlus={() => onChange(value + 1)}
    onChange={(event) => {
      const v = Number((event.target as HTMLInputElement).value);
      if (!Number.isNaN(v)) {
        onChange(Math.max(min, Math.trunc(v)));
      }
    }}
  />
);

const Stat = ({ label, value, sub }: { label: string; value: string | number; sub?: string }) => (
  <div>
    <div style={{ fontSize: "1.6rem", fontWeight: 700, lineHeight: 1.1 }}>{value}</div>
    <div className="pf-v6-u-color-200" style={{ fontSize: "0.85rem" }}>
      {label}
    </div>
    {sub ? (
      <div className="pf-v6-u-color-200" style={{ fontSize: "0.8rem" }}>
        {sub}
      </div>
    ) : null}
  </div>
);

// ── Overview tab ─────────────────────────────────────────────────────────────
const Overview = ({ hosts }: { hosts: RouterHost[] }) => {
  const [range, setRange] = useState<StatsRange>("LastDay");
  const [dash, setDash] = useState<TechnitiumDashboard | null>(null);
  const [topDomains, setTopDomains] = useState<TechnitiumTopEntry[]>([]);
  const [topBlocked, setTopBlocked] = useState<TechnitiumTopEntry[]>([]);
  const [topClients, setTopClients] = useState<TechnitiumTopEntry[]>([]);
  const [byGroup, setByGroup] = useState<TopEntry[]>([]);
  const [byPolicy, setByPolicy] = useState<TopEntry[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [logdError, setLogdError] = useState("");

  const load = useCallback(() => {
    void Promise.all([
      statsGet(range),
      statsGetTop("TopDomains", range, 10),
      statsGetTop("TopBlockedDomains", range, 10),
      statsGetTop("TopClients", range, 10),
    ])
      .then(([dashboard, domains, blocked, clients]) => {
        setDash(dashboard);
        setTopDomains(domains);
        setTopBlocked(blocked);
        setTopClients(clients);
        setError("");
      })
      .catch((e: unknown) => setError(errMsg(e)))
      .finally(() => setLoading(false));

    // Group/policy attribution lives in router-logd, not the DNS engine; its
    // failure must not take down the Technitium cards.
    const rangeMs = RANGES.find((r) => r.id === range)?.ms ?? 86_400_000;
    const start = new Date(Date.now() - rangeMs).toISOString();
    void Promise.all([statsTop("group", { start }, 20), statsTop("policy", { start }, 20)])
      .then(([groups, policies]) => {
        setByGroup(groups);
        setByPolicy(policies);
        setLogdError("");
      })
      .catch((e: unknown) => setLogdError(errMsg(e)));
  }, [range]);

  useEffect(() => {
    load();
    const id = setInterval(load, REFRESH_MS);
    return () => clearInterval(id);
  }, [load]);

  const clientRows = useMemo<[string, number][]>(
    () =>
      topClients.map((t) => {
        const host = hosts.find((h) => h.staticIp === t.name);
        const label = host
          ? `${host.name} (${t.name})`
          : t.domain
            ? `${t.domain} (${t.name})`
            : t.name;
        return [label, t.hits];
      }),
    [topClients, hosts],
  );

  const dataset = (label: string): number[] =>
    dash?.mainChartData.datasets.find((d) => d.label === label)?.data ?? [];

  const logdRows = (top: TopEntry[]): [string, number][] =>
    top.map((t) => {
      const name = t.name || _("(unattributed)");
      return [t.blocked > 0 ? cockpit.format(_("$0 — $1 blocked"), name, t.blocked) : name, t.hits];
    });

  if (loading) {
    return <Loading />;
  }

  return (
    <Stack hasGutter className="ct-router-stack">
      <StackItem>
        <Toolbar>
          <ToolbarContent>
            <ToolbarItem>
              <ToggleGroup aria-label={_("Time range")}>
                {RANGES.map((r) => (
                  <ToggleGroupItem
                    key={r.id}
                    text={r.label}
                    buttonId={`range-${r.id}`}
                    isSelected={range === r.id}
                    onChange={() => setRange(r.id)}
                  />
                ))}
              </ToggleGroup>
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
          <Alert variant="danger" isInline title={_("Could not load DNS statistics")}>
            {error}
          </Alert>
        </StackItem>
      )}
      {logdError && (
        <StackItem>
          <Alert
            variant="warning"
            isInline
            title={_("Query-log daemon not reachable — group and policy breakdowns unavailable")}
          >
            {logdError}
          </Alert>
        </StackItem>
      )}
      <StackItem isFilled style={{ overflowY: "auto" }}>
        {!dash && !error ? (
          <EmptyState>
            <EmptyStateBody>{_("No statistics have been collected yet.")}</EmptyStateBody>
          </EmptyState>
        ) : dash ? (
          <Stack hasGutter>
            <StackItem>
              <Card isCompact>
                <CardTitle>{_("DNS statistics")}</CardTitle>
                <CardBody>
                  <Gallery hasGutter minWidths={{ default: "150px" }}>
                    <Stat label={_("Queries")} value={dash.stats.totalQueries} />
                    <Stat
                      label={_("Blocked")}
                      value={dash.stats.totalBlocked}
                      sub={pct(dash.stats.totalBlocked, dash.stats.totalQueries)}
                    />
                    <Stat label={_("Clients")} value={dash.stats.totalClients} />
                    <Stat label={_("Cached")} value={dash.stats.totalCached} />
                    <Stat label={_("Block list zones")} value={dash.stats.blockListZones} />
                  </Gallery>
                </CardBody>
              </Card>
            </StackItem>
            <StackItem>
              <QueriesChart
                title={_("Queries over time")}
                total={dataset("Total")}
                blocked={dataset("Blocked")}
                labels={dash.mainChartData.labels}
                labelFormat={dash.mainChartData.labelFormat}
              />
            </StackItem>
            <StackItem>
              <Gallery hasGutter minWidths={{ default: "320px" }}>
                <RankCard title={_("Top domains")} rows={topDomains.map((t) => [t.name, t.hits])} />
                <RankCard
                  title={_("Top blocked domains")}
                  rows={topBlocked.map((t) => [t.name, t.hits])}
                />
                <RankCard title={_("Top clients")} rows={clientRows} />
              </Gallery>
            </StackItem>
            {!logdError && (
              <StackItem>
                <Gallery hasGutter minWidths={{ default: "320px" }}>
                  <RankCard title={_("By group")} rows={logdRows(byGroup)} />
                  <RankCard title={_("By policy")} rows={logdRows(byPolicy)} />
                </Gallery>
              </StackItem>
            )}
          </Stack>
        ) : null}
      </StackItem>
    </Stack>
  );
};

// ── Query log tab ────────────────────────────────────────────────────────────
const QUICK_RANGES: { id: string; label: string; ms: number }[] = [
  { id: "1h", label: _("Last hour"), ms: 3_600_000 },
  { id: "24h", label: _("Last 24 hours"), ms: 86_400_000 },
  { id: "7d", label: _("Last 7 days"), ms: 604_800_000 },
  { id: "30d", label: _("Last 30 days"), ms: 2_592_000_000 },
];

const isBlockedResponse = (responseType: string): boolean =>
  responseType === "Blocked" || responseType.startsWith("UpstreamBlocked");

const QueryLog = ({ hostGroups }: { hostGroups: HostGroup[] }) => {
  const [rangeId, setRangeId] = useState("24h");
  const [client, setClient] = useState("");
  const [qname, setQname] = useState("");
  const [group, setGroup] = useState("");
  const [blockedOnly, setBlockedOnly] = useState(false);
  const [page, setPage] = useState(1);
  const [data, setData] = useState<LogPage | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [exporting, setExporting] = useState(false);

  const filters = useMemo<LogFilters>(() => {
    const ms = QUICK_RANGES.find((r) => r.id === rangeId)?.ms ?? 86_400_000;
    const f: LogFilters = { start: new Date(Date.now() - ms).toISOString() };
    if (client.trim()) {
      f.client = client.trim();
    }
    if (qname.trim()) {
      f.qname = qname.trim();
    }
    if (group) {
      f.group = group;
    }
    if (blockedOnly) {
      f.blocked = true;
    }
    return f;
  }, [rangeId, client, qname, group, blockedOnly]);

  // Debounced fetch: text filters re-query 300 ms after the last keystroke.
  useEffect(() => {
    const t = setTimeout(() => {
      void logsQuery(filters, page, PAGE_SIZE)
        .then((p) => {
          setData(p);
          setError("");
        })
        .catch((e: unknown) => setError(errMsg(e)))
        .finally(() => setLoading(false));
    }, 300);
    return () => clearTimeout(t);
  }, [filters, page]);

  const exportCsv = () => {
    setExporting(true);
    void logsCsv(filters)
      .then((csv) => {
        const stamp = new Date().toISOString().slice(0, 19).replaceAll(":", "-");
        downloadBlob(`query-log-${stamp}.csv`, new Blob([csv], { type: "text/csv" }));
      })
      .catch((e: unknown) => setError(errMsg(e)))
      .finally(() => setExporting(false));
  };

  if (loading && !data && !error) {
    return <Loading />;
  }

  const entries = data?.entries ?? [];

  return (
    <Stack hasGutter className="ct-router-stack">
      <StackItem>
        <Toolbar>
          <ToolbarContent>
            <ToolbarItem>
              <FormSelect
                value={rangeId}
                aria-label={_("Time range")}
                onChange={(_e, v) => {
                  setRangeId(v);
                  setPage(1);
                }}
                style={{ minWidth: "9rem" }}
              >
                {QUICK_RANGES.map((r) => (
                  <FormSelectOption key={r.id} value={r.id} label={r.label} />
                ))}
              </FormSelect>
            </ToolbarItem>
            <ToolbarItem>
              <TextInput
                value={client}
                type="text"
                aria-label={_("Client")}
                placeholder={_("Client IP")}
                onChange={(_e, v) => {
                  setClient(v);
                  setPage(1);
                }}
              />
            </ToolbarItem>
            <ToolbarItem>
              <TextInput
                value={qname}
                type="text"
                aria-label={_("Domain contains")}
                placeholder={_("Domain contains")}
                onChange={(_e, v) => {
                  setQname(v);
                  setPage(1);
                }}
              />
            </ToolbarItem>
            <ToolbarItem>
              <FormSelect
                value={group}
                aria-label={_("Group")}
                onChange={(_e, v) => {
                  setGroup(v);
                  setPage(1);
                }}
                style={{ minWidth: "9rem" }}
              >
                <FormSelectOption value="" label={_("All groups")} />
                {hostGroups.map((g) => (
                  <FormSelectOption key={g.name} value={g.name} label={g.name} />
                ))}
              </FormSelect>
            </ToolbarItem>
            <ToolbarItem>
              <Switch
                id="log-blocked-only"
                label={_("Blocked only")}
                isChecked={blockedOnly}
                onChange={(_e, c) => {
                  setBlockedOnly(c);
                  setPage(1);
                }}
              />
            </ToolbarItem>
            <ToolbarItem>
              <Button
                variant="secondary"
                onClick={exportCsv}
                isLoading={exporting}
                isDisabled={exporting}
              >
                {_("Export CSV")}
              </Button>
            </ToolbarItem>
            <ToolbarItem align={{ default: "alignEnd" }}>
              <Pagination
                itemCount={data?.total ?? 0}
                page={page}
                perPage={PAGE_SIZE}
                perPageOptions={[{ title: "50", value: PAGE_SIZE }]}
                onSetPage={(_e, p) => setPage(p)}
                isCompact
              />
            </ToolbarItem>
          </ToolbarContent>
        </Toolbar>
      </StackItem>
      {error && (
        <StackItem>
          <Alert variant="danger" isInline title={_("Could not query the log daemon")}>
            {error}
          </Alert>
        </StackItem>
      )}
      <StackItem isFilled style={{ overflowY: "auto" }}>
        <Table variant="compact" aria-label={_("DNS query log")}>
          <Thead>
            <Tr>
              <Th>{_("Time")}</Th>
              <Th>{_("Client")}</Th>
              <Th>{_("Domain")}</Th>
              <Th>{_("Type")}</Th>
              <Th>{_("Response")}</Th>
              <Th>{_("Policy")}</Th>
              <Th>{_("Answer")}</Th>
            </Tr>
          </Thead>
          <Tbody>
            {entries.length === 0 ? (
              <Tr>
                <Td colSpan={7}>
                  <span className="pf-v6-u-color-200">{_("No log entries match the filter.")}</span>
                </Td>
              </Tr>
            ) : (
              entries.map((e, i) => (
                <Tr key={`${e.ts}-${i}`}>
                  <Td dataLabel={_("Time")} modifier="nowrap">
                    {new Date(e.ts).toLocaleString()}
                  </Td>
                  <Td dataLabel={_("Client")}>
                    <span title={e.client_ip}>{e.device ?? e.client_ip}</span>
                  </Td>
                  <Td dataLabel={_("Domain")}>{e.qname}</Td>
                  <Td dataLabel={_("Type")}>{e.qtype}</Td>
                  <Td dataLabel={_("Response")}>
                    <Label isCompact color={isBlockedResponse(e.response_type) ? "red" : "green"}>
                      {e.response_type}
                    </Label>
                  </Td>
                  <Td dataLabel={_("Policy")}>{e.policy ?? "—"}</Td>
                  <Td dataLabel={_("Answer")}>
                    <div
                      title={e.answer}
                      style={{
                        maxInlineSize: "16rem",
                        overflow: "hidden",
                        textOverflow: "ellipsis",
                        whiteSpace: "nowrap",
                      }}
                    >
                      {e.answer || "—"}
                    </div>
                  </Td>
                </Tr>
              ))
            )}
          </Tbody>
        </Table>
      </StackItem>
    </Stack>
  );
};

// ── Scheduled reports tab ────────────────────────────────────────────────────
type ReportSection = NonNullable<ReportSchedule["sections"]>[number];

const SECTION_OPTIONS: { id: ReportSection; label: string }[] = [
  { id: "overview", label: _("Overview") },
  { id: "topDomains", label: _("Top domains") },
  { id: "topBlocked", label: _("Top blocked") },
  { id: "perGroup", label: _("Per group") },
  { id: "perDevice", label: _("Per device") },
  { id: "perUser", label: _("Per user") },
];

const DAYS: NonNullable<ReportSchedule["dayOfWeek"]>[] = [
  "Mon",
  "Tue",
  "Wed",
  "Thu",
  "Fri",
  "Sat",
  "Sun",
];

function nextScheduleName(schedules: ReportSchedule[]): string {
  const names = new Set(schedules.map((sc) => sc.name));
  let i = schedules.length + 1;
  while (names.has(`Report ${i}`)) {
    i += 1;
  }
  return `Report ${i}`;
}

const ScheduleCard = ({
  schedule,
  index,
  hostGroups,
  onChange,
  onRemove,
}: {
  schedule: ReportSchedule;
  index: number;
  hostGroups: HostGroup[];
  onChange: (patch: Partial<ReportSchedule>) => void;
  onRemove: () => void;
}) => {
  const sections = schedule.sections ?? [];
  const groups = schedule.groups ?? [];
  const frequency = schedule.frequency ?? "weekly";

  const toggleSection = (id: ReportSection, checked: boolean) =>
    onChange({ sections: checked ? [...sections, id] : sections.filter((x) => x !== id) });
  const toggleGroup = (name: string, checked: boolean) =>
    onChange({ groups: checked ? [...groups, name] : groups.filter((x) => x !== name) });

  return (
    <Card isCompact>
      <CardTitle>
        <Split>
          <SplitItem isFilled>{schedule.name || _("Unnamed schedule")}</SplitItem>
          <SplitItem>
            <Button variant="link" isDanger onClick={onRemove}>
              {_("Remove")}
            </Button>
          </SplitItem>
        </Split>
      </CardTitle>
      <CardBody>
        <FormGroup label={_("Name")} fieldId={`sched-${index}-name`}>
          <TextInput
            id={`sched-${index}-name`}
            value={schedule.name}
            onChange={(_e, v) => onChange({ name: v })}
          />
        </FormGroup>
        <FormGroup label={_("Frequency")} fieldId={`sched-${index}-freq`}>
          <FormSelect
            id={`sched-${index}-freq`}
            value={frequency}
            onChange={(_e, v) => onChange({ frequency: v as ReportSchedule["frequency"] })}
          >
            <FormSelectOption value="daily" label={_("Daily")} />
            <FormSelectOption value="weekly" label={_("Weekly")} />
            <FormSelectOption value="monthly" label={_("Monthly")} />
          </FormSelect>
        </FormGroup>
        {frequency === "weekly" && (
          <FormGroup label={_("Day of week")} fieldId={`sched-${index}-dow`}>
            <FormSelect
              id={`sched-${index}-dow`}
              value={schedule.dayOfWeek ?? "Mon"}
              onChange={(_e, v) => onChange({ dayOfWeek: v as ReportSchedule["dayOfWeek"] })}
            >
              {DAYS.map((d) => (
                <FormSelectOption key={d} value={d} label={d} />
              ))}
            </FormSelect>
          </FormGroup>
        )}
        <FormGroup
          label={_("Time")}
          fieldId={`sched-${index}-time`}
          labelHelp={hint(_("24-hour local time, HH:MM."))}
        >
          <TextInput
            id={`sched-${index}-time`}
            value={schedule.time ?? ""}
            placeholder="08:00"
            onChange={(_e, v) => onChange({ time: v })}
          />
        </FormGroup>
        <FormGroup
          label={_("Recipients")}
          fieldId={`sched-${index}-recipients`}
          labelHelp={hint(_("Empty = generate the PDF only, no delivery."))}
        >
          <ListEditor
            value={schedule.recipients ?? []}
            onChange={(v) => onChange({ recipients: v })}
            placeholder="user@example.org"
          />
        </FormGroup>
        <FormGroup label={_("Sections")} fieldId={`sched-${index}-sections`} role="group">
          <Split hasGutter style={{ flexWrap: "wrap" }}>
            {SECTION_OPTIONS.map((opt) => (
              <SplitItem key={opt.id}>
                <Checkbox
                  id={`sched-${index}-sec-${opt.id}`}
                  label={opt.label}
                  isChecked={sections.includes(opt.id)}
                  onChange={(_e, c) => toggleSection(opt.id, c)}
                />
              </SplitItem>
            ))}
          </Split>
        </FormGroup>
        <FormGroup
          label={_("Host groups")}
          fieldId={`sched-${index}-groups`}
          role="group"
          labelHelp={hint(_("Restrict group breakdowns to these host groups; none = all."))}
        >
          {hostGroups.length === 0 ? (
            <span className="pf-v6-u-color-200">
              {_("No host groups are defined — all devices are included.")}
            </span>
          ) : (
            <Split hasGutter style={{ flexWrap: "wrap" }}>
              {hostGroups.map((g) => (
                <SplitItem key={g.name}>
                  <Checkbox
                    id={`sched-${index}-group-${g.name}`}
                    label={g.name}
                    isChecked={groups.includes(g.name)}
                    onChange={(_e, c) => toggleGroup(g.name, c)}
                  />
                </SplitItem>
              ))}
            </Split>
          )}
        </FormGroup>
      </CardBody>
    </Card>
  );
};

interface ReportFile {
  name: string;
  size: number;
  mtime: number;
}

const fmtSize = (n: number): string => {
  if (n >= 1_048_576) {
    return `${(n / 1_048_576).toFixed(1)} MiB`;
  }
  if (n >= 1024) {
    return `${(n / 1024).toFixed(1)} KiB`;
  }
  return `${n} B`;
};

const GeneratedReports = () => {
  const [files, setFiles] = useState<ReportFile[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");

  const load = useCallback(() => {
    void cockpit
      .spawn(
        ["find", REPORTS_DIR, "-maxdepth", "1", "-type", "f", "-printf", String.raw`%f\t%s\t%T@\n`],
        { superuser: "try" },
      )
      .then((out: string) => {
        const parsed = out
          .split("\n")
          .map((line) => line.trim())
          .filter((line) => line !== "")
          .map((line) => {
            const [name, size, mtime] = line.split("\t");
            return { name: name ?? "", size: Number(size ?? "0"), mtime: Number(mtime ?? "0") };
          })
          .filter((f) => f.name !== "");
        setFiles(parsed.toSorted((a, b) => b.mtime - a.mtime));
      })
      .catch(() => setFiles([])) // reports dir absent → nothing generated yet
      .finally(() => setLoading(false));
  }, []);
  useEffect(() => {
    load();
  }, [load]);

  const download = (file: ReportFile) => {
    const path = `${REPORTS_DIR}/${file.name}`;
    const lower = file.name.toLowerCase();
    if (lower.endsWith(".pdf")) {
      void cockpit
        .file(path, { superuser: "require", binary: true })
        .read()
        .then((bytes) => {
          if (bytes) {
            // Copy into a fresh Uint8Array so the part is typed over ArrayBuffer
            // (BlobPart rejects ArrayBufferLike-backed views).
            downloadBlob(file.name, new Blob([new Uint8Array(bytes)], { type: "application/pdf" }));
          }
        })
        .catch((e: unknown) => setError(errMsg(e)));
    } else {
      const type = lower.endsWith(".csv") ? "text/csv" : "application/octet-stream";
      void cockpit
        .file(path, { superuser: "require" })
        .read()
        .then((text) => {
          if (text != null) {
            downloadBlob(file.name, new Blob([text], { type }));
          }
        })
        .catch((e: unknown) => setError(errMsg(e)));
    }
  };

  return (
    <Card isCompact>
      <CardTitle>
        <Split>
          <SplitItem isFilled>{_("Generated reports")}</SplitItem>
          <SplitItem>
            <Button variant="link" onClick={load}>
              {_("Refresh")}
            </Button>
          </SplitItem>
        </Split>
      </CardTitle>
      <CardBody>
        {error && (
          <Alert variant="danger" isInline title={_("Could not download the report")}>
            {error}
          </Alert>
        )}
        {loading ? (
          <Loading />
        ) : files.length === 0 ? (
          <EmptyState>
            <EmptyStateBody>{_("No reports have been generated yet.")}</EmptyStateBody>
          </EmptyState>
        ) : (
          <Table variant="compact" aria-label={_("Generated reports")}>
            <Thead>
              <Tr>
                <Th>{_("Name")}</Th>
                <Th>{_("Size")}</Th>
                <Th>{_("Date")}</Th>
                <Th screenReaderText={_("Actions")} />
              </Tr>
            </Thead>
            <Tbody>
              {files.map((f) => (
                <Tr key={f.name}>
                  <Td dataLabel={_("Name")}>{f.name}</Td>
                  <Td dataLabel={_("Size")}>{fmtSize(f.size)}</Td>
                  <Td dataLabel={_("Date")}>{new Date(f.mtime * 1000).toLocaleString()}</Td>
                  <Td dataLabel={_("Actions")} modifier="fitContent">
                    <Button variant="link" isInline onClick={() => download(f)}>
                      {_("Download")}
                    </Button>
                  </Td>
                </Tr>
              ))}
            </Tbody>
          </Table>
        )}
      </CardBody>
    </Card>
  );
};

const ScheduledReports = ({ s }: { s: Settings }) => {
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

  const schedules = s.valueOf<ReportSchedule[]>("reporting.schedules", []);
  const hostGroups = s.valueOf<HostGroup[]>("hostGroups", []);
  const setSchedules = (list: ReportSchedule[]) =>
    s.setLeaf("reporting.schedules", list as unknown as Json);

  const addSchedule = () =>
    setSchedules([
      ...schedules,
      {
        name: nextScheduleName(schedules),
        frequency: "weekly",
        dayOfWeek: "Mon",
        time: "08:00",
        recipients: [],
        sections: ["overview", "topDomains", "topBlocked"],
        groups: [],
      },
    ]);

  const pathHint = hint(_("Path to a root-owned file on the router — never the secret itself."));

  return (
    <Stack hasGutter className="ct-router-stack">
      <StackItem isFilled style={{ overflowY: "auto" }}>
        <Form isHorizontal onSubmit={(e) => e.preventDefault()}>
          <FormSection title={_("Reporting")} titleElement="h2">
            <FormGroup label={_("Retention (days)")} fieldId="rep-retention">
              <IntInput
                id="rep-retention"
                min={1}
                value={s.valueOf("reporting.retentionDays", 90)}
                onChange={(v) => s.setLeaf("reporting.retentionDays", v)}
              />
            </FormGroup>
          </FormSection>

          <FormSection title={_("Email delivery")} titleElement="h2">
            <FormGroup label={_("Cloudflare account id")} fieldId="rep-account">
              <TextInput
                id="rep-account"
                value={s.valueOf("reporting.email.accountId", "")}
                isDisabled={s.lockedOf("reporting.email.accountId")}
                onChange={(_e, v) => s.setLeaf("reporting.email.accountId", v)}
              />
            </FormGroup>
            <FormGroup label={_("API token file")} fieldId="rep-token" labelHelp={pathHint}>
              <TextInput
                id="rep-token"
                value={s.valueOf<string | null>("reporting.email.apiTokenFile", "") ?? ""}
                isDisabled={s.lockedOf("reporting.email.apiTokenFile")}
                onChange={(_e, v) => s.setLeaf("reporting.email.apiTokenFile", v)}
              />
            </FormGroup>
            <FormGroup label={_("From address")} fieldId="rep-from">
              <TextInput
                id="rep-from"
                value={s.valueOf("reporting.email.fromAddress", "")}
                isDisabled={s.lockedOf("reporting.email.fromAddress")}
                onChange={(_e, v) => s.setLeaf("reporting.email.fromAddress", v)}
              />
            </FormGroup>
          </FormSection>

          <FormSection title={_("Schedules")} titleElement="h2">
            {schedules.map((sc, index) => (
              <ScheduleCard
                key={index}
                schedule={sc}
                index={index}
                hostGroups={hostGroups}
                onChange={(patch) =>
                  setSchedules(schedules.map((x, i) => (i === index ? { ...x, ...patch } : x)))
                }
                onRemove={() => setSchedules(schedules.filter((_x, i) => i !== index))}
              />
            ))}
            <div>
              <Button variant="secondary" onClick={addSchedule}>
                {_("Add schedule")}
              </Button>
            </div>
          </FormSection>

          <SaveBar
            saving={s.saving}
            status={s.status}
            onSave={s.save}
            onSaveApply={s.saveAndApply}
          />
        </Form>

        <div style={{ marginBlockStart: "1.5rem" }}>
          <GeneratedReports />
        </div>
      </StackItem>
    </Stack>
  );
};

// ── Page ─────────────────────────────────────────────────────────────────────
export const Reports = () => {
  const [tab, setTab] = useState("overview");
  const s = useSettings();
  const hosts = s.valueOf<RouterHost[]>("hosts", []);
  const hostGroups = s.valueOf<HostGroup[]>("hostGroups", []);

  return (
    <TabbedPage
      subnav={
        <SubNav
          active={tab}
          onSelect={setTab}
          items={[
            { id: "overview", label: _("Overview") },
            { id: "log", label: _("Query log") },
            { id: "schedules", label: _("Scheduled reports") },
          ]}
        />
      }
    >
      {tab === "overview" ? (
        <Overview hosts={hosts} />
      ) : tab === "log" ? (
        <QueryLog hostGroups={hostGroups} />
      ) : (
        <ScheduledReports s={s} />
      )}
    </TabbedPage>
  );
};
