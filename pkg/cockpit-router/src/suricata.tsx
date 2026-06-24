// IPS page — a Synology-Threat-Prevention-style surface over Suricata.
//
// Five sub-tabs:
//   • Overview   — service status, 7-day severity chart, top offending sources
//   • Events     — live alert/drop stream (journald) with filters + drill-down
//   • Policies   — category + per-signature actions and per-host suppressions
//   • Statistics — top-N rankings over 7d / 30d / All
//   • Settings   — enable, IDS/IPS mode, extra local rules
//
// Events/Overview/Statistics read security events from the systemd journal
// (see suricata-events.ts). Policies/Settings edit router.suricata.* through the
// shared settings store (nix.ts), applied on the next rebuild via the changes tray.
import { useEffect, useState, useCallback, useMemo } from "react";
import { loadState, writeDesired, getPath, setPath, errMsg } from "./nix";
import type { Json } from "./nix";
import { resolveNames } from "./hosts";
import suricataCategories from "./suricata-categories.json";
import {
  followEvents,
  fetchEvents,
  sinceDays,
  sevColor,
  sevLabel,
  wasBlocked,
} from "./suricata-events";
import type { Ev } from "./suricata-events";
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
  Split,
  SplitItem,
  Form,
  FormGroup,
  FormSection,
  FormSelect,
  FormSelectOption,
  Switch,
  TextInput,
  TextArea,
  Card,
  CardBody,
  CardTitle,
  Gallery,
  DescriptionList,
  DescriptionListGroup,
  DescriptionListTerm,
  DescriptionListDescription,
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
import { useSettings, Loading, SubNav, SaveBar, hint, TabbedPage } from "./settings";

const _ = cockpit.gettext;

// ── shared types & helpers ──────────────────────────────────────────────────
interface Policy {
  sid: number;
  action?: "alert" | "drop" | "disable";
  comment?: string;
}
interface Suppression {
  sid: number;
  ip: string;
  track?: "by_src" | "by_dst" | "by_either";
  comment?: string;
}

const fmtTime = (iso: string) => {
  const d = new Date(iso);
  return Number.isNaN(d.getTime()) ? iso : d.toLocaleString();
};

// Count occurrences of a key across events; return the top `n`, descending.
function topN(items: Ev[], key: (e: Ev) => string | undefined, n: number): [string, number][] {
  const m = new Map<string, number>();
  for (const it of items) {
    const k = key(it);
    if (!k) {
      continue;
    }
    m.set(k, (m.get(k) ?? 0) + 1);
  }
  return [...m.entries()].toSorted((a, b) => b[1] - a[1]).slice(0, n);
}

// Horizontal ranking-bar list (used by Overview + Statistics). Pure CSS bars to
// avoid pulling in a charting dependency.
const RankCard = ({ title, rows }: { title: string; rows: [string, number][] }) => {
  const max = Math.max(0, ...rows.map((r) => r[1])) || 1;
  return (
    <Card isCompact>
      <CardTitle>{title}</CardTitle>
      <CardBody>
        {rows.length === 0 ? (
          <div className="pf-v6-u-color-200">{_("No data in range.")}</div>
        ) : (
          rows.map(([k, count]) => (
            <div key={k} style={{ marginBlockEnd: "0.5rem" }}>
              <Split>
                <SplitItem
                  isFilled
                  style={{
                    overflow: "hidden",
                    textOverflow: "ellipsis",
                    whiteSpace: "nowrap",
                    fontSize: "0.85rem",
                  }}
                >
                  {k}
                </SplitItem>
                <SplitItem style={{ paddingInlineStart: "0.5rem", fontWeight: 600 }}>
                  {count}
                </SplitItem>
              </Split>
              <div
                style={{
                  height: "4px",
                  borderRadius: "2px",
                  background: "#0066cc",
                  inlineSize: `${Math.max(2, (count / max) * 100)}%`,
                }}
              />
            </div>
          ))
        )}
      </CardBody>
    </Card>
  );
};

// ── Overview tab ────────────────────────────────────────────────────────────
interface DayBucket {
  label: string;
  key: string;
  high: number;
  med: number;
  low: number;
}

const dayKey = (d: Date) => `${d.getFullYear()}-${d.getMonth() + 1}-${d.getDate()}`;

const SeverityChart = ({ events }: { events: Ev[] }) => {
  const buckets = useMemo<DayBucket[]>(() => {
    const now = new Date();
    const list: DayBucket[] = [];
    const byKey = new Map<string, DayBucket>();
    for (let i = 6; i >= 0; i--) {
      const d = new Date(now.getFullYear(), now.getMonth(), now.getDate() - i);
      const b: DayBucket = {
        key: dayKey(d),
        label: `${d.getMonth() + 1}/${d.getDate()}`,
        high: 0,
        med: 0,
        low: 0,
      };
      list.push(b);
      byKey.set(b.key, b);
    }
    for (const e of events) {
      const b = byKey.get(dayKey(new Date(e.timestamp)));
      if (!b) {
        continue;
      }
      const s = e.alert?.severity ?? 3;
      if (s === 1) {
        b.high += 1;
      } else if (s === 2) {
        b.med += 1;
      } else {
        b.low += 1;
      }
    }
    return list;
  }, [events]);

  const max = Math.max(0, ...buckets.map((b) => b.high + b.med + b.low)) || 1;

  return (
    <Card isCompact>
      <CardTitle>{_("Malicious events — last 7 days")}</CardTitle>
      <CardBody>
        <div style={{ display: "flex", alignItems: "flex-end", gap: "0.75rem", height: "160px" }}>
          {buckets.map((b) => {
            const total = b.high + b.med + b.low;
            const h = (n: number) => `${(n / max) * 140}px`;
            return (
              <div
                key={b.key}
                style={{ flex: "1 1 0", textAlign: "center", minInlineSize: 0 }}
                title={`${b.label}: ${total} (${b.high} high, ${b.med} med, ${b.low} low)`}
              >
                <div
                  style={{
                    display: "flex",
                    flexDirection: "column",
                    justifyContent: "flex-end",
                    height: "140px",
                  }}
                >
                  <div style={{ background: "#c9190b", blockSize: h(b.high) }} />
                  <div style={{ background: "#ef9234", blockSize: h(b.med) }} />
                  <div style={{ background: "#8a8d90", blockSize: h(b.low) }} />
                </div>
                <div style={{ fontSize: "0.75rem", marginBlockStart: "0.25rem" }}>{b.label}</div>
                <div style={{ fontSize: "0.75rem", fontWeight: 600 }}>{total}</div>
              </div>
            );
          })}
        </div>
        <div
          style={{ display: "flex", gap: "1rem", marginBlockStart: "0.5rem", fontSize: "0.8rem" }}
        >
          <span>
            <Label color="red" isCompact>
              {_("High")}
            </Label>
          </span>
          <span>
            <Label color="orange" isCompact>
              {_("Medium")}
            </Label>
          </span>
          <span>
            <Label color="grey" isCompact>
              {_("Low")}
            </Label>
          </span>
        </div>
      </CardBody>
    </Card>
  );
};

const statusColor = (s: string): "green" | "orange" | "red" | "grey" =>
  s === "active" ? "green" : s === "activating" ? "orange" : s === "inactive" ? "grey" : "red";

const SuricataOverview = () => {
  const [events, setEvents] = useState<Ev[]>([]);
  const [names, setNames] = useState<Record<string, string>>({});
  const [status, setStatus] = useState("");
  const [enabled, setEnabled] = useState(false);
  const [mode, setMode] = useState("ids");
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");

  const load = useCallback(() => {
    setError("");
    cockpit
      .spawn(["sh", "-c", "systemctl is-active suricata.service 2>/dev/null || true"], {
        superuser: "try",
        err: "message",
      })
      .then((o: string) => setStatus(o.trim()))
      .catch(() => setStatus("unknown"));
    void loadState().then((st) => {
      setEnabled(Boolean(getPath(st.effective, "suricata.enable")));
      setMode(String(getPath(st.effective, "suricata.mode") ?? "ids"));
    });
    fetchEvents({ since: sinceDays(7) })
      .then((r) => {
        setEvents(r.events);
        setLoading(false);
        const ips = [...new Set(r.events.map((e) => e.src_ip).filter(Boolean))] as string[];
        void resolveNames(ips.slice(0, 50)).then((m) => setNames((prev) => ({ ...prev, ...m })));
      })
      .catch((e: unknown) => {
        setError(errMsg(e));
        setLoading(false);
      });
  }, []);

  useEffect(() => {
    load();
  }, [load]);

  const sevCounts = useMemo(() => {
    let high = 0;
    let med = 0;
    let low = 0;
    for (const e of events) {
      const s = e.alert?.severity ?? 3;
      if (s === 1) {
        high += 1;
      } else if (s === 2) {
        med += 1;
      } else {
        low += 1;
      }
    }
    return { high, med, low };
  }, [events]);

  // Top offending sources, weighting high-severity events more heavily.
  const topSources = useMemo(() => {
    const m = new Map<string, number>();
    for (const e of events) {
      if (!e.src_ip) {
        continue;
      }
      const w = e.alert?.severity === 1 ? 3 : e.alert?.severity === 2 ? 2 : 1;
      m.set(e.src_ip, (m.get(e.src_ip) ?? 0) + w);
    }
    return [...m.entries()].toSorted((a, b) => b[1] - a[1]).slice(0, 10);
  }, [events]);

  if (loading) {
    return <Loading />;
  }

  return (
    <Stack hasGutter className="ct-router-stack">
      <StackItem isFilled style={{ overflowY: "auto" }}>
        {error && (
          <Alert variant="danger" title={_("Could not read Suricata events")} isInline>
            {error}
          </Alert>
        )}
        <Gallery hasGutter minWidths={{ default: "320px" }}>
          <Card isCompact>
            <CardTitle>{_("Status")}</CardTitle>
            <CardBody>
              <DescriptionList isHorizontal isCompact>
                <DescriptionListGroup>
                  <DescriptionListTerm>{_("Service")}</DescriptionListTerm>
                  <DescriptionListDescription>
                    <Label color={statusColor(status)} isCompact>
                      {status || _("unknown")}
                    </Label>
                  </DescriptionListDescription>
                </DescriptionListGroup>
                <DescriptionListGroup>
                  <DescriptionListTerm>{_("Protection")}</DescriptionListTerm>
                  <DescriptionListDescription>
                    {enabled ? (
                      <Label color={mode === "ips" ? "green" : "blue"} isCompact>
                        {mode === "ips" ? _("IPS — dropping") : _("IDS — alert only")}
                      </Label>
                    ) : (
                      <Label color="grey" isCompact>
                        {_("disabled")}
                      </Label>
                    )}
                  </DescriptionListDescription>
                </DescriptionListGroup>
                <DescriptionListGroup>
                  <DescriptionListTerm>{_("Events (7d)")}</DescriptionListTerm>
                  <DescriptionListDescription>{events.length}</DescriptionListDescription>
                </DescriptionListGroup>
                <DescriptionListGroup>
                  <DescriptionListTerm>{_("By severity")}</DescriptionListTerm>
                  <DescriptionListDescription>
                    <Label color="red" isCompact>
                      {cockpit.format(_("$0 high"), sevCounts.high)}
                    </Label>{" "}
                    <Label color="orange" isCompact>
                      {cockpit.format(_("$0 med"), sevCounts.med)}
                    </Label>{" "}
                    <Label color="grey" isCompact>
                      {cockpit.format(_("$0 low"), sevCounts.low)}
                    </Label>
                  </DescriptionListDescription>
                </DescriptionListGroup>
              </DescriptionList>
            </CardBody>
          </Card>

          <SeverityChart events={events} />

          <RankCard
            title={_("Top offending sources (7d)")}
            rows={topSources.map(([ip, score]): [string, number] => [
              names[ip] ? `${ip} (${names[ip]})` : ip,
              score,
            ])}
          />
        </Gallery>
      </StackItem>
    </Stack>
  );
};

// ── Events tab ──────────────────────────────────────────────────────────────
const PRELOAD = 500;
const MAX_ROWS = 2000;

// Append one item to an array setting on disk (load → append → validate → write).
// Used by "Add policy" so it works without sharing state across tabs.
function appendSetting(path: string, item: Json): Promise<void> {
  return loadState().then((st) => {
    const arr = (getPath(st.desired, path) as Json[] | undefined) ?? [];
    return writeDesired(setPath(st.desired, path, [...arr, item])).then(() => {});
  });
}

const EventDetail = ({ event, onClose }: { event: Ev; onClose: () => void }) => {
  const sid = event.alert?.signature_id;
  const [action, setAction] = useState("disable");
  const [ip, setIp] = useState(event.src_ip ?? "");
  const [track, setTrack] = useState("by_src");
  const [comment, setComment] = useState("");
  const [saving, setSaving] = useState(false);
  const [done, setDone] = useState<{ ok: boolean; msg: string } | null>(null);

  const save = () => {
    if (sid === undefined) {
      return;
    }
    setSaving(true);
    setDone(null);
    const p =
      action === "suppress"
        ? appendSetting("suricata.suppressions", {
            sid,
            ip,
            track,
            ...(comment ? { comment } : {}),
          })
        : appendSetting("suricata.policies", { sid, action, ...(comment ? { comment } : {}) });
    p.then(() =>
      setDone({
        ok: true,
        msg: _("Added. Review under Policies, then apply from the changes tray."),
      }),
    )
      .catch((e: unknown) => setDone({ ok: false, msg: errMsg(e) }))
      .finally(() => setSaving(false));
  };

  return (
    <Card isCompact>
      <CardTitle>
        <Split hasGutter>
          <SplitItem isFilled>{event.alert?.signature || _("Event detail")}</SplitItem>
          <SplitItem>
            <Button variant="link" isInline onClick={onClose}>
              {_("Close")}
            </Button>
          </SplitItem>
        </Split>
      </CardTitle>
      <CardBody>
        <DescriptionList isHorizontal isCompact isFluid>
          <DescriptionListGroup>
            <DescriptionListTerm>{_("Time")}</DescriptionListTerm>
            <DescriptionListDescription>{fmtTime(event.timestamp)}</DescriptionListDescription>
          </DescriptionListGroup>
          <DescriptionListGroup>
            <DescriptionListTerm>{_("Signature")}</DescriptionListTerm>
            <DescriptionListDescription>
              {event.alert?.signature || "—"} {sid !== undefined ? `(SID ${sid})` : ""}
            </DescriptionListDescription>
          </DescriptionListGroup>
          <DescriptionListGroup>
            <DescriptionListTerm>{_("Category")}</DescriptionListTerm>
            <DescriptionListDescription>{event.alert?.category || "—"}</DescriptionListDescription>
          </DescriptionListGroup>
          <DescriptionListGroup>
            <DescriptionListTerm>{_("Severity / action")}</DescriptionListTerm>
            <DescriptionListDescription>
              {`${sevLabel(event.alert?.severity)} · ${
                wasBlocked(event) ? _("blocked") : _("alerted")
              }`}
            </DescriptionListDescription>
          </DescriptionListGroup>
          <DescriptionListGroup>
            <DescriptionListTerm>{_("Source → Destination")}</DescriptionListTerm>
            <DescriptionListDescription>
              {`${event.src_ip ?? ""}${event.src_port ? `:${event.src_port}` : ""} → ${
                event.dest_ip ?? ""
              }${event.dest_port ? `:${event.dest_port}` : ""} (${event.proto || "—"}${
                event.app_proto ? `/${event.app_proto}` : ""
              })`}
            </DescriptionListDescription>
          </DescriptionListGroup>
        </DescriptionList>

        <FormSection title={_("Add self-defined policy")} titleElement="h3">
          {sid === undefined ? (
            <div className="pf-v6-u-color-200">
              {_("This event has no signature ID, so no policy can be derived from it.")}
            </div>
          ) : (
            <Form onSubmit={(e) => e.preventDefault()}>
              <FormGroup label={_("Action")} fieldId="evAction">
                <FormSelect
                  id="evAction"
                  value={action}
                  onChange={(_e, v) => setAction(v)}
                  aria-label={_("Action")}
                >
                  <FormSelectOption value="disable" label={_("Disable signature")} />
                  <FormSelectOption value="drop" label={_("Drop (IPS mode)")} />
                  <FormSelectOption value="alert" label={_("Alert (default)")} />
                  <FormSelectOption value="suppress" label={_("Suppress for a host")} />
                </FormSelect>
              </FormGroup>
              {action === "suppress" && (
                <>
                  <FormGroup label={_("Host IP / subnet")} fieldId="evIp">
                    <TextInput
                      id="evIp"
                      value={ip}
                      onChange={(_e, v) => setIp(v)}
                      placeholder="10.0.0.5"
                      aria-label={_("Host IP")}
                    />
                  </FormGroup>
                  <FormGroup label={_("Track by")} fieldId="evTrack">
                    <FormSelect
                      id="evTrack"
                      value={track}
                      onChange={(_e, v) => setTrack(v)}
                      aria-label={_("Track by")}
                    >
                      <FormSelectOption value="by_src" label={_("Source")} />
                      <FormSelectOption value="by_dst" label={_("Destination")} />
                      <FormSelectOption value="by_either" label={_("Either")} />
                    </FormSelect>
                  </FormGroup>
                </>
              )}
              <FormGroup label={_("Comment")} fieldId="evComment">
                <TextInput
                  id="evComment"
                  value={comment}
                  onChange={(_e, v) => setComment(v)}
                  aria-label={_("Comment")}
                />
              </FormGroup>
              {done && (
                <Alert
                  variant={done.ok ? "success" : "danger"}
                  isInline
                  title={done.ok ? _("Saved") : _("Could not save")}
                >
                  {done.msg}
                </Alert>
              )}
              <Button
                variant="primary"
                onClick={save}
                isLoading={saving}
                isDisabled={saving || (action === "suppress" && !ip.trim())}
              >
                {_("Save policy")}
              </Button>
            </Form>
          )}
        </FormSection>
      </CardBody>
    </Card>
  );
};

const SuricataEvents = () => {
  const [rows, setRows] = useState<Ev[]>([]);
  const [error, setError] = useState("");
  const [filter, setFilter] = useState("");
  const [sev, setSev] = useState("all");
  const [act, setAct] = useState("all");
  const [selected, setSelected] = useState<Ev | null>(null);
  const [isStuck, setIsStuck] = useState(false);

  useEffect(() => {
    const h = followEvents(
      PRELOAD,
      (evs) => setRows((prev) => [...evs.toReversed(), ...prev].slice(0, MAX_ROWS)),
      (m) => setError(m),
    );
    return () => h.stop();
  }, []);

  const shown = rows.filter((r) => {
    if (sev !== "all") {
      const s = r.alert?.severity ?? 3;
      if (sev === "3" ? s < 3 : String(s) !== sev) {
        return false;
      }
    }
    if (act === "blocked" && !wasBlocked(r)) {
      return false;
    }
    if (act === "alerted" && wasBlocked(r)) {
      return false;
    }
    if (filter) {
      const hay = [
        r.src_ip,
        r.dest_ip,
        r.proto,
        r.event_type,
        r.alert?.signature,
        r.alert?.category,
        String(r.alert?.signature_id ?? ""),
      ]
        .join(" ")
        .toLowerCase();
      if (!hay.includes(filter.toLowerCase())) {
        return false;
      }
    }
    return true;
  });

  return (
    <Stack hasGutter className="ct-router-stack">
      <StackItem>
        <Toolbar>
          <ToolbarContent>
            <ToolbarItem>
              <SearchInput
                placeholder={_("Filter by IP, signature, category, SID")}
                value={filter}
                onChange={(_e, v) => setFilter(v)}
                onClear={() => setFilter("")}
              />
            </ToolbarItem>
            <ToolbarItem>
              <FormSelect
                value={sev}
                onChange={(_e, v) => setSev(v)}
                aria-label={_("Severity")}
                style={{ minWidth: "10rem" }}
              >
                <FormSelectOption value="all" label={_("All severities")} />
                <FormSelectOption value="1" label={_("High")} />
                <FormSelectOption value="2" label={_("Medium")} />
                <FormSelectOption value="3" label={_("Low")} />
              </FormSelect>
            </ToolbarItem>
            <ToolbarItem>
              <FormSelect
                value={act}
                onChange={(_e, v) => setAct(v)}
                aria-label={_("Action")}
                style={{ minWidth: "9rem" }}
              >
                <FormSelectOption value="all" label={_("All actions")} />
                <FormSelectOption value="blocked" label={_("Blocked")} />
                <FormSelectOption value="alerted" label={_("Alerted")} />
              </FormSelect>
            </ToolbarItem>
          </ToolbarContent>
        </Toolbar>
      </StackItem>
      {error && (
        <StackItem>
          <Alert variant="danger" title={_("Could not read Suricata events")} isInline>
            {error}
          </Alert>
        </StackItem>
      )}
      {selected && (
        <StackItem>
          <EventDetail event={selected} onClose={() => setSelected(null)} />
        </StackItem>
      )}
      <StackItem isFilled className="ct-table-scroll">
        {shown.length === 0 ? (
          <EmptyState>
            <EmptyStateBody>{_("No matching alerts or drops.")}</EmptyStateBody>
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
                    <Th>{_("Severity")}</Th>
                    <Th>{_("Action")}</Th>
                    <Th>{_("Source")}</Th>
                    <Th>{_("Destination")}</Th>
                    <Th>{_("Proto")}</Th>
                    <Th>{_("Signature")}</Th>
                  </Tr>
                </Thead>
                <Tbody>
                  {shown.map((r, i) => (
                    <Tr
                      key={i}
                      onClick={() => setSelected(r)}
                      style={{
                        cursor: "pointer",
                        background: selected === r ? "#e7f1fa" : undefined,
                      }}
                    >
                      <Td>{fmtTime(r.timestamp)}</Td>
                      <Td>
                        <Label color={sevColor(r.alert?.severity)} isCompact>
                          {sevLabel(r.alert?.severity)}
                        </Label>
                      </Td>
                      <Td>
                        <Label color={wasBlocked(r) ? "red" : "blue"} isCompact>
                          {wasBlocked(r) ? _("blocked") : _("alert")}
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

// ── Statistics tab ──────────────────────────────────────────────────────────
const RANGES: { id: string; label: string; days: number | null }[] = [
  { id: "7", label: "7 days", days: 7 },
  { id: "30", label: "30 days", days: 30 },
  { id: "all", label: "All", days: null },
];

const SuricataStatistics = () => {
  const [range, setRange] = useState("7");
  const [events, setEvents] = useState<Ev[]>([]);
  const [capped, setCapped] = useState(false);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");

  useEffect(() => {
    setLoading(true);
    setError("");
    const days = RANGES.find((r) => r.id === range)?.days ?? null;
    fetchEvents(days ? { since: sinceDays(days) } : {})
      .then((r) => {
        setEvents(r.events);
        setCapped(r.capped);
        setLoading(false);
      })
      .catch((e: unknown) => {
        setError(errMsg(e));
        setLoading(false);
      });
  }, [range]);

  return (
    <Stack hasGutter className="ct-router-stack">
      <StackItem>
        <Toolbar>
          <ToolbarContent>
            <ToolbarItem>
              <FormSelect
                value={range}
                onChange={(_e, v) => setRange(v)}
                aria-label={_("Time range")}
                style={{ minWidth: "10rem" }}
              >
                {RANGES.map((r) => (
                  <FormSelectOption key={r.id} value={r.id} label={_(r.label)} />
                ))}
              </FormSelect>
            </ToolbarItem>
            <ToolbarItem>{cockpit.format(_("$0 events"), events.length)}</ToolbarItem>
          </ToolbarContent>
        </Toolbar>
      </StackItem>
      {capped && (
        <StackItem>
          <Alert variant="warning" isInline title={_("Showing the most recent events only")}>
            {_("The range exceeded the query cap; older events are not included in these totals.")}
          </Alert>
        </StackItem>
      )}
      {error && (
        <StackItem>
          <Alert variant="danger" title={_("Could not read Suricata events")} isInline>
            {error}
          </Alert>
        </StackItem>
      )}
      <StackItem isFilled style={{ overflowY: "auto" }}>
        {loading ? (
          <Spinner />
        ) : (
          <Gallery hasGutter minWidths={{ default: "320px" }}>
            <RankCard title={_("Top source IPs")} rows={topN(events, (e) => e.src_ip, 5)} />
            <RankCard title={_("Top destination IPs")} rows={topN(events, (e) => e.dest_ip, 5)} />
            <RankCard
              title={_("Top signatures")}
              rows={topN(events, (e) => e.alert?.signature, 5)}
            />
            <RankCard
              title={_("Top categories")}
              rows={topN(events, (e) => e.alert?.category, 5)}
            />
            <RankCard
              title={_("By severity")}
              rows={topN(events, (e) => sevLabel(e.alert?.severity), 4)}
            />
            <RankCard
              title={_("By protocol")}
              rows={topN(events, (e) => e.app_proto || e.proto, 5)}
            />
          </Gallery>
        )}
      </StackItem>
    </Stack>
  );
};

// ── Policies tab ────────────────────────────────────────────────────────────
const CategoryEditor = ({
  value,
  onChange,
  mode,
  isDisabled,
}: {
  value: Record<string, string>;
  onChange: (v: Record<string, string>) => void;
  mode: string;
  isDisabled: boolean;
}) => {
  const set = (id: string, val: string) => {
    // "enabled" is the default → drop the key rather than store it.
    onChange(
      val === "enabled"
        ? Object.fromEntries(Object.entries(value).filter(([k]) => k !== id))
        : { ...value, [id]: val },
    );
  };
  return (
    <Gallery hasGutter minWidths={{ default: "340px" }}>
      {suricataCategories.map((c) => {
        const cur = value[c.id] ?? "enabled";
        return (
          <Card key={c.id} isCompact>
            <CardBody>
              <Split hasGutter>
                <SplitItem isFilled>
                  <div style={{ fontWeight: 600 }}>{c.label}</div>
                  <div
                    className="pf-v6-u-color-200"
                    style={{ fontSize: "0.8rem", marginBlockStart: "0.125rem" }}
                  >
                    {c.description}
                  </div>
                </SplitItem>
                <SplitItem>
                  <FormSelect
                    value={cur}
                    isDisabled={isDisabled}
                    onChange={(_e, v) => set(c.id, v)}
                    aria-label={cockpit.format(_("Action for $0"), c.label)}
                    style={{ minWidth: "8.5rem" }}
                  >
                    <FormSelectOption value="enabled" label={_("Default")} />
                    <FormSelectOption value="disabled" label={_("Disable")} />
                    <FormSelectOption
                      value="drop"
                      label={mode === "ips" ? _("Drop") : _("Drop (needs IPS)")}
                    />
                  </FormSelect>
                </SplitItem>
              </Split>
            </CardBody>
          </Card>
        );
      })}
    </Gallery>
  );
};

const PolicyEditor = ({
  value,
  onChange,
  isDisabled,
}: {
  value: Policy[];
  onChange: (v: Policy[]) => void;
  isDisabled: boolean;
}) => {
  const [sid, setSid] = useState("");
  const set = (i: number, patch: Partial<Policy>) =>
    onChange(value.map((p, j) => (j === i ? { ...p, ...patch } : p)));
  const add = () => {
    const n = Number(sid);
    if (!Number.isInteger(n) || n <= 0 || value.some((p) => p.sid === n)) {
      return;
    }
    onChange([...value, { sid: n, action: "disable" }]);
    setSid("");
  };
  return (
    <>
      {value.length > 0 && (
        <Table variant="compact" aria-label={_("Signature policies")}>
          <Thead>
            <Tr>
              <Th>{_("SID")}</Th>
              <Th>{_("Action")}</Th>
              <Th>{_("Comment")}</Th>
              <Th screenReaderText={_("Actions")} />
            </Tr>
          </Thead>
          <Tbody>
            {value.map((p, i) => (
              <Tr key={p.sid}>
                <Td>{p.sid}</Td>
                <Td>
                  <FormSelect
                    value={p.action ?? "alert"}
                    isDisabled={isDisabled}
                    onChange={(_e, v) => set(i, { action: v as Policy["action"] })}
                    aria-label={_("Action")}
                    style={{ minWidth: "8rem" }}
                  >
                    <FormSelectOption value="alert" label={_("Alert")} />
                    <FormSelectOption value="drop" label={_("Drop")} />
                    <FormSelectOption value="disable" label={_("Disable")} />
                  </FormSelect>
                </Td>
                <Td>
                  <TextInput
                    value={p.comment ?? ""}
                    isDisabled={isDisabled}
                    onChange={(_e, v) => set(i, { comment: v })}
                    aria-label={_("Comment")}
                  />
                </Td>
                <Td>
                  <Button
                    variant="link"
                    isInline
                    isDanger
                    isDisabled={isDisabled}
                    onClick={() => onChange(value.filter((_p, j) => j !== i))}
                  >
                    {_("Remove")}
                  </Button>
                </Td>
              </Tr>
            ))}
          </Tbody>
        </Table>
      )}
      {!isDisabled && (
        <Split hasGutter style={{ marginBlockStart: "0.5rem" }}>
          <SplitItem>
            <TextInput
              value={sid}
              type="number"
              aria-label={_("Signature ID")}
              placeholder={_("Signature ID")}
              onChange={(_e, v) => setSid(v)}
              onKeyDown={(e) => {
                if (e.key === "Enter") {
                  e.preventDefault();
                  add();
                }
              }}
            />
          </SplitItem>
          <SplitItem>
            <Button variant="secondary" onClick={add} isDisabled={!sid.trim()}>
              {_("Add signature")}
            </Button>
          </SplitItem>
        </Split>
      )}
    </>
  );
};

const SuppressionEditor = ({
  value,
  onChange,
  isDisabled,
}: {
  value: Suppression[];
  onChange: (v: Suppression[]) => void;
  isDisabled: boolean;
}) => {
  const [sid, setSid] = useState("");
  const [ip, setIp] = useState("");
  const set = (i: number, patch: Partial<Suppression>) =>
    onChange(value.map((p, j) => (j === i ? { ...p, ...patch } : p)));
  const add = () => {
    const n = Number(sid);
    if (!Number.isInteger(n) || n <= 0 || !ip.trim()) {
      return;
    }
    onChange([...value, { sid: n, ip: ip.trim(), track: "by_src" }]);
    setSid("");
    setIp("");
  };
  return (
    <>
      {value.length > 0 && (
        <Table variant="compact" aria-label={_("Suppressions")}>
          <Thead>
            <Tr>
              <Th>{_("SID")}</Th>
              <Th>{_("Host")}</Th>
              <Th>{_("Track")}</Th>
              <Th>{_("Comment")}</Th>
              <Th screenReaderText={_("Actions")} />
            </Tr>
          </Thead>
          <Tbody>
            {value.map((p, i) => (
              <Tr key={`${p.sid}-${p.ip}`}>
                <Td>{p.sid}</Td>
                <Td>{p.ip}</Td>
                <Td>
                  <FormSelect
                    value={p.track ?? "by_src"}
                    isDisabled={isDisabled}
                    onChange={(_e, v) => set(i, { track: v as Suppression["track"] })}
                    aria-label={_("Track")}
                    style={{ minWidth: "8rem" }}
                  >
                    <FormSelectOption value="by_src" label={_("Source")} />
                    <FormSelectOption value="by_dst" label={_("Destination")} />
                    <FormSelectOption value="by_either" label={_("Either")} />
                  </FormSelect>
                </Td>
                <Td>
                  <TextInput
                    value={p.comment ?? ""}
                    isDisabled={isDisabled}
                    onChange={(_e, v) => set(i, { comment: v })}
                    aria-label={_("Comment")}
                  />
                </Td>
                <Td>
                  <Button
                    variant="link"
                    isInline
                    isDanger
                    isDisabled={isDisabled}
                    onClick={() => onChange(value.filter((_p, j) => j !== i))}
                  >
                    {_("Remove")}
                  </Button>
                </Td>
              </Tr>
            ))}
          </Tbody>
        </Table>
      )}
      {!isDisabled && (
        <Split hasGutter style={{ marginBlockStart: "0.5rem" }}>
          <SplitItem>
            <TextInput
              value={sid}
              type="number"
              aria-label={_("Signature ID")}
              placeholder={_("Signature ID")}
              onChange={(_e, v) => setSid(v)}
            />
          </SplitItem>
          <SplitItem isFilled>
            <TextInput
              value={ip}
              aria-label={_("Host IP / subnet")}
              placeholder={_("Host IP / subnet")}
              onChange={(_e, v) => setIp(v)}
            />
          </SplitItem>
          <SplitItem>
            <Button variant="secondary" onClick={add} isDisabled={!sid.trim() || !ip.trim()}>
              {_("Add suppression")}
            </Button>
          </SplitItem>
        </Split>
      )}
    </>
  );
};

const SuricataPolicies = () => {
  const s = useSettings();
  const mode = s.valueOf("suricata.mode", "ids");
  const cats = s.valueOf<Record<string, string>>("suricata.categories", {});
  const policies = s.valueOf<Policy[]>("suricata.policies", []);
  const suppressions = s.valueOf<Suppression[]>("suricata.suppressions", []);

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
        <Form onSubmit={(e) => e.preventDefault()}>
          <FormSection title={_("Rule categories")} titleElement="h2">
            <div className="pf-v6-u-color-200" style={{ marginBlockEnd: "0.5rem" }}>
              {_(
                "Set an action per ET Open category. Drop only takes effect in IPS mode (Settings tab).",
              )}
            </div>
            <CategoryEditor
              value={cats}
              mode={mode}
              isDisabled={s.lockedOf("suricata.categories")}
              onChange={(v) => s.setLeaf("suricata.categories", v)}
            />
          </FormSection>

          <FormSection title={_("Signature policies")} titleElement="h2">
            <div className="pf-v6-u-color-200" style={{ marginBlockEnd: "0.5rem" }}>
              {_(
                "Per-signature overrides by SID — typically added from an event in the Events tab.",
              )}
            </div>
            <PolicyEditor
              value={policies}
              isDisabled={s.lockedOf("suricata.policies")}
              onChange={(v) => s.setLeaf("suricata.policies", v as unknown as Json)}
            />
          </FormSection>

          <FormSection title={_("Suppressions")} titleElement="h2">
            <div className="pf-v6-u-color-200" style={{ marginBlockEnd: "0.5rem" }}>
              {_("Stop a signature from firing for a specific host (threshold.config suppress).")}
            </div>
            <SuppressionEditor
              value={suppressions}
              isDisabled={s.lockedOf("suricata.suppressions")}
              onChange={(v) => s.setLeaf("suricata.suppressions", v as unknown as Json)}
            />
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

// ── Settings tab ────────────────────────────────────────────────────────────
const SuricataSettings = () => {
  const s = useSettings();

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
        <Form onSubmit={(e) => e.preventDefault()}>
          <FormGroup label={_("Enable Suricata IPS")} fieldId="ipsEnable">
            <Switch
              id="ipsEnable"
              isChecked={Boolean(s.valueOf("suricata.enable", false))}
              isDisabled={s.lockedOf("suricata.enable")}
              onChange={(_e, c) => s.setLeaf("suricata.enable", c)}
              aria-label={_("Enable Suricata IPS")}
            />
          </FormGroup>
          <FormGroup
            label={_("Drop high-risk packets automatically (IPS mode)")}
            fieldId="ipsMode"
            labelHelp={hint(
              _(
                "Off = IDS (alert only, never drop). On = IPS (honor the drop actions set per category/signature in the Policies tab).",
              ),
            )}
          >
            <Switch
              id="ipsMode"
              isChecked={s.valueOf<string>("suricata.mode", "ids") === "ips"}
              isDisabled={s.lockedOf("suricata.mode")}
              onChange={(_e, c) => s.setLeaf("suricata.mode", c ? "ips" : "ids")}
              aria-label={_("IPS mode")}
            />
          </FormGroup>
          <FormGroup
            label={_("Extra local rules")}
            fieldId="extraRules"
            labelHelp={hint(_("Custom Suricata rules, one per line"))}
          >
            <TextArea
              id="extraRules"
              value={s.valueOf("suricata.extraRules", "")}
              isDisabled={s.lockedOf("suricata.extraRules")}
              onChange={(_e, v) => s.setLeaf("suricata.extraRules", v)}
              rows={10}
              resizeOrientation="vertical"
              aria-label={_("Extra local rules")}
            />
          </FormGroup>
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

// ── page shell ──────────────────────────────────────────────────────────────
export const Suricata = () => {
  const [tab, setTab] = useState("overview");
  return (
    <TabbedPage
      subnav={
        <SubNav
          active={tab}
          onSelect={setTab}
          items={[
            { id: "overview", label: _("Overview") },
            { id: "events", label: _("Events") },
            { id: "policies", label: _("Policies") },
            { id: "statistics", label: _("Statistics") },
            { id: "settings", label: _("Settings") },
          ]}
        />
      }
    >
      {tab === "overview" && <SuricataOverview />}
      {tab === "events" && <SuricataEvents />}
      {tab === "policies" && <SuricataPolicies />}
      {tab === "statistics" && <SuricataStatistics />}
      {tab === "settings" && <SuricataSettings />}
    </TabbedPage>
  );
};
