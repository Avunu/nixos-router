// AdGuard Home dashboard — a Cockpit-native replica of the widgets the native
// AGH UI shows (which we hide, since it binds to localhost when Cockpit is on).
//
// Everything here is read-only live data from the AdGuard REST API on localhost:
//   • GET /control/stats   — summary counters, time-series arrays, top-N lists
//   • GET /control/clients — IP→name map so top-client rows read "name (ip)"
// Statistics/querylog are already enabled by modules/access-protection.nix, so
// no NixOS-side change is needed. Auto-refreshes every REFRESH_MS.
import { useEffect, useState, useCallback, useMemo } from "react";
import type { ReactNode } from "react";
import { errMsg } from "./nix";
import {
  Alert,
  Button,
  Card,
  CardBody,
  CardTitle,
  EmptyState,
  EmptyStateBody,
  Gallery,
  Stack,
  StackItem,
  Toolbar,
  ToolbarContent,
  ToolbarItem,
} from "@patternfly/react-core";
import { Loading } from "./settings";
import { RankCard, QueriesChart } from "./widgets";

const _ = cockpit.gettext;
const PORT = (window.cockpitRouterConfig && window.cockpitRouterConfig.adguardPort) || 3000;
const api = () => cockpit.http({ address: "127.0.0.1", port: PORT });
const REFRESH_MS = 10_000;

// AdGuard's /control/stats. The top_* lists are arrays of single-key objects
// ([{ "example.com": 5 }, …]); the *_queries/_filtering arrays are time series
// (one bucket per `time_units`, oldest→newest).
interface Stats {
  num_dns_queries?: number;
  num_blocked_filtering?: number;
  num_replaced_safebrowsing?: number;
  num_replaced_safesearch?: number;
  num_replaced_parental?: number;
  avg_processing_time?: number;
  time_units?: "hours" | "days";
  dns_queries?: number[];
  blocked_filtering?: number[];
  top_queried_domains?: Record<string, number>[];
  top_blocked_domains?: Record<string, number>[];
  top_clients?: Record<string, number>[];
  top_upstreams_responses?: Record<string, number>[];
}

interface ClientsResp {
  clients?: { name?: string; ids?: string[] }[];
  auto_clients?: { name?: string; ip?: string }[];
}

// Flatten AGH's [{ key: count }] lists into RankCard's [key, count][] (top 10).
const toRows = (list: Record<string, number>[] | undefined): [string, number][] =>
  (list ?? []).flatMap((o) => Object.entries(o)).slice(0, 10);

// Build an IP→friendly-name map from configured + auto-discovered clients.
const clientNameMap = (c: ClientsResp): Record<string, string> => {
  const m: Record<string, string> = {};
  for (const ac of c.auto_clients ?? []) {
    if (ac.ip && ac.name) {
      m[ac.ip] = ac.name;
    }
  }
  for (const cl of c.clients ?? []) {
    if (!cl.name) {
      continue;
    }
    for (const id of cl.ids ?? []) {
      m[id] = cl.name;
    }
  }
  return m;
};

const pct = (part?: number, whole?: number): string =>
  whole && part != null ? `${((part / whole) * 100).toFixed(1)}%` : "—";

const Stat = ({ label, value, sub }: { label: string; value: ReactNode; sub?: string }) => (
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

const SummaryCard = ({ stats }: { stats: Stats }) => {
  const q = stats.num_dns_queries;
  return (
    <Card isCompact>
      <CardTitle>{_("DNS statistics")}</CardTitle>
      <CardBody>
        <Gallery hasGutter minWidths={{ default: "150px" }}>
          <Stat label={_("Queries")} value={q ?? "—"} />
          <Stat
            label={_("Blocked by filters")}
            value={stats.num_blocked_filtering ?? "—"}
            sub={pct(stats.num_blocked_filtering, q)}
          />
          <Stat label={_("Malware / phishing")} value={stats.num_replaced_safebrowsing ?? "—"} />
          <Stat label={_("Adult sites")} value={stats.num_replaced_parental ?? "—"} />
          <Stat
            label={_("Avg. processing")}
            value={
              stats.avg_processing_time != null
                ? `${(stats.avg_processing_time * 1000).toFixed(1)} ms`
                : "—"
            }
          />
        </Gallery>
      </CardBody>
    </Card>
  );
};

export const AdGuardOverview = () => {
  const [stats, setStats] = useState<Stats>({});
  const [names, setNames] = useState<Record<string, string>>({});
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");

  const load = useCallback(() => {
    Promise.all([
      api().get("/control/stats"),
      api()
        .get("/control/clients")
        .catch(() => "{}"),
    ])
      .then(([st, cl]: [string, string]) => {
        setStats(JSON.parse(st) as Stats);
        setNames(clientNameMap(JSON.parse(cl) as ClientsResp));
        setError("");
        setLoading(false);
      })
      .catch((e: unknown) => {
        setError(errMsg(e));
        setLoading(false);
      });
  }, []);

  useEffect(() => {
    load();
    const id = setInterval(load, REFRESH_MS);
    return () => clearInterval(id);
  }, [load]);

  const clientRows = useMemo<[string, number][]>(
    () =>
      toRows(stats.top_clients).map(([ip, n]) => {
        const name = names[ip];
        return [name ? `${name} (${ip})` : ip, n];
      }),
    [stats.top_clients, names],
  );

  const upstreamRows = toRows(stats.top_upstreams_responses);

  if (loading) {
    return <Loading />;
  }

  const hasData = stats.num_dns_queries != null || (stats.dns_queries?.length ?? 0) > 0;

  return (
    <Stack hasGutter className="ct-router-stack">
      <StackItem>
        <Toolbar>
          <ToolbarContent>
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
      <StackItem isFilled style={{ overflowY: "auto" }}>
        {!hasData && !error ? (
          <EmptyState>
            <EmptyStateBody>{_("No statistics have been collected yet.")}</EmptyStateBody>
          </EmptyState>
        ) : (
          <Stack hasGutter>
            <StackItem>
              <SummaryCard stats={stats} />
            </StackItem>
            <StackItem>
              <QueriesChart
                title={_("Queries over time")}
                total={stats.dns_queries ?? []}
                blocked={stats.blocked_filtering ?? []}
                timeUnits={stats.time_units ?? "days"}
              />
            </StackItem>
            <StackItem>
              <Gallery hasGutter minWidths={{ default: "320px" }}>
                <RankCard
                  title={_("Top queried domains")}
                  rows={toRows(stats.top_queried_domains)}
                />
                <RankCard
                  title={_("Top blocked domains")}
                  rows={toRows(stats.top_blocked_domains)}
                />
                <RankCard title={_("Top clients")} rows={clientRows} />
                {upstreamRows.length > 0 && (
                  <RankCard title={_("Top upstreams")} rows={upstreamRows} />
                )}
              </Gallery>
            </StackItem>
          </Stack>
        )}
      </StackItem>
    </Stack>
  );
};
