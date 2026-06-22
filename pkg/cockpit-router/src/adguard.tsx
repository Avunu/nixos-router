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
} from "@patternfly/react-core";
import { Table, Thead, Tbody, Tr, Th, Td, OuterScrollContainer, InnerScrollContainer } from "@patternfly/react-table";

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

export const AdGuard = () => {
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
