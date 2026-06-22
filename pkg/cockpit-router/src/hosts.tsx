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
} from "@patternfly/react-core";
import { Table, Thead, Tbody, Tr, Th, Td } from "@patternfly/react-table";

const _ = cockpit.gettext;

interface Neigh {
  dst: string;
  lladdr?: string;
  dev: string;
  state?: string[];
}

export const Hosts = () => {
  const [rows, setRows] = useState<Neigh[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [filter, setFilter] = useState("");

  const load = useCallback(() => {
    setError("");
    cockpit
      .spawn(["ip", "-j", "neigh"], { err: "message" })
      .then((out: string) => {
        const parsed: Neigh[] = JSON.parse(out || "[]");
        // Only real, resolvable neighbours (have a MAC and a usable state).
        const hosts = parsed.filter(
          (n) => n.lladdr && !(n.state || []).includes("FAILED"),
        );
        hosts.sort((a, b) => a.dst.localeCompare(b.dst, undefined, { numeric: true }));
        setRows(hosts);
        setLoading(false);
      })
      .catch((e: any) => {
        setError(e.message || String(e));
        setLoading(false);
      });
  }, []);

  useEffect(() => {
    load();
    const timer = setInterval(load, 15000);
    return () => clearInterval(timer);
  }, [load]);

  const shown = rows.filter(
    (r) =>
      !filter ||
      [r.dst, r.lladdr, r.dev].join(" ").toLowerCase().includes(filter.toLowerCase()),
  );

  if (loading) return <Spinner />;

  return (
    <>
      <Toolbar>
        <ToolbarContent>
          <ToolbarItem>
            <SearchInput
              placeholder={_("Filter by IP, MAC, interface")}
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
      {error && <Alert variant="danger" title={error} isInline />}
      {shown.length === 0 ? (
        <EmptyState>
          <EmptyStateBody>{_("No connected hosts found.")}</EmptyStateBody>
        </EmptyState>
      ) : (
        <Table variant="compact" aria-label={_("Connected hosts")}>
          <Thead>
            <Tr>
              <Th>{_("IP address")}</Th>
              <Th>{_("MAC address")}</Th>
              <Th>{_("Interface")}</Th>
              <Th>{_("State")}</Th>
            </Tr>
          </Thead>
          <Tbody>
            {shown.map((r, i) => (
              <Tr key={i}>
                <Td>{r.dst}</Td>
                <Td>{r.lladdr || "—"}</Td>
                <Td>{r.dev}</Td>
                <Td>{(r.state || []).join(", ")}</Td>
              </Tr>
            ))}
          </Tbody>
        </Table>
      )}
    </>
  );
};
