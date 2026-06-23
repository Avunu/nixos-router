import { useEffect, useState, useCallback, useRef } from "react";
import {
  Button,
  Alert,
  Stack,
  StackItem,
  Card,
  CardTitle,
  CardBody,
  Spinner,
  CodeBlock,
  CodeBlockCode,
  Split,
  SplitItem,
  Label,
  EmptyState,
  EmptyStateBody,
} from "@patternfly/react-core";
import { Table, Thead, Tbody, Tr, Th, Td } from "@patternfly/react-table";
import { flakeHostRef, writeApplied, loadState } from "./nix";

const _ = cockpit.gettext;

interface Generation {
  generation: number;
  date?: string;
  nixosVersion?: string;
  kernelVersion?: string;
  current?: boolean;
}

export const System = () => {
  const [log, setLog] = useState("");
  const [running, setRunning] = useState(""); // label of the in-flight operation
  const [done, setDone] = useState<{ ok: boolean; label: string } | null>(null);
  const [gens, setGens] = useState<Generation[]>([]);
  const [gensError, setGensError] = useState("");
  const [gensLoading, setGensLoading] = useState(true);
  const procRef = useRef<any>(null);
  const logRef = useRef<HTMLDivElement>(null);

  const loadGenerations = useCallback(() => {
    setGensLoading(true);
    setGensError("");
    cockpit
      .spawn(["nixos-rebuild", "list-generations", "--json"], { superuser: "try", err: "message" })
      .then((out: string) => {
        setGens(JSON.parse(out || "[]"));
        setGensLoading(false);
      })
      .catch((e: any) => {
        setGensError(e.message || String(e));
        setGensLoading(false);
      });
  }, []);

  useEffect(() => {
    loadGenerations();
  }, [loadGenerations]);

  // Keep the log scrolled to the newest output.
  useEffect(() => {
    if (logRef.current) logRef.current.scrollTop = logRef.current.scrollHeight;
  }, [log]);

  const run = useCallback(
    (label: string, argv: string[], onSuccess?: () => void) => {
      if (running) return;
      setRunning(label);
      setLog("");
      setDone(null);
      const proc = cockpit.spawn(argv, { superuser: "require", err: "out" });
      procRef.current = proc;
      proc.stream((d: string) => setLog((prev) => prev + d));
      proc
        .then(() => {
          setDone({ ok: true, label });
          onSuccess?.();
        })
        .catch((e: any) => {
          setLog((prev) => prev + "\n" + (e.message || String(e)) + "\n");
          setDone({ ok: false, label });
        })
        .finally(() => {
          setRunning("");
          procRef.current = null;
        });
    },
    [running],
  );

  const cancel = () => {
    if (procRef.current) procRef.current.close("terminated");
  };

  // After a successful switch, snapshot the saved JSON as the applied baseline
  // so the global changes tray clears, and refresh the generation list.
  const onApplied = () => {
    loadState()
      .then((st) => writeApplied(st.desired))
      .catch(() => {})
      .finally(() => {
        window.dispatchEvent(new Event("router:changed"));
        loadGenerations();
      });
  };

  const apply = () =>
    run(_("Apply configuration"), ["nixos-rebuild", "switch", "--flake", flakeHostRef(), "--impure"], onApplied);
  const check = () =>
    run(_("Check flake"), ["nixos-rebuild", "dry-build", "--flake", flakeHostRef(), "--impure"]);
  const update = () => run(_("Update system"), ["system-upgrade"], onApplied);
  const rollback = () =>
    run(_("Roll back"), ["nixos-rebuild", "switch", "--rollback"], () => loadGenerations());

  const busy = !!running;

  return (
    <Stack hasGutter className="ct-router-stack">
      <StackItem isFilled style={{ overflowY: "auto" }}>
        <Card isCompact style={{ marginBlockEnd: "1rem" }}>
          <CardTitle>{_("Configuration")}</CardTitle>
          <CardBody>
            <Split hasGutter>
              <SplitItem>
                <Button variant="primary" onClick={apply} isDisabled={busy}>
                  {_("Apply configuration")}
                </Button>
              </SplitItem>
              <SplitItem>
                <Button variant="secondary" onClick={check} isDisabled={busy}>
                  {_("Check flake")}
                </Button>
              </SplitItem>
              <SplitItem>
                <Button variant="secondary" onClick={update} isDisabled={busy}>
                  {_("Update system")}
                </Button>
              </SplitItem>
              <SplitItem isFilled />
              {busy && (
                <SplitItem>
                  <Button variant="link" isDanger onClick={cancel}>
                    {_("Cancel")}
                  </Button>
                </SplitItem>
              )}
            </Split>
          </CardBody>
        </Card>

        {(running || log || done) && (
          <Card isCompact style={{ marginBlockEnd: "1rem" }}>
            <CardTitle>
              {running ? (
                <Split hasGutter>
                  <SplitItem>
                    <Spinner size="md" />
                  </SplitItem>
                  <SplitItem>{running}…</SplitItem>
                </Split>
              ) : done ? (
                <Label color={done.ok ? "green" : "red"}>
                  {done.label}: {done.ok ? _("succeeded") : _("failed")}
                </Label>
              ) : null}
            </CardTitle>
            <CardBody>
              <div ref={logRef} style={{ maxBlockSize: "24rem", overflow: "auto" }}>
                <CodeBlock>
                  <CodeBlockCode>{log || _("(no output yet)")}</CodeBlockCode>
                </CodeBlock>
              </div>
            </CardBody>
          </Card>
        )}

        <Card isCompact>
          <CardTitle>
            <Split>
              <SplitItem isFilled>{_("Generations")}</SplitItem>
              <SplitItem>
                <Button
                  variant="secondary"
                  onClick={rollback}
                  isDisabled={busy || gens.length < 2}
                >
                  {_("Roll back to previous")}
                </Button>
              </SplitItem>
            </Split>
          </CardTitle>
          <CardBody>
            {gensLoading ? (
              <Spinner />
            ) : gensError ? (
              <Alert variant="danger" isInline title={_("Could not list generations")}>{gensError}</Alert>
            ) : gens.length === 0 ? (
              <EmptyState>
                <EmptyStateBody>{_("No generations found.")}</EmptyStateBody>
              </EmptyState>
            ) : (
              <Table variant="compact" aria-label={_("Generations")}>
                <Thead>
                  <Tr>
                    <Th>{_("Generation")}</Th>
                    <Th>{_("Date")}</Th>
                    <Th>{_("NixOS version")}</Th>
                    <Th>{_("Kernel")}</Th>
                    <Th>{_("Current")}</Th>
                  </Tr>
                </Thead>
                <Tbody>
                  {gens
                    .slice()
                    .sort((a, b) => b.generation - a.generation)
                    .map((g) => (
                      <Tr key={g.generation}>
                        <Td>{g.generation}</Td>
                        <Td>{g.date || "—"}</Td>
                        <Td>{g.nixosVersion || "—"}</Td>
                        <Td>{g.kernelVersion || "—"}</Td>
                        <Td>{g.current ? <Label color="green" isCompact>{_("current")}</Label> : ""}</Td>
                      </Tr>
                    ))}
                </Tbody>
              </Table>
            )}
          </CardBody>
        </Card>
      </StackItem>
    </Stack>
  );
};
