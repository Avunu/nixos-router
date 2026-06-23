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
  Form,
  FormGroup,
  FormSection,
  FormSelect,
  FormSelectOption,
  TextInput,
} from "@patternfly/react-core";
import { Table, Thead, Tbody, Tr, Th, Td } from "@patternfly/react-table";
import { flakeHostRef, writeApplied, loadState, errMsg } from "./nix";
import { useSettings, SubNav, SaveBar, Loading, ListEditor, hint, TabbedPage } from "./settings";

const _ = cockpit.gettext;

interface Generation {
  generation: number;
  date?: string;
  nixosVersion?: string;
  kernelVersion?: string;
  current?: boolean;
}

const SystemOps = () => {
  const [log, setLog] = useState("");
  const [running, setRunning] = useState(""); // Label of the in-flight operation
  const [done, setDone] = useState<{ ok: boolean; label: string } | null>(null);
  const [gens, setGens] = useState<Generation[]>([]);
  const [gensError, setGensError] = useState("");
  const [gensLoading, setGensLoading] = useState(true);
  const procRef = useRef<CockpitProcess | null>(null);
  const logRef = useRef<HTMLDivElement>(null);

  const loadGenerations = useCallback(() => {
    setGensLoading(true);
    setGensError("");
    cockpit
      .spawn(["nixos-rebuild", "list-generations", "--json"], { superuser: "try", err: "message" })
      .then((out: string) => {
        setGens(JSON.parse(out || "[]") as Generation[]);
        setGensLoading(false);
      })
      .catch((e: unknown) => {
        setGensError(errMsg(e));
        setGensLoading(false);
      });
  }, []);

  useEffect(() => {
    loadGenerations();
  }, [loadGenerations]);

  // Keep the log scrolled to the newest output.
  useEffect(() => {
    if (logRef.current) {
      logRef.current.scrollTop = logRef.current.scrollHeight;
    }
  }, [log]);

  const run = useCallback(
    (label: string, argv: string[], onSuccess?: () => void) => {
      if (running) {
        return;
      }
      setRunning(label);
      setLog("");
      setDone(null);
      const proc = cockpit.spawn(argv, { superuser: "require", err: "out" });
      procRef.current = proc;
      void proc.stream((d: string) => setLog((prev) => prev + d));
      proc
        .then(() => {
          setDone({ ok: true, label });
          onSuccess?.();
        })
        .catch((e: unknown) => {
          setLog((prev) => `${prev}\n${errMsg(e)}\n`);
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
    if (procRef.current) {
      procRef.current.close("terminated");
    }
  };

  // After a successful switch, snapshot the saved JSON as the applied baseline
  // So the global changes tray clears, and refresh the generation list.
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
    run(
      _("Apply configuration"),
      ["nixos-rebuild", "switch", "--flake", flakeHostRef(), "--impure"],
      onApplied,
    );
  const check = () =>
    run(_("Check flake"), ["nixos-rebuild", "dry-build", "--flake", flakeHostRef(), "--impure"]);
  const update = () => run(_("Update system"), ["system-upgrade"], onApplied);
  const rollback = () =>
    run(_("Roll back"), ["nixos-rebuild", "switch", "--rollback"], () => loadGenerations());

  const busy = Boolean(running);

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
                <Button variant="secondary" onClick={rollback} isDisabled={busy || gens.length < 2}>
                  {_("Roll back to previous")}
                </Button>
              </SplitItem>
            </Split>
          </CardTitle>
          <CardBody>
            {gensLoading ? (
              <Spinner />
            ) : gensError ? (
              <Alert variant="danger" isInline title={_("Could not list generations")}>
                {gensError}
              </Alert>
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
                  {[...gens]
                    .toSorted((a, b) => b.generation - a.generation)
                    .map((g) => (
                      <Tr key={g.generation}>
                        <Td>{g.generation}</Td>
                        <Td>{g.date || "—"}</Td>
                        <Td>{g.nixosVersion || "—"}</Td>
                        <Td>{g.kernelVersion || "—"}</Td>
                        <Td>
                          {g.current ? (
                            <Label color="green" isCompact>
                              {_("current")}
                            </Label>
                          ) : (
                            ""
                          )}
                        </Td>
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

// ── Settings: system identity + admin user ──────────────────────────────────
const SystemSettings = () => {
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
        <Form isHorizontal onSubmit={(e) => e.preventDefault()}>
          <FormSection title={_("Identity")} titleElement="h2">
            <FormGroup
              label={_("Time zone")}
              fieldId="tz"
              labelHelp={hint(_("e.g. America/New_York, Europe/Berlin"))}
            >
              <TextInput
                id="tz"
                value={s.valueOf("timeZone", "")}
                isDisabled={s.lockedOf("timeZone")}
                onChange={(_e, v) => s.setLeaf("timeZone", v)}
              />
            </FormGroup>
            <FormGroup label={_("Host name")} fieldId="hn">
              <TextInput
                id="hn"
                value={s.valueOf("hostName", "")}
                isDisabled={s.lockedOf("hostName")}
                onChange={(_e, v) => s.setLeaf("hostName", v)}
              />
              <Alert
                variant="warning"
                isInline
                isPlain
                title={_(
                  "Changing the host name renames the flake configuration; the rebuild target will not match until the system is redeployed.",
                )}
              />
            </FormGroup>
          </FormSection>

          <FormSection title={_("Admin user")} titleElement="h2">
            <FormGroup label={_("User name")} fieldId="adminName">
              <TextInput
                id="adminName"
                value={s.valueOf("adminUser.name", "admin")}
                isDisabled={s.lockedOf("adminUser.name")}
                onChange={(_e, v) => s.setLeaf("adminUser.name", v)}
              />
            </FormGroup>
            <FormGroup label={_("SSH public keys")} fieldId="adminKeys">
              <ListEditor
                value={s.valueOf("adminUser.sshKeys", [])}
                isDisabled={s.lockedOf("adminUser.sshKeys")}
                onChange={(v) => s.setLeaf("adminUser.sshKeys", v)}
                placeholder={_("ssh-ed25519 AAAA…")}
              />
            </FormGroup>
            <FormGroup label={_("Initial password")} fieldId="adminPw">
              <TextInput
                id="adminPw"
                type="password"
                value={s.valueOf("adminUser.initialPassword", "") ?? ""}
                isDisabled={s.lockedOf("adminUser.initialPassword")}
                onChange={(_e, v) => s.setLeaf("adminUser.initialPassword", v)}
              />
              <Alert
                variant="warning"
                isInline
                isPlain
                title={_(
                  "Only sets the password when the account is first created. Change an existing password with `passwd` over SSH instead.",
                )}
              />
            </FormGroup>
          </FormSection>

          <FormSection title={_("Advanced / install-time")} titleElement="h2">
            <Alert
              variant="warning"
              isInline
              title={_(
                "These apply at install time. Changing them on a running router has no effect (or, for the disk, is dangerous).",
              )}
              style={{ marginBlockEnd: "1rem" }}
            />
            <FormGroup label={_("State version")} fieldId="sv">
              <TextInput
                id="sv"
                value={s.valueOf("stateVersion", "")}
                isDisabled={s.lockedOf("stateVersion")}
                onChange={(_e, v) => s.setLeaf("stateVersion", v)}
              />
            </FormGroup>
            <FormGroup label={_("Disk device")} fieldId="disk">
              <TextInput
                id="disk"
                value={s.valueOf("diskDevice", "")}
                isDisabled={s.lockedOf("diskDevice")}
                placeholder="/dev/sda"
                onChange={(_e, v) => s.setLeaf("diskDevice", v)}
              />
            </FormGroup>
            <FormGroup label={_("Boot mode")} fieldId="boot">
              <FormSelect
                id="boot"
                value={s.valueOf("bootMode", "uefi")}
                isDisabled={s.lockedOf("bootMode")}
                onChange={(_e, v) => s.setLeaf("bootMode", v)}
              >
                <FormSelectOption value="uefi" label="uefi" />
                <FormSelectOption value="legacy" label="legacy" />
              </FormSelect>
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

export const System = () => {
  const [tab, setTab] = useState("operations");
  return (
    <TabbedPage
      subnav={
        <SubNav
          active={tab}
          onSelect={setTab}
          items={[
            { id: "operations", label: _("Operations") },
            { id: "settings", label: _("Settings") },
          ]}
        />
      }
    >
      {tab === "operations" ? <SystemOps /> : <SystemSettings />}
    </TabbedPage>
  );
};
