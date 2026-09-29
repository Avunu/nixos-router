import { useEffect, useState, useCallback } from "react";
import {
  Button,
  Alert,
  Stack,
  StackItem,
  Card,
  CardTitle,
  CardBody,
  Spinner,
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
  Content,
} from "@patternfly/react-core";
import { Table, Thead, Tbody, Tr, Th, Td } from "@patternfly/react-table";
import { errMsg } from "./nix";
import {
  useSettings,
  usePageSettings,
  useTabRoute,
  SettingsProvider,
  Loading,
  ListEditor,
  hint,
  SubNav,
  TabbedPage,
} from "./settings";
import { SaveActions } from "./save-actions";
import { ChangesPanel, SystemStatus, useAdmin } from "./changes";
import {
  busyLabel,
  getRebuildJob,
  startRebuild,
  subscribeRebuildJob,
  useRebuildJob,
} from "./rebuild-job";
import type { RebuildOp } from "./rebuild-status";

const _ = cockpit.gettext;

interface Generation {
  generation: number;
  date?: string;
  nixosVersion?: string;
  kernelVersion?: string;
  current?: boolean;
}

// Rebuilds run as router-rebuild.service (see rebuild-job.ts), so they carry
// on when this page is closed and show in the changes panel above wherever
// they were started. Their output is in the journal, not here.
const SystemOps = () => {
  const job = useRebuildJob();
  const admin = useAdmin();
  const [error, setError] = useState("");
  const [gens, setGens] = useState<Generation[]>([]);
  const [gensError, setGensError] = useState("");
  const [gensLoading, setGensLoading] = useState(true);

  const fetchGenerations = useCallback(() => {
    cockpit
      .spawn(["nixos-rebuild", "list-generations", "--json"], { superuser: "try", err: "message" })
      .then((out: string) => {
        setGens(JSON.parse(out || "[]") as Generation[]);
        setGensError("");
        setGensLoading(false);
      })
      .catch((e: unknown) => {
        setGensError(errMsg(e));
        setGensLoading(false);
      });
  }, []);

  // Again whenever a rebuild starts or ends: a switch or rollback adds or
  // moves the current generation.
  useEffect(() => {
    fetchGenerations();
    let { kind } = getRebuildJob();
    return subscribeRebuildJob(() => {
      const { kind: next } = getRebuildJob();
      if (next !== kind) {
        kind = next;
        fetchGenerations();
      }
    });
  }, [fetchGenerations]);

  const run = (op: RebuildOp) => {
    setError("");
    startRebuild(op).catch((e: unknown) => setError(errMsg(e)));
  };
  const busy = busyLabel(job);

  return (
    <Stack hasGutter className="ct-router-stack">
      <StackItem isFilled style={{ overflowY: "auto" }}>
        <Stack hasGutter>
          <StackItem>
            <ChangesPanel />
          </StackItem>

          <StackItem>
            <Card isCompact>
              <CardTitle>{_("Configuration")}</CardTitle>
              <CardBody>
                {error && (
                  <Alert
                    variant="danger"
                    isInline
                    title={_("Could not start the rebuild")}
                    style={{ marginBlockEnd: "1rem", whiteSpace: "pre-line" }}
                  >
                    {error}
                  </Alert>
                )}
                {admin ? (
                  <Split hasGutter>
                    <SplitItem>
                      <Button
                        variant="secondary"
                        onClick={() => run("apply")}
                        isDisabled={Boolean(busy)}
                      >
                        {_("Apply configuration")}
                      </Button>
                    </SplitItem>
                    <SplitItem>
                      <Button
                        variant="secondary"
                        onClick={() => run("check")}
                        isDisabled={Boolean(busy)}
                      >
                        {_("Check configuration")}
                      </Button>
                    </SplitItem>
                    <SplitItem>
                      <Button
                        variant="secondary"
                        onClick={() => run("update")}
                        isDisabled={Boolean(busy)}
                      >
                        {_("Update system")}
                      </Button>
                    </SplitItem>
                    {busy && (
                      <SplitItem isFilled style={{ alignSelf: "center" }}>
                        <Content component="small">{busy}</Content>
                      </SplitItem>
                    )}
                  </Split>
                ) : (
                  <Content component="p">
                    {_("Administrative access is needed to rebuild the router.")}
                  </Content>
                )}
              </CardBody>
            </Card>
          </StackItem>

          <StackItem>
            <Card isCompact>
              <CardTitle>
                <Split>
                  <SplitItem isFilled>{_("Generations")}</SplitItem>
                  {admin && (
                    <SplitItem>
                      <Button
                        variant="secondary"
                        onClick={() => run("rollback")}
                        isDisabled={Boolean(busy) || gens.length < 2}
                      >
                        {_("Roll back to previous")}
                      </Button>
                    </SplitItem>
                  )}
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
                  "Only sets the password when the account is first created, and is readable by every local user. After the first login, change the password under Accounts (or with `passwd`) and clear this field.",
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
        </Form>
      </StackItem>
    </Stack>
  );
};

const TABS = ["operations", "settings"];

// Preloaded (manifest.json), so this page's sidebar entry carries the whole
// router's state from login on; see SystemStatus. Its own unsaved edits (the
// Settings tab) are part of that status rather than a status of their own.
export const System = () => {
  const s = usePageSettings({ publishStatus: false });
  const [tab, setTab] = useTabRoute(TABS);
  return (
    <SettingsProvider value={s}>
      <SystemStatus dirty={s.dirty} />
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
        footer={s.ready && (tab === "settings" || s.dirty) ? <SaveActions s={s} /> : null}
      >
        {tab === "operations" ? <SystemOps /> : <SystemSettings />}
      </TabbedPage>
    </SettingsProvider>
  );
};
