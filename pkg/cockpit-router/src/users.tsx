// Users page — read-only view of the directory-synced users/groups (state files
// written by router-directory-sync) plus the directory provider settings form.
// Policy attribution mirrors the backend compiler via resolvePolicy.
import { useCallback, useEffect, useMemo, useState } from "react";
import type { ReactElement } from "react";
import {
  Alert,
  Button,
  EmptyState,
  EmptyStateActions,
  EmptyStateBody,
  EmptyStateFooter,
  Form,
  FormGroup,
  FormSection,
  FormSelect,
  FormSelectOption,
  Label,
  LabelGroup,
  NumberInput,
  SearchInput,
  Split,
  SplitItem,
  Stack,
  StackItem,
  TextInput,
  Toolbar,
  ToolbarContent,
  ToolbarItem,
} from "@patternfly/react-core";
import { ExpandableRowContent, Table, Tbody, Td, Th, Thead, Tr } from "@patternfly/react-table";
import { errMsg } from "./nix";
import { ListEditor, Loading, SaveBar, SubNav, TabbedPage, hint, useSettings } from "./settings";
import { loadDirectory, loadDirectoryStatus, syncNow } from "./directory";
import { resolvePolicy } from "./policy-resolver";
import type { NetworkCidrs } from "./policy-resolver";
import type {
  AccessPoliciesSection,
  DirectoryGroup,
  DirectoryState,
  DirectoryStatus,
  DirectoryUser,
  RouterHost,
} from "./types";

const _ = cockpit.gettext;

type Settings = ReturnType<typeof useSettings>;

const delay = (ms: number) =>
  new Promise<void>((resolve) => {
    setTimeout(resolve, ms);
  });

// LAN/guest CIDRs for the resolver's network tier, derived from the settings.
function networksOf(s: Settings): NetworkCidrs {
  const networks: NetworkCidrs = {
    lan: `${s.valueOf("lan.networkAddress", "")}/${s.valueOf("lan.prefixLength", 24)}`,
    wireguard: [],
  };
  if (s.valueOf("guest.enable", false)) {
    networks.guest = `${s.valueOf("guest.networkAddress", "192.168.20.0")}/${s.valueOf(
      "guest.prefixLength",
      24,
    )}`;
  }
  return networks;
}

// Devices from the registry that belong to a directory user (hosts.user holds
// the user's id or email).
function devicesOf(user: DirectoryUser, hosts: RouterHost[]): RouterHost[] {
  const keys = new Set([user.id.toLowerCase(), user.email.toLowerCase()].filter((k) => k !== ""));
  return hosts.filter((h) => Boolean(h.user) && keys.has((h.user ?? "").toLowerCase()));
}

// Bounded integer input used by the settings forms.
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

const NoDirectoryState = ({ onGoToSettings }: { onGoToSettings: () => void }) => (
  <EmptyState headingLevel="h2" titleText={_("No directory data")}>
    <EmptyStateBody>
      {_(
        "No identity provider is configured, or no device and no policy references a directory user yet. Directory users are looked up on demand — only names referenced under Hosts or by a policy's directory groups appear here.",
      )}
    </EmptyStateBody>
    <EmptyStateFooter>
      <EmptyStateActions>
        <Button variant="link" onClick={onGoToSettings}>
          {_("Go to Directory settings")}
        </Button>
      </EmptyStateActions>
    </EmptyStateFooter>
  </EmptyState>
);

// ── Users tab ────────────────────────────────────────────────────────────────
const UsersTab = ({
  s,
  directory,
  loading,
  onGoToSettings,
}: {
  s: Settings;
  directory: DirectoryState | null;
  loading: boolean;
  onGoToSettings: () => void;
}) => {
  const [query, setQuery] = useState("");
  const [expanded, setExpanded] = useState<Set<string>>(new Set());

  const hosts = s.valueOf<RouterHost[]>("hosts", []);
  const section = s.valueOf<AccessPoliciesSection>("accessPolicies", {});
  const networks = networksOf(s);

  const groupNames = useMemo(() => {
    const m = new Map<string, string>();
    for (const g of directory?.groups ?? []) {
      m.set(g.id.toLowerCase(), g.name);
    }
    return m;
  }, [directory]);
  const groupName = (gid: string) => groupNames.get(gid.toLowerCase()) ?? gid;

  if (loading || !s.ready) {
    return <Loading />;
  }
  if (!directory || directory.users.length === 0) {
    return <NoDirectoryState onGoToSettings={onGoToSettings} />;
  }

  const effectiveOf = (device: RouterHost): string =>
    resolvePolicy({ host: device }, section, networks, directory, hosts).policy ?? "—";

  // Row-level policy: the shared value when every device agrees, otherwise
  // "mixed"; users without devices resolve through the directory-group tier.
  const effectiveFor = (user: DirectoryUser, devices: RouterHost[]): string => {
    if (devices.length === 0) {
      return (
        resolvePolicy({ userId: user.email || user.id }, section, networks, directory, hosts)
          .policy ?? "—"
      );
    }
    const names = new Set(devices.map((d) => effectiveOf(d)));
    if (names.size === 1) {
      const [only] = [...names];
      return only ?? "—";
    }
    return _("Mixed (per device)");
  };

  const q = query.trim().toLowerCase();
  const visible = directory.users.filter((u) => {
    if (!q) {
      return true;
    }
    const hay =
      `${u.name} ${u.id} ${u.email} ${u.groups.map((gid) => groupName(gid)).join(" ")}`.toLowerCase();
    return hay.includes(q);
  });

  const toggle = (id: string) =>
    setExpanded((prev) => {
      const next = new Set(prev);
      if (next.has(id)) {
        next.delete(id);
      } else {
        next.add(id);
      }
      return next;
    });

  return (
    <Stack hasGutter className="ct-router-stack">
      <StackItem>
        <Toolbar>
          <ToolbarContent>
            <ToolbarItem>
              <SearchInput
                placeholder={_("Filter by name, login or group")}
                value={query}
                onChange={(_e, v) => setQuery(v)}
                onClear={() => setQuery("")}
              />
            </ToolbarItem>
            <ToolbarItem>
              <span className="pf-v6-u-color-200">
                {cockpit.format(_("$0 of $1 users"), visible.length, directory.users.length)}
              </span>
            </ToolbarItem>
          </ToolbarContent>
        </Toolbar>
      </StackItem>
      <StackItem isFilled style={{ overflowY: "auto" }}>
        <Table variant="compact" aria-label={_("Directory users")}>
          <Thead>
            <Tr>
              <Th screenReaderText={_("Row expansion")} />
              <Th>{_("Name")}</Th>
              <Th>{_("Login")}</Th>
              <Th>{_("Groups")}</Th>
              <Th>{_("Devices")}</Th>
              <Th>{_("Effective policy")}</Th>
            </Tr>
          </Thead>
          {visible.map((u, rowIndex) => {
            const devices = devicesOf(u, hosts);
            const isExpanded = expanded.has(u.id);
            return (
              <Tbody key={u.id} isExpanded={isExpanded}>
                <Tr>
                  <Td
                    expand={{
                      rowIndex,
                      isExpanded,
                      expandId: `user-${u.id}`,
                      onToggle: () => toggle(u.id),
                    }}
                  />
                  <Td dataLabel={_("Name")}>{u.name || u.id}</Td>
                  <Td dataLabel={_("Login")}>
                    {u.id}
                    {u.email && (
                      <Label isCompact color="grey" className="pf-v6-u-ml-sm">
                        {cockpit.format(_("alias: $0"), u.email)}
                      </Label>
                    )}
                  </Td>
                  <Td dataLabel={_("Groups")}>
                    {u.groups.length === 0 ? (
                      "—"
                    ) : (
                      <LabelGroup numLabels={6}>
                        {u.groups.map((gid) => (
                          <Label key={gid} isCompact>
                            {groupName(gid)}
                          </Label>
                        ))}
                      </LabelGroup>
                    )}
                  </Td>
                  <Td dataLabel={_("Devices")}>{devices.length}</Td>
                  <Td dataLabel={_("Effective policy")}>{effectiveFor(u, devices)}</Td>
                </Tr>
                <Tr isExpanded={isExpanded}>
                  <Td />
                  <Td dataLabel={_("Devices")} colSpan={5}>
                    <ExpandableRowContent>
                      {devices.length === 0 ? (
                        <span className="pf-v6-u-color-200">
                          {_("No devices are assigned to this user in the device registry.")}
                        </span>
                      ) : (
                        <Table
                          variant="compact"
                          borders={false}
                          aria-label={cockpit.format(_("Devices of $0"), u.name || u.email)}
                        >
                          <Thead>
                            <Tr>
                              <Th>{_("Device")}</Th>
                              <Th>{_("Static IP")}</Th>
                              <Th>{_("Group")}</Th>
                              <Th>{_("Effective policy")}</Th>
                            </Tr>
                          </Thead>
                          <Tbody>
                            {devices.map((d) => (
                              <Tr key={d.mac}>
                                <Td dataLabel={_("Device")}>{d.name}</Td>
                                <Td dataLabel={_("Static IP")}>{d.staticIp ?? "—"}</Td>
                                <Td dataLabel={_("Group")}>{d.group ?? "—"}</Td>
                                <Td dataLabel={_("Effective policy")}>{effectiveOf(d)}</Td>
                              </Tr>
                            ))}
                          </Tbody>
                        </Table>
                      )}
                    </ExpandableRowContent>
                  </Td>
                </Tr>
              </Tbody>
            );
          })}
        </Table>
      </StackItem>
    </Stack>
  );
};

// ── Groups tab ───────────────────────────────────────────────────────────────
const GroupsTab = ({
  s,
  directory,
  loading,
  onGoToSettings,
}: {
  s: Settings;
  directory: DirectoryState | null;
  loading: boolean;
  onGoToSettings: () => void;
}) => {
  const section = s.valueOf<AccessPoliciesSection>("accessPolicies", {});

  if (loading || !s.ready) {
    return <Loading />;
  }
  if (!directory || directory.groups.length === 0) {
    return <NoDirectoryState onGoToSettings={onGoToSettings} />;
  }

  const memberCount = (g: DirectoryGroup): number =>
    directory.users.filter((u) => u.groups.some((id) => id.toLowerCase() === g.id.toLowerCase()))
      .length;

  const targetedBy = (g: DirectoryGroup): string[] =>
    (section.policies ?? [])
      .filter((p) =>
        (p.assignments?.directoryGroups ?? []).some(
          (t) => t.toLowerCase() === g.name.toLowerCase() || t.toLowerCase() === g.id.toLowerCase(),
        ),
      )
      .map((p) => p.name);

  return (
    <Stack hasGutter className="ct-router-stack">
      <StackItem isFilled style={{ overflowY: "auto" }}>
        <Table variant="compact" aria-label={_("Directory groups")}>
          <Thead>
            <Tr>
              <Th>{_("Name")}</Th>
              <Th>{_("Members")}</Th>
              <Th>{_("Targeted by policies")}</Th>
            </Tr>
          </Thead>
          <Tbody>
            {directory.groups.map((g) => {
              const policies = targetedBy(g);
              return (
                <Tr key={g.id}>
                  <Td dataLabel={_("Name")}>{g.name}</Td>
                  <Td dataLabel={_("Members")}>{memberCount(g)}</Td>
                  <Td dataLabel={_("Targeted by policies")}>
                    {policies.length === 0 ? (
                      "—"
                    ) : (
                      <LabelGroup numLabels={6}>
                        {policies.map((name) => (
                          <Label key={name} isCompact color="blue">
                            {name}
                          </Label>
                        ))}
                      </LabelGroup>
                    )}
                  </Td>
                </Tr>
              );
            })}
          </Tbody>
        </Table>
      </StackItem>
    </Stack>
  );
};

// ── Directory settings tab ───────────────────────────────────────────────────
const DirectorySettingsTab = ({ s }: { s: Settings }) => {
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

  const provider = s.valueOf<string>("directory.provider", "none");
  const adminGroup = s.valueOf<string>("directory.sssd.adminGroup", "");
  const pathHint = hint(_("Path to a root-owned file on the router — never the secret itself."));

  const field = (id: string, label: string, path: string, help?: ReactElement) => (
    <FormGroup label={label} fieldId={id} labelHelp={help}>
      <TextInput
        id={id}
        value={s.valueOf<string | null>(path, "") ?? ""}
        isDisabled={s.lockedOf(path)}
        onChange={(_e, v) => s.setLeaf(path, v)}
      />
    </FormGroup>
  );

  const list = (
    id: string,
    label: string,
    path: string,
    placeholder: string,
    help?: ReactElement,
  ) => (
    <FormGroup label={label} fieldId={id} labelHelp={help}>
      <ListEditor
        value={s.valueOf<string[]>(path, [])}
        isDisabled={s.lockedOf(path)}
        onChange={(v) => s.setLeaf(path, v)}
        placeholder={placeholder}
      />
    </FormGroup>
  );

  return (
    <Stack hasGutter className="ct-router-stack">
      <StackItem isFilled style={{ overflowY: "auto" }}>
        <Form isHorizontal onSubmit={(e) => e.preventDefault()}>
          <FormSection title={_("Identity provider")} titleElement="h2">
            <FormGroup
              label={_("Provider")}
              fieldId="dir-provider"
              labelHelp={hint(
                _(
                  "SSSD connects the router to your LDAP or Active Directory domain and answers user and group lookups. Only the names your policies reference are looked up — the directory is never enumerated, so its size costs nothing.",
                ),
              )}
            >
              <FormSelect
                id="dir-provider"
                value={provider}
                isDisabled={s.lockedOf("directory.provider")}
                onChange={(_e, v) => s.setLeaf("directory.provider", v)}
              >
                <FormSelectOption value="none" label={_("None")} />
                <FormSelectOption value="sssd" label={_("SSSD (LDAP / Active Directory)")} />
              </FormSelect>
            </FormGroup>
            <FormGroup label={_("Sync interval (minutes)")} fieldId="dir-interval">
              <IntInput
                id="dir-interval"
                min={5}
                value={s.valueOf("directory.syncIntervalMinutes", 60)}
                onChange={(v) => s.setLeaf("directory.syncIntervalMinutes", v)}
              />
            </FormGroup>
          </FormSection>

          {provider === "sssd" && (
            <>
              <FormSection title={_("Domain")} titleElement="h2">
                {field(
                  "sssd-domain",
                  _("Domain name"),
                  "directory.sssd.domain",
                  hint(_("e.g. school.example.org")),
                )}
                {list(
                  "sssd-servers",
                  _("Server URIs"),
                  "directory.sssd.servers",
                  "ldaps://dc1.example.org",
                  hint(_("Tried in order. Prefer ldaps:// — plain ldap:// negotiates StartTLS.")),
                )}
                {field(
                  "sssd-base-dn",
                  _("Search base"),
                  "directory.sssd.baseDn",
                  hint(_("e.g. dc=school,dc=example,dc=org")),
                )}
                <FormGroup
                  label={_("Schema")}
                  fieldId="sssd-schema"
                  labelHelp={hint(
                    _(
                      "Active Directory also covers Google Workspace Secure LDAP. Use RFC 2307bis for most OpenLDAP and 389-DS deployments.",
                    ),
                  )}
                >
                  <FormSelect
                    id="sssd-schema"
                    value={s.valueOf("directory.sssd.schema", "ad")}
                    isDisabled={s.lockedOf("directory.sssd.schema")}
                    onChange={(_e, v) => s.setLeaf("directory.sssd.schema", v)}
                  >
                    <FormSelectOption value="ad" label={_("Active Directory")} />
                    <FormSelectOption value="rfc2307bis" label="RFC 2307bis" />
                    <FormSelectOption value="rfc2307" label="RFC 2307" />
                  </FormSelect>
                </FormGroup>
                {list(
                  "sssd-groups",
                  _("Publish groups"),
                  "directory.sssd.groups",
                  _("e.g. Students"),
                  hint(
                    _(
                      "Group names to resolve even when no policy references them yet. Because the directory is never enumerated, this is what gives the directory-group picker something to offer on a fresh install.",
                    ),
                  ),
                )}
              </FormSection>

              <FormSection title={_("Credentials")} titleElement="h2">
                {field(
                  "sssd-bind-dn",
                  _("Bind DN"),
                  "directory.sssd.bindDn",
                  hint(_("Read-only service account. Leave empty to bind anonymously.")),
                )}
                {field(
                  "sssd-bind-pw",
                  _("Bind password file"),
                  "directory.sssd.bindPasswordFile",
                  pathHint,
                )}
                {field(
                  "sssd-cacert",
                  _("CA certificate file"),
                  "directory.sssd.tlsCaCertFile",
                  hint(
                    _(
                      "PEM bundle validating the directory server certificate. Active Directory LDAPS certificates are usually issued by an enterprise CA that is not in the system trust store.",
                    ),
                  ),
                )}
                {field(
                  "sssd-client-cert",
                  _("Client certificate file"),
                  "directory.sssd.tlsClientCertFile",
                  hint(
                    _(
                      "Mutual-TLS client certificate. Required by Google Workspace Secure LDAP, which authenticates by certificate rather than by bind DN and password.",
                    ),
                  ),
                )}
                {field(
                  "sssd-client-key",
                  _("Client key file"),
                  "directory.sssd.tlsClientKeyFile",
                  pathHint,
                )}
              </FormSection>

              <FormSection title={_("Router login")} titleElement="h2">
                <FormGroup
                  label={_("Admin group")}
                  fieldId="sssd-admin-group"
                  labelHelp={hint(
                    _(
                      "Leave empty (recommended) to use directory identity for policy assignment only: SSSD then runs without its authentication responder and no directory user can log in to the router. Set a group name to let its members administer the router through Cockpit.",
                    ),
                  )}
                >
                  <TextInput
                    id="sssd-admin-group"
                    value={adminGroup}
                    placeholder={_("— no directory logins —")}
                    isDisabled={s.lockedOf("directory.sssd.adminGroup")}
                    onChange={(_e, v) => s.setLeaf("directory.sssd.adminGroup", v)}
                  />
                </FormGroup>
                {adminGroup.trim() !== "" && (
                  <Alert
                    variant="warning"
                    isInline
                    title={_("Directory users can log in to this router")}
                  >
                    {cockpit.format(
                      _(
                        "Members of '$0' will be able to administer the router through Cockpit, with full sudo. Every other directory user is denied. SSH additionally requires the adminSsh setting.",
                      ),
                      adminGroup.trim(),
                    )}
                  </Alert>
                )}
              </FormSection>
            </>
          )}

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

// ── Page ─────────────────────────────────────────────────────────────────────
export const Users = () => {
  const [tab, setTab] = useState("users");
  const s = useSettings();
  const [directory, setDirectory] = useState<DirectoryState | null>(null);
  const [status, setStatus] = useState<DirectoryStatus | null>(null);
  const [dirLoading, setDirLoading] = useState(true);
  const [syncing, setSyncing] = useState(false);
  const [syncError, setSyncError] = useState("");

  const reloadDirectory = useCallback(() => {
    void Promise.all([loadDirectory(), loadDirectoryStatus()]).then(([state, st]) => {
      setDirectory(state);
      setStatus(st);
      setDirLoading(false);
    });
  }, []);
  useEffect(() => {
    reloadDirectory();
  }, [reloadDirectory]);

  const provider = s.valueOf("directory.provider", "none");

  const onSync = () => {
    setSyncing(true);
    setSyncError("");
    void syncNow()
      .then(() => delay(1500))
      .then(() => reloadDirectory())
      .catch((e: unknown) => setSyncError(errMsg(e)))
      .finally(() => setSyncing(false));
  };

  const banner = (
    <Stack hasGutter style={{ marginBlockEnd: "0.5rem" }}>
      <StackItem>
        <Split hasGutter>
          <SplitItem>
            <Label color={provider === "none" ? "grey" : "blue"}>
              {cockpit.format(_("Provider: $0"), provider)}
            </Label>
          </SplitItem>
          <SplitItem>
            <span className="pf-v6-u-color-200">
              {status?.lastSync
                ? cockpit.format(_("Last sync: $0"), new Date(status.lastSync).toLocaleString())
                : _("Never synced")}
            </span>
          </SplitItem>
          <SplitItem isFilled />
          <SplitItem>
            <Button
              variant="secondary"
              size="sm"
              onClick={onSync}
              isLoading={syncing}
              isDisabled={provider === "none" || syncing}
            >
              {_("Sync now")}
            </Button>
          </SplitItem>
        </Split>
      </StackItem>
      {status && status.ok === false && (
        <StackItem>
          <Alert variant="danger" isInline title={_("Directory sync failed")}>
            {status.error ?? ""}
          </Alert>
        </StackItem>
      )}
      {/* A name that does not resolve is a warning, never a failure: one stale
          reference must not blank the user tier for everyone else. It has a
          different remedy from a sync failure, so it gets its own alert. */}
      {status && status.unresolved && status.unresolved.length > 0 && (
        <StackItem>
          <Alert
            variant="warning"
            isInline
            title={_("Some referenced names could not be resolved")}
          >
            <LabelGroup numLabels={12}>
              {status.unresolved.map((n) => (
                <Label key={n} color="orange" isCompact>
                  {n}
                </Label>
              ))}
            </LabelGroup>
            <div className="pf-v6-u-mt-sm">
              {_(
                "Fix them under Hosts (device → user) or Access policies (directory groups). Everything else resolved normally.",
              )}
            </div>
          </Alert>
        </StackItem>
      )}
      {syncError && (
        <StackItem>
          <Alert variant="danger" isInline title={_("Could not start directory sync")}>
            {syncError}
          </Alert>
        </StackItem>
      )}
    </Stack>
  );

  return (
    <TabbedPage
      subnav={
        <>
          {banner}
          <SubNav
            active={tab}
            onSelect={setTab}
            items={[
              { id: "users", label: _("Users") },
              { id: "groups", label: _("Groups") },
              { id: "settings", label: _("Directory settings") },
            ]}
          />
        </>
      }
    >
      {tab === "users" ? (
        <UsersTab
          s={s}
          directory={directory}
          loading={dirLoading}
          onGoToSettings={() => setTab("settings")}
        />
      ) : tab === "groups" ? (
        <GroupsTab
          s={s}
          directory={directory}
          loading={dirLoading}
          onGoToSettings={() => setTab("settings")}
        />
      ) : (
        <DirectorySettingsTab s={s} />
      )}
    </TabbedPage>
  );
};
