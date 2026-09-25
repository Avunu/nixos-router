// Ingress → Tunnel: router.cloudflareTunnel — public hostnames served through
// a Cloudflare Tunnel the router creates and keeps in sync (no WAN port
// opens), plus the provisioner's last-run status and the connector's health.
//
// The API token never enters the settings JSON (TokenFileField). Disabling
// the tunnel keeps the token: the provisioner needs it to delete the tunnel
// and its DNS records.
import { useCallback, useEffect, useState } from "react";
import {
  ActionGroup,
  Alert,
  Button,
  Card,
  CardBody,
  CardTitle,
  DescriptionList,
  DescriptionListDescription,
  DescriptionListGroup,
  DescriptionListTerm,
  EmptyState,
  EmptyStateBody,
  Form,
  FormGroup,
  FormSelect,
  FormSelectOption,
  HelperText,
  HelperTextItem,
  Label,
  Split,
  SplitItem,
  Stack,
  StackItem,
  Switch,
  TextInput,
} from "@patternfly/react-core";
import { Table, Thead, Tbody, Tr, Th, Td } from "@patternfly/react-table";
import { useSettings, Loading, SaveBar, hint } from "./settings";
import { getPath, errMsg } from "./nix";
import type { Json } from "./nix";
import { checkIngress, checkPage, normalizeIngress } from "./ingress";
import {
  DEFAULT_TUNNEL_TOKEN_FILE,
  TUNNEL_CONNECTOR_UNIT,
  TUNNEL_SYNC_UNIT,
  loadTunnelStatus,
  startUnit,
  unitState,
} from "./ingress-runtime";
import type { UnitState } from "./ingress-runtime";
import {
  hasErrors,
  hostDetail,
  IssueList,
  ingressContext,
  TokenFileField,
  UnitLabel,
} from "./ingress-widgets";
import type { TunnelIngress, TunnelStatus } from "./types";

const _ = cockpit.gettext;

interface Draft {
  hostname: string;
  host: string;
  port: string;
  scheme: "http" | "https";
  noTLSVerify: boolean;
  httpHostHeader: string;
}

const EMPTY_DRAFT: Draft = {
  hostname: "",
  host: "",
  port: "80",
  scheme: "http",
  noTLSVerify: true,
  httpHostHeader: "",
};

const toIngress = (d: Draft): TunnelIngress => ({
  hostname: d.hostname.trim().toLowerCase(),
  host: d.host,
  port: d.port.trim() === "" ? Number.NaN : Number(d.port),
  scheme: d.scheme,
  noTLSVerify: d.noTLSVerify,
  httpHostHeader: d.httpHostHeader.trim(),
});

const TOKEN_SCOPES = _(
  "Create a token in the Cloudflare dashboard (My Profile → API Tokens) with Account → Cloudflare Tunnel → Edit, plus Zone → Zone → Read and Zone → DNS → Edit on the zones of the tunnel's hostnames.",
);

// ── Status ──────────────────────────────────────────────────────────────────
const StatusCard = ({ canSync }: { canSync: boolean }) => {
  const [status, setStatus] = useState<TunnelStatus | null>(null);
  const [connector, setConnector] = useState<UnitState | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");

  const reload = useCallback(() => {
    void loadTunnelStatus().then(setStatus);
    void unitState(TUNNEL_CONNECTOR_UNIT).then(setConnector);
  }, []);
  useEffect(() => {
    reload();
  }, [reload]);

  const run = () => {
    setBusy(true);
    setError("");
    startUnit(TUNNEL_SYNC_UNIT)
      .catch((e: unknown) => setError(errMsg(e)))
      .finally(() => {
        setBusy(false);
        reload();
      });
  };

  const records = Object.entries(status?.records ?? {});
  const connections = status?.connections ?? [];

  return (
    <Card isCompact>
      <CardTitle>
        <Split hasGutter>
          <SplitItem isFilled>{_("Tunnel status")}</SplitItem>
          <SplitItem>
            <Button
              variant="secondary"
              onClick={run}
              isDisabled={!canSync || busy}
              isLoading={busy}
            >
              {_("Sync now")}
            </Button>
          </SplitItem>
        </Split>
      </CardTitle>
      <CardBody>
        <Stack hasGutter>
          {!canSync && (
            <StackItem>
              <Alert
                variant="info"
                isInline
                isPlain
                title={_("The tunnel is not running — enable it and apply the configuration.")}
              />
            </StackItem>
          )}
          {error && (
            <StackItem>
              <Alert variant="danger" isInline isPlain title={_("The sync run failed")}>
                {error}
              </Alert>
            </StackItem>
          )}
          {!status ? (
            <StackItem>{_("No sync has run yet.")}</StackItem>
          ) : (
            <>
              <StackItem>
                <DescriptionList isHorizontal isCompact>
                  <DescriptionListGroup>
                    <DescriptionListTerm>{_("Last sync")}</DescriptionListTerm>
                    <DescriptionListDescription>
                      {status.updated ?? "—"}{" "}
                      {status.ok ? (
                        <Label color="green" isCompact>
                          {_("ok")}
                        </Label>
                      ) : (
                        <Label color="red" isCompact>
                          {status.error ?? _("failed")}
                        </Label>
                      )}
                    </DescriptionListDescription>
                  </DescriptionListGroup>
                  <DescriptionListGroup>
                    <DescriptionListTerm>{_("Tunnel")}</DescriptionListTerm>
                    <DescriptionListDescription>
                      {status.tunnel ? (
                        <>
                          {`${status.tunnel.name} `}
                          <Label
                            color={status.tunnel.status === "healthy" ? "green" : "orange"}
                            isCompact
                          >
                            {status.tunnel.status}
                          </Label>
                          <div>
                            <small>{status.tunnel.id}</small>
                          </div>
                        </>
                      ) : (
                        <>
                          {_("none")}
                          {status.message && (
                            <div>
                              <small>{status.message}</small>
                            </div>
                          )}
                        </>
                      )}
                    </DescriptionListDescription>
                  </DescriptionListGroup>
                  <DescriptionListGroup>
                    <DescriptionListTerm>{_("Connector")}</DescriptionListTerm>
                    <DescriptionListDescription>
                      <UnitLabel state={connector} /> <small>{TUNNEL_CONNECTOR_UNIT}</small>
                    </DescriptionListDescription>
                  </DescriptionListGroup>
                </DescriptionList>
              </StackItem>
              {connections.length > 0 && (
                <StackItem>
                  <Table variant="compact" aria-label={_("Tunnel connections")}>
                    <Thead>
                      <Tr>
                        <Th>{_("Data center")}</Th>
                        <Th>{_("Origin IP")}</Th>
                        <Th>{_("Opened")}</Th>
                        <Th>{_("Version")}</Th>
                      </Tr>
                    </Thead>
                    <Tbody>
                      {connections.map((c, i) => (
                        <Tr key={i}>
                          <Td>{c.colo}</Td>
                          <Td>{c.originIp}</Td>
                          <Td>{c.openedAt}</Td>
                          <Td>{c.clientVersion}</Td>
                        </Tr>
                      ))}
                    </Tbody>
                  </Table>
                </StackItem>
              )}
              {records.length > 0 && (
                <StackItem>
                  <Table variant="compact" aria-label={_("Tunnel DNS records")}>
                    <Thead>
                      <Tr>
                        <Th>{_("Hostname")}</Th>
                        <Th>{_("DNS record")}</Th>
                      </Tr>
                    </Thead>
                    <Tbody>
                      {records.map(([name, r]) => (
                        <Tr key={name}>
                          <Td>{name}</Td>
                          <Td>
                            <Label color={r.ok ? "green" : "red"} isCompact>
                              {r.ok ? _("ok") : _("error")}
                            </Label>
                            {r.message && <small>{` ${r.message}`}</small>}
                          </Td>
                        </Tr>
                      ))}
                    </Tbody>
                  </Table>
                </StackItem>
              )}
            </>
          )}
        </Stack>
      </CardBody>
    </Card>
  );
};

// ── Tab ─────────────────────────────────────────────────────────────────────
export const Tunnel = () => {
  const s = useSettings();
  const [draft, setDraft] = useState<Draft | null>(null);
  const [editIndex, setEditIndex] = useState<number | null>(null);

  if (!s.ready && !s.error) {
    return <Loading />;
  }
  if (s.error) {
    return (
      <Alert variant="danger" isInline title={_("Could not load tunnel settings")}>
        {s.error}
      </Alert>
    );
  }

  const ctx = ingressContext(s);
  const enabled = ctx.tunnel.enable;
  const rows = ctx.tunnel.ingress.map((i) => normalizeIngress(i));
  const { hosts } = ctx;
  const hostByName = new Map(hosts.map((h) => [h.name, h]));
  const locked = s.lockedOf("cloudflareTunnel.ingress");
  const pageIssues = checkPage(ctx).tunnel;
  // The provisioner is installed while the tunnel is on, and also while a
  // token remains after turning it off (so it can tear the tunnel down).
  const canSync =
    getPath(s.effective, "cloudflareTunnel.enable") === true ||
    typeof getPath(s.effective, "cloudflareTunnel.apiTokenFile") === "string";

  const setRows = (r: TunnelIngress[]) =>
    s.setLeaf("cloudflareTunnel.ingress", r as unknown as Json);

  const beginAdd = () => {
    setDraft({ ...EMPTY_DRAFT });
    setEditIndex(null);
  };
  const beginEdit = (i: number) => {
    const r = rows[i];
    if (!r) {
      return;
    }
    setDraft({
      hostname: r.hostname,
      host: r.host,
      port: String(r.port ?? 80),
      scheme: r.scheme ?? "http",
      noTLSVerify: r.noTLSVerify ?? true,
      httpHostHeader: r.httpHostHeader ?? "",
    });
    setEditIndex(i);
  };
  const cancel = () => {
    setDraft(null);
    setEditIndex(null);
  };
  const remove = (i: number) => setRows(rows.filter((_r, idx) => idx !== i));

  const issues = draft ? checkIngress(toIngress(draft), ctx, editIndex) : [];
  const commit = () => {
    if (!draft) {
      return;
    }
    const row = normalizeIngress(toIngress(draft));
    setRows(editIndex === null ? [...rows, row] : rows.map((r, i) => (i === editIndex ? row : r)));
    cancel();
  };

  return (
    <Stack hasGutter className="ct-router-stack">
      <StackItem isFilled style={{ overflowY: "auto" }}>
        <Stack hasGutter>
          <StackItem>
            <Form isHorizontal onSubmit={(e) => e.preventDefault()}>
              <FormGroup
                label={_("Enable Cloudflare Tunnel")}
                fieldId="cftEnable"
                labelHelp={hint(
                  _(
                    "The router creates a tunnel named after itself, runs its connector, and points each hostname below at it with a proxied CNAME. Nothing opens on the WAN.",
                  ),
                )}
              >
                <Switch
                  id="cftEnable"
                  isChecked={enabled}
                  isDisabled={s.lockedOf("cloudflareTunnel.enable")}
                  onChange={(_e, c) => s.setLeaf("cloudflareTunnel.enable", c)}
                  aria-label={_("Enable Cloudflare Tunnel")}
                />
                <HelperText>
                  <HelperTextItem>
                    {_(
                      "Turning the tunnel off keeps the token, so the router can delete the tunnel and its DNS records — remove the token only after that has run.",
                    )}
                  </HelperTextItem>
                </HelperText>
              </FormGroup>
              <TokenFileField
                s={s}
                leaf="cloudflareTunnel.apiTokenFile"
                fieldId="cftTokenFile"
                defaultFile={DEFAULT_TUNNEL_TOKEN_FILE}
                scopes={TOKEN_SCOPES}
                isRequired={enabled}
              />
            </Form>
          </StackItem>

          {pageIssues.length > 0 && (
            <StackItem>
              <Alert
                variant={hasErrors(pageIssues) ? "danger" : "warning"}
                isInline
                title={
                  hasErrors(pageIssues)
                    ? _("Fix these before applying")
                    : _("Check the tunnel configuration")
                }
              >
                <IssueList issues={pageIssues} />
              </Alert>
            </StackItem>
          )}

          {locked && (
            <StackItem>
              <Alert
                variant="info"
                isInline
                title={_("Tunnel hostnames are locked in the Nix configuration.")}
              />
            </StackItem>
          )}
          <StackItem>
            <Split>
              <SplitItem isFilled />
              <SplitItem>
                <Button
                  variant="secondary"
                  onClick={beginAdd}
                  isDisabled={Boolean(draft) || locked || hosts.length === 0}
                >
                  {_("Add hostname")}
                </Button>
              </SplitItem>
            </Split>
          </StackItem>

          <StackItem>
            {rows.length === 0 ? (
              <EmptyState>
                <EmptyStateBody>
                  {hosts.length === 0
                    ? _(
                        "No tunnel hostnames configured. Register the device on the Hosts page first.",
                      )
                    : _("No tunnel hostnames configured.")}
                </EmptyStateBody>
              </EmptyState>
            ) : (
              <Table variant="compact" aria-label={_("Tunnel hostnames")}>
                <Thead>
                  <Tr>
                    <Th>{_("Hostname")}</Th>
                    <Th>{_("Target")}</Th>
                    <Th>{_("Host header")}</Th>
                    <Th screenReaderText={_("Actions")} />
                  </Tr>
                </Thead>
                <Tbody>
                  {rows.map((r, i) => {
                    const host = hostByName.get(r.host);
                    return (
                      <Tr key={i}>
                        <Td>{r.hostname}</Td>
                        <Td>
                          <div>{`→ ${r.host}:${r.port ?? 80} (${r.scheme ?? "http"})`}</div>
                          <small>
                            {host ? (
                              hostDetail(host)
                            ) : (
                              <Label color="red" isCompact>
                                {_("unknown host")}
                              </Label>
                            )}
                          </small>
                        </Td>
                        <Td>{r.httpHostHeader || "—"}</Td>
                        <Td isActionCell>
                          <Button
                            variant="link"
                            isInline
                            onClick={() => beginEdit(i)}
                            isDisabled={locked}
                          >
                            {_("Edit")}
                          </Button>{" "}
                          <Button
                            variant="link"
                            isInline
                            isDanger
                            onClick={() => remove(i)}
                            isDisabled={locked}
                          >
                            {_("Delete")}
                          </Button>
                        </Td>
                      </Tr>
                    );
                  })}
                </Tbody>
              </Table>
            )}
          </StackItem>

          {draft && (
            <StackItem>
              <Card isCompact>
                <CardTitle>
                  {editIndex === null ? _("Add tunnel hostname") : _("Edit tunnel hostname")}
                </CardTitle>
                <CardBody>
                  <Form isHorizontal onSubmit={(e) => e.preventDefault()}>
                    <FormGroup label={_("Hostname")} fieldId="cftHostname" isRequired>
                      <TextInput
                        id="cftHostname"
                        value={draft.hostname}
                        placeholder="wiki.example.com"
                        onChange={(_e, v) => setDraft({ ...draft, hostname: v })}
                      />
                    </FormGroup>
                    <FormGroup label={_("Host")} fieldId="cftHost" isRequired>
                      <FormSelect
                        id="cftHost"
                        value={draft.host}
                        onChange={(_e, v) => setDraft({ ...draft, host: v })}
                      >
                        <FormSelectOption value="" label={_("— choose a host —")} isPlaceholder />
                        {hosts.map((h) => (
                          <FormSelectOption
                            key={h.mac}
                            value={h.name}
                            label={`${h.name} (${hostDetail(h)})`}
                          />
                        ))}
                      </FormSelect>
                    </FormGroup>
                    <FormGroup label={_("Port")} fieldId="cftPort" isRequired>
                      <TextInput
                        id="cftPort"
                        type="number"
                        value={draft.port}
                        onChange={(_e, v) => setDraft({ ...draft, port: v })}
                      />
                    </FormGroup>
                    <FormGroup
                      label={_("Scheme")}
                      fieldId="cftScheme"
                      labelHelp={hint(_("The protocol the host's service speaks."))}
                    >
                      <FormSelect
                        id="cftScheme"
                        value={draft.scheme}
                        onChange={(_e, v) => setDraft({ ...draft, scheme: v as "http" | "https" })}
                      >
                        <FormSelectOption value="http" label="http" />
                        <FormSelectOption value="https" label="https" />
                      </FormSelect>
                    </FormGroup>
                    {draft.scheme === "https" && (
                      <FormGroup
                        label={_("Skip certificate check")}
                        fieldId="cftNoVerify"
                        labelHelp={hint(
                          _(
                            "Accept the host's certificate unverified — services inside the network are mostly self-signed.",
                          ),
                        )}
                      >
                        <Switch
                          id="cftNoVerify"
                          isChecked={draft.noTLSVerify}
                          onChange={(_e, c) => setDraft({ ...draft, noTLSVerify: c })}
                          aria-label={_("Skip certificate check")}
                        />
                      </FormGroup>
                    )}
                    <FormGroup
                      label={_("Host header (optional)")}
                      fieldId="cftHostHeader"
                      labelHelp={hint(
                        _(
                          "Send this Host header to the service instead of the public name. Empty keeps the public name.",
                        ),
                      )}
                    >
                      <TextInput
                        id="cftHostHeader"
                        value={draft.httpHostHeader}
                        onChange={(_e, v) => setDraft({ ...draft, httpHostHeader: v })}
                      />
                    </FormGroup>
                    <IssueList issues={issues} />
                    <ActionGroup>
                      <Button variant="secondary" onClick={commit} isDisabled={hasErrors(issues)}>
                        {editIndex === null ? _("Add") : _("Update")}
                      </Button>
                      <Button variant="link" onClick={cancel}>
                        {_("Cancel")}
                      </Button>
                    </ActionGroup>
                  </Form>
                </CardBody>
              </Card>
            </StackItem>
          )}

          <StackItem>
            <StatusCard canSync={canSync} />
          </StackItem>

          <StackItem>
            <SaveBar
              saving={s.saving}
              status={s.status}
              onSave={s.save}
              onSaveApply={s.saveAndApply}
              applyDisabled={hasErrors(pageIssues)}
            />
          </StackItem>
        </Stack>
      </StackItem>
    </Stack>
  );
};
