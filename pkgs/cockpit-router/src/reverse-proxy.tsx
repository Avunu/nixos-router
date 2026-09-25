// Ingress → Reverse proxy: router.reverseProxy (hostname routes on the WAN's
// ports 80/443, proxied to registered hosts) and router.acme (the account its
// Let's Encrypt certificates are ordered with). One certificate per route,
// named after its first hostname (ingress.ts certName); its state comes from
// the cert.pem on disk and the acme-order-renew-<cert> unit.
import { useCallback, useEffect, useState } from "react";
import {
  ActionGroup,
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
  FormSelect,
  FormSelectOption,
  HelperText,
  HelperTextItem,
  Label,
  LabelGroup,
  Split,
  SplitItem,
  Stack,
  StackItem,
  Switch,
  TextInput,
} from "@patternfly/react-core";
import { Table, Thead, Tbody, Tr, Th, Td } from "@patternfly/react-table";
import { useSettings, Loading, SaveBar, hint, ListEditor } from "./settings";
import { getPath, errMsg } from "./nix";
import type { Json } from "./nix";
import { certName, checkRoute, checkPage, effectiveChallenge, normalizeRoute } from "./ingress";
import type { EffectiveChallenge } from "./ingress";
import {
  DEFAULT_ACME_TOKEN_FILE,
  PROXY_UNIT,
  loadCert,
  renewUnit,
  startUnit,
  unitState,
} from "./ingress-runtime";
import type { CertInfo, UnitState } from "./ingress-runtime";
import {
  hasErrors,
  hostDetail,
  IssueList,
  ingressContext,
  TokenFileField,
  UnitLabel,
} from "./ingress-widgets";
import { scanOpenPorts } from "./hosts-live";
import type { AcmeChallenge, ProxyRoute, RouterHost } from "./types";

const _ = cockpit.gettext;

interface Draft {
  name: string;
  hostnames: string[];
  host: string;
  port: string;
  scheme: "http" | "https";
  tlsVerify: boolean;
  challenge: AcmeChallenge;
  hsts: boolean;
}

const EMPTY_DRAFT: Draft = {
  name: "",
  hostnames: [],
  host: "",
  port: "80",
  scheme: "http",
  tlsVerify: false,
  challenge: "default",
  hsts: false,
};

const toRoute = (d: Draft): ProxyRoute => ({
  name: d.name.trim(),
  hostnames: d.hostnames,
  host: d.host,
  port: d.port.trim() === "" ? Number.NaN : Number(d.port),
  scheme: d.scheme,
  tlsVerify: d.tlsVerify,
  challenge: d.challenge,
  hsts: d.hsts,
});

const challengeLabel = (c: EffectiveChallenge) =>
  c === "dns-cloudflare" ? _("Cloudflare DNS") : _("HTTP (port 80)");

const TOKEN_SCOPES = _(
  "Create a token in the Cloudflare dashboard (My Profile → API Tokens) with Zone → Zone → Read and Zone → DNS → Edit on the zones of the certificates' names — the dynamic DNS token has exactly these.",
);

// ── Certificate state ───────────────────────────────────────────────────────
interface CertState {
  cert: CertInfo;
  unit: UnitState;
  // Days until notAfter, taken when the state was loaded.
  daysLeft: number;
}

const DAY = 86_400_000;

const CertStatus = ({ st }: { st: CertState | undefined }) => {
  if (!st) {
    return "—";
  }
  let label;
  if (st.unit.activeState === "activating") {
    label = (
      <Label color="blue" isCompact>
        {_("Renewing…")}
      </Label>
    );
  } else if (st.cert.state === "missing") {
    label = (
      <Label color="grey" isCompact>
        {_("No certificate")}
      </Label>
    );
  } else if (st.cert.state === "pending") {
    label = (
      <Label color="orange" isCompact>
        {_("Pending")}
      </Label>
    );
  } else {
    const end = st.cert.notAfter;
    const left = st.daysLeft;
    label = (
      <Label color={left <= 0 ? "red" : left < 14 ? "orange" : "green"} isCompact>
        {!end
          ? _("Issued")
          : left <= 0
            ? _("Expired")
            : cockpit.format(_("Valid until $0"), end.toLocaleDateString())}
      </Label>
    );
  }
  const failed =
    st.unit.activeState === "failed" || (st.unit.result && st.unit.result !== "success");
  return (
    <>
      <div>{label}</div>
      {failed && (
        <small>
          <Label color="red" isCompact>
            {_("last renewal failed")}
          </Label>
        </small>
      )}
      {!failed && st.unit.exitedAt && (
        <small>{cockpit.format(_("last run $0"), st.unit.exitedAt)}</small>
      )}
    </>
  );
};

// Certificate + renewal-unit state of every cert, refreshed on demand.
function useCertStates(certs: string[], active: boolean) {
  const [states, setStates] = useState<Record<string, CertState>>({});
  const key = certs.join(" ");
  const refresh = useCallback(() => {
    if (!active) {
      return;
    }
    const names = key.split(" ").filter(Boolean);
    void Promise.all(
      names.map((c) =>
        Promise.all([loadCert(c), unitState(renewUnit(c))]).then(([cert, unit]) => {
          const end = cert.notAfter;
          const daysLeft = end ? (end.getTime() - Date.now()) / DAY : 0;
          return [c, { cert, unit, daysLeft }] as const;
        }),
      ),
    ).then((entries) => setStates(Object.fromEntries(entries)));
  }, [key, active]);
  useEffect(() => {
    refresh();
  }, [refresh]);
  return { states: active ? states : {}, refresh };
}

// ── Port scan helper ────────────────────────────────────────────────────────
const PortScan = ({ ip, onPick }: { ip: string; onPick: (port: number) => void }) => {
  const [open, setOpen] = useState<number[] | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const scan = () => {
    setBusy(true);
    setError("");
    setOpen(null);
    scanOpenPorts([ip], (u) => setOpen(u[ip] ?? []))
      .then(() => setOpen((o) => o ?? []))
      .catch((e: unknown) => setError(errMsg(e)))
      .finally(() => setBusy(false));
  };
  return (
    <>
      <Button variant="link" isInline onClick={scan} isDisabled={busy} isLoading={busy}>
        {_("Scan ports")}
      </Button>
      {error && (
        <HelperText>
          <HelperTextItem variant="error">{error}</HelperTextItem>
        </HelperText>
      )}
      {open && (
        <HelperText>
          <HelperTextItem>
            {open.length === 0 ? (
              _("No open ports among the 100 most common.")
            ) : (
              <LabelGroup numLabels={20}>
                {open.map((p) => (
                  <Label key={p} isCompact onClick={() => onPick(p)}>
                    {p}
                  </Label>
                ))}
              </LabelGroup>
            )}
          </HelperTextItem>
        </HelperText>
      )}
    </>
  );
};

// ── Tab ─────────────────────────────────────────────────────────────────────
export const ReverseProxy = () => {
  const s = useSettings();
  const [draft, setDraft] = useState<Draft | null>(null);
  const [editIndex, setEditIndex] = useState<number | null>(null);
  const [proxyUnit, setProxyUnit] = useState<UnitState | null>(null);
  const [renewing, setRenewing] = useState("");
  const [renewError, setRenewError] = useState("");

  const ctx = ingressContext(s);
  const rows = ctx.proxy.routes.map((r) => normalizeRoute(r));
  // The units and certificates exist only once an enabled config is applied.
  const active = getPath(s.effective, "reverseProxy.enable") === true;
  const { states, refresh } = useCertStates(
    rows.map((r) => certName(r)),
    active,
  );

  useEffect(() => {
    if (active) {
      void unitState(PROXY_UNIT).then(setProxyUnit);
    }
  }, [active]);

  if (!s.ready && !s.error) {
    return <Loading />;
  }
  if (s.error) {
    return (
      <Alert variant="danger" isInline title={_("Could not load reverse proxy settings")}>
        {s.error}
      </Alert>
    );
  }

  const enabled = ctx.proxy.enable;
  const locked = s.lockedOf("reverseProxy.routes");
  const { hosts } = ctx;
  const hostByName = new Map(hosts.map((h) => [h.name, h]));
  const defaultChallenge = ctx.acme.defaultChallenge ?? "http";
  const ddnsToken = s.valueOf<string | null>("ddns.cloudflare.apiTokenFile", null);
  const acmeToken = ctx.acme.cloudflare?.apiTokenFile ?? null;
  const pageIssues = checkPage(ctx).proxy;

  const setRows = (r: ProxyRoute[]) => s.setLeaf("reverseProxy.routes", r as unknown as Json);

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
      name: r.name ?? "",
      hostnames: r.hostnames,
      host: r.host,
      port: String(r.port ?? 80),
      scheme: r.scheme ?? "http",
      tlsVerify: r.tlsVerify ?? false,
      challenge: r.challenge ?? "default",
      hsts: r.hsts ?? false,
    });
    setEditIndex(i);
  };
  const cancel = () => {
    setDraft(null);
    setEditIndex(null);
  };
  const remove = (i: number) => setRows(rows.filter((_r, idx) => idx !== i));

  const issues = draft ? checkRoute(toRoute(draft), ctx, editIndex) : [];
  const commit = () => {
    if (!draft) {
      return;
    }
    const row = normalizeRoute(toRoute(draft));
    setRows(editIndex === null ? [...rows, row] : rows.map((r, i) => (i === editIndex ? row : r)));
    cancel();
  };

  const renew = (cert: string) => {
    setRenewing(cert);
    setRenewError("");
    startUnit(renewUnit(cert))
      .catch((e: unknown) => setRenewError(`${cert}: ${errMsg(e)}`))
      .finally(() => {
        setRenewing("");
        refresh();
      });
  };

  const draftHost = draft ? hostByName.get(draft.host) : undefined;

  return (
    <Stack hasGutter className="ct-router-stack">
      <StackItem isFilled style={{ overflowY: "auto" }}>
        <Stack hasGutter>
          <StackItem>
            <Form isHorizontal onSubmit={(e) => e.preventDefault()}>
              <FormGroup
                label={_("Enable reverse proxy")}
                fieldId="rpEnable"
                labelHelp={hint(
                  _(
                    "Serves the routes below on the WAN's ports 80 and 443, choosing the host by name, with a Let's Encrypt certificate per route. Port 80 redirects to HTTPS and answers certificate challenges.",
                  ),
                )}
              >
                <Split hasGutter>
                  <SplitItem>
                    <Switch
                      id="rpEnable"
                      isChecked={enabled}
                      isDisabled={s.lockedOf("reverseProxy.enable")}
                      onChange={(_e, c) => s.setLeaf("reverseProxy.enable", c)}
                      aria-label={_("Enable reverse proxy")}
                    />
                  </SplitItem>
                  {active && (
                    <SplitItem>
                      <UnitLabel state={proxyUnit} />
                    </SplitItem>
                  )}
                </Split>
              </FormGroup>
              <FormGroup
                label={_("Publish hostnames")}
                fieldId="rpPublish"
                labelHelp={hint(
                  _(
                    "Dynamic DNS points every route hostname at the router (A = WAN IPv4, AAAA = the router's IPv6). The HTTP certificate challenge depends on it.",
                  ),
                )}
              >
                <Switch
                  id="rpPublish"
                  isChecked={ctx.proxy.publishDns}
                  isDisabled={s.lockedOf("reverseProxy.publishDns")}
                  onChange={(_e, c) => s.setLeaf("reverseProxy.publishDns", c)}
                  aria-label={_("Publish hostnames")}
                />
                {ctx.proxy.publishDns && !ctx.ddns.enable && (
                  <HelperText>
                    <HelperTextItem variant="warning">
                      {_(
                        "Dynamic DNS is off (Network → Dynamic DNS), so nothing publishes these names.",
                      )}
                    </HelperTextItem>
                  </HelperText>
                )}
              </FormGroup>
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
                    : _("Check the reverse proxy configuration")
                }
              >
                <IssueList issues={pageIssues} />
              </Alert>
            </StackItem>
          )}

          <StackItem>
            <Card isCompact>
              <CardTitle>{_("Certificates")}</CardTitle>
              <CardBody>
                <Form isHorizontal onSubmit={(e) => e.preventDefault()}>
                  <FormGroup
                    label={_("Contact email")}
                    fieldId="acmeEmail"
                    isRequired={enabled && rows.length > 0}
                    labelHelp={hint(_("Let's Encrypt sends certificate expiry warnings here."))}
                  >
                    <TextInput
                      id="acmeEmail"
                      type="email"
                      value={ctx.acme.email ?? ""}
                      placeholder="admin@example.com"
                      isDisabled={s.lockedOf("acme.email")}
                      onChange={(_e, v) => s.setLeaf("acme.email", v.trim())}
                    />
                  </FormGroup>
                  <FormGroup label={_("Terms of service")} fieldId="acmeTerms">
                    <Checkbox
                      id="acmeTerms"
                      label={_("I accept the Let's Encrypt Subscriber Agreement")}
                      description={
                        <a
                          href="https://letsencrypt.org/repository/"
                          target="_blank"
                          rel="noopener noreferrer"
                        >
                          {_("Read the agreement (letsencrypt.org/repository)")}
                        </a>
                      }
                      isChecked={Boolean(ctx.acme.acceptTerms)}
                      isDisabled={s.lockedOf("acme.acceptTerms")}
                      onChange={(_e, c) => s.setLeaf("acme.acceptTerms", c)}
                    />
                  </FormGroup>
                  <FormGroup
                    label={_("Staging CA")}
                    fieldId="acmeStaging"
                    labelHelp={hint(
                      _(
                        "Let's Encrypt's staging CA has far higher rate limits, but browsers do not trust its certificates. Use it while testing a new route, then switch back.",
                      ),
                    )}
                  >
                    <Switch
                      id="acmeStaging"
                      isChecked={Boolean(ctx.acme.staging)}
                      isDisabled={s.lockedOf("acme.staging")}
                      onChange={(_e, c) => s.setLeaf("acme.staging", c)}
                      aria-label={_("Staging CA")}
                    />
                  </FormGroup>
                  <FormGroup
                    label={_("Default challenge")}
                    fieldId="acmeChallenge"
                    labelHelp={hint(
                      _(
                        "HTTP: Let's Encrypt fetches a file over port 80, so the name must already resolve to the router. Cloudflare DNS: a TXT record via the Cloudflare API — needs a token, works before the name resolves, and is the only way to get a wildcard.",
                      ),
                    )}
                  >
                    <FormSelect
                      id="acmeChallenge"
                      value={defaultChallenge}
                      isDisabled={s.lockedOf("acme.defaultChallenge")}
                      onChange={(_e, v) => s.setLeaf("acme.defaultChallenge", v)}
                    >
                      <FormSelectOption value="http" label={challengeLabel("http")} />
                      <FormSelectOption
                        value="dns-cloudflare"
                        label={challengeLabel("dns-cloudflare")}
                      />
                    </FormSelect>
                  </FormGroup>
                  <TokenFileField
                    s={s}
                    leaf="acme.cloudflare.apiTokenFile"
                    fieldId="acmeTokenFile"
                    defaultFile={DEFAULT_ACME_TOKEN_FILE}
                    scopes={TOKEN_SCOPES}
                    isRequired={rows.some(
                      (r) => effectiveChallenge(r, ctx.acme) === "dns-cloudflare",
                    )}
                    helper={_("Needed only for the Cloudflare DNS challenge.")}
                    extra={
                      ddnsToken && ddnsToken !== acmeToken ? (
                        <Button
                          variant="link"
                          isDisabled={s.lockedOf("acme.cloudflare.apiTokenFile")}
                          onClick={() => s.setLeaf("acme.cloudflare.apiTokenFile", ddnsToken)}
                        >
                          {_("Use the DDNS token")}
                        </Button>
                      ) : null
                    }
                  />
                </Form>
              </CardBody>
            </Card>
          </StackItem>

          {locked && (
            <StackItem>
              <Alert
                variant="info"
                isInline
                title={_("Reverse proxy routes are locked in the Nix configuration.")}
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
                  {_("Add route")}
                </Button>
              </SplitItem>
            </Split>
          </StackItem>

          {renewError && (
            <StackItem>
              <Alert variant="danger" isInline title={_("Certificate renewal failed")}>
                {renewError}
              </Alert>
            </StackItem>
          )}

          <StackItem>
            {rows.length === 0 ? (
              <EmptyState>
                <EmptyStateBody>
                  {hosts.length === 0
                    ? _("No routes configured. Register the device on the Hosts page first.")
                    : _("No routes configured.")}
                </EmptyStateBody>
              </EmptyState>
            ) : (
              <Table variant="compact" aria-label={_("Reverse proxy routes")}>
                <Thead>
                  <Tr>
                    <Th>{_("Name")}</Th>
                    <Th>{_("Hostnames")}</Th>
                    <Th>{_("Target")}</Th>
                    <Th>{_("Challenge")}</Th>
                    <Th>{_("Certificate")}</Th>
                    <Th screenReaderText={_("Actions")} />
                  </Tr>
                </Thead>
                <Tbody>
                  {rows.map((r, i) => {
                    const host = hostByName.get(r.host);
                    const cert = certName(r);
                    return (
                      <Tr key={i}>
                        <Td>{r.name || "—"}</Td>
                        <Td>{r.hostnames.join(", ")}</Td>
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
                        <Td>
                          {challengeLabel(effectiveChallenge(r, ctx.acme))}
                          {(r.challenge ?? "default") === "default" && (
                            <small>{` ${_("(default)")}`}</small>
                          )}
                        </Td>
                        <Td>
                          <CertStatus st={states[cert]} />
                        </Td>
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
                          </Button>{" "}
                          <Button
                            variant="link"
                            isInline
                            onClick={() => renew(cert)}
                            isDisabled={!states[cert] || Boolean(renewing)}
                            isLoading={renewing === cert}
                          >
                            {_("Renew now")}
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
                <CardTitle>{editIndex === null ? _("Add route") : _("Edit route")}</CardTitle>
                <CardBody>
                  <Form isHorizontal onSubmit={(e) => e.preventDefault()}>
                    <FormGroup label={_("Name")} fieldId="rpName">
                      <TextInput
                        id="rpName"
                        value={draft.name}
                        onChange={(_e, v) => setDraft({ ...draft, name: v })}
                      />
                    </FormGroup>
                    <FormGroup
                      label={_("Hostnames")}
                      fieldId="rpHostnames"
                      isRequired
                      labelHelp={hint(
                        _(
                          "Public names routed to the host, all on one certificate named after the first. A leading *. matches one extra label and needs the Cloudflare DNS challenge.",
                        ),
                      )}
                    >
                      <ListEditor
                        value={draft.hostnames}
                        placeholder="app.example.com"
                        onChange={(v) =>
                          setDraft({ ...draft, hostnames: v.map((n) => n.toLowerCase()) })
                        }
                      />
                    </FormGroup>
                    <FormGroup label={_("Host")} fieldId="rpHost" isRequired>
                      <FormSelect
                        id="rpHost"
                        value={draft.host}
                        onChange={(_e, v) => setDraft({ ...draft, host: v })}
                      >
                        <FormSelectOption value="" label={_("— choose a host —")} isPlaceholder />
                        {hosts.map((h: RouterHost) => (
                          <FormSelectOption
                            key={h.mac}
                            value={h.name}
                            label={`${h.name} (${hostDetail(h)})`}
                          />
                        ))}
                      </FormSelect>
                    </FormGroup>
                    <FormGroup label={_("Port")} fieldId="rpPort" isRequired>
                      <TextInput
                        id="rpPort"
                        type="number"
                        value={draft.port}
                        onChange={(_e, v) => setDraft({ ...draft, port: v })}
                      />
                      {draftHost?.staticIp && (
                        <PortScan
                          key={draftHost.staticIp}
                          ip={draftHost.staticIp}
                          onPick={(p) => setDraft({ ...draft, port: String(p) })}
                        />
                      )}
                    </FormGroup>
                    <FormGroup
                      label={_("Scheme")}
                      fieldId="rpScheme"
                      labelHelp={hint(_("The protocol the host's service speaks."))}
                    >
                      <FormSelect
                        id="rpScheme"
                        value={draft.scheme}
                        onChange={(_e, v) => setDraft({ ...draft, scheme: v as "http" | "https" })}
                      >
                        <FormSelectOption value="http" label="http" />
                        <FormSelectOption value="https" label="https" />
                      </FormSelect>
                    </FormGroup>
                    {draft.scheme === "https" && (
                      <FormGroup
                        label={_("Verify the host's certificate")}
                        fieldId="rpTlsVerify"
                        labelHelp={hint(
                          _(
                            "Off by default: services inside the network mostly present self-signed certificates.",
                          ),
                        )}
                      >
                        <Switch
                          id="rpTlsVerify"
                          isChecked={draft.tlsVerify}
                          onChange={(_e, c) => setDraft({ ...draft, tlsVerify: c })}
                          aria-label={_("Verify the host's certificate")}
                        />
                      </FormGroup>
                    )}
                    <FormGroup label={_("Certificate challenge")} fieldId="rpChallenge">
                      <FormSelect
                        id="rpChallenge"
                        value={draft.challenge}
                        onChange={(_e, v) => setDraft({ ...draft, challenge: v as AcmeChallenge })}
                      >
                        <FormSelectOption
                          value="default"
                          label={cockpit.format(
                            _("Default ($0)"),
                            challengeLabel(defaultChallenge),
                          )}
                        />
                        <FormSelectOption
                          value="dns-cloudflare"
                          label={challengeLabel("dns-cloudflare")}
                        />
                        <FormSelectOption value="http" label={challengeLabel("http")} />
                      </FormSelect>
                    </FormGroup>
                    <FormGroup
                      label={_("HSTS")}
                      fieldId="rpHsts"
                      labelHelp={hint(
                        _(
                          "Send Strict-Transport-Security, so browsers refuse plain HTTP for these names for a year.",
                        ),
                      )}
                    >
                      <Switch
                        id="rpHsts"
                        isChecked={draft.hsts}
                        onChange={(_e, c) => setDraft({ ...draft, hsts: c })}
                        aria-label={_("HSTS")}
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
