// Network → Dynamic DNS: router.ddns settings (Cloudflare), the public names
// hosts carry (edited on the Hosts page), and the last router-ddns run.
//
// The API token itself never enters the settings JSON: the form stores a path,
// and "Set token" writes the token to that root-owned file (see ddns.ts).
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
  Form,
  FormGroup,
  FormSection,
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
import { ListEditor, hint } from "./settings";
import type { useSettings } from "./settings";
import { getPath, errMsg } from "./nix";
import { isHostname } from "./ip-math";
import { loadDdnsStatus, updateNow, saveToken, DEFAULT_TOKEN_FILE } from "./ddns";
import type { DdnsRecordStatus, DdnsStatus, RouterHost } from "./types";

const _ = cockpit.gettext;

type S = ReturnType<typeof useSettings>;

const stateColor = (st: DdnsRecordStatus["state"]) =>
  st === "error" ? "red" : st === "skipped" ? "orange" : st === "unchanged" ? "grey" : "green";

const validTtl = (n: number) => n === 1 || (n >= 60 && n <= 86_400);

// ── Token writer ────────────────────────────────────────────────────────────
const TokenForm = ({ path, onDone }: { path: string; onDone: (msg: string) => void }) => {
  const [token, setToken] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const save = () => {
    setBusy(true);
    setError("");
    saveToken(path, token)
      .then(() => {
        setToken("");
        onDone(cockpit.format(_("Token saved to $0."), path));
      })
      .catch((e: unknown) => setError(errMsg(e)))
      .finally(() => setBusy(false));
  };
  return (
    <Card isCompact>
      <CardTitle>{_("Set Cloudflare API token")}</CardTitle>
      <CardBody>
        <Form isHorizontal onSubmit={(e) => e.preventDefault()}>
          <FormGroup
            label={_("API token")}
            fieldId="ddnsToken"
            labelHelp={hint(
              _(
                "Create a token in the Cloudflare dashboard (My Profile → API Tokens) with Zone → Zone → Read and Zone → DNS → Edit on the zones of your names.",
              ),
            )}
          >
            <TextInput
              id="ddnsToken"
              type="password"
              value={token}
              autoComplete="off"
              onChange={(_e, v) => setToken(v)}
            />
            <HelperText>
              <HelperTextItem>
                {cockpit.format(_("Written to $0 (root only, never to the settings file)."), path)}
              </HelperTextItem>
            </HelperText>
          </FormGroup>
          {error && <Alert variant="danger" isInline isPlain title={error} />}
          <ActionGroup>
            <Button
              variant="secondary"
              onClick={save}
              isDisabled={!token.trim() || busy}
              isLoading={busy}
            >
              {_("Save token")}
            </Button>
            <Button variant="link" onClick={() => onDone("")}>
              {_("Cancel")}
            </Button>
          </ActionGroup>
        </Form>
      </CardBody>
    </Card>
  );
};

// ── Last run ────────────────────────────────────────────────────────────────
const StatusCard = ({ active }: { active: boolean }) => {
  const [status, setStatus] = useState<DdnsStatus | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");

  const reload = useCallback(() => {
    void loadDdnsStatus().then(setStatus);
  }, []);
  useEffect(() => {
    reload();
  }, [reload]);

  const run = () => {
    setBusy(true);
    setError("");
    updateNow()
      .catch((e: unknown) => setError(errMsg(e)))
      .finally(() => {
        setBusy(false);
        reload();
      });
  };

  return (
    <Card isCompact>
      <CardTitle>
        <Split hasGutter>
          <SplitItem isFilled>{_("Last update")}</SplitItem>
          <SplitItem>
            <Button variant="secondary" onClick={run} isDisabled={!active || busy} isLoading={busy}>
              {_("Update now")}
            </Button>
          </SplitItem>
        </Split>
      </CardTitle>
      <CardBody>
        <Stack hasGutter>
          {!active && (
            <StackItem>
              <Alert
                variant="info"
                isInline
                isPlain
                title={_("Dynamic DNS is not running — enable it and apply the configuration.")}
              />
            </StackItem>
          )}
          {error && (
            <StackItem>
              <Alert variant="danger" isInline isPlain title={_("The update run failed")}>
                {error}
              </Alert>
            </StackItem>
          )}
          {!status ? (
            <StackItem>{_("No update has run yet.")}</StackItem>
          ) : (
            <>
              <StackItem>
                <DescriptionList isHorizontal isCompact>
                  <DescriptionListGroup>
                    <DescriptionListTerm>{_("Last run")}</DescriptionListTerm>
                    <DescriptionListDescription>
                      {status.lastRun ?? "—"}{" "}
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
                    <DescriptionListTerm>{_("WAN IPv4")}</DescriptionListTerm>
                    <DescriptionListDescription>
                      {status.addresses?.ipv4 ?? _("none")}
                      {status.addresses?.ipv4Source === "trace" &&
                        ` ${_("(behind another NAT — detected via Cloudflare)")}`}
                    </DescriptionListDescription>
                  </DescriptionListGroup>
                  <DescriptionListGroup>
                    <DescriptionListTerm>{_("Router IPv6")}</DescriptionListTerm>
                    <DescriptionListDescription>
                      {status.addresses?.ipv6 ?? _("none")}
                    </DescriptionListDescription>
                  </DescriptionListGroup>
                </DescriptionList>
              </StackItem>
              {(status.records ?? []).length > 0 && (
                <StackItem>
                  <Table variant="compact" aria-label={_("Published records")}>
                    <Thead>
                      <Tr>
                        <Th>{_("Name")}</Th>
                        <Th>{_("Type")}</Th>
                        <Th>{_("Address")}</Th>
                        <Th>{_("Result")}</Th>
                      </Tr>
                    </Thead>
                    <Tbody>
                      {(status.records ?? []).map((r) => (
                        <Tr key={`${r.name}/${r.type}`}>
                          <Td>
                            {r.name}
                            {r.host && <small>{` (${r.host})`}</small>}
                          </Td>
                          <Td>{r.type}</Td>
                          <Td>{r.content ?? "—"}</Td>
                          <Td>
                            <Label color={stateColor(r.state)} isCompact>
                              {r.state}
                            </Label>
                            {r.detail && <small>{` ${r.detail}`}</small>}
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
export const DynamicDnsTab = ({ s }: { s: S }) => {
  const [tokenOpen, setTokenOpen] = useState(false);
  const [tokenMsg, setTokenMsg] = useState("");

  const enabled = Boolean(s.valueOf("ddns.enable", false));
  const tokenFile = s.valueOf<string | null>("ddns.cloudflare.apiTokenFile", null) ?? "";
  const names = s.valueOf<string[]>("ddns.names", []);
  const ttl = s.valueOf<number>("ddns.ttl", 1);
  const interval = s.valueOf<number>("ddns.intervalMinutes", 5);
  const hosts = s.valueOf<RouterHost[]>("hosts", []).filter((h) => h.publicHostname);
  const badNames = names.filter((n) => !isHostname(n));
  // The unit exists only once an enabled config has been applied.
  const active = getPath(s.effective, "ddns.enable") === true;

  return (
    <Stack hasGutter>
      <StackItem>
        <Form isHorizontal onSubmit={(e) => e.preventDefault()}>
          <FormGroup label={_("Enable dynamic DNS")} fieldId="ddnsEnable">
            <Switch
              id="ddnsEnable"
              isChecked={enabled}
              isDisabled={s.lockedOf("ddns.enable")}
              onChange={(_e, c) => s.setLeaf("ddns.enable", c)}
              aria-label={_("Enable dynamic DNS")}
            />
          </FormGroup>
          <FormGroup
            label={_("Cloudflare API token file")}
            fieldId="ddnsTokenFile"
            isRequired={enabled}
            labelHelp={hint(_("Path to a root-owned file on the router — never the token itself."))}
          >
            <Split hasGutter>
              <SplitItem isFilled>
                <TextInput
                  id="ddnsTokenFile"
                  value={tokenFile}
                  placeholder={DEFAULT_TOKEN_FILE}
                  isDisabled={s.lockedOf("ddns.cloudflare.apiTokenFile")}
                  validated={enabled && !tokenFile ? "error" : "default"}
                  onChange={(_e, v) => s.setLeaf("ddns.cloudflare.apiTokenFile", v || null)}
                />
              </SplitItem>
              <SplitItem>
                <Button
                  variant="secondary"
                  onClick={() => {
                    if (!tokenFile) {
                      s.setLeaf("ddns.cloudflare.apiTokenFile", DEFAULT_TOKEN_FILE);
                    }
                    setTokenMsg("");
                    setTokenOpen(true);
                  }}
                >
                  {_("Set token…")}
                </Button>
              </SplitItem>
            </Split>
            {tokenMsg && (
              <HelperText>
                <HelperTextItem variant="success">{tokenMsg}</HelperTextItem>
              </HelperText>
            )}
          </FormGroup>
          {tokenOpen && (
            <TokenForm
              path={tokenFile || DEFAULT_TOKEN_FILE}
              onDone={(msg) => {
                setTokenMsg(msg);
                setTokenOpen(false);
              }}
            />
          )}
          <FormGroup
            label={_("Router names")}
            fieldId="ddnsNames"
            labelHelp={hint(
              _(
                "Public names for the router itself: A = the WAN IPv4 address, AAAA = the router's own IPv6 address. Devices get their own names on the Hosts page.",
              ),
            )}
          >
            <ListEditor
              value={names}
              placeholder="home.example.com"
              isDisabled={s.lockedOf("ddns.names")}
              onChange={(v) =>
                s.setLeaf(
                  "ddns.names",
                  v.map((n) => n.toLowerCase()),
                )
              }
            />
            {badNames.length > 0 && (
              <HelperText>
                <HelperTextItem variant="error">
                  {cockpit.format(_("Not a valid DNS name: $0"), badNames.join(", "))}
                </HelperTextItem>
              </HelperText>
            )}
          </FormGroup>
          <FormGroup label={_("Device names")} fieldId="ddnsHosts">
            {hosts.length === 0 ? (
              <HelperText>
                <HelperTextItem>
                  {_("No device has a public hostname — set one on the Hosts page.")}
                </HelperTextItem>
              </HelperText>
            ) : (
              <HelperText>
                {hosts.map((h) => (
                  <HelperTextItem key={h.mac}>
                    {cockpit.format(
                      h.ipv6Suffix
                        ? _("$0 → $1 (A + AAAA)")
                        : _("$0 → $1 (A only — no IPv6 suffix)"),
                      h.publicHostname,
                      h.name,
                    )}
                  </HelperTextItem>
                ))}
              </HelperText>
            )}
          </FormGroup>
          <FormSection title={_("Records")} titleElement="h2">
            <FormGroup label={_("Publish IPv4 (A)")} fieldId="ddnsV4">
              <Switch
                id="ddnsV4"
                isChecked={Boolean(s.valueOf("ddns.ipv4", true))}
                isDisabled={s.lockedOf("ddns.ipv4")}
                onChange={(_e, c) => s.setLeaf("ddns.ipv4", c)}
                aria-label={_("Publish IPv4 (A)")}
              />
            </FormGroup>
            <FormGroup label={_("Publish IPv6 (AAAA)")} fieldId="ddnsV6">
              <Switch
                id="ddnsV6"
                isChecked={Boolean(s.valueOf("ddns.ipv6", true))}
                isDisabled={s.lockedOf("ddns.ipv6")}
                onChange={(_e, c) => s.setLeaf("ddns.ipv6", c)}
                aria-label={_("Publish IPv6 (AAAA)")}
              />
            </FormGroup>
            <FormGroup
              label={_("Proxy through Cloudflare")}
              fieldId="ddnsProxied"
              labelHelp={hint(
                _(
                  "Orange-cloud the records. Only HTTP(S) on Cloudflare's supported ports passes a proxied name — leave off for anything else a port forward exposes.",
                ),
              )}
            >
              <Switch
                id="ddnsProxied"
                isChecked={Boolean(s.valueOf("ddns.proxied", false))}
                isDisabled={s.lockedOf("ddns.proxied")}
                onChange={(_e, c) => s.setLeaf("ddns.proxied", c)}
                aria-label={_("Proxy through Cloudflare")}
              />
            </FormGroup>
            <FormGroup
              label={_("TTL (seconds)")}
              fieldId="ddnsTtl"
              labelHelp={hint(_("1 for Cloudflare's automatic TTL, otherwise 60-86400."))}
            >
              <TextInput
                id="ddnsTtl"
                type="number"
                value={ttl}
                isDisabled={s.lockedOf("ddns.ttl")}
                validated={validTtl(ttl) ? "default" : "error"}
                onChange={(_e, v) => s.setLeaf("ddns.ttl", Number(v))}
              />
            </FormGroup>
            <FormGroup label={_("Check every (minutes)")} fieldId="ddnsInterval">
              <TextInput
                id="ddnsInterval"
                type="number"
                value={interval}
                isDisabled={s.lockedOf("ddns.intervalMinutes")}
                validated={interval >= 1 && interval <= 1440 ? "default" : "error"}
                onChange={(_e, v) => s.setLeaf("ddns.intervalMinutes", Number(v))}
              />
            </FormGroup>
          </FormSection>
        </Form>
      </StackItem>
      <StackItem>
        <StatusCard active={active} />
      </StackItem>
    </Stack>
  );
};
