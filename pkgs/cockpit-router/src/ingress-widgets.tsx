// Pieces shared by the Ingress tabs (and Network → Dynamic DNS): the API
// token path + writer, host labels, unit-state labels, and the text for the
// validation issues ingress.ts reports by code.
import { useState } from "react";
import type { ReactNode } from "react";
import {
  ActionGroup,
  Alert,
  Button,
  Card,
  CardBody,
  CardTitle,
  Form,
  FormGroup,
  HelperText,
  HelperTextItem,
  Label,
  Split,
  SplitItem,
  TextInput,
} from "@patternfly/react-core";
import { hint } from "./settings";
import type { useSettings } from "./settings";
import { errMsg } from "./nix";
import { saveSecret } from "./ddns";
import type { IngressContext, IngressIssue } from "./ingress";
import type { UnitState } from "./ingress-runtime";
import type {
  AcmeSettings,
  CloudflareTunnelSettings,
  PortForward,
  ReverseProxySettings,
  RouterHost,
} from "./types";

const _ = cockpit.gettext;

type S = ReturnType<typeof useSettings>;

export const hostDetail = (h: RouterHost | undefined) =>
  h ? [h.staticIp, h.ipv6Suffix].filter(Boolean).join(" · ") || _("no addresses") : "";

// The settings the Ingress checks read, with the module defaults filled in.
export const ingressContext = (s: S): IngressContext => {
  const proxy = s.valueOf<ReverseProxySettings>("reverseProxy", {});
  const tunnel = s.valueOf<CloudflareTunnelSettings>("cloudflareTunnel", {});
  return {
    hosts: s.valueOf<RouterHost[]>("hosts", []),
    portForwards: s.valueOf<PortForward[]>("portForwards", []),
    ddns: {
      enable: Boolean(s.valueOf("ddns.enable", false)),
      names: s.valueOf<string[]>("ddns.names", []),
    },
    acme: s.valueOf<AcmeSettings>("acme", {}),
    proxy: {
      enable: Boolean(proxy.enable),
      publishDns: proxy.publishDns ?? true,
      routes: proxy.routes ?? [],
    },
    tunnel: {
      enable: Boolean(tunnel.enable),
      apiTokenFile: tunnel.apiTokenFile ?? null,
      ingress: tunnel.ingress ?? [],
    },
  };
};

// ── Issues ──────────────────────────────────────────────────────────────────
const list = (it: IngressIssue) => (it.names ?? []).join(", ");

function issueBody(it: IngressIssue): string {
  switch (it.code) {
    case "noHostnames": {
      return _("Enter at least one public hostname.");
    }
    case "badHostname": {
      return cockpit.format(_("Not a valid public DNS name: $0"), list(it));
    }
    case "noHost": {
      return _("Choose the host to send the traffic to.");
    }
    case "unknownHost": {
      return cockpit.format(_("Host '$0' is not registered."), list(it));
    }
    case "noStaticIp": {
      return cockpit.format(
        _("$0 has no static IP to send the traffic to — reserve one on the Hosts page."),
        list(it),
      );
    }
    case "badPort": {
      return _("Enter a port between 1 and 65535.");
    }
    case "wildcardNeedsDns": {
      return _(
        "A wildcard hostname needs a DNS-01 certificate — choose the Cloudflare DNS challenge.",
      );
    }
    case "dnsNeedsToken": {
      return _(
        "The Cloudflare DNS challenge needs an API token — set the token file under Certificates.",
      );
    }
    case "httpNotPublished": {
      return _(
        "The HTTP challenge needs these names to resolve to the router, and publishing them is off — point them at the router yourself.",
      );
    }
    case "dupRoute": {
      return cockpit.format(_("$0 already appears in another route."), list(it));
    }
    case "dupIngress": {
      return cockpit.format(_("$0 already has a tunnel entry."), list(it));
    }
    case "clashDdns": {
      return cockpit.format(
        _("$0 is also a dynamic DNS router name — remove it there (Network → Dynamic DNS)."),
        list(it),
      );
    }
    case "clashPublicHost": {
      return cockpit.format(
        _("$0 is also a host's public hostname — a name can point one way only."),
        list(it),
      );
    }
    case "clashTunnel": {
      return cockpit.format(_("$0 is also served through the Cloudflare Tunnel."), list(it));
    }
    case "clashProxy": {
      return cockpit.format(_("$0 is also a reverse proxy route."), list(it));
    }
    case "acmeTerms": {
      return _("Accept the Let's Encrypt terms of service before certificates can be requested.");
    }
    case "acmeEmail": {
      return _("Set a contact email for the certificates.");
    }
    case "publishWithoutDdns": {
      return _(
        "Publishing the hostnames needs dynamic DNS, which is off — enable it (Network → Dynamic DNS) or point the names at the router yourself.",
      );
    }
    case "forwardOnWeb": {
      return cockpit.format(
        _(
          "Port forward(s) $0 forward tcp 80/443 over IPv4, which belong to the reverse proxy — route the host here instead, or make the forward IPv6 only.",
        ),
        list(it),
      );
    }
    case "tunnelToken": {
      return _("The tunnel needs a Cloudflare API token file.");
    }
    case "tunnelNoIngress": {
      return _(
        "The tunnel has no hostnames, so its connector doesn't run. Add a hostname and the router creates the tunnel, or reuses the one it already has.",
      );
    }
    default: {
      return it.code;
    }
  }
}

export const issueText = (it: IngressIssue) =>
  it.subject ? `${it.subject}: ${issueBody(it)}` : issueBody(it);

export const hasErrors = (issues: IngressIssue[]) => issues.some((it) => it.level === "error");

export const IssueList = ({ issues }: { issues: IngressIssue[] }) =>
  issues.length > 0 ? (
    <HelperText>
      {issues.map((it) => (
        <HelperTextItem key={issueText(it)} variant={it.level}>
          {issueText(it)}
        </HelperTextItem>
      ))}
    </HelperText>
  ) : null;

// ── Unit state ──────────────────────────────────────────────────────────────
export const UnitLabel = ({ state }: { state: UnitState | null }) => {
  if (!state?.activeState) {
    return (
      <Label color="grey" isCompact>
        {_("unknown")}
      </Label>
    );
  }
  const color =
    state.activeState === "active"
      ? "green"
      : state.activeState === "failed"
        ? "red"
        : state.activeState === "activating" || state.activeState === "reloading"
          ? "blue"
          : "grey";
  return (
    <Label color={color} isCompact>
      {state.activeState}
    </Label>
  );
};

// ── API token ───────────────────────────────────────────────────────────────
// The token itself never enters the settings JSON: the form stores a path,
// and "Set token" writes the token to that root-owned file (saveSecret).
export const TokenForm = ({
  path,
  fieldId,
  scopes,
  onDone,
}: {
  path: string;
  fieldId: string;
  scopes: string;
  onDone: (msg: string) => void;
}) => {
  const [token, setToken] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const save = () => {
    setBusy(true);
    setError("");
    saveSecret(path, token)
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
          <FormGroup label={_("API token")} fieldId={fieldId} labelHelp={hint(scopes)}>
            <TextInput
              id={fieldId}
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

// The token-file path field, its "Set token…" button and the writer card, for
// a settings leaf holding `string | null`. Renders inside the caller's Form.
export const TokenFileField = ({
  s,
  leaf,
  fieldId,
  defaultFile,
  scopes,
  isRequired,
  label = _("Cloudflare API token file"),
  helper,
  extra,
}: {
  s: S;
  leaf: string;
  fieldId: string;
  defaultFile: string;
  scopes: string;
  isRequired?: boolean;
  label?: string;
  helper?: ReactNode;
  extra?: ReactNode;
}) => {
  const [open, setOpen] = useState(false);
  const [msg, setMsg] = useState("");
  const file = s.valueOf<string | null>(leaf, null) ?? "";
  return (
    <>
      <FormGroup
        label={label}
        fieldId={fieldId}
        isRequired={isRequired}
        labelHelp={hint(_("Path to a root-owned file on the router — never the token itself."))}
      >
        <Split hasGutter>
          <SplitItem isFilled>
            <TextInput
              id={fieldId}
              value={file}
              placeholder={defaultFile}
              isDisabled={s.lockedOf(leaf)}
              validated={isRequired && !file ? "error" : "default"}
              onChange={(_e, v) => s.setLeaf(leaf, v || null)}
            />
          </SplitItem>
          {extra && <SplitItem>{extra}</SplitItem>}
          <SplitItem>
            <Button
              variant="secondary"
              onClick={() => {
                if (!file) {
                  s.setLeaf(leaf, defaultFile);
                }
                setMsg("");
                setOpen(true);
              }}
            >
              {_("Set token…")}
            </Button>
          </SplitItem>
        </Split>
        {(msg || helper) && (
          <HelperText>
            {msg && <HelperTextItem variant="success">{msg}</HelperTextItem>}
            {helper && <HelperTextItem>{helper}</HelperTextItem>}
          </HelperText>
        )}
      </FormGroup>
      {open && (
        <TokenForm
          path={file || defaultFile}
          fieldId={`${fieldId}Value`}
          scopes={scopes}
          onDone={(m) => {
            setMsg(m);
            setOpen(false);
          }}
        />
      )}
    </>
  );
};
