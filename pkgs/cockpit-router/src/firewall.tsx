// Firewall page: UPnP / NAT-PMP and the live nftables ruleset. Static port
// forwards moved to the Routing page (port-forwards.tsx).
import { useEffect, useState, useCallback } from "react";
import { errMsg } from "./nix";
import {
  Button,
  Alert,
  AlertActionLink,
  Stack,
  StackItem,
  Form,
  FormGroup,
  TextArea,
  Switch,
  Spinner,
  CodeBlock,
  CodeBlockCode,
  Split,
  SplitItem,
} from "@patternfly/react-core";
import { useSettings, Loading, SubNav, SaveBar, hint, TabbedPage } from "./settings";

const _ = cockpit.gettext;

// ── UPnP-IGD / NAT-PMP (miniupnpd) ──────────────────────────────────────────
const UpnpSettings = () => {
  const s = useSettings();

  if (!s.ready && !s.error) {
    return <Loading />;
  }
  if (s.error) {
    return (
      <Alert variant="danger" isInline title={_("Could not load UPnP settings")}>
        {s.error}
      </Alert>
    );
  }

  return (
    <Stack hasGutter className="ct-router-stack">
      <StackItem isFilled style={{ overflowY: "auto" }}>
        <Alert
          variant="info"
          isInline
          title={_(
            "UPnP lets LAN devices open inbound ports automatically, with no authentication. Enable only when needed; it is never offered to the guest network.",
          )}
          style={{ marginBlockEnd: "1rem" }}
        />
        <Form onSubmit={(e) => e.preventDefault()}>
          <FormGroup label={_("Enable UPnP / NAT-PMP")} fieldId="upnpEnable">
            <Switch
              id="upnpEnable"
              isChecked={Boolean(s.valueOf("upnp.enable", false))}
              isDisabled={s.lockedOf("upnp.enable")}
              onChange={(_e, c) => s.setLeaf("upnp.enable", c)}
              aria-label={_("Enable UPnP / NAT-PMP")}
            />
          </FormGroup>
          <FormGroup
            label={_("Extra miniupnpd.conf")}
            fieldId="upnpExtra"
            labelHelp={hint(_("Appended after the hardened defaults"))}
          >
            <TextArea
              id="upnpExtra"
              value={s.valueOf("upnp.extraConfig", "")}
              isDisabled={s.lockedOf("upnp.extraConfig")}
              onChange={(_e, v) => s.setLeaf("upnp.extraConfig", v)}
              rows={6}
              resizeOrientation="vertical"
              aria-label={_("Extra miniupnpd.conf")}
            />
          </FormGroup>
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

// ── Live nftables ruleset (read-only) ───────────────────────────────────────
const ActiveRules = () => {
  const [text, setText] = useState("");
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");

  // Fetch only (`loading` starts true for the mount effect); Refresh shows
  // the spinner first.
  const fetchRules = useCallback(() => {
    cockpit
      .spawn(["nft", "list", "ruleset"], { superuser: "require", err: "message" })
      .then((out: string) => {
        setText(out || "");
        setError("");
        setLoading(false);
      })
      .catch((e: unknown) => {
        setError(errMsg(e));
        setLoading(false);
      });
  }, []);

  const load = () => {
    setLoading(true);
    setError("");
    fetchRules();
  };

  useEffect(() => {
    fetchRules();
  }, [fetchRules]);

  return (
    <Stack hasGutter className="ct-router-stack">
      <StackItem>
        <Split>
          <SplitItem isFilled />
          <SplitItem>
            <Button variant="secondary" onClick={load} isDisabled={loading}>
              {_("Refresh")}
            </Button>
          </SplitItem>
        </Split>
      </StackItem>
      {error && (
        <StackItem>
          <Alert variant="danger" isInline title={_("Could not read the ruleset")}>
            {error}
          </Alert>
        </StackItem>
      )}
      <StackItem isFilled style={{ overflow: "auto", minBlockSize: 0 }}>
        {loading ? (
          <Spinner />
        ) : (
          <CodeBlock>
            <CodeBlockCode>{text}</CodeBlockCode>
          </CodeBlock>
        )}
      </StackItem>
    </Stack>
  );
};

export const Firewall = () => {
  const [tab, setTab] = useState("upnp");
  return (
    <TabbedPage
      header={
        <Alert
          variant="info"
          isInline
          isPlain
          title={_("Port forwards have moved to the Routing page.")}
          actionLinks={
            <AlertActionLink onClick={() => cockpit.jump("/router/routing")}>
              {_("Go to Routing")}
            </AlertActionLink>
          }
        />
      }
      subnav={
        <SubNav
          active={tab}
          onSelect={setTab}
          items={[
            { id: "upnp", label: _("UPnP") },
            { id: "rules", label: _("Active rules") },
          ]}
        />
      }
    >
      {tab === "upnp" && <UpnpSettings />}
      {tab === "rules" && <ActiveRules />}
    </TabbedPage>
  );
};
