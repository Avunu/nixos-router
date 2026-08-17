// Wireless controllers page — deliberately NOT a second management UI.
//
// UniFi and OpenWISP both ship substantial web applications of their own, and
// reimplementing any of that here would guarantee drift. This page owns exactly
// the parts Cockpit is better placed to answer: whether the controller is
// enabled, the handful of router-side settings that feed it (ports, domain,
// adoption), whether its containers are actually running, and a link straight
// into the real interface.
//
// The provisioning values for OpenWISP are here for the same reason: unlike
// UniFi, OpenWISP has no DHCP-based discovery at all, so every access point has
// to be pointed at the controller by hand. Making the exact URL copyable beats
// making someone reconstruct it from the domain and port options.
import { useEffect, useState } from "react";
import {
  Alert,
  Button,
  Card,
  CardBody,
  CardTitle,
  ClipboardCopy,
  DescriptionList,
  DescriptionListDescription,
  DescriptionListGroup,
  DescriptionListTerm,
  Form,
  FormGroup,
  Label,
  Split,
  SplitItem,
  Stack,
  StackItem,
  Switch,
  TextInput,
} from "@patternfly/react-core";
import { ExternalLinkAltIcon } from "@patternfly/react-icons";
import { useSettings, Loading, SubNav, SaveBar, hint, TabbedPage } from "./settings";
import { errMsg } from "./nix";

const _ = cockpit.gettext;

// The container units each controller owns. Names mirror the
// virtualisation.oci-containers.containers keys in the wireless modules.
const UNIFI_UNITS = ["podman-unifi-mongo.service", "podman-unifi.service"];
const OPENWISP_UNITS = [
  "podman-openwisp-dashboard.service",
  "podman-openwisp-api.service",
  "podman-openwisp-websocket.service",
  "podman-openwisp-celery.service",
  "podman-openwisp-celerybeat.service",
  "podman-openwisp-nginx.service",
];

type UnitState = { unit: string; active: string; sub: string };

// systemctl rather than the systemd D-Bus API: these are plain oneshot-ish
// container units and `show` gives everything needed in a single call, without
// the subscription bookkeeping a live D-Bus view would need.
const useUnits = (units: string[], enabled: boolean) => {
  const [rows, setRows] = useState<UnitState[] | null>(null);
  const [error, setError] = useState("");

  useEffect(() => {
    if (!enabled) {
      setRows(null);
      return;
    }
    let cancelled = false;
    const poll = () => {
      cockpit
        .spawn(["systemctl", "show", "--property=Id,ActiveState,SubState", "--value", ...units], {
          superuser: "try",
          err: "message",
        })
        .then((out: string) => {
          if (cancelled) {
            return;
          }
          // `--value` prints the three properties per unit, one per line, in
          // the order requested.
          const lines = out.trim().split("\n");
          const parsed: UnitState[] = units.map((unit, i) => ({
            unit,
            active: lines[i * 3 + 1] ?? "unknown",
            sub: lines[i * 3 + 2] ?? "",
          }));
          setRows(parsed);
          setError("");
        })
        .catch((e: unknown) => {
          if (!cancelled) {
            setError(errMsg(e));
          }
        });
    };
    poll();
    const timer = window.setInterval(poll, 5000);
    return () => {
      cancelled = true;
      window.clearInterval(timer);
    };
  }, [units, enabled]);

  return { rows, error };
};

const UnitStatus = ({ units, enabled }: { units: string[]; enabled: boolean }) => {
  const { rows, error } = useUnits(units, enabled);

  if (!enabled) {
    return null;
  }
  if (error) {
    return (
      <Alert variant="warning" isInline title={_("Could not read container status")}>
        {error}
      </Alert>
    );
  }
  if (!rows) {
    return <Loading />;
  }

  return (
    <DescriptionList isCompact isHorizontal>
      {rows.map((r) => (
        <DescriptionListGroup key={r.unit}>
          <DescriptionListTerm>{r.unit.replaceAll(/^podman-|\.service$/g, "")}</DescriptionListTerm>
          <DescriptionListDescription>
            <Label color={r.active === "active" ? "green" : r.active === "failed" ? "red" : "grey"}>
              {r.sub ? `${r.active} (${r.sub})` : r.active}
            </Label>
          </DescriptionListDescription>
        </DescriptionListGroup>
      ))}
    </DescriptionList>
  );
};

const OpenLink = ({ href, label }: { href: string; label: string }) => (
  <Button
    variant="primary"
    component="a"
    href={href}
    target="_blank"
    rel="noreferrer"
    icon={<ExternalLinkAltIcon />}
    iconPosition="end"
  >
    {label}
  </Button>
);

// ── UniFi ───────────────────────────────────────────────────────────────────
const Unifi = () => {
  const s = useSettings();
  if (!s.ready) {
    return s.error ? (
      <Alert variant="danger" isInline title={_("Could not load settings")}>
        {s.error}
      </Alert>
    ) : (
      <Loading />
    );
  }

  const enabled = s.valueOf<boolean>("wireless.unifi.enable", false);
  const lanAddress = s.valueOf<string>("lan.address", "");
  const option43 = s.valueOf<boolean>("wireless.unifi.dhcpOption43", true);
  const upnp = s.valueOf<boolean>("upnp.enable", false);
  const l2 = s.valueOf<boolean>("wireless.unifi.l2Discovery", false);

  return (
    <Stack hasGutter>
      <StackItem>
        <Card>
          <CardTitle>{_("UniFi Network Application")}</CardTitle>
          <CardBody>
            <Form isHorizontal>
              <FormGroup
                label={_("Enable")}
                labelHelp={hint(
                  _(
                    "Runs the UniFi controller on this router with its own MongoDB. " +
                      "Budget at least 2 GB of RAM for the pair.",
                  ),
                )}
              >
                <Switch
                  id="unifi-enable"
                  isChecked={enabled}
                  isDisabled={s.lockedOf("wireless.unifi.enable")}
                  onChange={(_e, v) => s.setLeaf("wireless.unifi.enable", v)}
                />
              </FormGroup>

              <FormGroup
                label={_("Advertise via DHCP option 43")}
                labelHelp={hint(
                  _(
                    "Tells factory-default access points where the controller is, " +
                      "so they appear for adoption without being configured first.",
                  ),
                )}
              >
                <Switch
                  id="unifi-option43"
                  isChecked={option43}
                  isDisabled={!enabled || s.lockedOf("wireless.unifi.dhcpOption43")}
                  onChange={(_e, v) => s.setLeaf("wireless.unifi.dhcpOption43", v)}
                />
              </FormGroup>

              <FormGroup
                label={_("Layer 2 discovery")}
                labelHelp={hint(
                  _(
                    "SSDP on 1900/udp, used by the UniFi mobile app. Conflicts with " +
                      "UPnP, which binds the same port. Adoption does not need it.",
                  ),
                )}
              >
                <Switch
                  id="unifi-l2"
                  isChecked={l2}
                  isDisabled={!enabled || upnp || s.lockedOf("wireless.unifi.l2Discovery")}
                  onChange={(_e, v) => s.setLeaf("wireless.unifi.l2Discovery", v)}
                />
              </FormGroup>
            </Form>

            {enabled && l2 && upnp ? (
              <Alert variant="danger" isInline title={_("Port conflict")}>
                {_(
                  "Layer 2 discovery and UPnP both need 1900/udp. Turn one off, or the " +
                    "configuration will not build.",
                )}
              </Alert>
            ) : null}
          </CardBody>
        </Card>
      </StackItem>

      {enabled ? (
        <>
          <StackItem>
            <Card>
              <CardTitle>{_("Management interface")}</CardTitle>
              <CardBody>
                <Stack hasGutter>
                  <StackItem>
                    <OpenLink
                      href={`https://${lanAddress}:8443/`}
                      label={_("Open UniFi Network")}
                    />
                  </StackItem>
                  <StackItem>
                    <Alert
                      variant="info"
                      isInline
                      isPlain
                      title={_("The controller uses a self-signed certificate.")}
                    />
                  </StackItem>
                </Stack>
              </CardBody>
            </Card>
          </StackItem>

          <StackItem>
            <Card>
              <CardTitle>{_("Adoption")}</CardTitle>
              <CardBody>
                <DescriptionList isCompact isHorizontal>
                  <DescriptionListGroup>
                    <DescriptionListTerm>{_("Inform URL")}</DescriptionListTerm>
                    <DescriptionListDescription>
                      <ClipboardCopy isReadOnly hoverTip={_("Copy")} clickTip={_("Copied")}>
                        {`http://${lanAddress}:8080/inform`}
                      </ClipboardCopy>
                    </DescriptionListDescription>
                  </DescriptionListGroup>
                </DescriptionList>
                <p>
                  {_(
                    "A device that has already been pointed elsewhere will not pick up " +
                      "option 43. Set it over SSH with `set-inform <URL>`, adopt it, then " +
                      "run the same command again — devices revert to their default " +
                      "inform URL partway through adoption.",
                  )}
                </p>
              </CardBody>
            </Card>
          </StackItem>

          <StackItem>
            <Card>
              <CardTitle>{_("Containers")}</CardTitle>
              <CardBody>
                <UnitStatus units={UNIFI_UNITS} enabled={enabled} />
              </CardBody>
            </Card>
          </StackItem>
        </>
      ) : null}

      <StackItem>
        <SaveBar saving={s.saving} status={s.status} onSave={s.save} onSaveApply={s.saveAndApply} />
      </StackItem>
    </Stack>
  );
};

// ── OpenWISP ────────────────────────────────────────────────────────────────
const OpenWisp = () => {
  const s = useSettings();
  if (!s.ready) {
    return s.error ? (
      <Alert variant="danger" isInline title={_("Could not load settings")}>
        {s.error}
      </Alert>
    ) : (
      <Loading />
    );
  }

  const enabled = s.valueOf<boolean>("wireless.openwisp.enable", false);
  const domain = s.valueOf<string>("wireless.openwisp.domain", "openwisp.home.arpa");
  const httpsPort = s.valueOf<number>("wireless.openwisp.httpsPort", 8444);
  const dashboardUrl = `https://dashboard.${domain}:${httpsPort}`;
  const apiUrl = `https://api.${domain}:${httpsPort}`;

  return (
    <Stack hasGutter>
      <StackItem>
        <Card>
          <CardTitle>{_("OpenWISP")}</CardTitle>
          <CardBody>
            <Form isHorizontal>
              <FormGroup
                label={_("Enable")}
                labelHelp={hint(
                  _(
                    "Runs the core OpenWISP stack — dashboard, API, websocket, workers " +
                      "and nginx — against this router's own PostgreSQL and Redis.",
                  ),
                )}
              >
                <Switch
                  id="openwisp-enable"
                  isChecked={enabled}
                  isDisabled={s.lockedOf("wireless.openwisp.enable")}
                  onChange={(_e, v) => s.setLeaf("wireless.openwisp.enable", v)}
                />
              </FormGroup>

              <FormGroup
                label={_("Domain")}
                labelHelp={hint(
                  _(
                    "Parent for the dashboard and API hostnames. It must be under a real " +
                      "public suffix — .lan, .local and .internal are not, and OpenWISP " +
                      "silently rejects every request when it cannot derive a cookie " +
                      "domain from it.",
                  ),
                )}
              >
                <TextInput
                  id="openwisp-domain"
                  value={domain}
                  isDisabled={!enabled || s.lockedOf("wireless.openwisp.domain")}
                  onChange={(_e, v) => s.setLeaf("wireless.openwisp.domain", v)}
                />
              </FormGroup>

              <FormGroup
                label={_("HTTPS port")}
                labelHelp={hint(
                  _(
                    "Not 443: the block page binds that on every interface. This port is " +
                      "part of the URL devices are configured with, so changing it later " +
                      "means reconfiguring them.",
                  ),
                )}
              >
                <TextInput
                  id="openwisp-https-port"
                  type="number"
                  value={httpsPort}
                  isDisabled={!enabled || s.lockedOf("wireless.openwisp.httpsPort")}
                  onChange={(_e, v) => s.setLeaf("wireless.openwisp.httpsPort", Number(v))}
                />
              </FormGroup>
            </Form>
          </CardBody>
        </Card>
      </StackItem>

      {enabled ? (
        <>
          <StackItem>
            <Card>
              <CardTitle>{_("Management interface")}</CardTitle>
              <CardBody>
                <Split hasGutter>
                  <SplitItem>
                    <OpenLink href={dashboardUrl} label={_("Open OpenWISP dashboard")} />
                  </SplitItem>
                </Split>
              </CardBody>
            </Card>
          </StackItem>

          <StackItem>
            <Card>
              <CardTitle>{_("Device provisioning")}</CardTitle>
              <CardBody>
                <Stack hasGutter>
                  <StackItem>
                    <Alert variant="info" isInline title={_("OpenWISP has no auto-discovery.")}>
                      {_(
                        "Unlike UniFi, there is no DHCP option that points devices here. " +
                          "Each access point runs the openwisp-config agent and must be " +
                          "given the API URL and its organisation's shared secret — either " +
                          "baked into the firmware image or set once on the device.",
                      )}
                    </Alert>
                  </StackItem>
                  <StackItem>
                    <DescriptionList isCompact isHorizontal>
                      <DescriptionListGroup>
                        <DescriptionListTerm>{_("Controller URL")}</DescriptionListTerm>
                        <DescriptionListDescription>
                          <ClipboardCopy isReadOnly hoverTip={_("Copy")} clickTip={_("Copied")}>
                            {apiUrl}
                          </ClipboardCopy>
                        </DescriptionListDescription>
                      </DescriptionListGroup>
                      <DescriptionListGroup>
                        <DescriptionListTerm>{_("On the device")}</DescriptionListTerm>
                        <DescriptionListDescription>
                          <ClipboardCopy isReadOnly hoverTip={_("Copy")} clickTip={_("Copied")}>
                            {`uci set openwisp.http.url='${apiUrl}'; uci set openwisp.http.shared_secret='<secret>'; uci commit openwisp`}
                          </ClipboardCopy>
                        </DescriptionListDescription>
                      </DescriptionListGroup>
                    </DescriptionList>
                  </StackItem>
                  <StackItem>
                    <p>
                      {_(
                        "The shared secret is per organisation and is shown in the OpenWISP " +
                          "dashboard under the organisation's settings.",
                      )}
                    </p>
                  </StackItem>
                </Stack>
              </CardBody>
            </Card>
          </StackItem>

          <StackItem>
            <Card>
              <CardTitle>{_("Containers")}</CardTitle>
              <CardBody>
                <UnitStatus units={OPENWISP_UNITS} enabled={enabled} />
              </CardBody>
            </Card>
          </StackItem>
        </>
      ) : null}

      <StackItem>
        <SaveBar saving={s.saving} status={s.status} onSave={s.save} onSaveApply={s.saveAndApply} />
      </StackItem>
    </Stack>
  );
};

export const Wireless = () => {
  const [tab, setTab] = useState("unifi");

  return (
    <TabbedPage
      subnav={
        <SubNav
          items={[
            { id: "unifi", label: _("UniFi") },
            { id: "openwisp", label: _("OpenWISP") },
          ]}
          active={tab}
          onSelect={setTab}
        />
      }
    >
      {tab === "unifi" ? <Unifi /> : <OpenWisp />}
    </TabbedPage>
  );
};
