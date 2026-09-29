// Ingress page: how services inside the network are reached from outside —
// static port forwards, the hostname-routing reverse proxy (with its ACME
// certificates), and the Cloudflare Tunnel. The tabs share the page's
// settings, so "Save and apply" is held back while any of them has errors.
//
// (Not ingress.tsx: that would shadow ingress.ts, the pure validation module
// modules/reverse-proxy.nix refers to.)
import { SubNav, TabbedPage, usePageSettings, useTabRoute, SettingsProvider } from "./settings";
import { SaveActions } from "./save-actions";
import { hasErrors, ingressContext } from "./ingress-widgets";
import { checkPage } from "./ingress";
import { PortForwards } from "./port-forwards";
import { ReverseProxy } from "./reverse-proxy";
import { Tunnel } from "./tunnel";

const _ = cockpit.gettext;

const TABS = ["forwards", "proxy", "tunnel"];

export const Ingress = () => {
  const s = usePageSettings();
  const [tab, setTab] = useTabRoute(TABS);

  let issues: string | undefined;
  if (s.ready) {
    const page = checkPage(ingressContext(s));
    const failing = [
      hasErrors(page.proxy) ? _("Reverse proxy") : null,
      hasErrors(page.tunnel) ? _("Tunnel") : null,
    ].filter((t) => t !== null);
    if (failing.length > 0) {
      issues = cockpit.format(_("Fix the errors on the $0 tab first"), failing.join(", "));
    }
  }

  return (
    <SettingsProvider value={s}>
      <TabbedPage
        subnav={
          <SubNav
            active={tab}
            onSelect={setTab}
            items={[
              { id: "forwards", label: _("Port forwards") },
              { id: "proxy", label: _("Reverse proxy") },
              { id: "tunnel", label: _("Tunnel") },
            ]}
          />
        }
        footer={s.ready ? <SaveActions s={s} issues={issues} /> : null}
      >
        {tab === "forwards" && <PortForwards />}
        {tab === "proxy" && <ReverseProxy />}
        {tab === "tunnel" && <Tunnel />}
      </TabbedPage>
    </SettingsProvider>
  );
};
