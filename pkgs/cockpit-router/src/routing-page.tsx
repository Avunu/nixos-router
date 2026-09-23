// Routing page: how services inside the network are reached from outside —
// static port forwards, the hostname-routing reverse proxy (with its ACME
// certificates), and the Cloudflare Tunnel. Each tab owns its useSettings().
//
// (Not routing.tsx: that would shadow routing.ts, the pure validation module
// modules/reverse-proxy.nix refers to.)
import { useState } from "react";
import { SubNav, TabbedPage } from "./settings";
import { PortForwards } from "./port-forwards";
import { ReverseProxy } from "./reverse-proxy";
import { Tunnel } from "./tunnel";

const _ = cockpit.gettext;

export const Routing = () => {
  const [tab, setTab] = useState("forwards");
  return (
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
    >
      {tab === "forwards" && <PortForwards />}
      {tab === "proxy" && <ReverseProxy />}
      {tab === "tunnel" && <Tunnel />}
    </TabbedPage>
  );
};
