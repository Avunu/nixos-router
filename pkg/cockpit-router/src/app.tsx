import type { ReactNode } from "react";
import { Page, PageSidebar } from "@patternfly/react-core";
import { Hosts } from "./hosts";
import { Suricata } from "./suricata";
import { AdGuard } from "./adguard";
import { Diagnostics } from "./diagnostics";
import { Firewall } from "./firewall";
import { System } from "./system";
import { Network } from "./network";
import { ChangesTray } from "./changes";

// Hide the PatternFly 6 Page sidebar area (the Cockpit shell provides the real
// nav). <Page> itself supplies the scrollable main area + page padding, which a
// bare layout lacks; the empty sidebar removes the otherwise-reserved gutter.
const emptySidebar = <PageSidebar isSidebarOpen={false} />;

// Each Cockpit menu entry (see manifest.json) is its own top-level page that
// renders one of these views. The host HTML picks the view via `data-view`. Each
// view supplies its own PageSection(s) via TabbedPage, mirroring Cockpit's native
// pages (subnav section + content section as siblings under <Page>).
export const views: Record<string, ReactNode> = {
  network: <Network />,
  hosts: <Hosts />,
  ips: <Suricata />,
  dns: <AdGuard />,
  firewall: <Firewall />,
  system: <System />,
  diagnostics: <Diagnostics />,
};

export const App = ({ view }: { view: ReactNode }) => (
  <Page sidebar={emptySidebar} isContentFilled>
    <ChangesTray />
    {view}
  </Page>
);
