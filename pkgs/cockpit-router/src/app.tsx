import type { ReactNode } from "react";
import { Page, PageSidebar } from "@patternfly/react-core";
import { Suricata } from "./suricata";
import { AccessPolicies } from "./access-policies";
import { Hosts } from "./hosts";
import { Users } from "./users";
import { Reports } from "./reports";
import { Firewall } from "./firewall";
import { System } from "./system";
import { Network } from "./network";
import { Wireless } from "./wireless";
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
  reports: <Reports />,
  "access-policies": <AccessPolicies />,
  hosts: <Hosts />,
  users: <Users />,
  network: <Network />,
  "threat-protection": <Suricata />,
  firewall: <Firewall />,
  wireless: <Wireless />,
  system: <System />,
};

export const App = ({ view }: { view: ReactNode }) => (
  <Page sidebar={emptySidebar} isContentFilled>
    <ChangesTray />
    {view}
  </Page>
);
