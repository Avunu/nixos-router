import type { ReactNode } from "react";
import { Page, PageSidebar, PageSection } from "@patternfly/react-core";
import { Hosts } from "./hosts";
import { Suricata } from "./suricata";
import { AdGuard } from "./adguard";
import { Diagnostics } from "./diagnostics";
import { Firewall } from "./firewall";
import { System } from "./system";

// Hide the PatternFly 6 Page sidebar area (the Cockpit shell provides the real
// nav). <Page> itself supplies the scrollable main area + page padding, which a
// bare layout lacks; the empty sidebar removes the otherwise-reserved gutter.
const emptySidebar = <PageSidebar isSidebarOpen={false} />;

interface View {
  node: ReactNode;
  // Fill views own an internal scroll region (their sticky-header table scrolls
  // inside an InnerScrollContainer), so the page section must be bounded to the
  // viewport and never scroll itself. Non-fill views (Diagnostics) hold
  // free-flowing content and scroll the page section normally.
  fills: boolean;
}

// Each Cockpit menu entry (see manifest.json) is its own top-level page that
// renders one of these views. The host HTML picks the view via `data-view`.
export const views: Record<string, View> = {
  hosts: { node: <Hosts />, fills: true },
  ips: { node: <Suricata />, fills: true },
  dns: { node: <AdGuard />, fills: true },
  firewall: { node: <Firewall />, fills: true },
  system: { node: <System />, fills: true },
  diagnostics: { node: <Diagnostics />, fills: false },
};

export const App = ({ view }: { view: View | null }) => (
  <Page sidebar={emptySidebar} isContentFilled>
    <PageSection isFilled className={view?.fills ? "ct-router-body" : undefined}>
      {view?.node}
    </PageSection>
  </Page>
);
