import type { ReactNode } from "react";
import { Page, PageSidebar, PageSection } from "@patternfly/react-core";
import { Hosts } from "./hosts";
import { Suricata } from "./suricata";
import { AdGuard } from "./adguard";
import { Diagnostics } from "./diagnostics";

// Hide the PatternFly 6 Page sidebar area (the Cockpit shell provides the real
// nav). <Page> itself supplies the scrollable main area + page padding, which a
// bare layout lacks; the empty sidebar removes the otherwise-reserved gutter.
const emptySidebar = <PageSidebar isSidebarOpen={false} />;

// Each Cockpit menu entry (see manifest.json) is its own top-level page that
// renders one of these views. The host HTML picks the view via `data-view`.
export const views: Record<string, ReactNode> = {
  hosts: <Hosts />,
  ips: <Suricata />,
  dns: <AdGuard />,
  diagnostics: <Diagnostics />,
};

export const App = ({ view }: { view: ReactNode }) => (
  <Page sidebar={emptySidebar}>
    <PageSection isFilled className="ct-router-body">
      {view}
    </PageSection>
  </Page>
);
