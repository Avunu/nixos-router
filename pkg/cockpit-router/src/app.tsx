import { useState } from "react";
import {
  Page,
  PageSidebar,
  PageSection,
  Tabs,
  Tab,
  TabTitleText,
} from "@patternfly/react-core";
import { Hosts } from "./hosts";
import { Suricata } from "./suricata";
import { AdGuard } from "./adguard";
import { Diagnostics } from "./diagnostics";

const _ = cockpit.gettext;

// Hide the PatternFly 6 Page sidebar area (the Cockpit shell provides the real
// nav). <Page> itself supplies the scrollable main area + page padding, which a
// bare layout lacks; the empty sidebar removes the otherwise-reserved gutter.
const emptySidebar = <PageSidebar isSidebarOpen={false} />;

export const App = () => {
  const [active, setActive] = useState<number | string>(0);

  return (
    <Page sidebar={emptySidebar}>
      <PageSection
        hasBodyWrapper={false}
        stickyOnBreakpoint={{ default: "top" }}
      >
        <Tabs
          activeKey={active}
          onSelect={(_e, key) => setActive(key)}
          isBox
          aria-label={_("Router")}
        >
          <Tab eventKey={0} title={<TabTitleText>{_("Connected hosts")}</TabTitleText>} />
          <Tab eventKey={1} title={<TabTitleText>{_("Suricata events")}</TabTitleText>} />
          <Tab eventKey={2} title={<TabTitleText>{_("AdGuard events")}</TabTitleText>} />
          <Tab eventKey={3} title={<TabTitleText>{_("Diagnostics")}</TabTitleText>} />
        </Tabs>
      </PageSection>
      <PageSection isFilled className="ct-router-body">
        {active === 0 && <Hosts />}
        {active === 1 && <Suricata />}
        {active === 2 && <AdGuard />}
        {active === 3 && <Diagnostics />}
      </PageSection>
    </Page>
  );
};
