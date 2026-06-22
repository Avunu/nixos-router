import { useState } from "react";
import { PageSection, Tabs, Tab, TabTitleText } from "@patternfly/react-core";
import { Hosts } from "./hosts";
import { Suricata } from "./suricata";
import { AdGuard } from "./adguard";
import { Diagnostics } from "./diagnostics";

const _ = cockpit.gettext;

export const App = () => {
  const [active, setActive] = useState<number | string>(0);

  // No <Page> wrapper: the Cockpit shell already provides the page frame, so
  // the plugin renders content directly into #app.ct-page-fill (matches the
  // native pages and avoids the extra left gutter a nested <Page> introduces).
  return (
    <Tabs
      activeKey={active}
      onSelect={(_e, key) => setActive(key)}
      isBox
      aria-label={_("Router")}
    >
      <Tab eventKey={0} title={<TabTitleText>{_("Connected hosts")}</TabTitleText>}>
        <PageSection>{active === 0 && <Hosts />}</PageSection>
      </Tab>
      <Tab eventKey={1} title={<TabTitleText>{_("Suricata events")}</TabTitleText>}>
        <PageSection>{active === 1 && <Suricata />}</PageSection>
      </Tab>
      <Tab eventKey={2} title={<TabTitleText>{_("AdGuard events")}</TabTitleText>}>
        <PageSection>{active === 2 && <AdGuard />}</PageSection>
      </Tab>
      <Tab eventKey={3} title={<TabTitleText>{_("Diagnostics")}</TabTitleText>}>
        <PageSection>{active === 3 && <Diagnostics />}</PageSection>
      </Tab>
    </Tabs>
  );
};
