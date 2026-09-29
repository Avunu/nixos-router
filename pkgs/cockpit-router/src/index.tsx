// Cockpit dark/light theme bridge — must be imported once per page so the
// Plugin follows the shell's theme (listens for the shell's `cockpit-style`
// Event). Then Cockpit's flavored PatternFly theme, then local tweaks.
import "cockpit-dark-theme";
import "patternfly/patternfly-6-cockpit.scss";
import "./app.scss";

import { createRoot } from "react-dom/client";
import { App, views } from "./app";
import { SystemStatus } from "./changes";

document.addEventListener("DOMContentLoaded", () => {
  const el = document.querySelector("#app");
  if (!(el instanceof HTMLElement)) {
    return;
  }
  const name = el.dataset.view ?? "";
  const root = createRoot(el);
  const show = () => root.render(<App view={views[name] ?? null} />);
  if (name !== "system") {
    show();
    return;
  }
  // The System page is preloaded (manifest.json) for its sidebar status, and
  // stays hidden until the admin opens it — perhaps never. Until then it only
  // publishes that status: no generation list, no forms. The shell says
  // whether a page is shown in a hint it sends right after answering the
  // page's init, so that is only known once the transport is up and the
  // message queued behind its answer has been handled.
  root.render(<SystemStatus />);
  cockpit.transport.wait(() => {
    window.setTimeout(() => {
      if (!cockpit.hidden) {
        show();
        return;
      }
      const onVisible = () => {
        if (!cockpit.hidden) {
          cockpit.removeEventListener("visibilitychange", onVisible);
          show();
        }
      };
      cockpit.addEventListener("visibilitychange", onVisible);
    }, 0);
  });
});
