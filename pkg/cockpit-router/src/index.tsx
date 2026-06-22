// Cockpit dark/light theme bridge — must be imported once per page so the
// plugin follows the shell's theme (listens for the shell's `cockpit-style`
// event). Then Cockpit's flavored PatternFly theme, then local tweaks.
import "cockpit-dark-theme";
import "patternfly/patternfly-6-cockpit.scss";
import "./app.scss";

import { createRoot } from "react-dom/client";
import { App, views } from "./app";

document.addEventListener("DOMContentLoaded", () => {
  const el = document.getElementById("app");
  if (el) {
    const view = views[el.dataset.view ?? ""] ?? null;
    createRoot(el).render(<App view={view} />);
  }
});
