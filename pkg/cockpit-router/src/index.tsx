import "@patternfly/patternfly/patternfly.css";
import "@patternfly/patternfly/patternfly-addons.css";
import { createRoot } from "react-dom/client";
import { App } from "./app";

const el = document.getElementById("app");
if (el) {
  createRoot(el).render(<App />);
}
