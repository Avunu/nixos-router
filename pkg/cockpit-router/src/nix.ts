// Helpers shared by the Settings tabs, the Firewall page, and the System page.
//
// Reads use `nix eval --json` against the host flake so the forms always show
// the *effective* option values (defaults included, merges applied). Writes use
// the nix-editor CLI to set an attribute path in the editable settings module
// (router.cockpit.settingsFile). nix-editor is on PATH because the plugin lists
// it in passthru.cockpitPath (→ /etc/cockpit/bin).

const cfg = (window.cockpitRouterConfig || {}) as {
  adguardPort?: number;
  macPrefixesPath?: string;
  hostName?: string;
  flakePath?: string;
  settingsFile?: string;
};

export const HOST = cfg.hostName || "";
export const FLAKE_PATH = cfg.flakePath || "/etc/nixos";
export const SETTINGS_FILE = cfg.settingsFile || "/etc/nixos/router-settings.nix";

// `<flake>#nixosConfigurations.<host>.config.router.<path>` — the effective value.
export const configRef = (path: string) =>
  `${FLAKE_PATH}#nixosConfigurations.${HOST}.config.router.${path}`;

// `<flake>#<host>` — the rebuild target used by the System page.
export const flakeHostRef = () => `${FLAKE_PATH}#${HOST}`;

// Read an effective option value as JSON. Runs as the session user (no prompt);
// escalates only if superuser is already available.
export function readOption<T = any>(path: string): Promise<T> {
  return cockpit
    .spawn(["nix", "eval", "--json", "--impure", configRef(path)], {
      superuser: "try",
      err: "message",
    })
    .then((s: string) => JSON.parse(s) as T);
}

// Double-quoted Nix string: escape \, ", the ${ interpolation start, and
// whitespace. Values we write are domains / IPs / paths / filter rules.
function nixString(s: string): string {
  const esc = s
    .replace(/\\/g, "\\\\")
    .replace(/"/g, '\\"')
    .replace(/\$\{/g, "\\${")
    .replace(/\n/g, "\\n")
    .replace(/\t/g, "\\t");
  return `"${esc}"`;
}

function nixAttrName(k: string): string {
  return /^[A-Za-z_][A-Za-z0-9_'-]*$/.test(k) ? k : nixString(k);
}

// Serialize a JS value to a Nix expression literal for nix-editor's -v argument.
export function toNix(v: unknown): string {
  if (v === null || v === undefined) return "null";
  switch (typeof v) {
    case "boolean":
      return v ? "true" : "false";
    case "number":
      return String(v);
    case "string":
      return nixString(v);
  }
  if (Array.isArray(v)) return v.length ? `[ ${v.map(toNix).join(" ")} ]` : "[ ]";
  if (typeof v === "object") {
    const entries = Object.entries(v as Record<string, unknown>);
    if (!entries.length) return "{ }";
    return `{ ${entries.map(([k, val]) => `${nixAttrName(k)} = ${toNix(val)};`).join(" ")} }`;
  }
  return "null";
}

// Persist a value by writing `router.<path>` into the settings module in place.
// Requires superuser (the settings file is root-owned under /etc/nixos).
export function writeOption(path: string, value: unknown): Promise<string> {
  return cockpit.spawn(
    ["nix-editor", SETTINGS_FILE, `router.${path}`, "-v", toNix(value), "-i"],
    { superuser: "require", err: "message" },
  );
}

// Cross-page "apply needed" flag. Each Cockpit menu entry is its own document,
// so the banner state is shared through localStorage rather than React state.
const PENDING = "routerPendingApply";
export const markPending = () => {
  try {
    localStorage.setItem(PENDING, "1");
  } catch {
    /* ignore */
  }
};
export const clearPending = () => {
  try {
    localStorage.removeItem(PENDING);
  } catch {
    /* ignore */
  }
};
export const isPending = () => {
  try {
    return localStorage.getItem(PENDING) === "1";
  } catch {
    return false;
  }
};
