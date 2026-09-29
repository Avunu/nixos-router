// Ambient declarations for the `cockpit` global (provided at runtime by
// ../base1/cockpit.js) and the window config the Nix build writes into config.js.

interface CockpitSpawnOptions {
  superuser?: "require" | "try";
  err?: "message" | "out" | "ignore";
  pty?: boolean;
  directory?: string;
  // Stream batching (bytes per chunk / max latency ms), as used by Cockpit's
  // own journal helper for efficient `journalctl --follow` streaming.
  batch?: number;
  latency?: number;
}

// A spawned process resolves to its stdout; `.stream` delivers incremental
// output, `.input` writes to stdin (closing it unless `stream` is true), and
// `.close` terminates it.
interface CockpitProcess extends Promise<string> {
  stream: (callback: (data: string) => void) => CockpitProcess;
  input: (data: string, stream?: boolean) => CockpitProcess;
  close: (problem?: string) => void;
}

interface CockpitFileOptions {
  superuser?: "require" | "try";
  binary?: boolean;
}

// A bridge error: `problem` is the machine-readable code ("access-denied",
// "not-authorized", "change-conflict", …).
interface CockpitError {
  problem?: string | null;
  message: string;
}

interface CockpitFileWatchHandle {
  remove: () => void;
}

interface CockpitFile {
  read: () => Promise<string | null>;
  // With `expectedTag`, the bridge refuses ("change-conflict") unless the file
  // is still the one that tag was read from, and keeps its mode and owner.
  replace: (content: string, expectedTag?: string) => Promise<string>;
  // Called with the content (null: no such file, tag "-") on every change,
  // and once at the start; `error` when it cannot be read.
  watch: (
    callback: (content: string | null, tag: string | null, error: CockpitError | null) => void,
    options?: { read?: boolean },
  ) => CockpitFileWatchHandle;
  close: () => void;
}

// Binary variant (cockpit.file(path, { binary: true })) — used for PDF report
// downloads; read() resolves to raw bytes.
interface CockpitBinaryFile {
  read: () => Promise<Uint8Array | null>;
}

interface CockpitHttpOptions {
  address: string;
  port: number;
}

interface CockpitHttpRequestOptions {
  method: string;
  path: string;
  params?: Record<string, unknown>;
  headers?: Record<string, string>;
  body?: string;
}

interface CockpitHttp {
  // cockpit.js supports an optional third headers argument on get().
  get: (
    path: string,
    params?: Record<string, unknown> | null,
    headers?: Record<string, string>,
  ) => Promise<string>;
  request: (options: CockpitHttpRequestOptions) => Promise<string>;
}

// The page's own address below its Cockpit path: `#/<path>?<options>`.
interface CockpitLocation {
  path: string[];
  options: Record<string, string | string[]>;
  go: (path: string[] | string, options?: Record<string, string>) => void;
  replace: (path: string[] | string, options?: Record<string, string>) => void;
}

interface Cockpit {
  gettext: (message: string) => string;
  format: (template: string, ...args: unknown[]) => string;
  spawn: (args: string[], options?: CockpitSpawnOptions) => CockpitProcess;
  file: ((path: string, options: CockpitFileOptions & { binary: true }) => CockpitBinaryFile) &
    ((path: string, options?: CockpitFileOptions) => CockpitFile);
  http: (options: CockpitHttpOptions) => CockpitHttp;
  // Navigate the shell to another page, e.g. "/router/ingress".
  jump: (path: string, host?: string) => void;
  location: CockpitLocation;
  // True while the page is not the one shown (a preloaded page, or one the
  // admin navigated away from); "visibilitychange" fires when that changes.
  hidden: boolean;
  addEventListener: (event: "locationchanged" | "visibilitychange", handler: () => void) => void;
  removeEventListener: (event: "locationchanged" | "visibilitychange", handler: () => void) => void;
  transport: {
    // Messages for the shell, e.g. "notify" with a page_status.
    control: (command: string, options: Record<string, unknown>) => void;
    // Call `callback` once the connection to the shell is up.
    wait: (callback: () => void) => void;
  };
}

declare const cockpit: Cockpit;

interface Window {
  cockpitRouterConfig?: {
    technitiumPort?: number;
    technitiumTokenPath?: string;
    logdPort?: number;
    logdTokenPath?: string;
    directoryStatePath?: string;
    directoryStatusPath?: string;
    reportsDir?: string;
    ddnsStatusPath?: string;
    macPrefixesPath?: string;
    // Baked in by package.nix: where the editable JSON config lives, the host
    // name, and the flake path router-rebuild builds.
    hostName?: string;
    flakePath?: string;
    settingsFile?: string;
  };
}

// Side-effect imports resolved by esbuild via pkg/lib (nodePaths) and the sass plugin.
declare module "cockpit-dark-theme";
declare module "patternfly/*";
declare module "*.scss";
declare module "*.css";

// Cockpit's administrative-access state (pkg/lib/superuser.js), resolved the
// same way as `journal` below. `allowed` is null until the session settles and
// while a switch is in progress; "changed" fires on every change of it.
declare module "superuser" {
  export const superuser: {
    allowed: boolean | null;
    addEventListener: (type: "changed", handler: () => void) => void;
    removeEventListener: (type: "changed", handler: () => void) => void;
  };
}

// Cockpit's journal helper (pkg/lib/journal.js), vendored into the build by
// package.nix and resolved by esbuild's nodePaths. We reuse only `build_cmd`,
// which turns match strings + an options object into a journalctl argv (the IPS
// views splice `--namespace suricata` into the result and spawn it themselves).
declare module "journal" {
  interface JournalOptions {
    count?: number | null;
    follow?: boolean;
    since?: string;
    until?: string;
    directory?: string;
    boot?: string | null;
    cursor?: string;
    after?: string;
    priority?: string;
    grep?: string;
    reverse?: boolean;
    output?: string;
  }
  export const journal: {
    build_cmd: (...args: (string | string[] | JournalOptions)[]) => string[];
  };
}

// Cockpit's systemd unit watcher (pkg/lib/service.js), resolved like
// `superuser`. Unprivileged: it only reads unit state over D-Bus, so it works
// with Limited access. `unit` is the org.freedesktop.systemd1.Unit proxy.
declare module "service" {
  interface ServiceProxy {
    exists: boolean | null;
    state: "starting" | "running" | "stopping" | "stopped" | "failed" | null | undefined;
    unit?: { ActiveState?: string; InvocationID?: unknown };
    addEventListener: (type: "changed", handler: () => void) => void;
    removeEventListener: (type: "changed", handler: () => void) => void;
  }
  export function proxy(name: string, kind?: string): ServiceProxy;
}
