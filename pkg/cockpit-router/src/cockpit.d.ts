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
// output and `.close` terminates it.
interface CockpitProcess extends Promise<string> {
  stream: (callback: (data: string) => void) => CockpitProcess;
  close: (problem?: string) => void;
}

interface CockpitFileOptions {
  superuser?: "require" | "try";
  binary?: boolean;
}

interface CockpitFile {
  read: () => Promise<string | null>;
  replace: (content: string) => Promise<unknown>;
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

interface Cockpit {
  gettext: (message: string) => string;
  format: (template: string, ...args: unknown[]) => string;
  spawn: (args: string[], options?: CockpitSpawnOptions) => CockpitProcess;
  file: ((path: string, options: CockpitFileOptions & { binary: true }) => CockpitBinaryFile) &
    ((path: string, options?: CockpitFileOptions) => CockpitFile);
  http: (options: CockpitHttpOptions) => CockpitHttp;
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
    macPrefixesPath?: string;
    // Baked in by package.nix: where the editable JSON config lives, the host
    // name, and the flake path used for nixos-rebuild.
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
