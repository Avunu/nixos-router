// Ambient declarations for the `cockpit` global (provided at runtime by
// ../base1/cockpit.js) and the window config the Nix build writes into config.js.

interface CockpitSpawnOptions {
  superuser?: "require" | "try";
  err?: "message" | "out" | "ignore";
  pty?: boolean;
  directory?: string;
}

// A spawned process resolves to its stdout; `.stream` delivers incremental
// output and `.close` terminates it.
interface CockpitProcess extends Promise<string> {
  stream: (callback: (data: string) => void) => CockpitProcess;
  close: (problem?: string) => void;
}

interface CockpitFileOptions {
  superuser?: "require" | "try";
}

interface CockpitFile {
  read: () => Promise<string | null>;
  replace: (content: string) => Promise<unknown>;
}

interface CockpitHttpOptions {
  address: string;
  port: number;
}

interface CockpitHttp {
  get: (path: string, params?: Record<string, unknown>) => Promise<string>;
}

interface Cockpit {
  gettext: (message: string) => string;
  format: (template: string, ...args: unknown[]) => string;
  spawn: (args: string[], options?: CockpitSpawnOptions) => CockpitProcess;
  file: (path: string, options?: CockpitFileOptions) => CockpitFile;
  http: (options: CockpitHttpOptions) => CockpitHttp;
}

declare const cockpit: Cockpit;

interface Window {
  cockpitRouterConfig?: {
    adguardPort: number;
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
