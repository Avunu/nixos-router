// Reading the settings file without ever mistaking a failed read for an empty
// file, and refusing a write that was not built on a successful read.
//
// nix.ts used to turn every read failure into {}. The settings file is
// root-only (0600) on a router installed with local/deploy.sh, so a Cockpit
// session in Limited access loaded it as {}. Once the owner switched to
// administrative access, the next Save built on that {} and, because
// writeDesired replaces the whole file, kept only the edited fields: lan, wan,
// hosts and the rest were gone. A missing or empty file is still a legitimate
// {} (cockpit.file().read() resolves null for a missing file); anything else
// is an error for the page to show.
//
// Kept free of the `cockpit` global, like settings-json.ts, so `node --test`
// can import it: callers pass the read, and the superuser object, in.
import type { Json } from "./settings-json";

export const ADMIN_NEEDED =
  'Administrative access is needed to read and change the router settings. Click "Limited access" in the top bar and enter your password.';

export const NOT_LOADED =
  "Not saved: the router settings have not been read, so saving would overwrite them.";

// The problems Cockpit's bridge reports for EACCES and for a superuser channel
// it is not allowed to open.
const DENIED = new Set(["access-denied", "not-authorized"]);

const problemOf = (e: unknown): unknown =>
  typeof e === "object" && e !== null && "problem" in e ? e.problem : undefined;

const messageOf = (e: unknown): string =>
  typeof e === "object" && e !== null && "message" in e ? String(e.message) : String(e);

// Did Cockpit refuse a file channel for lack of privileges? Administrative
// access is what fixes it.
export function isDenied(e: unknown): boolean {
  return DENIED.has(String(problemOf(e)));
}

// The settings as `read()` returned them: null (no file) or blank text is {},
// anything that is not a JSON object throws.
export function parseSettings(path: string, text: string | null): Json {
  if (text === null || !text.trim()) {
    return {};
  }
  let parsed: unknown;
  try {
    parsed = JSON.parse(text);
  } catch (e) {
    throw new Error(`${path} is not valid JSON: ${messageOf(e)}`, { cause: e });
  }
  if (typeof parsed !== "object" || parsed === null || Array.isArray(parsed)) {
    throw new Error(`${path} does not hold a JSON object`);
  }
  return parsed as Json;
}

// Read and parse a file the UI writes back, rejecting on every failure but a
// missing or empty file. A permission error says what fixes it.
export function readStrict(path: string, read: () => Promise<string | null>): Promise<Json> {
  return read().then(
    (text) => parseSettings(path, text),
    (e: unknown) => {
      throw isDenied(e)
        ? new Error(ADMIN_NEEDED, { cause: e })
        : new Error(`Could not read ${path}: ${messageOf(e)}`, { cause: e });
    },
  );
}

// Settings states that came from a successful read; loadState marks each one.
// writeDesired takes the state its object was built on and writes nothing
// unless it is in here, so a page whose read failed cannot save even if a form
// was left usable. Membership is by identity: a copy is not a read.
const loaded = new WeakSet<object>();

export function markLoaded<T extends object>(state: T): T {
  loaded.add(state);
  return state;
}

export function isLoaded(state: object | null | undefined): boolean {
  return state != null && loaded.has(state);
}

// The part of Cockpit's `superuser` object (pkg/lib/superuser.js) that
// onSettledChange needs.
export interface SuperuserLike {
  allowed: boolean | null;
  addEventListener: (type: "changed", handler: () => void) => void;
  removeEventListener: (type: "changed", handler: () => void) => void;
}

// Call `cb` each time administrative access settles on or off, and return the
// unsubscribe. `allowed` passes through null while a switch is in progress
// (and once at startup, when the first settled value is worth a reload too,
// since a read may have raced it); only a settled value can change what a read
// with superuser "try" gets.
export function onSettledChange(su: SuperuserLike, cb: () => void): () => void {
  const handler = () => {
    if (su.allowed !== null) {
      cb();
    }
  };
  su.addEventListener("changed", handler);
  return () => su.removeEventListener("changed", handler);
}
