// Hostnames and router portal origins.
//
// Two jobs, both pure so they are unit-tested without a browser:
//
//   • checkableHost(url) — the one piece of a failed navigation that is ever
//     sent to a router: its hostname, normalized to the form the router's
//     /portal/check accepts, or null when the URL is not something the router
//     could have blocked by name (an IP literal, a single-label name, a
//     non-web scheme).
//   • normalizePortalOrigin(input) — what the user typed on the options page
//     (or an administrator put in policy) turned into the canonical
//     `https://blocked.<router fqdn>:<port>` origin, or null. Only https: is
//     ever accepted: the extension must never talk to a router, or send a
//     user to one, over plain http.

/** The router's own hostname rule for /portal/check (lowercase ASCII). */
const HOST_RE = /^[a-z0-9_.-]{1,253}$/;
/** WHATWG URL already canonicalizes every IPv4 spelling to a dotted quad. */
const IPV4_RE = /^\d{1,3}(?:\.\d{1,3}){3}$/;
/** The port the router's portal listens on unless the address says otherwise. */
export const DEFAULT_PORTAL_PORT = 8068;

/**
 * Normalizes a URL hostname: lowercase, one trailing dot stripped. Returns null
 * for IP literals, names without a dot, and anything outside the router's
 * character set. An internationalized name reaches here already in punycode
 * (`new URL` converts it), so it passes as its `xn--` form.
 */
export function normalizeHostname(hostname: string): string | null {
  let host = hostname.toLowerCase();
  if (host.endsWith(".")) {
    host = host.slice(0, -1);
  }
  if (host.startsWith("[") || IPV4_RE.test(host)) {
    return null;
  }
  if (!host.includes(".") || !HOST_RE.test(host)) {
    return null;
  }
  return host;
}

/**
 * The hostname of an http(s) URL in the form the router checks, or null when
 * there is nothing to ask the router about. Never the path, query, port or
 * scheme — only the name the browser resolved through the router's DNS.
 */
export function checkableHost(url: string): string | null {
  let parsed: URL;
  try {
    parsed = new URL(url);
  } catch {
    return null;
  }
  if (parsed.protocol !== "https:" && parsed.protocol !== "http:") {
    return null;
  }
  return normalizeHostname(parsed.hostname);
}

/** The explicit `:port` of an authority, if it has one. */
function explicitPort(input: string): string | null {
  const afterScheme = input.includes("://") ? input.slice(input.indexOf("://") + 3) : input;
  const authority = afterScheme.split(/[/?#]/, 1)[0] ?? "";
  return /:(\d+)$/.exec(authority)?.[1] ?? null;
}

/**
 * Canonical portal origin for an address a person typed or a policy listed:
 * `blocked.gw.example.com`, `blocked.gw.example.com:8068` and
 * `https://blocked.gw.example.com:8068/anything` all become
 * `https://blocked.gw.example.com:8068`. A missing port means the portal's
 * default, 8068 — not https' 443 — because that is where the router serves it.
 * Rejects http: and every other scheme, credentials, IP literals and names
 * without a dot. Returns null when the input is not acceptable.
 */
export function normalizePortalOrigin(input: string): string | null {
  const trimmed = input.trim();
  if (trimmed === "") {
    return null;
  }
  // "host:8068" would otherwise parse as the scheme "host:", so a bare address
  // gets https:// in front, and anything that names a scheme must name https.
  const withScheme = trimmed.includes("://") ? trimmed : `https://${trimmed}`;
  let url: URL;
  try {
    url = new URL(withScheme);
  } catch {
    return null;
  }
  if (url.protocol !== "https:" || url.username !== "" || url.password !== "") {
    return null;
  }
  const host = normalizeHostname(url.hostname);
  if (host === null) {
    return null;
  }
  // WHATWG URL drops an explicit :443 (the scheme default), so tell "no port"
  // from ":443" by looking at what was written.
  const written = explicitPort(withScheme);
  const port = written === null ? DEFAULT_PORTAL_PORT : Number(url.port === "" ? 443 : url.port);
  return port === 443 ? `https://${host}` : `https://${host}:${port}`;
}

/** The hostname of a canonical portal origin. */
export function originHostname(origin: string): string {
  return new URL(origin).hostname;
}

/**
 * The optional host permission a portal origin needs. No port: Firefox match
 * patterns cannot carry one, and Chrome treats a pattern without a port as
 * matching every port.
 */
export function permissionPattern(origin: string): string {
  return `https://${originHostname(origin)}/*`;
}

/** The address as the options page shows it: the origin without `https://`. */
export function displayAddress(origin: string): string {
  return origin.replace(/^https:\/\//, "");
}
