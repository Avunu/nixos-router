// Routing page logic that needs no browser: certificate naming, row
// normalization, validation, and the host rename/remove cascade.
//
// The checks mirror the assertions of modules/reverse-proxy.nix,
// modules/cloudflare-tunnel.nix and modules/acme.nix, so a rebuild never fails
// on something the Routing forms let through. Issues carry a code rather than
// a sentence, so this module stays free of `cockpit` (node --test runs it);
// routing-widgets.tsx turns them into translated text.
//
// Imports carry their .ts extension: node --test resolves them as plain ESM.
import { isHostname } from "./ip-math.ts";
import { normalizeForward, renameForwardHost } from "./forwards.ts";
import type { AcmeSettings, PortForward, ProxyRoute, RouterHost, TunnelIngress } from "./types.ts";

// ── Certificates ────────────────────────────────────────────────────────────
// The certificate (its /var/lib/acme directory and acme-* units) is named
// after the route's first hostname, `*` replaced — reverse-proxy.nix's certName.
export const certName = (r: Pick<ProxyRoute, "hostnames">) =>
  (r.hostnames[0] ?? "").toLowerCase().replaceAll("*", "_");

export const isWildcard = (n: string) => n.startsWith("*.");

// A proxy route may carry a leading `*.` (one extra label); tunnel names may not.
export const isRouteName = (n: string) => isHostname(isWildcard(n) ? n.slice(2) : n);

export type EffectiveChallenge = "dns-cloudflare" | "http";

export const effectiveChallenge = (
  r: Pick<ProxyRoute, "challenge">,
  acme: AcmeSettings,
): EffectiveChallenge =>
  r.challenge && r.challenge !== "default" ? r.challenge : (acme.defaultChallenge ?? "http");

export const routeLabel = (r: ProxyRoute) => r.name || r.hostnames[0] || r.host;

// ── Normalization ───────────────────────────────────────────────────────────
// Rows as the Routing page writes them back: fields left at their defaults
// are dropped (port is kept — it is the part a reader looks for), so a list
// that came from the effective-config fallback is stored as tidily as one the
// admin typed. Hostnames are lowercased, as the modules do.
export const normalizeRoute = (r: ProxyRoute): ProxyRoute => {
  const https = r.scheme === "https";
  return {
    ...(r.name ? { name: r.name } : {}),
    hostnames: r.hostnames.map((n) => n.toLowerCase()),
    host: r.host,
    port: r.port ?? 80,
    ...(https ? { scheme: "https" as const } : {}),
    ...(https && r.tlsVerify ? { tlsVerify: true } : {}),
    ...(r.challenge && r.challenge !== "default" ? { challenge: r.challenge } : {}),
    ...(r.hsts ? { hsts: true } : {}),
  };
};

export const normalizeIngress = (i: TunnelIngress): TunnelIngress => {
  const https = i.scheme === "https";
  return {
    hostname: i.hostname.toLowerCase(),
    host: i.host,
    port: i.port ?? 80,
    ...(https ? { scheme: "https" as const } : {}),
    ...(https && i.noTLSVerify === false ? { noTLSVerify: false } : {}),
    ...(i.httpHostHeader ? { httpHostHeader: i.httpHostHeader } : {}),
  };
};

// ── Validation ──────────────────────────────────────────────────────────────
export type IssueCode =
  | "noHostnames"
  | "badHostname"
  | "noHost"
  | "unknownHost"
  | "noStaticIp"
  | "badPort"
  | "wildcardNeedsDns"
  | "dnsNeedsToken"
  | "httpNotPublished"
  | "dupRoute"
  | "dupIngress"
  | "clashDdns"
  | "clashPublicHost"
  | "clashTunnel"
  | "clashProxy"
  | "acmeTerms"
  | "acmeEmail"
  | "publishWithoutDdns"
  | "forwardOnWeb"
  | "tunnelToken";

export interface RoutingIssue {
  level: "error" | "warning";
  code: IssueCode;
  // The row an issue belongs to, set by the page-level check (the per-row
  // form check leaves it out: the row is the one being edited).
  subject?: string;
  // Offending names: hostnames, a host name, or port-forward labels.
  names?: string[];
}

// Everything the checks read, already defaulted.
export interface RoutingContext {
  hosts: RouterHost[];
  portForwards: PortForward[];
  ddns: { enable: boolean; names: string[] };
  acme: AcmeSettings;
  proxy: { enable: boolean; publishDns: boolean; routes: ProxyRoute[] };
  tunnel: { enable: boolean; apiTokenFile: string | null; ingress: TunnelIngress[] };
}

const lower = (xs: string[]) => xs.map((x) => x.toLowerCase());
const validPort = (p: number | undefined) =>
  p === undefined || (Number.isInteger(p) && p >= 1 && p <= 65_535);

// Names among `names` that also occur in `taken` (both compared lowercased).
const overlap = (names: string[], taken: string[]) => {
  const set = new Set(lower(taken));
  return [...new Set(lower(names).filter((n) => set.has(n)))];
};

const publicHostnames = (ctx: RoutingContext) =>
  ctx.hosts.flatMap((h) => (h.publicHostname ? [h.publicHostname] : []));

function checkTarget(hostName: string, port: number | undefined, ctx: RoutingContext) {
  const issues: RoutingIssue[] = [];
  const host = ctx.hosts.find((h) => h.name === hostName);
  if (!hostName) {
    issues.push({ level: "error", code: "noHost" });
  } else if (!host) {
    issues.push({ level: "error", code: "unknownHost", names: [hostName] });
  } else if (!host.staticIp) {
    issues.push({ level: "error", code: "noStaticIp", names: [hostName] });
  }
  if (!validPort(port)) {
    issues.push({ level: "error", code: "badPort" });
  }
  return issues;
}

// One proxy route. `self` is its index in ctx.proxy.routes (null for a row
// being added), so it is not compared with itself.
export function checkRoute(r: ProxyRoute, ctx: RoutingContext, self: number | null) {
  const issues: RoutingIssue[] = [];
  const names = lower(r.hostnames);
  if (names.length === 0) {
    issues.push({ level: "error", code: "noHostnames" });
  }
  const bad = r.hostnames.filter((n) => !isRouteName(n));
  if (bad.length > 0) {
    issues.push({ level: "error", code: "badHostname", names: bad });
  }
  issues.push(...checkTarget(r.host, r.port, ctx));

  const challenge = effectiveChallenge(r, ctx.acme);
  if (challenge !== "dns-cloudflare" && names.some((n) => isWildcard(n))) {
    issues.push({ level: "error", code: "wildcardNeedsDns" });
  }
  if (challenge === "dns-cloudflare" && !ctx.acme.cloudflare?.apiTokenFile) {
    issues.push({ level: "error", code: "dnsNeedsToken" });
  }
  if (challenge === "http" && !ctx.proxy.publishDns && names.length > 0) {
    issues.push({ level: "warning", code: "httpNotPublished" });
  }

  const others = ctx.proxy.routes.filter((_r, i) => i !== self).flatMap((o) => o.hostnames);
  const twice = names.filter((n, i) => names.indexOf(n) !== i);
  const dup = [...new Set([...overlap(names, others), ...twice])];
  if (dup.length > 0) {
    issues.push({ level: "error", code: "dupRoute", names: dup });
  }
  const pub = overlap(names, publicHostnames(ctx));
  if (pub.length > 0) {
    issues.push({ level: "error", code: "clashPublicHost", names: pub });
  }
  if (ctx.proxy.enable && ctx.proxy.publishDns) {
    const ddns = overlap(names, ctx.ddns.names);
    if (ddns.length > 0) {
      issues.push({ level: "error", code: "clashDdns", names: ddns });
    }
  }
  if (ctx.proxy.enable && ctx.tunnel.enable) {
    const tun = overlap(
      names,
      ctx.tunnel.ingress.map((i) => i.hostname),
    );
    if (tun.length > 0) {
      issues.push({ level: "error", code: "clashTunnel", names: tun });
    }
  }
  return issues;
}

// One tunnel ingress row; `self` as for checkRoute.
export function checkIngress(ing: TunnelIngress, ctx: RoutingContext, self: number | null) {
  const issues: RoutingIssue[] = [];
  const name = ing.hostname.toLowerCase();
  if (!name) {
    issues.push({ level: "error", code: "noHostnames" });
  } else if (!isHostname(name)) {
    issues.push({ level: "error", code: "badHostname", names: [ing.hostname] });
  }
  issues.push(...checkTarget(ing.host, ing.port, ctx));
  if (!name) {
    return issues;
  }
  const others = ctx.tunnel.ingress.filter((_i, i) => i !== self).map((o) => o.hostname);
  if (overlap([name], others).length > 0) {
    issues.push({ level: "error", code: "dupIngress", names: [name] });
  }
  // cloudflare-tunnel.nix checks the clashes only while the tunnel is on.
  if (ctx.tunnel.enable) {
    if (overlap([name], ctx.ddns.names).length > 0) {
      issues.push({ level: "error", code: "clashDdns", names: [name] });
    }
    if (overlap([name], publicHostnames(ctx)).length > 0) {
      issues.push({ level: "error", code: "clashPublicHost", names: [name] });
    }
    if (
      ctx.proxy.enable &&
      overlap(
        [name],
        ctx.proxy.routes.flatMap((r) => r.hostnames),
      ).length > 0
    ) {
      issues.push({ level: "error", code: "clashProxy", names: [name] });
    }
  }
  return issues;
}

// An IPv4 tcp forward of 80 or 443 — the ports the reverse proxy owns.
export const claimsWebPorts = (f: Pick<PortForward, "protocol" | "family" | "ports">) =>
  (f.family ?? "both") !== "ipv6" &&
  (f.protocol ?? "tcp") === "tcp" &&
  f.ports.some((p) => p === 80 || p === 443);

const forwardLabel = (f: PortForward) => f.name || f.host;

// Tag freshly made row issues with the row they belong to.
const about = (issues: RoutingIssue[], subject: string) => {
  for (const it of issues) {
    it.subject = subject;
  }
  return issues;
};

// Whole-page check: every row plus the section-level assertions, split by the
// tab that shows them.
export function checkRouting(ctx: RoutingContext) {
  const proxy: RoutingIssue[] = ctx.proxy.routes.flatMap((r, i) =>
    about(checkRoute(r, ctx, i), routeLabel(r)),
  );
  if (ctx.proxy.enable && ctx.proxy.routes.length > 0) {
    if (!ctx.acme.acceptTerms) {
      proxy.push({ level: "error", code: "acmeTerms" });
    }
    if (!ctx.acme.email?.trim()) {
      proxy.push({ level: "error", code: "acmeEmail" });
    }
    if (ctx.proxy.publishDns && !ctx.ddns.enable) {
      proxy.push({ level: "warning", code: "publishWithoutDdns" });
    }
  }
  if (ctx.proxy.enable) {
    const web = ctx.portForwards.filter((f) => claimsWebPorts(f));
    if (web.length > 0) {
      proxy.push({ level: "error", code: "forwardOnWeb", names: web.map((f) => forwardLabel(f)) });
    }
  }

  const tunnel: RoutingIssue[] = ctx.tunnel.ingress.flatMap((ing, i) =>
    about(checkIngress(ing, ctx, i), ing.hostname || ing.host),
  );
  if (ctx.tunnel.enable && !ctx.tunnel.apiTokenFile) {
    tunnel.push({ level: "error", code: "tunnelToken" });
  }
  return { proxy, tunnel };
}

// ── Host rename / remove cascade ────────────────────────────────────────────
// Port forwards, proxy routes and tunnel ingress all reference a registered
// host by name. A rename carries them along; removing the host removes them
// (a row naming a host that no longer exists fails the rebuild).
export interface HostRefs {
  portForwards: PortForward[];
  routes: ProxyRoute[];
  ingress: TunnelIngress[];
}

export const countHostRefs = (refs: HostRefs, name: string) => {
  const forwards = refs.portForwards.filter((f) => f.host === name).length;
  const routes = refs.routes.filter((r) => r.host === name).length;
  const ingress = refs.ingress.filter((i) => i.host === name).length;
  return { forwards, routes, ingress, total: forwards + routes + ingress };
};

export const renameHostRefs = (refs: HostRefs, from: string, to: string): HostRefs => ({
  portForwards: renameForwardHost(refs.portForwards, from, to),
  routes: refs.routes.map((r) => normalizeRoute(r.host === from ? { ...r, host: to } : r)),
  ingress: refs.ingress.map((i) => normalizeIngress(i.host === from ? { ...i, host: to } : i)),
});

export const removeHostRefs = (refs: HostRefs, name: string): HostRefs => ({
  portForwards: refs.portForwards.filter((f) => f.host !== name).map((f) => normalizeForward(f)),
  routes: refs.routes.filter((r) => r.host !== name).map((r) => normalizeRoute(r)),
  ingress: refs.ingress.filter((i) => i.host !== name).map((i) => normalizeIngress(i)),
});
