// Unit tests for the Ingress page's pure logic (ingress.ts).
//
// The checks exist so that a configuration the Reverse proxy and Tunnel tabs
// accept also passes the assertions of modules/reverse-proxy.nix,
// modules/cloudflare-tunnel.nix and modules/acme.nix on rebuild — and so that
// the certificate name the page probes is the one the module creates.
//
// Run with `npm test`.
import { test } from "node:test";
import assert from "node:assert/strict";

import type { HostRefs, IssueCode, IngressContext, IngressIssue } from "./ingress.ts";
import {
  certName,
  checkIngress,
  checkRoute,
  checkPage,
  claimsWebPorts,
  countHostRefs,
  effectiveChallenge,
  normalizeIngress,
  normalizeRoute,
  removeHostRefs,
  renameHostRefs,
} from "./ingress.ts";
import type { ProxyRoute, TunnelIngress } from "./types.ts";

const ctx = (over: Partial<IngressContext> = {}): IngressContext => ({
  hosts: [
    { mac: "aa:aa:aa:aa:aa:01", name: "nas", staticIp: "10.0.0.10" },
    { mac: "aa:aa:aa:aa:aa:02", name: "cam", staticIp: null },
    {
      mac: "aa:aa:aa:aa:aa:03",
      name: "game",
      staticIp: "10.0.0.30",
      publicHostname: "Game.Example.com",
    },
  ],
  portForwards: [],
  ddns: { enable: true, names: ["home.example.com"] },
  acme: { email: "admin@example.com", acceptTerms: true, defaultChallenge: "http" },
  proxy: { enable: true, publishDns: true, routes: [] },
  tunnel: { enable: true, apiTokenFile: "/etc/router/secrets/t", ingress: [] },
  ...over,
});

const route = (over: Partial<ProxyRoute> = {}): ProxyRoute => ({
  hostnames: ["app.example.com"],
  host: "nas",
  ...over,
});

const ingress = (over: Partial<TunnelIngress> = {}): TunnelIngress => ({
  hostname: "wiki.example.com",
  host: "nas",
  ...over,
});

const codes = (issues: IngressIssue[], level?: "error" | "warning"): IssueCode[] =>
  issues.filter((i) => !level || i.level === level).map((i) => i.code);

// Issue codes of one route / ingress row (kept shallow for unicorn/max-nested-calls).
const rc = (r: ProxyRoute, c: IngressContext, self: number | null, level?: "error" | "warning") =>
  codes(checkRoute(r, c, self), level);
const ic = (
  i: TunnelIngress,
  c: IngressContext,
  self: number | null,
  level?: "error" | "warning",
) => codes(checkIngress(i, c, self), level);

// ── certName ────────────────────────────────────────────────────────────────
void test("certName: first hostname, lowercased, * replaced (reverse-proxy.nix certName)", () => {
  assert.equal(certName({ hostnames: ["App.Example.com", "b.example.com"] }), "app.example.com");
  assert.equal(certName({ hostnames: ["*.Example.com"] }), "_.example.com");
});

void test("effectiveChallenge: default falls back to acme.defaultChallenge", () => {
  assert.equal(effectiveChallenge({}, {}), "http");
  assert.equal(
    effectiveChallenge({ challenge: "default" }, { defaultChallenge: "dns-cloudflare" }),
    "dns-cloudflare",
  );
  assert.equal(
    effectiveChallenge({ challenge: "http" }, { defaultChallenge: "dns-cloudflare" }),
    "http",
  );
});

// ── normalization ───────────────────────────────────────────────────────────
void test("normalizeRoute drops defaults and lowercases hostnames", () => {
  assert.deepEqual(
    normalizeRoute({
      name: "",
      hostnames: ["App.Example.com"],
      host: "nas",
      port: 80,
      scheme: "http",
      tlsVerify: true, // meaningless without https
      challenge: "default",
      hsts: false,
    }),
    { hostnames: ["app.example.com"], host: "nas", port: 80 },
  );
  assert.deepEqual(
    normalizeRoute(
      route({
        name: "App",
        scheme: "https",
        tlsVerify: true,
        challenge: "http",
        hsts: true,
        port: 8443,
      }),
    ),
    {
      name: "App",
      hostnames: ["app.example.com"],
      host: "nas",
      port: 8443,
      scheme: "https",
      tlsVerify: true,
      challenge: "http",
      hsts: true,
    },
  );
});

void test("normalizeIngress drops defaults", () => {
  assert.deepEqual(
    normalizeIngress({
      hostname: "Wiki.Example.com",
      host: "nas",
      scheme: "http",
      noTLSVerify: false,
      httpHostHeader: "",
    }),
    { hostname: "wiki.example.com", host: "nas", port: 80 },
  );
  assert.deepEqual(normalizeIngress(ingress({ scheme: "https", noTLSVerify: true, port: 443 })), {
    hostname: "wiki.example.com",
    host: "nas",
    port: 443,
    scheme: "https",
  });
  assert.deepEqual(
    normalizeIngress(ingress({ scheme: "https", noTLSVerify: false, httpHostHeader: "nas.lan" })),
    {
      hostname: "wiki.example.com",
      host: "nas",
      port: 80,
      scheme: "https",
      noTLSVerify: false,
      httpHostHeader: "nas.lan",
    },
  );
});

// ── proxy routes ────────────────────────────────────────────────────────────
void test("checkRoute: a plain route to a host with a static IP is clean", () => {
  assert.deepEqual(checkRoute(route(), ctx(), null), []);
});

void test("checkRoute: hostnames — required, valid, wildcard only as a leading *.", () => {
  assert.deepEqual(rc(route({ hostnames: [] }), ctx(), null), ["noHostnames"]);
  assert.deepEqual(rc(route({ hostnames: ["localhost"] }), ctx(), null), ["badHostname"]);
  assert.deepEqual(rc(route({ hostnames: ["a.*.example.com"] }), ctx(), null), ["badHostname"]);
  const wild = route({ hostnames: ["*.example.com"], challenge: "dns-cloudflare" });
  const c = ctx({ acme: { ...ctx().acme, cloudflare: { apiTokenFile: "/t" } } });
  assert.deepEqual(checkRoute(wild, c, null), []);
});

void test("checkRoute: unknown host, host without a static IP, bad port", () => {
  assert.deepEqual(rc(route({ host: "" }), ctx(), null), ["noHost"]);
  assert.deepEqual(rc(route({ host: "ghost" }), ctx(), null), ["unknownHost"]);
  assert.deepEqual(rc(route({ host: "cam" }), ctx(), null), ["noStaticIp"]);
  assert.deepEqual(rc(route({ port: 0 }), ctx(), null), ["badPort"]);
  assert.deepEqual(rc(route({ port: Number.NaN }), ctx(), null), ["badPort"]);
});

void test("checkRoute: a wildcard needs the effective challenge to be dns-cloudflare", () => {
  const wild = route({ hostnames: ["*.example.com"] });
  assert.ok(rc(wild, ctx(), null).includes("wildcardNeedsDns"));
  // The default challenge counts: dns-cloudflare by default is enough.
  const c = ctx({
    acme: { ...ctx().acme, defaultChallenge: "dns-cloudflare", cloudflare: { apiTokenFile: "/t" } },
  });
  assert.deepEqual(checkRoute(wild, c, null), []);
  // …unless the route overrides it back to http.
  assert.ok(rc({ ...wild, challenge: "http" }, c, null).includes("wildcardNeedsDns"));
});

void test("checkRoute: dns-cloudflare needs acme.cloudflare.apiTokenFile", () => {
  const r = route({ challenge: "dns-cloudflare" });
  assert.deepEqual(rc(r, ctx(), null), ["dnsNeedsToken"]);
  const c = ctx({ acme: { ...ctx().acme, cloudflare: { apiTokenFile: "/t" } } });
  assert.deepEqual(checkRoute(r, c, null), []);
});

void test("checkRoute: http challenge with publishing off is a warning, not an error", () => {
  const c = ctx({ proxy: { enable: true, publishDns: false, routes: [] } });
  assert.deepEqual(rc(route(), c, null, "warning"), ["httpNotPublished"]);
  assert.deepEqual(rc(route(), c, null, "error"), []);
});

void test("checkRoute: a hostname belongs to one route (case-insensitive), not to itself", () => {
  const c = ctx({
    proxy: { enable: true, publishDns: true, routes: [route({ hostnames: ["APP.example.com"] })] },
  });
  assert.deepEqual(rc(route(), c, null), ["dupRoute"]);
  // Editing row 0 compares it with the others only.
  assert.deepEqual(checkRoute(route(), c, 0), []);
  // Twice within one route counts too.
  assert.deepEqual(rc(route({ hostnames: ["app.example.com", "App.example.com"] }), ctx(), null), [
    "dupRoute",
  ]);
});

void test("checkRoute: disjoint from publicHostname always, ddns.names only with publishDns", () => {
  assert.deepEqual(rc(route({ hostnames: ["game.example.com"] }), ctx(), null), [
    "clashPublicHost",
  ]);
  const home = route({ hostnames: ["Home.example.com"] });
  assert.deepEqual(rc(home, ctx(), null), ["clashDdns"]);
  const off = ctx({ proxy: { enable: true, publishDns: false, routes: [] } });
  assert.deepEqual(rc(home, off, null, "error"), []);
});

void test("checkRoute: disjoint from tunnel ingress while both are enabled", () => {
  const c = ctx({
    tunnel: {
      enable: true,
      apiTokenFile: "/t",
      ingress: [ingress({ hostname: "app.example.com" })],
    },
  });
  assert.deepEqual(rc(route(), c, null), ["clashTunnel"]);
  const off = { ...c, tunnel: { ...c.tunnel, enable: false } };
  assert.deepEqual(checkRoute(route(), off, null), []);
});

// ── tunnel ingress ──────────────────────────────────────────────────────────
void test("checkIngress: valid names only, no wildcard", () => {
  assert.deepEqual(checkIngress(ingress(), ctx(), null), []);
  assert.deepEqual(ic(ingress({ hostname: "" }), ctx(), null), ["noHostnames"]);
  assert.deepEqual(ic(ingress({ hostname: "*.example.com" }), ctx(), null), ["badHostname"]);
});

void test("checkIngress: host checks", () => {
  assert.deepEqual(ic(ingress({ host: "ghost" }), ctx(), null), ["unknownHost"]);
  assert.deepEqual(ic(ingress({ host: "cam" }), ctx(), null), ["noStaticIp"]);
});

void test("checkIngress: one entry per hostname", () => {
  const c = ctx({
    tunnel: {
      enable: true,
      apiTokenFile: "/t",
      ingress: [ingress({ hostname: "WIKI.example.com" })],
    },
  });
  assert.deepEqual(ic(ingress(), c, null), ["dupIngress"]);
  assert.deepEqual(checkIngress(ingress(), c, 0), []);
});

void test("checkIngress: disjoint from ddns.names, publicHostname and proxy routes while enabled", () => {
  const c = ctx({
    proxy: {
      enable: true,
      publishDns: false,
      routes: [route({ hostnames: ["wiki.example.com"] })],
    },
  });
  assert.deepEqual(ic(ingress(), c, null), ["clashProxy"]);
  assert.deepEqual(ic(ingress({ hostname: "home.example.com" }), ctx(), null), ["clashDdns"]);
  assert.deepEqual(ic(ingress({ hostname: "game.example.com" }), ctx(), null), ["clashPublicHost"]);
  // A disabled tunnel publishes nothing, so nothing clashes.
  const off = ctx({ tunnel: { enable: false, apiTokenFile: null, ingress: [] } });
  assert.deepEqual(checkIngress(ingress({ hostname: "home.example.com" }), off, null), []);
  // Nor does a disabled proxy.
  const proxyOff = { ...c, proxy: { ...c.proxy, enable: false } };
  assert.deepEqual(checkIngress(ingress(), proxyOff, null), []);
});

// ── page level ──────────────────────────────────────────────────────────────
void test("checkPage: ACME terms and email once the proxy has a route", () => {
  const c = ctx({
    acme: { email: "", acceptTerms: false },
    proxy: { enable: true, publishDns: true, routes: [route()] },
  });
  assert.deepEqual(codes(checkPage(c).proxy), ["acmeTerms", "acmeEmail"]);
  // No route (or the proxy off) orders no certificate, so nothing to accept.
  assert.deepEqual(codes(checkPage({ ...c, proxy: { ...c.proxy, routes: [] } }).proxy), []);
  assert.deepEqual(codes(checkPage({ ...c, proxy: { ...c.proxy, enable: false } }).proxy), []);
});

void test("checkPage: row issues carry the row as subject", () => {
  const c = ctx({
    proxy: { enable: true, publishDns: true, routes: [route({ name: "Nas", host: "ghost" })] },
    tunnel: { enable: true, apiTokenFile: "/t", ingress: [ingress({ host: "cam" })] },
  });
  const { proxy, tunnel } = checkPage(c);
  assert.deepEqual(proxy, [
    { level: "error", code: "unknownHost", names: ["ghost"], subject: "Nas" },
  ]);
  assert.deepEqual(tunnel, [
    { level: "error", code: "noStaticIp", names: ["cam"], subject: "wiki.example.com" },
  ]);
});

void test("checkPage: publishDns without dynamic DNS warns", () => {
  const c = ctx({
    ddns: { enable: false, names: [] },
    proxy: { enable: true, publishDns: true, routes: [route()] },
  });
  assert.deepEqual(codes(checkPage(c).proxy), ["publishWithoutDdns"]);
});

void test("checkPage: IPv4 tcp 80/443 forwards conflict with an enabled proxy", () => {
  const c = ctx({
    portForwards: [
      { name: "web", host: "nas", ports: [443] },
      { host: "nas", ports: [80], family: "ipv6" },
      { host: "nas", ports: [443], protocol: "udp" },
      { host: "game", ports: [8080, 80], family: "ipv4" },
    ],
  });
  const issues = checkPage(c).proxy;
  assert.deepEqual(issues, [{ level: "error", code: "forwardOnWeb", names: ["web", "game"] }]);
  assert.deepEqual(checkPage({ ...c, proxy: { ...c.proxy, enable: false } }).proxy, []);
});

void test("claimsWebPorts", () => {
  assert.equal(claimsWebPorts({ ports: [80] }), true);
  assert.equal(claimsWebPorts({ ports: [443], family: "both", protocol: "tcp" }), true);
  assert.equal(claimsWebPorts({ ports: [443], family: "ipv6" }), false);
  assert.equal(claimsWebPorts({ ports: [80], protocol: "udp" }), false);
  assert.equal(claimsWebPorts({ ports: [8080] }), false);
});

void test("checkPage: an enabled tunnel needs a token file", () => {
  const c = ctx({ tunnel: { enable: true, apiTokenFile: null, ingress: [] } });
  assert.deepEqual(codes(checkPage(c).tunnel), ["tunnelToken"]);
  assert.deepEqual(checkPage({ ...c, tunnel: { ...c.tunnel, enable: false } }).tunnel, []);
});

// ── host cascade ────────────────────────────────────────────────────────────
const refs: HostRefs = {
  portForwards: [
    { host: "nas", ports: [22] },
    { host: "game", ports: [25_565] },
  ],
  routes: [route(), route({ hostnames: ["b.example.com"], host: "game" })],
  ingress: [ingress(), ingress({ hostname: "x.example.com", host: "nas" })],
};

void test("countHostRefs counts every list", () => {
  assert.deepEqual(countHostRefs(refs, "nas"), { forwards: 1, routes: 1, ingress: 2, total: 4 });
  assert.deepEqual(countHostRefs(refs, "none"), { forwards: 0, routes: 0, ingress: 0, total: 0 });
});

void test("renameHostRefs carries every reference along", () => {
  const next = renameHostRefs(refs, "nas", "storage");
  assert.deepEqual(countHostRefs(next, "nas").total, 0);
  assert.deepEqual(countHostRefs(next, "storage"), {
    forwards: 1,
    routes: 1,
    ingress: 2,
    total: 4,
  });
  assert.equal(next.routes[1]?.host, "game");
});

void test("removeHostRefs drops every reference and keeps the rest", () => {
  const next = removeHostRefs(refs, "nas");
  assert.deepEqual(countHostRefs(next, "nas").total, 0);
  assert.equal(next.portForwards.length, 1);
  assert.equal(next.routes.length, 1);
  assert.equal(next.ingress.length, 0);
});
