// Unit tests for browser-extension.ts: when the Block page tab offers the
// extension, and the address and policies it hands out. The portal's name and
// port must match modules/cockpit-cert.nix (blocked.<fqdn>) and
// router.reporting.logd.tlsPort.
//
// Run with `npm test`.
import { test } from "node:test";
import assert from "node:assert/strict";

import { EXTENSION_IDS, chromePolicy, firefoxPolicy, portalState } from "./browser-extension.ts";

const applied = (over: Record<string, unknown> = {}) => ({
  fqdn: "GW.Example.com",
  accessPolicies: { blockPage: { enable: true } },
  dns: { technitium: { enable: true } },
  reporting: { logd: { tlsPort: 8068 } },
  ...over,
});

void test("ready: blocked.<fqdn> on the TLS port, lowercased", () => {
  assert.deepEqual(portalState(applied()), {
    state: "ready",
    name: "blocked.gw.example.com",
    port: 8068,
    origin: "https://blocked.gw.example.com:8068",
    address: "blocked.gw.example.com:8068",
  });
});

void test("a moved TLS port is used, a missing one defaults", () => {
  const moved = portalState(applied({ reporting: { logd: { tlsPort: 9443 } } }));
  assert.equal(moved.state === "ready" && moved.origin, "https://blocked.gw.example.com:9443");
  const missing = portalState(applied({ reporting: {} }));
  assert.equal(missing.state === "ready" && missing.port, 8068);
});

void test("no portal without a name, a block page, or Technitium", () => {
  assert.equal(portalState(applied({ fqdn: null })).state, "needsName");
  assert.equal(portalState(applied({ fqdn: "  " })).state, "needsName");
  assert.equal(
    portalState(applied({ accessPolicies: { blockPage: { enable: false } } })).state,
    "needsBlockPage",
  );
  assert.equal(portalState(applied({ dns: { technitium: { enable: false } } })).state, "needsDns");
});

void test("policies carry the origin under the extension's id", () => {
  const origin = "https://blocked.gw.example.com:8068";
  const id = "abcdefghijklmnopabcdefghijklmnop";
  assert.deepEqual(JSON.parse(firefoxPolicy(origin)) as unknown, {
    policies: { "3rdparty": { Extensions: { [EXTENSION_IDS.firefox]: { routers: [origin] } } } },
  });
  assert.deepEqual(JSON.parse(chromePolicy(origin, id)) as unknown, {
    "3rdparty": { extensions: { [id]: { routers: [origin] } } },
  });
});
