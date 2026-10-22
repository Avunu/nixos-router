// Unit tests for hostname extraction and portal-origin normalization.
//
// checkableHost() decides the only data that ever leaves the browser (a
// hostname, to the user's own router), so its tests pin down that no path,
// query, port or scheme survives, and that names the router cannot have
// blocked by DNS are never sent at all.
import { test } from "node:test";
import assert from "node:assert/strict";

import {
  checkableHost,
  displayAddress,
  normalizeHostname,
  normalizePortalOrigin,
  permissionPattern,
} from "./host.ts";

void test("checkableHost keeps only the lowercase hostname", () => {
  assert.equal(checkableHost("https://Ads.Example.COM/track?id=1#x"), "ads.example.com");
  assert.equal(checkableHost("http://example.com:8080/path"), "example.com");
  assert.equal(checkableHost("https://user:pw@tracker.example.net/"), "tracker.example.net");
  assert.equal(checkableHost("https://_dmarc.example.com/"), "_dmarc.example.com");
  assert.equal(checkableHost("https://a-b.c-d.example/"), "a-b.c-d.example");
});

void test("checkableHost strips exactly one trailing dot", () => {
  assert.equal(checkableHost("https://example.com./"), "example.com");
  // WHATWG URL keeps a doubled dot; one is stripped and the rest is the
  // router's to reject (a 400, which counts as not blocked).
  assert.equal(checkableHost("https://example.com../"), "example.com.");
});

void test("checkableHost passes internationalized names through as punycode", () => {
  assert.equal(checkableHost("https://bücher.example/"), "xn--bcher-kva.example");
  assert.equal(checkableHost("https://xn--bcher-kva.example/"), "xn--bcher-kva.example");
});

void test("checkableHost skips IP literals in every spelling", () => {
  for (const url of [
    "https://192.168.1.1/",
    "https://192.168.1.1./",
    "http://10.0.0.1:8080/",
    // WHATWG URL canonicalizes these to dotted quads.
    "https://0x7f.1/",
    "https://3232235777/",
    "https://[::1]/",
    "https://[fd00::1]:8443/",
  ]) {
    assert.equal(checkableHost(url), null, url);
  }
});

void test("checkableHost skips single-label names and non-web schemes", () => {
  for (const url of [
    "https://router/",
    "https://localhost./",
    "ftp://files.example.com/",
    "chrome-error://chromewebdata/",
    "about:certerror?e=nssBadCert&u=https%3A//ads.example.com/",
    "file:///etc/hosts",
    "data:text/html,hi",
    "not a url",
    "",
  ]) {
    assert.equal(checkableHost(url), null, url);
  }
});

void test("normalizeHostname enforces the router's character set and length", () => {
  assert.equal(normalizeHostname("EXAMPLE.com"), "example.com");
  assert.equal(normalizeHostname("exa mple.com"), null);
  assert.equal(normalizeHostname("ex*ample.com"), null);
  const label = "a".repeat(63);
  const longest = `${label}.${label}.${label}.${"a".repeat(61)}`;
  assert.equal(longest.length, 253);
  assert.equal(normalizeHostname(longest), longest);
  assert.equal(normalizeHostname(`a${longest}`), null);
});

void test("normalizePortalOrigin accepts the forms a person types", () => {
  const canonical = "https://blocked.gw.example.com:8068";
  for (const input of [
    "blocked.gw.example.com",
    "blocked.gw.example.com:8068",
    "https://blocked.gw.example.com:8068",
    "https://blocked.gw.example.com:8068/anything?x=1#y",
    "https://blocked.gw.example.com/portal/blocked",
    "  BLOCKED.GW.Example.COM.  ",
    "blocked.gw.example.com.:8068",
  ]) {
    assert.equal(normalizePortalOrigin(input), canonical, input);
  }
});

void test("normalizePortalOrigin keeps an explicit port, including 443", () => {
  assert.equal(
    normalizePortalOrigin("blocked.gw.example.com:9443"),
    "https://blocked.gw.example.com:9443",
  );
  assert.equal(
    normalizePortalOrigin("blocked.gw.example.com:443"),
    "https://blocked.gw.example.com",
  );
  assert.equal(
    normalizePortalOrigin("https://blocked.gw.example.com:443/x"),
    "https://blocked.gw.example.com",
  );
  assert.equal(
    normalizePortalOrigin("blocked.gw.example.com:08068"),
    "https://blocked.gw.example.com:8068",
  );
});

void test("normalizePortalOrigin rejects anything but https to a DNS name", () => {
  for (const input of [
    "",
    "   ",
    "http://blocked.gw.example.com:8068",
    "HTTP://blocked.gw.example.com",
    "ftp://blocked.gw.example.com",
    "wss://blocked.gw.example.com",
    "https://user@blocked.gw.example.com",
    "https://user:pw@blocked.gw.example.com:8068",
    "192.168.1.1:8068",
    "https://192.168.1.1:8068",
    "[fd00::1]:8068",
    "https://[fd00::1]:8068",
    "router:8068",
    "https://router",
    "blocked.gw.example.com:99999",
    // oxlint-disable-next-line no-script-url -- an input that must be rejected, not a link
    "javascript:alert(1)",
    "blocked gw.example.com",
  ]) {
    assert.equal(normalizePortalOrigin(input), null, input);
  }
});

void test("the permission pattern drops the port and path", () => {
  assert.equal(
    permissionPattern("https://blocked.gw.example.com:8068"),
    "https://blocked.gw.example.com/*",
  );
  assert.equal(
    permissionPattern("https://blocked.gw.example.com"),
    "https://blocked.gw.example.com/*",
  );
});

void test("displayAddress is the origin without its scheme", () => {
  assert.equal(
    displayAddress("https://blocked.gw.example.com:8068"),
    "blocked.gw.example.com:8068",
  );
});
