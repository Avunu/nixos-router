// Unit tests for the IPv6 / prefix / hostname helpers the port-forward and
// dynamic-DNS forms validate with.
//
// Their contract is agreement with modules/lib/net.nix: a value the form lets
// through must pass the module's assertion on rebuild, and a suffix the form
// normalizes must be byte-for-byte the one the nftables pinhole matches on.
//
// Run with `npm test`.
import { test } from "node:test";
import assert from "node:assert/strict";

import {
  eui64Suffix,
  isGlobalIPv6,
  isHostname,
  isPrefix,
  isV4Prefix,
  isV6Prefix,
  normalizeSuffix,
  parseIPv6,
  suffixOf,
} from "./ip-math.ts";

void test("parseIPv6 expands compression and rejects what the Nix parser rejects", () => {
  const hx = (s: string) => Number.parseInt(s, 16);
  assert.deepEqual(parseIPv6("::42"), [0, 0, 0, 0, 0, 0, 0, hx("42")]);
  assert.deepEqual(parseIPv6("2001:db8::1"), [hx("2001"), hx("db8"), 0, 0, 0, 0, 0, 1]);
  assert.deepEqual(parseIPv6("::"), [0, 0, 0, 0, 0, 0, 0, 0]);
  assert.deepEqual(parseIPv6("1:2:3:4:5:6:7:8"), [1, 2, 3, 4, 5, 6, 7, 8]);
  for (const bad of [
    "",
    "zz",
    "1:::2",
    "1::2::3",
    ":1::",
    "::ffff:1.2.3.4",
    "fe80::1%eth0",
    "1:2:3:4:5:6:7",
    "12345::",
  ]) {
    assert.equal(parseIPv6(bad), null, bad);
  }
});

void test("normalizeSuffix matches the form modules/lib/net.nix emits", () => {
  // Pairs verified against `parseSuffix` in modules/lib/net.nix.
  assert.equal(normalizeSuffix("::42"), "::42");
  assert.equal(normalizeSuffix("::0042"), "::42");
  assert.equal(normalizeSuffix("::A8BB:CCFF:FEDD:EE01"), "::a8bb:ccff:fedd:ee01");
  assert.equal(normalizeSuffix("::1:0:0"), "::1:0:0");
  assert.equal(normalizeSuffix("0:0:0:0:0:0:0:42"), "::42");
});

void test("normalizeSuffix refuses anything that is not an interface identifier", () => {
  assert.equal(normalizeSuffix("::"), null, "all zero");
  assert.equal(normalizeSuffix("1::42"), null, "upper 64 bits set");
  assert.equal(normalizeSuffix("2001:db8::1"), null, "a full address");
  assert.equal(normalizeSuffix("::42/64"), null, "a prefix");
});

void test("suffixOf takes the low 64 bits of an observed address", () => {
  assert.equal(suffixOf("2001:db8:4:0:a8bb:ccff:fedd:ee01"), "::a8bb:ccff:fedd:ee01");
  assert.equal(suffixOf("2001:db8:4::42"), "::42");
  assert.equal(suffixOf("2001:db8:4::"), null, "subnet-router anycast has no identifier");
});

void test("eui64Suffix flips the universal/local bit and inserts ff:fe", () => {
  // RFC 4291 appendix A: 34-56-78-9A-BC-DE → 3656:78ff:fe9a:bcde.
  assert.equal(eui64Suffix("34:56:78:9a:bc:de"), "::3656:78ff:fe9a:bcde");
  assert.equal(eui64Suffix("02:00:00:00:00:42"), "::ff:fe00:42");
  assert.equal(eui64Suffix("not-a-mac"), null);
});

void test("isGlobalIPv6 keeps global unicast only", () => {
  assert.ok(isGlobalIPv6("2001:db8::1"));
  assert.ok(!isGlobalIPv6("fe80::1"));
  assert.ok(!isGlobalIPv6("fd00::1"));
  assert.ok(!isGlobalIPv6("ff02::1"));
  assert.ok(!isGlobalIPv6("10.0.0.1"));
});

void test("prefix validation accepts both families and nothing malformed", () => {
  assert.ok(isV4Prefix("203.0.113.0/24"));
  assert.ok(isV4Prefix("198.51.100.7"));
  assert.ok(!isV4Prefix("256.1.1.1"));
  assert.ok(!isV4Prefix("010.1.1.1"), "leading zeros");
  assert.ok(!isV4Prefix("1.2.3.4/33"));
  assert.ok(isV6Prefix("2001:db8::/32"));
  assert.ok(isV6Prefix("2001:db8::1"));
  assert.ok(!isV6Prefix("2001:db8::/129"));
  assert.ok(!isV6Prefix("2001:db8::/32/1"));
  assert.ok(isPrefix("2001:db8:100::/48") && isPrefix("203.0.113.0/24"));
  assert.ok(!isPrefix("not-a-prefix"));
});

void test("isHostname is strict LDH with at least two labels", () => {
  assert.ok(isHostname("nas.example.com"));
  assert.ok(isHostname("xn--bcher-kva.example"));
  assert.ok(!isHostname("example"), "single label");
  assert.ok(!isHostname("no_underscores.example.com"));
  assert.ok(!isHostname("-x.example.com"));
  assert.ok(!isHostname("x.example.com."), "trailing dot");
  assert.ok(!isHostname(`${"a".repeat(64)}.example.com`), "label over 63");
});
