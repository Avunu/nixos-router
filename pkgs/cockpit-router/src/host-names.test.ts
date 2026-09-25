// Unit tests for the device-name rules (host-names.ts).
//
// Their contract is agreement with modules/hosts.nix: a name the Hosts editor
// lets through must pass the module's type and uniqueness assertion on
// rebuild. The Adopt form used to pre-fill every mDNS name the device answered
// to, joined with ", ", and the comma alone failed the rebuild.
//
// Run with `npm test`.
import { test } from "node:test";
import assert from "node:assert/strict";

import { hostNameError, sanitizeHostName } from "./host-names.ts";

const MAC = "aa:bb:cc:dd:ee:01";

void test("hostNameError: mirrors strMatching [A-Za-z0-9][A-Za-z0-9_. -]*", () => {
  for (const ok of ["nas", "Kiosk 1", "printer.office", "cam_2", "7-eleven", "a"]) {
    assert.equal(hostNameError(ok, []), null, ok);
  }
  for (const bad of ["-nas", ".nas", "_nas", "nas, nas-2", "Kevin's iPhone", "nas/1", "café"]) {
    assert.equal(hostNameError(bad, []), "pattern", bad);
  }
});

void test("hostNameError: checks the trimmed name the editor saves", () => {
  assert.equal(hostNameError("  nas  ", []), null);
  assert.equal(hostNameError("", []), "empty");
  assert.equal(hostNameError("   ", []), "empty");
});

void test("hostNameError: names are unique, compared exactly", () => {
  assert.equal(hostNameError("nas", ["nas", "tv"]), "duplicate");
  assert.equal(hostNameError(" nas ", ["nas"]), "duplicate");
  assert.equal(hostNameError("NAS", ["nas"]), null);
});

void test("sanitizeHostName: the default always passes hostNameError", () => {
  const taken = ["nas", "iPhone"];
  for (const live of [
    "",
    "nas.local",
    "iPhone.local, iPhone-2.local",
    "Kevin’s MacBook Pro.local",
    "Café-Printer.local",
    "--- (),. ---",
    "日本語.local",
    "_airplay._tcp.local",
  ]) {
    const name = sanitizeHostName(live, MAC, taken);
    assert.equal(hostNameError(name, taken), null, `${live} → ${name}`);
  }
});

void test("sanitizeHostName: first mDNS name, without .local", () => {
  assert.equal(sanitizeHostName("tv.local", MAC, []), "tv");
  assert.equal(sanitizeHostName("tv.LOCAL.", MAC, []), "tv");
  assert.equal(sanitizeHostName("tv.local, tv-2.local", MAC, []), "tv");
  // Only the mDNS domain goes; other dots are allowed.
  assert.equal(sanitizeHostName("printer.office.local", MAC, []), "printer.office");
});

void test("sanitizeHostName: replaces what the pattern refuses", () => {
  assert.equal(sanitizeHostName("Kevin’s MacBook Pro.local", MAC, []), "Kevin-s MacBook Pro");
  assert.equal(sanitizeHostName("Café-Printer.local", MAC, []), "Cafe-Printer");
  assert.equal(sanitizeHostName("_airplay._tcp.local", MAC, []), "airplay._tcp");
  assert.equal(sanitizeHostName("Printer (2).local", MAC, []), "Printer -2");
});

void test("sanitizeHostName: falls back to the MAC when nothing is left", () => {
  assert.equal(sanitizeHostName("", MAC, []), "device-ddee01");
  assert.equal(sanitizeHostName("日本語.local", "AA:BB:CC:DD:EE:FF", []), "device-ddeeff");
});

void test("sanitizeHostName: steers clear of registered names", () => {
  assert.equal(sanitizeHostName("nas.local", MAC, ["nas"]), "nas-2");
  assert.equal(sanitizeHostName("nas.local", MAC, ["nas", "nas-2"]), "nas-3");
  assert.equal(sanitizeHostName("", MAC, ["device-ddee01"]), "device-ddee01-2");
});
