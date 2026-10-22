// Unit tests for which navigation errors reach the router.
import { test } from "node:test";
import assert from "node:assert/strict";

import { shouldCheck } from "./errors.ts";

void test("Chromium: certificate, TLS and ECH errors are checked", () => {
  for (const error of [
    "net::ERR_CERT_AUTHORITY_INVALID",
    "net::ERR_CERT_COMMON_NAME_INVALID",
    "net::ERR_CERT_DATE_INVALID",
    "net::ERR_SSL_PROTOCOL_ERROR",
    "net::ERR_SSL_VERSION_OR_CIPHER_MISMATCH",
    "net::ERR_ECH_FALLBACK_CERTIFICATE_INVALID",
  ]) {
    assert.equal(shouldCheck(error), true, error);
  }
});

void test("Chromium: a refused, reset or silent Block Page port is checked", () => {
  for (const error of [
    "net::ERR_CONNECTION_REFUSED",
    "net::ERR_CONNECTION_RESET",
    "net::ERR_CONNECTION_CLOSED",
    "net::ERR_CONNECTION_TIMED_OUT",
    "net::ERR_TIMED_OUT",
    "net::ERR_ADDRESS_INVALID",
    "net::ERR_ADDRESS_UNREACHABLE",
    "net::ERR_EMPTY_RESPONSE",
  ]) {
    assert.equal(shouldCheck(error), true, error);
  }
});

void test("Chromium: everything else is not sent to the router", () => {
  for (const error of [
    "net::ERR_ABORTED",
    "net::ERR_NAME_NOT_RESOLVED",
    "net::ERR_BLOCKED_BY_CLIENT",
    "net::ERR_BLOCKED_BY_ADMINISTRATOR",
    "net::ERR_INTERNET_DISCONNECTED",
    "net::ERR_TOO_MANY_REDIRECTS",
    // Exact names only: a longer error that merely starts like one is not it.
    "net::ERR_CONNECTION_REFUSED_BY_POLICY",
    "net::ERR_CERTIFICATE_TRANSPARENCY_REQUIRED",
  ]) {
    assert.equal(shouldCheck(error), false, error);
  }
});

void test("Firefox: any error but an abort is checked", () => {
  for (const error of [
    // SEC_ERROR_UNKNOWN_ISSUER (0x805A1FF3)
    "Error code 2153390067",
    // NS_ERROR_CONNECTION_REFUSED (0x804B000D)
    "Error code 2152398861",
    // Localized prose carries no code at all.
    "Échec de la connexion sécurisée",
  ]) {
    assert.equal(shouldCheck(error), true, error);
  }
});

void test("Firefox: aborts are not checked, by code or by name", () => {
  for (const error of [
    "Error code 2152398850",
    "NS_BINDING_ABORTED",
    "Error code 2147500036",
    "NS_ERROR_ABORT",
  ]) {
    assert.equal(shouldCheck(error), false, error);
  }
});

void test("a missing error is checked", () => {
  // oxlint-disable-next-line no-useless-undefined -- the absent field is the case under test
  assert.equal(shouldCheck(undefined), true);
  assert.equal(shouldCheck(""), true);
});
