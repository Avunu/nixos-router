// Unit tests for the portal client: request shape, strict answer validation,
// the 30 s answer cache and the 5 min per-router backoff — with a fake fetch
// and a fake clock.
import { test } from "node:test";
import assert from "node:assert/strict";

import {
  BACKOFF_MS,
  blockPageUrl,
  CACHE_MS,
  checkUrl,
  isBlockPageFor,
  looksLikeBlockPage,
  parseInfo,
  parseVerdict,
  PortalClient,
} from "./portal.ts";
import type { FetchLike } from "./portal.ts";

const ORIGIN = "https://blocked.gw.example.com:8068";
const OTHER = "https://blocked.office.example.org:8068";

type Reply = { status: number; body?: unknown; raw?: string } | "network-error";

interface FakeNet {
  readonly fetch: FetchLike;
  readonly calls: { url: string; init: RequestInit }[];
  reply: (url: string) => Reply;
}

function fakeNet(reply: (url: string) => Reply): FakeNet {
  const net: FakeNet = {
    calls: [],
    reply,
    fetch: async (url, init) => {
      net.calls.push({ url, init });
      const answer = net.reply(url);
      if (answer === "network-error") {
        throw new TypeError("Failed to fetch");
      }
      const text = answer.raw ?? JSON.stringify(answer.body ?? null);
      return new Response(text, {
        status: answer.status,
        headers: { "Content-Type": "application/json" },
      });
    },
  };
  return net;
}

function checkReply(url: string, blocked: boolean, reason: string | null = null): Reply {
  const host = new URL(url).searchParams.get("host");
  return { status: 200, body: { blocked, host, reason } };
}

function fakeClock(start = 1_000_000) {
  const clock = { time: start, now: () => clock.time };
  return clock;
}

/** The `blocked` of a check, or null when the router was unavailable. */
async function blockedAnswer(
  client: PortalClient,
  origin: string,
  host: string,
): Promise<boolean | null> {
  const verdict = await client.checkHost(origin, host);
  return verdict === null ? null : verdict.blocked;
}

void test("parseVerdict accepts exactly the contract's answer", () => {
  assert.deepEqual(
    parseVerdict({ blocked: true, host: "ads.example.com", reason: "Ads" }, "ads.example.com"),
    { blocked: true, reason: "Ads" },
  );
  assert.deepEqual(
    parseVerdict({ blocked: false, host: "ads.example.com", reason: null }, "ads.example.com"),
    { blocked: false, reason: null },
  );
  assert.deepEqual(parseVerdict({ blocked: true, host: "ads.example.com" }, "ads.example.com"), {
    blocked: true,
    reason: null,
  });
  const long = parseVerdict(
    { blocked: true, host: "ads.example.com", reason: "x".repeat(500) },
    "ads.example.com",
  );
  assert.equal(long?.reason?.length, 200);
});

void test("parseVerdict rejects anything else", () => {
  const host = "ads.example.com";
  for (const body of [
    null,
    undefined,
    "blocked",
    [true],
    {},
    { blocked: "true", host },
    { blocked: 1, host },
    { blocked: true },
    { blocked: true, host: "other.example.com" },
    { blocked: true, host: "ADS.example.com" },
    { blocked: true, host, reason: 7 },
    { blocked: true, host, reason: { text: "x" } },
  ]) {
    assert.equal(parseVerdict(body, host), null, JSON.stringify(body));
  }
});

void test("parseInfo accepts apiVersion 1 and later, and nothing that is not a portal", () => {
  assert.deepEqual(parseInfo({ service: "nixos-router-portal", apiVersion: 1, name: "gw" }), {
    apiVersion: 1,
    name: "gw",
  });
  assert.deepEqual(parseInfo({ service: "nixos-router-portal", apiVersion: 2, extra: [1] }), {
    apiVersion: 2,
    name: null,
  });
  assert.deepEqual(parseInfo({ service: "nixos-router-portal", apiVersion: 1, name: "  " }), {
    apiVersion: 1,
    name: null,
  });
  for (const body of [
    null,
    [],
    { service: "something-else", apiVersion: 1 },
    { apiVersion: 1, name: "gw" },
    { service: "nixos-router-portal" },
    { service: "nixos-router-portal", apiVersion: 0 },
    { service: "nixos-router-portal", apiVersion: 1.5 },
    { service: "nixos-router-portal", apiVersion: "1" },
    { service: "nixos-router-portal", apiVersion: 1, name: 42 },
  ]) {
    assert.equal(parseInfo(body), null, JSON.stringify(body));
  }
});

void test("block page URLs are built and recognized by parsing", () => {
  assert.equal(
    blockPageUrl(ORIGIN, "ads.example.com"),
    "https://blocked.gw.example.com:8068/portal/blocked?host=ads.example.com",
  );
  assert.equal(
    checkUrl(ORIGIN, "a b&c"),
    "https://blocked.gw.example.com:8068/portal/check?host=a%20b%26c",
  );
  const url = blockPageUrl(ORIGIN, "ads.example.com");
  assert.equal(isBlockPageFor(url, ORIGIN, "ads.example.com"), true);
  assert.equal(isBlockPageFor(`${url}&lang=en#top`, ORIGIN, "ads.example.com"), true);
  assert.equal(isBlockPageFor(url, ORIGIN, "other.example.com"), false);
  assert.equal(isBlockPageFor(url, OTHER, "ads.example.com"), false);
  assert.equal(
    isBlockPageFor(
      "https://blocked.gw.example.com/portal/blocked?host=ads.example.com",
      ORIGIN,
      "ads.example.com",
    ),
    false,
  );
  assert.equal(
    isBlockPageFor(`${ORIGIN}/portal/blockedx?host=ads.example.com`, ORIGIN, "ads.example.com"),
    false,
  );
  assert.equal(isBlockPageFor("not a url", ORIGIN, "ads.example.com"), false);

  assert.equal(looksLikeBlockPage(url), true);
  assert.equal(looksLikeBlockPage(`${ORIGIN}/portal/blocked`), false);
  assert.equal(
    looksLikeBlockPage("http://blocked.gw.example.com:8068/portal/blocked?host=a.example"),
    false,
  );
  assert.equal(looksLikeBlockPage("https://ads.example.com/"), false);
});

void test("checkHost sends only the host, with the portal header and no credentials", async () => {
  const net = fakeNet((url) => checkReply(url, true, "Advertising"));
  const client = new PortalClient({ fetch: net.fetch, now: fakeClock().now });
  assert.deepEqual(await client.checkHost(ORIGIN, "ads.example.com"), {
    blocked: true,
    reason: "Advertising",
  });
  assert.equal(net.calls.length, 1);
  const [call] = net.calls;
  assert.equal(call?.url, `${ORIGIN}/portal/check?host=ads.example.com`);
  assert.deepEqual(call?.init.headers, { "X-Router-Portal": "1" });
  assert.equal(call?.init.credentials, "omit");
  assert.equal(call?.init.cache, "no-store");
  assert.equal(call?.init.redirect, "error");
  assert.ok(call?.init.signal instanceof AbortSignal);
});

void test("answers are cached for 30 s, blocked and not blocked alike", async () => {
  const clock = fakeClock();
  const net = fakeNet((url) => checkReply(url, url.includes("ads.")));
  const client = new PortalClient({ fetch: net.fetch, now: clock.now });

  assert.equal(await blockedAnswer(client, ORIGIN, "ads.example.com"), true);
  assert.equal(await blockedAnswer(client, ORIGIN, "news.example.com"), false);
  clock.time += CACHE_MS - 1;
  assert.equal(await blockedAnswer(client, ORIGIN, "ads.example.com"), true);
  assert.equal(await blockedAnswer(client, ORIGIN, "news.example.com"), false);
  assert.equal(net.calls.length, 2);

  clock.time += 1;
  await client.checkHost(ORIGIN, "ads.example.com");
  assert.equal(net.calls.length, 3);
  // Cached per origin: another router is asked on its own.
  await client.checkHost(OTHER, "news.example.com");
  assert.equal(net.calls.length, 4);
});

void test("an unavailable router is skipped for 5 minutes", async () => {
  for (const failure of [
    "network-error",
    { status: 503, body: { error: "oracle unavailable" } },
    { status: 429 },
    { status: 500 },
    { status: 403 },
    { status: 200, raw: "<html>not json</html>" },
    { status: 200, body: { blocked: true, host: "someone-else.example" } },
  ] satisfies Reply[]) {
    const clock = fakeClock();
    let down = true;
    const net = fakeNet((url) => (down ? failure : checkReply(url, true)));
    const client = new PortalClient({ fetch: net.fetch, now: clock.now });
    const label = JSON.stringify(failure);

    assert.equal(await client.checkHost(ORIGIN, "ads.example.com"), null, label);
    down = false;
    clock.time += BACKOFF_MS - 1;
    assert.equal(await client.checkHost(ORIGIN, "other.example.com"), null, label);
    assert.equal(net.calls.length, 1, label);
    // Backoff is per origin.
    assert.equal(await blockedAnswer(client, OTHER, "ads.example.com"), true, label);

    clock.time += 1;
    assert.equal(await blockedAnswer(client, ORIGIN, "ads.example.com"), true, label);
    assert.equal(net.calls.length, 3, label);
  }
});

void test("a 400 is not blocked, without backoff", async () => {
  const clock = fakeClock();
  const net = fakeNet((url) =>
    url.includes("bad") ? { status: 400, body: { error: "invalid host" } } : checkReply(url, true),
  );
  const client = new PortalClient({ fetch: net.fetch, now: clock.now });
  assert.deepEqual(await client.checkHost(ORIGIN, "bad..example.com"), {
    blocked: false,
    reason: null,
  });
  assert.equal(await blockedAnswer(client, ORIGIN, "ads.example.com"), true);
  assert.equal(net.calls.length, 2);
});

void test("reset forgets cached answers and backoff", async () => {
  const clock = fakeClock();
  let down = true;
  const net = fakeNet((url) => (down ? "network-error" : checkReply(url, true)));
  const client = new PortalClient({ fetch: net.fetch, now: clock.now });
  assert.equal(await client.checkHost(ORIGIN, "ads.example.com"), null);
  down = false;
  client.reset();
  assert.equal(await blockedAnswer(client, ORIGIN, "ads.example.com"), true);
});

void test("getInfo tells unreachable, not-a-portal and HTTP errors apart", async () => {
  const cases: [Reply, unknown][] = [
    [
      { status: 200, body: { service: "nixos-router-portal", apiVersion: 1, name: "gw" } },
      { ok: true, info: { apiVersion: 1, name: "gw" } },
    ],
    ["network-error", { ok: false, problem: "unreachable" }],
    [{ status: 404 }, { ok: false, problem: "not-portal" }],
    [
      { status: 200, body: { hello: "world" } },
      { ok: false, problem: "not-portal" },
    ],
    [
      { status: 200, raw: "<!doctype html>" },
      { ok: false, problem: "not-portal" },
    ],
    [{ status: 503 }, { ok: false, problem: "http", status: 503 }],
  ];
  for (const [reply, expected] of cases) {
    const net = fakeNet(() => reply);
    const client = new PortalClient({ fetch: net.fetch, now: fakeClock().now });
    assert.deepEqual(await client.getInfo(ORIGIN), expected, JSON.stringify(reply));
    assert.equal(net.calls[0]?.url, `${ORIGIN}/portal/info`);
    assert.deepEqual(net.calls[0]?.init.headers, { "X-Router-Portal": "1" });
  }
});

void test("getInfo ignores and then lifts a router's backoff", async () => {
  let down = true;
  const net = fakeNet((url) => {
    if (down) {
      return "network-error";
    }
    return url.endsWith("/portal/info")
      ? { status: 200, body: { service: "nixos-router-portal", apiVersion: 1, name: "gw" } }
      : checkReply(url, true);
  });
  const client = new PortalClient({ fetch: net.fetch, now: fakeClock().now });
  assert.equal(await client.checkHost(ORIGIN, "ads.example.com"), null);
  down = false;
  const info = await client.getInfo(ORIGIN);
  assert.equal(info.ok, true);
  assert.equal(await blockedAnswer(client, ORIGIN, "ads.example.com"), true);
});
