// The router portal's HTTP API, as the extension uses it.
//
//   GET <origin>/portal/info             → {"service":"nixos-router-portal","apiVersion":1,"name":…}
//   GET <origin>/portal/check?host=<h>   → {"blocked":bool,"host":<h>,"reason":string|null}
//   <origin>/portal/blocked?host=<h>       the block page a blocked tab is sent to
//
// Every request carries `X-Router-Portal: 1` (the router answers 403 without
// it, so an ordinary web page cannot drive the API through a user's browser),
// omits credentials, refuses redirects and gives up after 2.5 s. Answers are
// validated strictly: a malformed one is treated as the router being
// unavailable, never as "blocked".
//
// fetch and the clock are injected so the cache and backoff are unit-tested
// with fakes.

const PORTAL_HEADERS = { "X-Router-Portal": "1" } as const;
const REQUEST_TIMEOUT_MS = 2500;
/** How long an answer — blocked or not — is reused for the same origin and host. */
export const CACHE_MS = 30_000;
/** How long a router that failed to answer is skipped. */
export const BACKOFF_MS = 5 * 60_000;
const REASON_MAX = 200;
const NAME_MAX = 253;
/** Past this many cached answers, expired ones are swept on the next write. */
const CACHE_SWEEP_SIZE = 256;

export interface Verdict {
  readonly blocked: boolean;
  readonly reason: string | null;
}

export interface PortalInfo {
  readonly apiVersion: number;
  readonly name: string | null;
}

export type InfoResult =
  | { readonly ok: true; readonly info: PortalInfo }
  | { readonly ok: false; readonly problem: "unreachable" | "not-portal" }
  | { readonly ok: false; readonly problem: "http"; readonly status: number };

export type FetchLike = (url: string, init: RequestInit) => Promise<Response>;

export interface PortalClientOptions {
  readonly fetch: FetchLike;
  readonly now: () => number;
  readonly timeoutMs?: number;
}

const NOT_BLOCKED: Verdict = { blocked: false, reason: null };

export function checkUrl(origin: string, host: string): string {
  return `${origin}/portal/check?host=${encodeURIComponent(host)}`;
}

export function infoUrl(origin: string): string {
  return `${origin}/portal/info`;
}

/** Where a blocked tab is sent: the router's block page, on its own trusted origin. */
export function blockPageUrl(origin: string, host: string): string {
  return `${origin}/portal/blocked?host=${encodeURIComponent(host)}`;
}

function parseUrl(url: string): URL | null {
  try {
    return new URL(url);
  } catch {
    return null;
  }
}

/** Whether `url` is `origin`'s block page for `host` (parsed, not string-matched). */
export function isBlockPageFor(url: string, origin: string, host: string): boolean {
  const parsed = parseUrl(url);
  return (
    parsed !== null &&
    parsed.origin === origin &&
    parsed.pathname === "/portal/blocked" &&
    parsed.searchParams.get("host") === host
  );
}

/**
 * Whether `url` has the shape of some portal's block page. Used to decide what
 * the back-button guard remembers, before knowing which router it came from.
 */
export function looksLikeBlockPage(url: string): boolean {
  const parsed = parseUrl(url);
  return (
    parsed !== null &&
    parsed.protocol === "https:" &&
    parsed.pathname === "/portal/blocked" &&
    parsed.searchParams.has("host")
  );
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

/** Validates a /portal/check answer for `host`; null when it is not one. */
export function parseVerdict(body: unknown, host: string): Verdict | null {
  if (!isRecord(body) || typeof body.blocked !== "boolean" || body.host !== host) {
    return null;
  }
  const { reason } = body;
  if (reason !== undefined && reason !== null && typeof reason !== "string") {
    return null;
  }
  return {
    blocked: body.blocked,
    reason: typeof reason === "string" ? reason.slice(0, REASON_MAX) : null,
  };
}

/**
 * Validates a /portal/info answer. apiVersion 1 is this contract; later
 * versions only add fields, so any integer from 1 up is accepted.
 */
export function parseInfo(body: unknown): PortalInfo | null {
  if (!isRecord(body) || body.service !== "nixos-router-portal") {
    return null;
  }
  const { apiVersion, name } = body;
  if (typeof apiVersion !== "number" || !Number.isInteger(apiVersion) || apiVersion < 1) {
    return null;
  }
  if (name !== undefined && name !== null && typeof name !== "string") {
    return null;
  }
  const trimmed = typeof name === "string" ? name.trim().slice(0, NAME_MAX) : "";
  return { apiVersion, name: trimmed === "" ? null : trimmed };
}

async function readJson(response: Response): Promise<unknown> {
  try {
    const body: unknown = await response.json();
    return body;
  } catch {
    return undefined;
  }
}

interface CacheEntry {
  readonly verdict: Verdict;
  readonly expires: number;
}

export class PortalClient {
  readonly #fetch: FetchLike;
  readonly #now: () => number;
  readonly #timeoutMs: number;
  readonly #cache = new Map<string, CacheEntry>();
  /** origin → time until which it is skipped. */
  readonly #backoff = new Map<string, number>();

  public constructor(options: PortalClientOptions) {
    this.#fetch = options.fetch;
    this.#now = options.now;
    this.#timeoutMs = options.timeoutMs ?? REQUEST_TIMEOUT_MS;
  }

  #request(url: string): Promise<Response> {
    return this.#fetch(url, {
      method: "GET",
      credentials: "omit",
      cache: "no-store",
      redirect: "error",
      referrerPolicy: "no-referrer",
      headers: PORTAL_HEADERS,
      signal: AbortSignal.timeout(this.#timeoutMs),
    });
  }

  /**
   * Whether `origin`'s router blocks `host` for this device, or null when that
   * router is unavailable: unreachable, timed out, rate limiting, its DNS
   * oracle down (503), or an answer that fails validation. An unavailable
   * router is skipped for BACKOFF_MS so a browser off that router's network
   * does not wait on it for every failed page. A 400 means the router rejects
   * the name, which it therefore cannot have blocked.
   */
  public async checkHost(origin: string, host: string): Promise<Verdict | null> {
    const key = `${origin}|${host}`;
    const cached = this.#cache.get(key);
    if (cached !== undefined && cached.expires > this.#now()) {
      return cached.verdict;
    }
    if ((this.#backoff.get(origin) ?? 0) > this.#now()) {
      return null;
    }
    let verdict: Verdict | null = null;
    try {
      const response = await this.#request(checkUrl(origin, host));
      if (response.status === 400) {
        verdict = NOT_BLOCKED;
      } else if (response.status === 200) {
        verdict = parseVerdict(await readJson(response), host);
      }
    } catch {
      verdict = null;
    }
    if (verdict === null) {
      this.#backoff.set(origin, this.#now() + BACKOFF_MS);
      return null;
    }
    this.#remember(key, verdict);
    return verdict;
  }

  #remember(key: string, verdict: Verdict): void {
    const now = this.#now();
    if (this.#cache.size >= CACHE_SWEEP_SIZE) {
      for (const [k, entry] of this.#cache) {
        if (entry.expires <= now) {
          this.#cache.delete(k);
        }
      }
    }
    this.#cache.set(key, { verdict, expires: now + CACHE_MS });
  }

  /**
   * Pairing: whether `origin` is a nixos-router portal, and its router's name.
   * Always asks (no cache, no backoff) — it runs on a person's click — and a
   * successful answer lifts that origin's backoff.
   */
  public async getInfo(origin: string): Promise<InfoResult> {
    let response: Response;
    try {
      response = await this.#request(infoUrl(origin));
    } catch {
      return { ok: false, problem: "unreachable" };
    }
    if (response.status === 404) {
      return { ok: false, problem: "not-portal" };
    }
    if (response.status !== 200) {
      return { ok: false, problem: "http", status: response.status };
    }
    const info = parseInfo(await readJson(response));
    if (info === null) {
      return { ok: false, problem: "not-portal" };
    }
    this.#backoff.delete(origin);
    return { ok: true, info };
  }

  /** Forgets every cached answer and backoff (the router list changed). */
  public reset(): void {
    this.#cache.clear();
    this.#backoff.clear();
  }
}
