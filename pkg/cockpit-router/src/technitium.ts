// Technitium DNS Server HTTP API client (read-only dashboard surface).
//
// Auth: a non-expiring API token for the read-only `cockpit` Technitium user,
// provisioned by technitium-reconcile into a root-owned file — read here via
// the Cockpit superuser bridge (an administrative session is required). Calls
// go over cockpit.http to 127.0.0.1:<technitiumPort>.
import { TECHNITIUM_PORT, TECHNITIUM_TOKEN_PATH } from "./nix";
import type { StatsRange, TechnitiumDashboard, TechnitiumTopEntry } from "./types";

let cachedToken: string | null = null;

export class TechnitiumError extends Error {
  public override name = "TechnitiumError";
}

async function token(): Promise<string> {
  if (cachedToken) {
    return cachedToken;
  }
  const raw = await cockpit.file(TECHNITIUM_TOKEN_PATH, { superuser: "require" }).read();
  if (!raw || !raw.trim()) {
    throw new TechnitiumError(
      "Technitium dashboard token is not provisioned yet (technitium-reconcile has not run?)",
    );
  }
  cachedToken = raw.trim();
  return cachedToken;
}

async function apiGet<T>(path: string, params: Record<string, unknown>): Promise<T> {
  const http = cockpit.http({ address: "127.0.0.1", port: TECHNITIUM_PORT });
  const call = async (): Promise<string> =>
    http.get(path, params, { Authorization: `Bearer ${await token()}` });
  let body = await call();
  let parsed = JSON.parse(body) as { status: string; response?: T; errorMessage?: string };
  if (parsed.status === "invalid-token") {
    // Token rotated (e.g. reconcile re-provisioned) — re-read once and retry.
    cachedToken = null;
    body = await call();
    parsed = JSON.parse(body) as { status: string; response?: T; errorMessage?: string };
  }
  if (parsed.status !== "ok" || parsed.response === undefined) {
    throw new TechnitiumError(parsed.errorMessage ?? `Technitium API error (${parsed.status})`);
  }
  return parsed.response;
}

export function statsGet(range: StatsRange): Promise<TechnitiumDashboard> {
  return apiGet<TechnitiumDashboard>("/api/dashboard/stats/get", {
    type: range,
    utc: "true",
  });
}

export function statsGetTop(
  statsType: "TopClients" | "TopDomains" | "TopBlockedDomains",
  range: StatsRange,
  limit = 10,
): Promise<TechnitiumTopEntry[]> {
  return apiGet<Record<string, TechnitiumTopEntry[]>>("/api/dashboard/stats/getTop", {
    type: range,
    statsType,
    limit,
    noReverseLookup: "true",
  }).then((r) => r.topClients ?? r.topDomains ?? r.topBlockedDomains ?? []);
}
