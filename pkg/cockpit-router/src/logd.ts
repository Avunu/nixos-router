// router-logd HTTP API client — the query-log store, stats aggregates, and the
// exception-request queue. Same token-from-file pattern as technitium.ts (the
// query token is root-owned; an administrative Cockpit session is required).
import { LOGD_PORT, LOGD_TOKEN_PATH } from "./nix";
import type { ExceptionRequest, LogPage, LogSummary, TopEntry } from "./types";

let cachedToken: string | null = null;

export class LogdError extends Error {
  public override name = "LogdError";
}

async function token(): Promise<string> {
  if (cachedToken) {
    return cachedToken;
  }
  const raw = await cockpit.file(LOGD_TOKEN_PATH, { superuser: "require" }).read();
  if (!raw || !raw.trim()) {
    throw new LogdError("router-logd query token is not provisioned yet");
  }
  cachedToken = raw.trim();
  return cachedToken;
}

async function call<T>(
  method: string,
  path: string,
  params?: Record<string, unknown>,
  body?: string,
): Promise<T> {
  const http = cockpit.http({ address: "127.0.0.1", port: LOGD_PORT });
  const headers = { Authorization: `Bearer ${await token()}` };
  const text =
    method === "GET"
      ? await http.get(path, params ?? null, headers)
      : await http.request({ method, path, params, headers, body });
  return JSON.parse(text) as T;
}

export interface LogFilters {
  start?: string; // ISO8601 UTC
  end?: string;
  client?: string;
  qname?: string; // substring match
  group?: string;
  policy?: string;
  blocked?: boolean;
}

function filterParams(f: LogFilters): Record<string, unknown> {
  const params: Record<string, unknown> = {};
  for (const key of ["start", "end", "client", "qname", "group", "policy"] as const) {
    if (f[key]) {
      params[key] = f[key];
    }
  }
  if (f.blocked) {
    params.blocked = "1";
  }
  return params;
}

export function logsQuery(filters: LogFilters, page = 1, pageSize = 50): Promise<LogPage> {
  return call<LogPage>("GET", "/logs", { ...filterParams(filters), page, pageSize });
}

// Raw CSV of the current filter (for a client-side Blob download).
export async function logsCsv(filters: LogFilters): Promise<string> {
  const http = cockpit.http({ address: "127.0.0.1", port: LOGD_PORT });
  return http.get("/logs.csv", filterParams(filters), {
    Authorization: `Bearer ${await token()}`,
  });
}

export function statsTop(
  by: "domain" | "blocked" | "client" | "group" | "policy" | "device",
  filters: LogFilters,
  limit = 10,
): Promise<TopEntry[]> {
  return call<{ top: TopEntry[] }>("GET", "/stats/top", {
    ...filterParams(filters),
    by,
    limit,
  }).then((r) => r.top);
}

export function statsSummary(filters: LogFilters): Promise<LogSummary> {
  return call<LogSummary>("GET", "/stats/summary", filterParams(filters));
}

export function exceptionRequests(status?: string): Promise<ExceptionRequest[]> {
  return call<{ requests: ExceptionRequest[] }>(
    "GET",
    "/portal/requests",
    status ? { status } : undefined,
  ).then((r) => r.requests);
}

export function setExceptionStatus(
  id: number,
  status: "approved" | "denied" | "pending",
): Promise<unknown> {
  return call("POST", `/portal/requests/${id}/status`, undefined, JSON.stringify({ status }));
}
