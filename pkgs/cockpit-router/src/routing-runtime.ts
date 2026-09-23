// Routing runtime: unit states, the reverse proxy's certificates and the
// Cloudflare Tunnel status file — read-only probes plus the "Renew now" /
// "Sync now" triggers. Settings live in router-settings.json (useSettings);
// nothing here writes them.
import { HOST } from "./nix";
import type { TunnelStatus } from "./types";

export const DEFAULT_ACME_TOKEN_FILE = "/etc/router/secrets/cloudflare-acme.token";
export const DEFAULT_TUNNEL_TOKEN_FILE = "/etc/router/secrets/cloudflare-tunnel.token";
export const TUNNEL_STATUS_PATH = "/var/lib/router-cloudflared/status.json";

export const PROXY_UNIT = "router-proxy.service";
export const TUNNEL_SYNC_UNIT = "router-cloudflare-tunnel.service";
// cloudflare-tunnel.nix names the tunnel (and its connector) after the host.
export const TUNNEL_CONNECTOR_UNIT = `cloudflared-tunnel-${HOST}.service`;

export const renewUnit = (cert: string) => `acme-order-renew-${cert}.service`;

export interface UnitState {
  activeState: string; // active | inactive | activating | failed | … ("" = unknown)
  result: string; // success | exit-code | …
  exitedAt: string; // ExecMainExitTimestamp, "" when it never ran
}

const UNKNOWN_UNIT: UnitState = { activeState: "", result: "", exitedAt: "" };

// `systemctl show` answers for a unit that does not exist too (inactive,
// LoadState=not-found), so this only fails when systemctl itself does.
export function unitState(unit: string): Promise<UnitState> {
  return cockpit
    .spawn(["systemctl", "show", "-p", "ActiveState,Result,ExecMainExitTimestamp", "--", unit], {
      err: "ignore",
    })
    .then((out: string) => {
      const kv = new Map(
        out
          .split("\n")
          .filter((l) => l.includes("="))
          .map((l) => [l.slice(0, l.indexOf("=")), l.slice(l.indexOf("=") + 1).trim()]),
      );
      return {
        activeState: kv.get("ActiveState") ?? "",
        result: kv.get("Result") ?? "",
        exitedAt: kv.get("ExecMainExitTimestamp") ?? "",
      };
    })
    .catch(() => UNKNOWN_UNIT);
}

// Start a oneshot and wait for it to finish; a failed run rejects.
export function startUnit(unit: string): Promise<void> {
  return cockpit
    .spawn(["systemctl", "start", "--", unit], { superuser: "require", err: "message" })
    .then(() => {});
}

// ── Certificates ────────────────────────────────────────────────────────────
export interface CertInfo {
  // "missing": no cert.pem yet. "pending": still the self-signed minica
  // placeholder security.acme installs until the first order succeeds.
  state: "missing" | "pending" | "issued";
  notAfter: Date | null;
  issuer: string;
}

// /var/lib/acme/<cert> is readable by root and the acme group only.
export function loadCert(cert: string): Promise<CertInfo> {
  return cockpit
    .spawn(
      ["openssl", "x509", "-issuer", "-enddate", "-noout", "-in", `/var/lib/acme/${cert}/cert.pem`],
      { superuser: "try", err: "ignore" },
    )
    .then((out: string): CertInfo => {
      const issuer = /^issuer=(.*)$/m.exec(out)?.[1]?.trim() ?? "";
      const end = /^notAfter=(.*)$/m.exec(out)?.[1]?.trim();
      const notAfter = end ? new Date(end) : null;
      return {
        state: /minica/i.test(issuer) ? "pending" : "issued",
        notAfter: notAfter && !Number.isNaN(notAfter.getTime()) ? notAfter : null,
        issuer,
      };
    })
    .catch((): CertInfo => ({ state: "missing", notAfter: null, issuer: "" }));
}

// ── Cloudflare Tunnel ───────────────────────────────────────────────────────
// Absent, unreadable or invalid → null ("no status yet"), as loadDdnsStatus.
export async function loadTunnelStatus(): Promise<TunnelStatus | null> {
  try {
    const raw = await cockpit.file(TUNNEL_STATUS_PATH, { superuser: "try" }).read();
    if (!raw || !raw.trim()) {
      return null;
    }
    return JSON.parse(raw) as TunnelStatus;
  } catch {
    return null;
  }
}
