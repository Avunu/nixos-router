// Port-forward rows as the Firewall and Hosts pages write them back: reduced
// to the fields that carry information, so a list that came from the
// effective-config fallback (every default spelled out) is stored as tidily as
// one the admin typed.
import type { PortForward } from "./types";

export const normalizeForward = (r: PortForward): PortForward => ({
  ...(r.name ? { name: r.name } : {}),
  protocol: r.protocol ?? "tcp",
  host: r.host,
  family: r.family ?? "both",
  ports: r.ports,
  ...(r.sources && r.sources.length > 0 ? { sources: r.sources } : {}),
});

// A host rename carries its forwards along, the way a group rename carries
// its member hosts.
export const renameForwardHost = (rows: PortForward[], from: string, to: string) =>
  rows.map((r) => normalizeForward(r.host === from ? { ...r, host: to } : r));
