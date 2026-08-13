// Pure client-side mirror of the backend policy compiler's precedence, used by
// the Access Policies preview tab and the Users page effective-policy display:
//   host group > directory group (of the device's user) > subnet/network >
//   defaultPolicy; within a tier the highest `priority` wins.
//
// Devices without a static IP can never receive a device-tier policy — they
// follow their network's assignment (mirrors router-policy-compile).
import { cidrContains, cidrPrefix } from "./ip-math";
import type { AccessPoliciesSection, AccessPolicy, DirectoryState, RouterHost } from "./types";

export interface MatchStep {
  tier: "hostGroup" | "directoryGroup" | "subnet" | "network" | "default";
  detail: string;
  policy: string | null;
  won: boolean;
}

export interface Resolution {
  policy: string | null;
  chain: MatchStep[];
}

export interface NetworkCidrs {
  lan?: string;
  guest?: string;
  wireguard?: string[];
}

function byPriority(policies: AccessPolicy[]): AccessPolicy | null {
  let best: AccessPolicy | null = null;
  for (const policy of policies) {
    if (best === null || (policy.priority ?? 0) > (best.priority ?? 0)) {
      best = policy;
    }
  }
  return best;
}

function userGroupKeys(directory: DirectoryState, userRef: string): Set<string> {
  const ref = userRef.toLowerCase();
  const user = directory.users.find(
    (u) => u.id.toLowerCase() === ref || u.email.toLowerCase() === ref,
  );
  const keys = new Set<string>();
  if (!user) {
    return keys;
  }
  for (const gid of user.groups) {
    keys.add(gid.toLowerCase());
    const group = directory.groups.find((g) => g.id.toLowerCase() === gid.toLowerCase());
    if (group) {
      keys.add(group.name.toLowerCase());
    }
  }
  return keys;
}

export function resolvePolicy(
  input: { host?: RouterHost; ip?: string; userId?: string },
  section: AccessPoliciesSection,
  networks: NetworkCidrs,
  directory: DirectoryState | null,
  hosts: RouterHost[],
): Resolution {
  const policies = section.policies ?? [];
  const chain: MatchStep[] = [];
  const host =
    input.host ??
    (input.ip ? hosts.find((h) => h.staticIp === input.ip) : undefined) ??
    (input.userId ? hosts.find((h) => h.user === input.userId) : undefined);
  const ip = input.ip ?? host?.staticIp ?? undefined;
  const pinned = Boolean(host?.staticIp);

  // ── device tier: host group ──
  if (host?.group && pinned) {
    const winner = byPriority(
      policies.filter((p) => (p.assignments?.hostGroups ?? []).includes(host.group ?? "")),
    );
    chain.push({
      tier: "hostGroup",
      detail: `device '${host.name}' in group '${host.group}'`,
      policy: winner?.name ?? null,
      won: Boolean(winner),
    });
    if (winner) {
      return { policy: winner.name, chain };
    }
  } else if (host?.group && !pinned) {
    chain.push({
      tier: "hostGroup",
      detail: `device '${host.name}' has group '${host.group}' but NO static IP — tier skipped`,
      policy: null,
      won: false,
    });
  }

  // ── device tier: directory group of the assigned user ──
  const userRef = input.userId ?? host?.user ?? null;
  if (userRef && directory && (pinned || !host)) {
    const keys = userGroupKeys(directory, userRef);
    const winner = byPriority(
      policies.filter((p) =>
        (p.assignments?.directoryGroups ?? []).some((g) => keys.has(g.toLowerCase())),
      ),
    );
    chain.push({
      tier: "directoryGroup",
      detail: `user '${userRef}' (${keys.size} directory group memberships)`,
      policy: winner?.name ?? null,
      won: Boolean(winner),
    });
    if (winner) {
      return { policy: winner.name, chain };
    }
  }

  // ── subnet / network tier (most specific CIDR wins; priority breaks ties) ──
  if (ip) {
    interface Candidate {
      policy: AccessPolicy;
      cidr: string;
      via: string;
    }
    const candidates: Candidate[] = [];
    for (const policy of policies) {
      for (const cidr of policy.assignments?.subnets ?? []) {
        if (cidrContains(cidr, ip)) {
          candidates.push({ policy, cidr, via: `subnet ${cidr}` });
        }
      }
      for (const net of policy.assignments?.networks ?? []) {
        const cidrs =
          net === "wireguard" ? (networks.wireguard ?? []) : [networks[net]].filter(Boolean);
        for (const cidr of cidrs as string[]) {
          if (cidrContains(cidr, ip)) {
            candidates.push({ policy, cidr, via: `network ${net} (${cidr})` });
          }
        }
      }
    }
    candidates.sort(
      (a, b) =>
        cidrPrefix(b.cidr) - cidrPrefix(a.cidr) ||
        (b.policy.priority ?? 0) - (a.policy.priority ?? 0),
    );
    const [winner] = candidates;
    chain.push({
      tier: "network",
      detail: winner ? `matched via ${winner.via}` : `no network/subnet assignment matches ${ip}`,
      policy: winner?.policy.name ?? null,
      won: Boolean(winner),
    });
    if (winner) {
      return { policy: winner.policy.name, chain };
    }
  }

  // ── default ──
  const fallback = section.defaultPolicy ?? null;
  chain.push({
    tier: "default",
    detail: "defaultPolicy",
    policy: fallback,
    won: fallback !== null,
  });
  return { policy: fallback, chain };
}
