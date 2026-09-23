// Minimal IPv4 arithmetic for the Hosts page (static-IP suggestions) and the
// policy resolver (subnet matching) — DHCP reservations and the compiled policy
// map are IPv4. Plain arithmetic (no bitwise ops): 32-bit values are exact in
// JS doubles. The IPv6 half at the bottom covers only what port forwards and
// dynamic DNS need: interface identifiers (host suffixes) and prefix syntax.

export function ipToInt(ip: string): number | null {
  const parts = ip.split(".");
  if (parts.length !== 4) {
    return null;
  }
  let value = 0;
  for (const part of parts) {
    if (!/^\d{1,3}$/.test(part)) {
      return null;
    }
    const octet = Number(part);
    if (octet > 255) {
      return null;
    }
    value = value * 256 + octet;
  }
  return value;
}

export function intToIp(value: number): string {
  const octets: number[] = [];
  let rest = value;
  for (let i = 0; i < 4; i++) {
    octets.unshift(rest % 256);
    rest = Math.floor(rest / 256);
  }
  return octets.join(".");
}

// Network part of an address for a prefix length: drop the host bits.
function networkPart(value: number, prefix: number): number {
  const hostBits = 2 ** (32 - prefix);
  return Math.floor(value / hostBits) * hostBits;
}

export function cidrContains(cidr: string, ip: string): boolean {
  const [base, prefixStr] = cidr.split("/");
  const prefix = prefixStr === undefined ? 32 : Number(prefixStr);
  const baseInt = ipToInt(base ?? "");
  const ipInt = ipToInt(ip);
  if (baseInt === null || ipInt === null || Number.isNaN(prefix)) {
    return false;
  }
  if (prefix <= 0) {
    return true;
  }
  return networkPart(baseInt, prefix) === networkPart(ipInt, prefix);
}

export function cidrPrefix(cidr: string): number {
  const [, prefixStr] = cidr.split("/");
  return prefixStr === undefined ? 32 : Number(prefixStr);
}

export interface NetworkShape {
  networkAddress: string; // e.g. 10.48.4.0
  prefixLength: number; // e.g. 24
  gateway: string; // e.g. 10.48.4.1
  poolOffset: number; // first dynamic address = network + poolOffset
  poolSize: number;
}

// Suggest a reservation address: keep the device's current lease if it already
// sits OUTSIDE the dynamic pool; otherwise the first free address in the
// reserved range between gateway+1 and the pool start.
export function suggestStaticIp(
  net: NetworkShape,
  currentIp: string | undefined,
  taken: string[],
): string | null {
  const base = ipToInt(net.networkAddress);
  const gateway = ipToInt(net.gateway);
  if (base === null || gateway === null) {
    return null;
  }
  const poolStart = base + net.poolOffset;
  const poolEnd = poolStart + net.poolSize - 1;
  const inPool = (ip: number) => ip >= poolStart && ip <= poolEnd;

  if (currentIp) {
    const cur = ipToInt(currentIp);
    if (
      cur !== null &&
      !inPool(cur) &&
      cur !== gateway &&
      cidrContains(`${net.networkAddress}/${net.prefixLength}`, currentIp) &&
      !taken.includes(currentIp)
    ) {
      return currentIp;
    }
  }

  const takenInts = new Set(taken.map((t) => ipToInt(t)).filter((v): v is number => v !== null));
  for (let candidate = gateway + 1; candidate < poolStart; candidate++) {
    if (candidate !== gateway && !takenInts.has(candidate)) {
      return intToIp(candidate);
    }
  }
  return null;
}

// ── IPv4 / IPv6 prefixes (port-forward source restrictions) ─────────────────
// Same acceptance as modules/lib/net.nix: no leading zeros in IPv4 octets, no
// IPv4-embedded or zoned IPv6 literals.
export function isV4Prefix(s: string): boolean {
  const m =
    /^(0|[1-9]\d{0,2})\.(0|[1-9]\d{0,2})\.(0|[1-9]\d{0,2})\.(0|[1-9]\d{0,2})(?:\/(0|[1-9]\d?))?$/.exec(
      s,
    );
  if (!m) {
    return false;
  }
  return m.slice(1, 5).every((o) => Number(o) <= 255) && (m[5] === undefined || Number(m[5]) <= 32);
}

export function isV6Prefix(s: string): boolean {
  const [addr = "", len, ...rest] = s.split("/");
  if (rest.length > 0 || (len !== undefined && !/^(0|[1-9]\d{0,2})$/.test(len))) {
    return false;
  }
  return parseIPv6(addr) !== null && (len === undefined || Number(len) <= 128);
}

export const isPrefix = (s: string) => isV4Prefix(s) || isV6Prefix(s);

// ── IPv6 interface identifiers ──────────────────────────────────────────────
// The eight hextets of an IPv6 literal, or null.
export function parseIPv6(s: string): number[] | null {
  if (!/^[0-9A-Fa-f:]+$/.test(s)) {
    return null;
  }
  const halves = s.split("::");
  if (halves.length > 2) {
    return null;
  }
  const groupsOf = (part: string) => (part === "" ? [] : part.split(":"));
  const head = groupsOf(halves[0] ?? "");
  const tail = halves.length === 2 ? groupsOf(halves[1] ?? "") : [];
  const groups = [...head, ...tail];
  if (groups.some((g) => !/^[0-9A-Fa-f]{1,4}$/.test(g))) {
    return null;
  }
  if (halves.length === 1 ? groups.length !== 8 : groups.length > 7) {
    return null;
  }
  const fill: string[] = Array.from({ length: 8 - groups.length }, () => "0");
  return [...head, ...fill, ...tail].map((g) => Number.parseInt(g, 16));
}

// An interface identifier (the low 64 bits a host appends to whatever /64 the
// ISP currently delegates) in the normalized form modules/lib/net.nix emits:
// "::" plus the low hextets with leading zero hextets dropped ("::42",
// "::a8bb:ccff:fedd:ee01"). Null when the value sets any of the upper 64 bits
// or is all zero.
export function normalizeSuffix(s: string): string | null {
  const h = parseIPv6(s.trim());
  if (!h || h.slice(0, 4).some((x) => x !== 0)) {
    return null;
  }
  const low = h.slice(4);
  const first = low.findIndex((x) => x !== 0);
  if (first === -1) {
    return null;
  }
  return `::${low
    .slice(first)
    .map((x) => x.toString(16))
    .join(":")}`;
}

// The interface identifier of a full address, e.g. the one a device is
// already using: "2001:db8:4:0:a8bb:ccff:fedd:ee01" → "::a8bb:ccff:fedd:ee01".
export function suffixOf(addr: string): string | null {
  const h = parseIPv6(addr.trim());
  if (!h) {
    return null;
  }
  return normalizeSuffix(
    `::${h
      .slice(4)
      .map((x) => x.toString(16))
      .join(":")}`,
  );
}

// The modified EUI-64 identifier SLAAC derives from a MAC (RFC 4291 §2.5.1):
// ff:fe in the middle, universal/local bit flipped.
export function eui64Suffix(mac: string): string | null {
  const bytes = mac.split(/[:-]/).map((b) => Number.parseInt(b, 16));
  if (bytes.length !== 6 || bytes.some((b) => Number.isNaN(b) || b < 0 || b > 255)) {
    return null;
  }
  const [b0 = 0, b1 = 0, b2 = 0, b3 = 0, b4 = 0, b5 = 0] = bytes;
  const hex = (hi: number, lo: number) => (hi * 256 + lo).toString(16);
  // Flip bit 1 (the universal/local bit) of the first octet.
  const ul = Math.floor(b0 / 2) % 2 === 1 ? b0 - 2 : b0 + 2;
  return normalizeSuffix(`::${hex(ul, b1)}:${hex(b2, 255)}:${hex(254, b3)}:${hex(b4, b5)}`);
}

// Global unicast (2000::/3) check for picking an observed address to take a
// suffix from: excludes link-local (fe80::/10), ULA (fc00::/7) and multicast.
export function isGlobalIPv6(addr: string): boolean {
  const h = parseIPv6(addr);
  // The top three bits of the first hextet are 001, i.e. 2000 through 3fff.
  return h !== null && Math.floor((h[0] ?? 0) / 8192) === 1;
}

// ── Public DNS names (dynamic DNS) ──────────────────────────────────────────
// Strict LDH, at least two labels, as modules/lib/net.nix's isHostname.
const LABEL = "[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?";
const HOSTNAME_RE = new RegExp(`^(?=.{1,253}$)${LABEL}(?:\\.${LABEL})+$`);
export const isHostname = (s: string) => HOSTNAME_RE.test(s);
