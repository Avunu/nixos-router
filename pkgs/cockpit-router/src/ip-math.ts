// Minimal IPv4 arithmetic for the Hosts page (static-IP suggestions) and the
// policy resolver (subnet matching). IPv4-only by design — DHCP reservations
// and the compiled policy map are IPv4. Plain arithmetic (no bitwise ops):
// 32-bit values are exact in JS doubles.

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
