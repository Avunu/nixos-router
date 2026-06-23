// Physical-NIC discovery and client-side validation of the interface/VLAN
// assignment model, shared by the Network page. Validation mirrors the module's
// `assertions` (flake.nix) so the UI can warn before a rebuild would fail.
import { useEffect, useState, useCallback } from "react";

export interface Nic {
  name: string;
  up: boolean;
  carrier: boolean;
  mac: string;
}

// Names that `ip -j link` reports but are not assignable physical ports.
const isVirtual = (n: string) =>
  n === "lo" ||
  n.includes(".") || // VLAN sub-interface (eth0.20)
  /^(br-|wg|veth|docker|virbr|tap|tun|bond|dummy)/.test(n);

export function useInterfaces() {
  const [nics, setNics] = useState<Nic[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");

  const reload = useCallback(() => {
    setLoading(true);
    cockpit
      .spawn(["ip", "-j", "link"], { err: "message" })
      .then((out: string) => {
        const parsed: any[] = JSON.parse(out || "[]");
        const list: Nic[] = parsed
          .filter((l) => l.link_type === "ether" && !isVirtual(l.ifname))
          .map((l) => ({
            name: l.ifname,
            up: (l.flags || []).includes("UP"),
            carrier: (l.flags || []).includes("LOWER_UP"),
            mac: l.address || "",
          }));
        list.sort((a, b) => a.name.localeCompare(b.name, undefined, { numeric: true }));
        setNics(list);
        setLoading(false);
      })
      .catch((e: any) => {
        setError(e.message || String(e));
        setLoading(false);
      });
  }, []);

  useEffect(() => {
    reload();
  }, [reload]);

  return { nics, loading, error, reload };
}

// Resolved view of the interface/VLAN settings (built from leaf reads so that
// effective defaults are not shadowed by a partial `desired` object).
export interface NetView {
  trunkInterfaces: string[];
  wan: { interface: string | null; vlan: number | null };
  lan: { interfaces: string[]; vlan: number | null; taggedInterfaces: string[] };
  guest: { enable: boolean; interfaces: string[]; vlan: number | null; taggedInterfaces: string[] };
}

const uniq = (a: string[]) => [...new Set(a)];

// Returns human-readable error strings (empty list = valid). Mirrors the
// assertions in flake.nix so Save & Apply can be blocked on an invalid topology.
export function validateNetwork(n: NetView): string[] {
  const errs: string[] = [];
  const wanIf = n.wan.interface ? [n.wan.interface] : [];
  const lanIf = n.lan.interfaces || [];
  const guestIf = n.guest.enable ? n.guest.interfaces || [] : [];

  if (!n.wan.interface && n.wan.vlan == null) errs.push("WAN: assign an untagged interface and/or set a VLAN id.");
  if (lanIf.length === 0 && n.lan.vlan == null) errs.push("LAN: assign interface(s) and/or set a VLAN id.");
  if (n.guest.enable && guestIf.length === 0 && n.guest.vlan == null)
    errs.push("Guest: assign interface(s) and/or set a VLAN id.");

  const owned = [...wanIf, ...lanIf, ...guestIf];
  if (owned.length === 0) errs.push("Assign at least one physical interface to a network.");
  const dup = uniq(owned.filter((p, i) => owned.indexOf(p) !== i));
  if (dup.length) errs.push(`Interface assigned to more than one network: ${dup.join(", ")}.`);

  const tagged = (extra: string[]) => uniq([...(n.trunkInterfaces || []), ...extra]);
  if (n.wan.vlan != null && tagged([]).length === 0)
    errs.push("WAN VLAN is set but no trunk port carries its tag — add a trunk port.");
  if (n.lan.vlan != null && tagged(n.lan.taggedInterfaces || []).length === 0)
    errs.push("LAN VLAN is set but no port carries its tag.");
  if (n.guest.enable && n.guest.vlan != null && tagged(n.guest.taggedInterfaces || []).length === 0)
    errs.push("Guest VLAN is set but no port carries its tag.");

  if ((n.lan.taggedInterfaces || []).length && n.lan.vlan == null)
    errs.push("LAN tagged interfaces are set but no VLAN id is set.");
  if (n.guest.enable && (n.guest.taggedInterfaces || []).length && n.guest.vlan == null)
    errs.push("Guest tagged interfaces are set but no VLAN id is set.");

  const vids = [n.wan.vlan, n.lan.vlan, n.guest.enable ? n.guest.vlan : null].filter(
    (v): v is number => v != null,
  );
  if (vids.length !== new Set(vids).size) errs.push("VLAN ids must be distinct across networks.");
  for (const v of vids) if (v < 1 || v > 4094) errs.push(`VLAN id ${v} is out of range (1–4094).`);

  const checkLen = (ports: string[], vid: number | null) => {
    if (vid == null) return;
    for (const p of ports)
      if (`${p}.${vid}`.length > 15) errs.push(`VLAN sub-interface "${p}.${vid}" exceeds the 15-char kernel limit.`);
  };
  checkLen(tagged([]), n.wan.vlan);
  checkLen(tagged(n.lan.taggedInterfaces || []), n.lan.vlan);
  if (n.guest.enable) checkLen(tagged(n.guest.taggedInterfaces || []), n.guest.vlan);

  return errs;
}
