"""Split-horizon DNS reconciliation.

Asserts the zones and records generated from `router.dns.overrides`,
`router.dns.forwardZones` and `router.dns.registerStaticHosts`.

The zone MODEL lives in Nix (modules/dns-technitium.nix): by the time the
spec arrives here every record already carries the zone that owns it, so
this module never re-derives grouping. What it does own is the imperative
half Nix cannot express — creating zones of the right TYPE, writing rdata
with the per-type parameter Technitium expects, and reaping what an admin
removed.

Reaping needs memory: Technitium cannot tell a record the router wrote from
one an operator added in its web console, so anything this module created is
recorded in its own managed-state file (`localDns.managedFile`) and only
those entries are ever deleted. SafeSearch keeps its separate
`managedZonesFile` — the two reapers must not be able to eat each other's
zones.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

from .technitium_api import TechnitiumClient, TechnitiumError

MANAGED_VERSION = 1


def rdata_for(rtype: str, value: str) -> dict:
    """Map a record's flat `value` onto Technitium's per-type API parameters.

    Every add/delete of the same record must produce the SAME dict — deletion
    matches on rdata, so an asymmetry here silently leaks records.
    """
    if rtype in ("A", "AAAA"):
        return {"ipAddress": value}
    if rtype == "CNAME":
        return {"cname": value}
    if rtype == "ANAME":
        return {"aname": value}
    if rtype == "TXT":
        return {"text": value}
    if rtype == "SRV":
        parts = value.split()
        if len(parts) != 4:
            raise ValueError(f"SRV value must be 'priority weight port target', got {value!r}")
        priority, weight, port, target = parts
        return {"priority": priority, "weight": weight, "port": port, "target": target}
    if rtype == "FWD":
        # Only ever produced from a zone's `forwarders` list, never from a
        # user-facing record.
        raise ValueError("FWD rdata is built by _fwd_rdata, not rdata_for")
    raise ValueError(f"unsupported record type: {rtype}")


def _fwd_rdata(fwd: dict) -> dict:
    return {
        "protocol": fwd["protocol"],
        "forwarder": fwd["forwarder"],
        "dnssecValidation": str(bool(fwd.get("dnssecValidation", False))).lower(),
    }


def _record_key(zone: str, name: str, rtype: str, value: str) -> str:
    return "\t".join((zone, name, rtype, value))


def _load_managed(path: Path) -> dict:
    if not path.exists():
        return {"version": MANAGED_VERSION, "zones": {}, "records": []}
    try:
        data = json.loads(path.read_text())
    except ValueError:
        return {"version": MANAGED_VERSION, "zones": {}, "records": []}
    if not isinstance(data, dict):
        return {"version": MANAGED_VERSION, "zones": {}, "records": []}
    data.setdefault("zones", {})
    data.setdefault("records", [])
    return data


def _ensure_zone(client: TechnitiumClient, existing: dict[str, str], spec: dict, managed: dict) -> None:
    """Create the zone if absent; recreate it if its TYPE drifted.

    A drifted type is only fixable by delete+create, so it is restricted to
    zones this module created — never one an operator made by hand.
    """
    zone, want = spec["zone"], spec["type"]
    have = existing.get(zone)
    if have == want:
        return
    if have is not None:
        if managed["zones"].get(zone) is None:
            print(
                f"local-dns: zone {zone} exists as {have}, not {want}, and was not "
                "created by the router — leaving it alone",
                file=sys.stderr,
            )
            return
        client.delete_zone(zone)
    # A Forwarder zone is created EMPTY (initializeForwarder=false) and its FWD
    # records are added below like any other record, so one code path owns them
    # and the reaper can see them.
    extra = {"initializeForwarder": "false"} if want == "Forwarder" else {}
    client.create_zone(zone, want, **extra)
    existing[zone] = want


def reconcile_local_dns(client: TechnitiumClient, cfg: dict, zones: dict[str, str]) -> None:
    """Assert the split-horizon zone set. `zones` maps zone name → type and is
    updated in place so a later caller sees the same view."""
    spec = cfg.get("localDns")
    if spec is None:
        return
    managed_file = Path(spec["managedFile"])
    managed = _load_managed(managed_file)

    desired_zones: dict[str, str] = {}
    desired_records: dict[str, dict] = {}
    # (zone, name, type) triples still wanted. `overwrite` on the first write of
    # each triple already replaced whatever the name held, so a value that only
    # CHANGED needs no delete — only a name/type that disappeared entirely does.
    desired_names: set[tuple[str, str, str]] = set()

    for zone_spec in spec.get("zones", []):
        zone = zone_spec["zone"]
        desired_zones[zone] = zone_spec["type"]
        _ensure_zone(client, zones, zone_spec, managed)

        # `overwrite` clears whatever the name held before, so it must be set
        # on the FIRST record of each (name, type) and cleared for the rest —
        # otherwise a name with two values keeps only the last one written.
        seen: set[tuple[str, str]] = set()

        def write(name: str, rtype: str, value: str, rdata: dict, ttl: int, extra: dict) -> None:
            first = (name, rtype) not in seen
            seen.add((name, rtype))
            desired_names.add((zone, name, rtype))
            client.add_record(zone, name, rtype, ttl=ttl, overwrite=first, **rdata, **extra)
            desired_records[_record_key(zone, name, rtype, value)] = {
                "zone": zone,
                "name": name,
                "type": rtype,
                "value": value,
                "rdata": rdata,
            }

        # The apex FWD records ARE the public horizon: a name inside this zone
        # that the admin did not override falls through them to the real
        # upstream instead of becoming NXDOMAIN.
        for fwd in zone_spec.get("forwarders", []):
            write(zone, "FWD", fwd["forwarder"], _fwd_rdata(fwd), 3600, {})

        for rec in zone_spec.get("records", []):
            write(
                rec["name"],
                rec["type"],
                rec["value"],
                rdata_for(rec["type"], rec["value"]),
                rec["ttl"],
                # `ptr`/`createPtrZone` are add-time options, not part of the
                # record's identity, so they stay out of the managed rdata the
                # reaper deletes with. The in-addr.arpa zone Technitium creates
                # for them is its own zone and is deliberately NOT tracked here:
                # it is shared with anything else that asks for a PTR, so
                # reaping it on a config change could take out records this
                # module never wrote.
                {"ptr": "true", "createPtrZone": "true"} if rec.get("ptr") else {},
            )

    # ── reap ─────────────────────────────────────────────────
    # Records first: deleting a zone that is still wanted would drop records
    # this run just wrote.
    for prev in managed["records"]:
        triple = (prev["zone"], prev["name"], prev["type"])
        if triple in desired_names or prev["zone"] not in zones:
            continue
        if prev["zone"] not in desired_zones:
            continue  # the whole zone is going away below
        try:
            client.delete_record(prev["zone"], prev["name"], prev["type"], **prev.get("rdata", {}))
            print(f"local-dns: removed {prev['type']} {prev['name']}", file=sys.stderr)
        except TechnitiumError as exc:
            print(f"local-dns: could not remove {prev['type']} {prev['name']}: {exc}", file=sys.stderr)

    for stale in sorted(set(managed["zones"]) - set(desired_zones)):
        if stale in zones:
            client.delete_zone(stale)
            zones.pop(stale, None)
            print(f"local-dns: removed zone {stale}", file=sys.stderr)

    managed_file.parent.mkdir(parents=True, exist_ok=True)
    managed_file.write_text(
        json.dumps(
            {
                "version": MANAGED_VERSION,
                "zones": desired_zones,
                "records": sorted(
                    desired_records.values(),
                    key=lambda r: (r["zone"], r["name"], r["type"], r["value"]),
                ),
            },
            indent=2,
        )
    )
