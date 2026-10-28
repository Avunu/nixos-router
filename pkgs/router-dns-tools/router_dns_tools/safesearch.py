"""Per-policy SafeSearch zones.

Each access policy enforces SafeSearch per catalog site
(`accessPolicies.policies[].safeSearch.<site>`, see modules/filter-catalog.nix).
Every host of a site that some client's policy enforces gets a Forwarder zone
whose apex APP record dispatches to the Split Horizon app's SimpleCNAME class.
Its data maps each networkGroupMap prefix the policy compiler produced to the
enforcement endpoint that prefix's policy chose for the site (policies on
different levels, such as YouTube's strict and moderate, get different
endpoints from the same zone), or to "" when the policy does not enforce it. SimpleCNAME picks the longest matching prefix, exactly as
Advanced Blocking picks a client's group, and answers an apex with an ANAME;
"" makes it return nothing, so the query falls through to the zone's FWD
records and the real answer.

The zones depend on the COMPILED map (directory-group tiers included), so both
reconcile and router-policy-push rebuild them after compiling.
"""

from __future__ import annotations

import json
from pathlib import Path

from .local_dns import reconcile_zone_set
from .technitium_api import TechnitiumClient

APP_NAME = "Split Horizon"
CLASS_PATH = "SplitHorizon.SimpleCNAME"
# Short, so a client follows a policy change soon after it is pushed.
RECORD_TTL = 300


def safesearch_zones(static: dict, compiled: dict, forwarders: list[dict]) -> list[dict]:
    """Zone specs (local_dns.reconcile_zone_set shape) for every SafeSearch
    host some client's policy enforces."""
    endpoints = {p["name"]: p.get("safeSearch", {}) for p in static["policies"]}
    network_map = compiled["networkGroupMap"]

    specs = []
    for site_id, site in sorted(static.get("safeSearchSites", {}).items()):
        answers = {
            prefix: endpoints.get(group, {}).get(site_id, "")
            for prefix, group in network_map.items()
        }
        if not any(answers.values()):
            continue  # no client gets it: leave the real record alone
        data = json.dumps(answers, sort_keys=True)
        for host in site["hosts"]:
            specs.append(
                {
                    "zone": host,
                    "type": "Forwarder",
                    "forwarders": forwarders,
                    "appRecords": [
                        {
                            "name": host,
                            "appName": APP_NAME,
                            "classPath": CLASS_PATH,
                            "data": data,
                            "ttl": RECORD_TTL,
                        }
                    ],
                    "records": [],
                }
            )
    return specs


def reconcile_safesearch(
    client: TechnitiumClient,
    cfg: dict,
    zones: dict[str, str],
    static: dict,
    compiled: dict,
) -> None:
    spec = cfg["safeSearch"]
    reconcile_zone_set(
        client,
        zones,
        Path(spec["managedFile"]),
        safesearch_zones(static, compiled, spec["forwarders"]),
        "safesearch",
    )
