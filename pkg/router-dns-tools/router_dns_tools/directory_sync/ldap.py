"""LDAP / Active Directory provider."""

from __future__ import annotations


def fetch(cfg: dict, bind_password: str | None) -> tuple[list[dict], list[dict]]:
    import ldap3

    server = ldap3.Server(cfg["url"], get_info=ldap3.NONE)
    conn = ldap3.Connection(
        server,
        user=cfg.get("bindDn") or None,
        password=bind_password,
        auto_bind=True,
        receive_timeout=60,
    )

    conn.search(
        cfg["baseDn"],
        cfg.get("groupFilter") or "(objectClass=group)",
        attributes=["cn", "distinguishedName", "entryUUID", "objectGUID"],
    )
    groups, dn_to_id = [], {}
    for entry in conn.entries:
        dn = str(entry.entry_dn)
        gid = _first(entry, "objectGUID") or _first(entry, "entryUUID") or dn
        name = _first(entry, "cn") or dn
        groups.append({"id": gid, "name": name})
        dn_to_id[dn.lower()] = gid

    conn.search(
        cfg["baseDn"],
        cfg.get("userFilter") or "(objectClass=person)",
        attributes=["cn", "displayName", "mail", "userPrincipalName", "memberOf", "entryUUID", "objectGUID"],
    )
    users = []
    for entry in conn.entries:
        member_of = entry.memberOf.values if "memberOf" in entry else []
        users.append(
            {
                "id": _first(entry, "objectGUID") or _first(entry, "entryUUID") or str(entry.entry_dn),
                "name": _first(entry, "displayName") or _first(entry, "cn") or "",
                "email": (_first(entry, "mail") or _first(entry, "userPrincipalName") or "").lower(),
                "groups": [dn_to_id.get(str(dn).lower(), str(dn)) for dn in member_of],
            }
        )
    conn.unbind()
    return users, groups


def _first(entry, attr: str) -> str | None:
    if attr in entry and entry[attr].values:
        return str(entry[attr].values[0])
    return None
