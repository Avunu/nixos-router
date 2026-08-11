"""SSSD / NSS directory provider.

Resolves ONLY the users and groups the access-policy configuration references.
SSSD domains are not enumerated — `enumerate = false` is the SSSD default and
the recommended production setting, because enumeration downloads and caches
every entry in the directory — so `getpwent`/`getgrent` return nothing for
directory identities and "list every user" is impossible by construction.

Group membership comes from os.getgrouplist(name, pw_gid), the NSS *initgroups*
path. It is the only correct call here:

  * grp.getgrall() walks setgrent/getgrent — i.e. enumeration. Against a real
    AD/LDAP domain it returns nothing at all.
  * Scanning a group's gr_mem misses the PRIMARY group. Active Directory
    records primary membership in the user's primaryGroupID attribute and never
    in the group's member list, so "Domain Users" — or any group made primary
    for a class or department — lists no members. getgrouplist() always includes
    the gid it is handed (pw_gid) and asks the backend for the supplementary
    ones, so both halves come back.
  * It is one round trip per user and it is exactly the path id(1) uses, so what
    an admin sees while debugging is what the policy compiler got.

Output is the directory.json contract, consumed unchanged by
router-policy-compile, router-logd and the Cockpit Users page:

  user.id     POSIX login name — what router.hosts[].user holds
  user.name   GECOS "full name" (field 1 of the comma-separated GECOS)
  user.email  "" (POSIX carries no mail attribute), OR the referenced spelling
              when NSS canonicalized it to a different login. The compiler
              matches on id OR email, so that preserves the alias for free.
  group.id    == group.name == POSIX group name
"""

from __future__ import annotations

import grp
import os
import pwd
from collections.abc import Iterable


def _full_name(record: pwd.struct_passwd) -> str:
    """GECOS field 1.

    passwd(5) defines GECOS as a comma-separated (full name, office, work
    phone, home phone, other) tuple; SSSD maps the directory's gecos —
    falling back to displayName/cn — into it. Fall back to the login name so
    the Users page never renders a blank row.
    """
    return (record.pw_gecos or "").split(",")[0].strip() or record.pw_name


def _groups_of(record: pwd.struct_passwd) -> list[str]:
    names = []
    for gid in os.getgrouplist(record.pw_name, record.pw_gid):
        try:
            names.append(grp.getgrgid(gid).gr_name)
        except KeyError:
            continue  # a gid with no NSS entry (stale or foreign membership)
    return names


def fetch(
    usernames: Iterable[str],
    groupnames: Iterable[str],
) -> tuple[list[dict], list[dict], list[str]]:
    """Resolve the referenced POSIX names through NSS.

    Returns (users, groups, unresolved). `unresolved` holds every referenced
    name NSS could not resolve: a typo in the device registry, a user who has
    left, a renamed group — or, if it is all of them, a backend that is still
    offline. main() decides what that means.
    """
    unresolved: list[str] = []
    users: list[dict] = []
    by_login: dict[str, dict] = {}
    seen_refs: set[str] = set()
    referenced_groups: set[str] = set()

    for raw in usernames:
        ref = (raw or "").strip()
        if not ref or ref.lower() in seen_refs:
            continue
        seen_refs.add(ref.lower())
        try:
            record = pwd.getpwnam(ref)
        except KeyError:
            # NSS returns KeyError both for an unknown name and for a name
            # whose backend is offline with a cold cache. main() tells them
            # apart by whether ANY name resolved.
            unresolved.append(ref)
            continue

        groups = _groups_of(record)
        referenced_groups.update(groups)

        login = record.pw_name
        if login.lower() in by_login:
            continue  # a second reference canonicalized onto a listed login
        entry = {
            "id": login,
            "name": _full_name(record),
            # Only set when NSS canonicalized the reference (a UPN or alias
            # mapping to the sAMAccountName). _user_group_keys matches on id OR
            # email, so this keeps hosts[].user matching without widening the
            # contract.
            "email": "" if login.lower() == ref.lower() else ref,
            "groups": sorted(set(groups)),
        }
        by_login[login.lower()] = entry
        users.append(entry)

    # Groups a policy targets, validated independently so the UI can flag a typo
    # even when no resolved user is a member yet.
    for raw in groupnames:
        name = (raw or "").strip()
        if not name:
            continue
        try:
            referenced_groups.add(grp.getgrnam(name).gr_name)
        except KeyError:
            if name not in unresolved:
                unresolved.append(name)

    groups = [{"id": g, "name": g} for g in sorted(referenced_groups)]
    return users, groups, unresolved
