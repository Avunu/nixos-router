"""router-directory-sync — resolve the policy's users/groups through NSS.

The router no longer speaks to a directory itself. SSSD owns the LDAP/AD
connection, its TLS, its credentials and its cache; this unit only asks NSS
(getpwnam / getgrouplist / getgrnam) about the identities the access-policy
configuration actually references.

SSSD domains are not enumerated, so "every user in the directory" is not a thing
that can be listed. The reference set comes from the Nix-generated
router-policy-static.json instead:

  hosts[].user                            → users to resolve
  policies[].assignments.directoryGroups  → groups to validate

plus router.directory.sssd.groups, which lets an admin publish candidate group
names before any policy references them (otherwise the Cockpit group picker
would have nothing to offer on a fresh install).

Shape (unchanged — the contract with the policy compiler, router-logd and the
Cockpit Users page):

  users:  [{"id", "name", "email", "groups": [group-name, …]}]
  groups: [{"id", "name"}]

State files:
  directory.json — written atomically ONLY on success (last-good is kept on
                   failure; the compiler tolerates stale data)
  status.json    — {"lastSync", "ok", "error", "unresolved"} written on success
                   AND failure
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import time
from pathlib import Path


def _atomic_write(path: Path, payload: dict, mode: int) -> None:
    tmp = path.with_suffix(".tmp")
    # os.open with the final mode, rather than write-then-chmod, so the file is
    # never briefly world-readable.
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, mode)
    with os.fdopen(fd, "w") as handle:
        json.dump(payload, handle, indent=2)
    os.chmod(tmp, mode)  # O_CREAT mode is masked by umask; force it
    tmp.rename(path)  # rename fires the router-policy-push path watch exactly once


def _referenced(static: dict, extra_groups: list[str]) -> tuple[list[str], list[str]]:
    """The user and group names the configured policies actually need."""
    users = [h["user"] for h in static.get("hosts", []) if h.get("user")]
    groups = list(extra_groups) + [
        g
        for p in static.get("policies", [])
        for g in p.get("assignments", {}).get("directoryGroups", [])
        if g
    ]
    return users, groups


def main() -> None:
    parser = argparse.ArgumentParser(description="Sync directory users/groups for policy assignment")
    parser.add_argument("--config", required=True, help="runtime config JSON (Nix-generated)")
    args = parser.parse_args()
    cfg_all = json.loads(Path(args.config).read_text())
    cfg = cfg_all["directory"]

    state_dir = Path(cfg["stateDir"])
    state_dir.mkdir(parents=True, exist_ok=True)
    status_file = state_dir / "status.json"
    now = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())

    provider = cfg.get("provider", "none")
    if provider != "sssd":
        sys.exit(f"directory sync invoked with provider '{provider}' — nothing to do")

    def fail(msg: str, unresolved: list[str]) -> None:
        """Keep the last-good directory.json; record why this run produced none."""
        _atomic_write(
            status_file,
            {"lastSync": now, "ok": False, "error": msg, "unresolved": unresolved},
            0o644,
        )
        sys.exit(f"directory sync failed: {msg}")

    try:
        static = json.loads(Path(cfg["staticInputs"]).read_text())
        wanted_users, wanted_groups = _referenced(static, cfg.get("groups", []))

        from . import sssd as mod

        users, groups, unresolved = mod.fetch(wanted_users, wanted_groups)
    except Exception as exc:  # keep last-good directory.json, record the failure
        fail(str(exc), [])
        return  # unreachable; keeps type checkers happy

    # NSS reports an offline backend with a cold cache exactly the way it
    # reports a typo: KeyError. Distinguish them by the only signal available —
    # if the policy references users and NOT ONE resolved, assume the domain is
    # unreachable and keep last-good rather than blanking the whole user tier.
    if wanted_users and not users:
        fail(
            f"no referenced user resolved via NSS ({len(unresolved)} unresolved)"
            " — check `systemctl status sssd` and `sssctl domain-status`",
            unresolved,
        )

    _atomic_write(
        state_dir / "directory.json",
        {"users": users, "groups": groups, "syncedAt": now},
        0o640,  # PII — Cockpit reads via the superuser bridge
    )
    # Unresolved names are a WARNING, never a failure: one graduated student's
    # stale hosts[].user must not suppress the sync for everyone else. `ok`
    # means "is directory.json current", and it still is.
    _atomic_write(
        status_file,
        {"lastSync": now, "ok": True, "error": None, "unresolved": unresolved},
        0o644,
    )
    print(
        f"resolved {len(users)} users, {len(groups)} groups via NSS"
        + (f"; unresolved: {', '.join(unresolved)}" if unresolved else ""),
        file=sys.stderr,
    )


if __name__ == "__main__":
    main()
