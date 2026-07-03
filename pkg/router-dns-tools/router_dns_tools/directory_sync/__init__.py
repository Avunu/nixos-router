"""router-directory-sync — pull users/groups from the configured directory.

Providers (ldap / entra / google) each expose fetch(cfg, secret) returning
({users}, {groups}) in the router's normalized shape:

  users:  [{"id", "name", "email", "groups": [group-id, …]}]
  groups: [{"id", "name"}]

State files (the contract with the policy compiler, router-logd, and the
Cockpit Users page):
  directory.json — written atomically ONLY on success (last-good is kept on
                   provider failure; the compiler tolerates stale data)
  status.json    — {"lastSync", "ok", "error"} written on success AND failure
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import time
from pathlib import Path


def _secret(path: str | None, credential_name: str) -> str | None:
    """Prefer systemd LoadCredential; fall back to the configured path."""
    cred_dir = os.environ.get("CREDENTIALS_DIRECTORY")
    if cred_dir and (Path(cred_dir) / credential_name).exists():
        return (Path(cred_dir) / credential_name).read_text().strip()
    if path and Path(path).exists():
        return Path(path).read_text().strip()
    return None


def _atomic_write(path: Path, payload: dict, mode: int) -> None:
    tmp = path.with_suffix(".tmp")
    tmp.write_text(json.dumps(payload, indent=2))
    tmp.chmod(mode)
    tmp.rename(path)  # rename fires the router-policy-push path watch exactly once


def main() -> None:
    parser = argparse.ArgumentParser(description="Sync directory users/groups for policy assignment")
    parser.add_argument("--config", required=True, help="runtime config JSON (Nix-generated)")
    args = parser.parse_args()
    cfg = json.loads(Path(args.config).read_text())["directory"]

    state_dir = Path(cfg["stateDir"])
    state_dir.mkdir(parents=True, exist_ok=True)
    status_file = state_dir / "status.json"
    now = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())

    provider = cfg.get("provider", "none")
    try:
        if provider == "ldap":
            from . import ldap as mod

            users, groups = mod.fetch(cfg["ldap"], _secret(cfg["ldap"].get("bindPasswordFile"), "directory-secret"))
        elif provider == "entra":
            from . import entra as mod

            users, groups = mod.fetch(cfg["entra"], _secret(cfg["entra"].get("clientSecretFile"), "directory-secret"))
        elif provider == "google":
            from . import google as mod

            users, groups = mod.fetch(cfg["google"], _secret(cfg["google"].get("serviceAccountKeyFile"), "directory-secret"))
        else:
            sys.exit(f"directory sync invoked with provider '{provider}' — nothing to do")
    except Exception as exc:  # keep last-good directory.json, record the failure
        _atomic_write(status_file, {"lastSync": now, "ok": False, "error": str(exc)}, 0o644)
        sys.exit(f"directory sync failed: {exc}")

    _atomic_write(
        state_dir / "directory.json",
        {"users": users, "groups": groups, "syncedAt": now},
        0o640,  # PII — Cockpit reads via the superuser bridge
    )
    _atomic_write(status_file, {"lastSync": now, "ok": True, "error": None}, 0o644)
    print(f"synced {len(users)} users, {len(groups)} groups from {provider}", file=sys.stderr)


if __name__ == "__main__":
    main()
