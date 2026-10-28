"""Idempotent Technitium DNS Server reconciliation.

Runs after the technitium-dns-server unit (and again on every nixos-rebuild
whose generated desired state changed). Asserts the desired configuration via
the HTTP API: server settings, the router's local zone, the split-horizon
zones (see local_dns.py), DNS app configs (Log Exporter, Block Page, Split
Horizon, compiled Advanced Blocking), the per-policy SafeSearch zones (see
safesearch.py), and the read-only Cockpit dashboard user/token.

All inputs come from one Nix-generated runtime config JSON (--config), so the
unit is a thin `router-technitium-reconcile --config /nix/store/….json`.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import secrets
import sys
import time
from pathlib import Path

from .compile_policies import _load_directory, compile_config
from .local_dns import reconcile_local_dns
from .safesearch import reconcile_safesearch
from .technitium_api import TechnitiumClient, TechnitiumError


def _read_secret(path: str, generate: bool = False) -> str:
    p = Path(path)
    if generate and not p.exists():
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(secrets.token_urlsafe(24))
        p.chmod(0o600)
    return p.read_text().strip()


def _login(client: TechnitiumClient, user: str, password: str) -> None:
    """Login with the managed password; rotate away from factory default if needed."""
    try:
        client.login(user, password)
        return
    except TechnitiumError:
        pass
    # Factory default (fresh state dir predating our env seeding) — rotate.
    client.login(user, "admin")
    client.change_password("admin", password)
    print("rotated factory-default admin password", file=sys.stderr)


def _ensure_zone(client: TechnitiumClient, existing: dict[str, str], zone: str) -> None:
    """Ensure a Primary zone exists. `existing` maps zone name → zone type; the
    type matters to the split-horizon reconciler, which shares this view."""
    if zone not in existing:
        client.create_zone(zone, "Primary")
        existing[zone] = "Primary"


def _push_policies(client: TechnitiumClient, cfg: dict, zones: dict[str, str]) -> None:
    """Compile the access policies against the current directory state and push
    everything that follows from the result: the Advanced Blocking config, then
    the SafeSearch zones keyed by its networkGroupMap."""
    static = json.loads(Path(cfg["policy"]["staticInputs"]).read_text())
    directory = _load_directory(cfg["policy"].get("directoryState"))
    compiled = compile_config(static, directory)
    _set_app_config_if_changed(client, "Advanced Blocking", compiled)
    reconcile_safesearch(client, cfg, zones, static, compiled)


def _set_app_config_if_changed(client: TechnitiumClient, name: str, desired: object) -> None:
    current_raw = client.get_app_config(name)
    try:
        current = json.loads(current_raw) if current_raw else None
    except ValueError:
        current = None
    if current != desired:
        client.set_app_config(name, json.dumps(desired, indent=2))
        print(f"updated app config: {name}", file=sys.stderr)


def _reconcile_cockpit_token(client: TechnitiumClient, cfg: dict) -> None:
    cockpit = cfg["cockpit"]
    password = _read_secret(cockpit["passFile"], generate=True)

    users = {u["username"] for u in client.list_users()}
    if cockpit["user"] not in users:
        client.create_user(cockpit["user"], password, "Cockpit dashboards (read-only)")
    else:
        client.set_user_password(cockpit["user"], password)
    for section in ("Dashboard", "Zones", "Logs"):
        client.grant_user_view(section, cockpit["user"])

    token_file = Path(cockpit["tokenFile"])
    # A createToken session is non-expiring, so the stored token is reused while
    # it authenticates AS THE COCKPIT USER. Authenticating is not enough: routers
    # provisioned before this check hold a token minted under the admin session
    # (see create_api_token), which authenticates fine and is not read-only.
    stored = token_file.read_text().strip() if token_file.exists() else ""
    if client.token_owner(stored) != cockpit["user"]:
        token = client.create_api_token(cockpit["user"], password, cockpit["tokenName"])
        token_file.parent.mkdir(parents=True, exist_ok=True)
        token_file.write_text(token)
        token_file.chmod(0o600)
        print("provisioned cockpit API token", file=sys.stderr)

    # Revoke any token of this name that belongs to someone else — the admin
    # tokens older reconciles minted. Only after the replacement is in place, so
    # the Cockpit plugin never finds the file holding a dead token.
    for session in client.list_sessions():
        if (
            session.get("type") == "ApiToken"
            and session.get("tokenName") == cockpit["tokenName"]
            and session.get("username") != cockpit["user"]
            and not session.get("isCurrentSession")
        ):
            client.delete_session(session["partialToken"])
            print(
                f"revoked {session.get('username')}-owned token {cockpit['tokenName']!r}",
                file=sys.stderr,
            )


def main() -> None:
    parser = argparse.ArgumentParser(description="Reconcile Technitium DNS Server state")
    parser.add_argument("--config", required=True, help="runtime config JSON (Nix-generated)")
    args = parser.parse_args()
    cfg = json.loads(Path(args.config).read_text())

    # Generous timeout: an app-config push can trigger the app's async reload,
    # and the first call right after startup is occasionally slow to answer.
    client = TechnitiumClient(cfg["webUrl"], timeout=90)
    client.wait_ready()
    _login(client, cfg["adminUser"], _read_secret(cfg["adminPassFile"]))

    client.set_settings(cfg["settings"])

    zones = {z["name"]: z.get("type", "Primary") for z in client.list_zones()}
    local = cfg["localZone"]
    _ensure_zone(client, zones, local["zone"])
    client.add_record(local["zone"], local["zone"], "A", ipAddress=local["address"])

    # Extra records contributed by other modules (e.g. the wireless controllers'
    # `unifi.<lan domain>` and `dashboard.<domain>`). Each names its own zone,
    # since these sit outside the router's `<host>.<domain>` zone.
    for record in local.get("records", []):
        _ensure_zone(client, zones, record["zone"])
        client.add_record(record["zone"], record["name"], "A", ipAddress=record["address"])

    # Split-horizon zones. Runs before SafeSearch only so a misconfigured
    # override surfaces early; the two own disjoint managed-state files.
    reconcile_local_dns(client, cfg, zones)

    # The Log Exporter config carries the logd ingest token, which is generated
    # at runtime — substitute the placeholder before pushing.
    ingest_token = _read_secret(cfg["logd"]["ingestTokenFile"], generate=True)
    for app_name, app_config in cfg.get("apps", {}).items():
        resolved = json.loads(json.dumps(app_config).replace("@INGEST_TOKEN@", ingest_token))
        _set_app_config_if_changed(client, app_name, resolved)

    # After the app configs: the SafeSearch APP records need Split Horizon's.
    _push_policies(client, cfg, zones)

    _reconcile_cockpit_token(client, cfg)

    stamp = Path(cfg["lastReconcileFile"])
    stamp.parent.mkdir(parents=True, exist_ok=True)
    stamp.write_text(
        json.dumps(
            {
                "at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                "configHash": hashlib.sha256(Path(args.config).read_bytes()).hexdigest(),
            }
        )
    )
    print("reconcile complete", file=sys.stderr)


def push_policies() -> None:
    """Entry point for router-policy-push: recompile and push only the
    Advanced Blocking config and the SafeSearch zones (triggered when
    directory state changes)."""
    parser = argparse.ArgumentParser(description="Compile and push Advanced Blocking config and SafeSearch zones")
    parser.add_argument("--config", required=True, help="runtime config JSON (Nix-generated)")
    args = parser.parse_args()
    cfg = json.loads(Path(args.config).read_text())

    client = TechnitiumClient(cfg["webUrl"], timeout=90)
    client.wait_ready()
    _login(client, cfg["adminUser"], _read_secret(cfg["adminPassFile"]))

    zones = {z["name"]: z.get("type", "Primary") for z in client.list_zones()}
    _push_policies(client, cfg, zones)


if __name__ == "__main__":
    main()
