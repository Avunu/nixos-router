"""Idempotent Technitium DNS Server reconciliation.

Runs after the technitium-dns-server unit (and again on every nixos-rebuild
whose generated desired state changed). Asserts the desired configuration via
the HTTP API: server settings, the router's local zone, SafeSearch zones,
DNS app configs (Log Exporter, Block Page, compiled Advanced Blocking), and
the read-only Cockpit dashboard user/token.

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


def _ensure_zone(client: TechnitiumClient, existing: set[str], zone: str) -> None:
    if zone not in existing:
        client.create_zone(zone, "Primary")
        existing.add(zone)


def _reconcile_safesearch(client: TechnitiumClient, cfg: dict, zones: set[str]) -> None:
    managed_file = Path(cfg["managedZonesFile"])
    previous = set(json.loads(managed_file.read_text())) if managed_file.exists() else set()
    desired = dict(cfg["safeSearch"]["records"]) if cfg["safeSearch"]["enable"] else {}

    for host, target in desired.items():
        _ensure_zone(client, zones, host)
        client.add_record(host, host, "ANAME", aname=target)
    for stale in sorted(previous - set(desired)):
        if stale in zones:
            client.delete_zone(stale)
            zones.discard(stale)

    managed_file.parent.mkdir(parents=True, exist_ok=True)
    managed_file.write_text(json.dumps(sorted(desired)))


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
    # A createToken session is non-expiring; reuse the stored token if it still
    # authenticates, otherwise mint a fresh one.
    if token_file.exists():
        probe = TechnitiumClient(client.base_url, token=token_file.read_text().strip())
        try:
            probe._call("/api/user/session/get")
            return
        except TechnitiumError:
            pass
    token = client.create_api_token(cockpit["user"], password, cockpit["tokenName"])
    token_file.parent.mkdir(parents=True, exist_ok=True)
    token_file.write_text(token)
    token_file.chmod(0o600)
    print("provisioned cockpit API token", file=sys.stderr)


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

    zones = {z["name"] for z in client.list_zones()}
    local = cfg["localZone"]
    _ensure_zone(client, zones, local["zone"])
    client.add_record(local["zone"], local["zone"], "A", ipAddress=local["address"])

    # Extra records contributed by other modules (e.g. the wireless controllers'
    # `unifi.<lan domain>` and `dashboard.<domain>`). Each names its own zone,
    # since these sit outside the router's `<host>.<domain>` zone.
    for record in local.get("records", []):
        _ensure_zone(client, zones, record["zone"])
        client.add_record(record["zone"], record["name"], "A", ipAddress=record["address"])

    _reconcile_safesearch(client, cfg, zones)

    # The Log Exporter config carries the logd ingest token, which is generated
    # at runtime — substitute the placeholder before pushing.
    ingest_token = _read_secret(cfg["logd"]["ingestTokenFile"], generate=True)
    for app_name, app_config in cfg.get("apps", {}).items():
        resolved = json.loads(json.dumps(app_config).replace("@INGEST_TOKEN@", ingest_token))
        _set_app_config_if_changed(client, app_name, resolved)

    static = json.loads(Path(cfg["policy"]["staticInputs"]).read_text())
    directory = _load_directory(cfg["policy"].get("directoryState"))
    _set_app_config_if_changed(client, "Advanced Blocking", compile_config(static, directory))

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
    Advanced Blocking config (triggered when directory state changes)."""
    parser = argparse.ArgumentParser(description="Compile and push Advanced Blocking config")
    parser.add_argument("--config", required=True, help="runtime config JSON (Nix-generated)")
    args = parser.parse_args()
    cfg = json.loads(Path(args.config).read_text())

    client = TechnitiumClient(cfg["webUrl"], timeout=90)
    client.wait_ready()
    _login(client, cfg["adminUser"], _read_secret(cfg["adminPassFile"]))

    static = json.loads(Path(cfg["policy"]["staticInputs"]).read_text())
    directory = _load_directory(cfg["policy"].get("directoryState"))
    _set_app_config_if_changed(client, "Advanced Blocking", compile_config(static, directory))


if __name__ == "__main__":
    main()
