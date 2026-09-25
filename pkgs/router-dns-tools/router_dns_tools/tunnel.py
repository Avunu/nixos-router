"""router-cloudflare-tunnel — own the router's Cloudflare Tunnel and its DNS.

Run from a timer and on every rebuild with the config JSON the Nix module
writes; every run converges on the configuration and a run with nothing to do
writes nothing:

  tunnel     one locally-managed tunnel (config_src "local": cloudflared's
             ingress rules come from its config file, not the dashboard). Its
             credentials — the account, the tunnel id and the secret generated
             here — are written to credentials.json (0600) for cloudflared.
             The secret is never logged. A tunnel deleted behind the router's
             back is created again, and its DNS records follow the new id.
  hostnames  one proxied CNAME each, `hostname → <tunnel id>.cfargotunnel.com`,
             carrying the same managed-by comment as router-ddns. A configured
             name belongs to the router: A, AAAA and CNAME records already
             holding it are replaced, remembered in state.json, and put back
             once the name is dropped from the configuration.

enable=false tears it all down — the CNAMEs (restoring what they replaced),
the tunnel, and the credentials — and does nothing at all when there is
nothing recorded to tear down.

The account is the one owning the zone of the first hostname; with no
hostnames, the existing tunnel's. With no hostnames and no tunnel yet there is
nothing to serve and no zone to name the account, so the run reports itself
idle and succeeds without creating one; the tunnel is created once a hostname
is added.

State directory:
  credentials.json — cloudflared's tunnel credentials
  state.json       — account id, tunnel id, zone cache, the managed name set
                     and the records replaced to take names over
  status.json      — last run summary for Cockpit, written on success AND
                     failure

Environment overrides (the sandbox test points it at a fake API):
  ROUTER_CLOUDFLARE_API_BASE
"""

from __future__ import annotations

import argparse
import base64
import json
import secrets
import sys
import time
from pathlib import Path

from .cloudflare import (
    COMMENT,
    Cloudflare,
    CloudflareError,
    load_json,
    load_token,
    restore,
    take_over,
    write_json,
)

TUNNEL_DOMAIN = "cfargotunnel.com"
PROG = "router-cloudflare-tunnel"
IDLE = "add a hostname to create the tunnel"


def _iso(ts: float) -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(ts))


def _hostnames(cfg: dict) -> list[str]:
    """Configured names, lowercased and deduplicated, in configured order."""
    return list(dict.fromkeys(h.strip().rstrip(".").lower() for h in cfg.get("hostnames", []) if h.strip()))


def _is_ours(r: dict) -> bool:
    """A CNAME this tool made: tagged, and pointing at some tunnel. The target
    is not compared, so records left pointing at a replaced tunnel are ours to
    repoint rather than someone else's to take over."""
    return (
        r.get("type") == "CNAME"
        and r.get("comment") == COMMENT
        and str(r.get("content", "")).rstrip(".").endswith("." + TUNNEL_DOMAIN)
    )


# ── Tunnel ───────────────────────────────────────────────────────────────────


def get_tunnel(cf: Cloudflare, acct: str, tid: str) -> dict | None:
    """The live tunnel `tid`, or None when it is deleted or unknown.

    Only an answer from the API about the tunnel counts as "gone" — a network
    or auth failure raises, so an outage never mints a second tunnel.
    """
    try:
        tunnel = cf.call("GET", f"/accounts/{acct}/cfd_tunnel/{tid}")
    except CloudflareError as exc:
        if exc.status in (400, 404):
            return None
        raise
    return None if not tunnel or tunnel.get("deleted_at") else tunnel


def ensure_tunnel(cf: Cloudflare, acct: str, name: str, creds_file: Path) -> tuple[dict, str]:
    """The tunnel credentials.json names, created first when there is none.

    Returns the tunnel object and what was done ("kept"/"created").
    """
    creds = load_json(creds_file)
    if creds.get("TunnelID") and creds.get("AccountTag") == acct:
        tunnel = get_tunnel(cf, acct, creds["TunnelID"])
        if tunnel:
            return tunnel, "kept"
    # Cloudflare keeps tunnel names unique per account. A live one by this name
    # with no credentials here belongs to someone else, or to this router
    # before its state was lost — either way its secret is not ours to reuse.
    clash = [
        t
        for t in cf.call("GET", f"/accounts/{acct}/cfd_tunnel", {"name": name, "is_deleted": "false"}) or []
        if not t.get("deleted_at")
    ]
    if clash:
        raise CloudflareError(
            f"a tunnel named {name!r} ({clash[0].get('id')}) already exists but its credentials are not in "
            f"{creds_file.parent} — delete it in the Cloudflare dashboard, or choose another tunnel name"
        )
    secret = base64.b64encode(secrets.token_bytes(32)).decode()
    tunnel = cf.call(
        "POST",
        f"/accounts/{acct}/cfd_tunnel",
        body={"name": name, "tunnel_secret": secret, "config_src": "local"},
    )
    write_json(creds_file, {"AccountTag": acct, "TunnelSecret": secret, "TunnelID": tunnel["id"]}, 0o600)
    return tunnel, "created"


def delete_tunnel(cf: Cloudflare, acct: str, tid: str) -> None:
    """Delete the tunnel; Cloudflare refuses while connections are open (a
    cloudflared that has not noticed yet), so those are cleaned up once."""
    if get_tunnel(cf, acct, tid) is None:
        return
    path = f"/accounts/{acct}/cfd_tunnel/{tid}"
    try:
        cf.call("DELETE", path)
    except CloudflareError:
        cf.call("DELETE", f"{path}/connections")
        cf.call("DELETE", path)


def connections(cf: Cloudflare, acct: str, tid: str) -> list[dict]:
    """The tunnel's open connections, one row per edge connection."""
    rows = []
    for client in cf.call("GET", f"/accounts/{acct}/cfd_tunnel/{tid}/connections") or []:
        for c in client.get("conns", []):
            rows.append(
                {
                    "colo": c.get("colo_name"),
                    "originIp": c.get("origin_ip"),
                    "openedAt": c.get("opened_at"),
                    "clientVersion": c.get("client_version") or client.get("version"),
                }
            )
    return rows


# ── DNS ──────────────────────────────────────────────────────────────────────


def point(cf: Cloudflare, zone: str, name: str, target: str, replaced: dict) -> str:
    """Make `name` carry exactly one managed CNAME to `target` and nothing
    that conflicts with it. Returns a note for the status file."""
    removed = take_over(cf, zone, name, replaced, ("A", "AAAA", "CNAME"), keep=_is_ours)
    ours = cf.records(zone, name, "CNAME")  # only ours are left
    want = {"type": "CNAME", "name": name, "content": target, "ttl": 1, "proxied": True, "comment": COMMENT}
    keep = next((r for r in ours if r.get("content") == target), ours[0] if ours else None)
    for r in ours:
        if r is not keep:
            cf.call("DELETE", f"/zones/{zone}/dns_records/{r['id']}")
    if keep is None:
        cf.call("POST", f"/zones/{zone}/dns_records", body=want)
        outcome = "created"
    elif {k: keep.get(k) for k in want} != want:
        cf.call("PATCH", f"/zones/{zone}/dns_records/{keep['id']}", body=want)
        outcome = "updated"
    else:
        outcome = "unchanged" if len(ours) == 1 else "updated"
    notes = [outcome] + [
        f"replaced {r['type']} → {r.get('content')} (restored if the name is dropped)" for r in removed
    ]
    return "; ".join(notes)


def release(cf: Cloudflare, zone: str, name: str, replaced: dict) -> str:
    """Delete the managed CNAME at `name` and put back what it replaced."""
    removed = 0
    for r in cf.records(zone, name, "CNAME"):
        if _is_ours(r):
            cf.call("DELETE", f"/zones/{zone}/dns_records/{r['id']}")
            removed += 1
    note = f"removed {removed} record(s)"
    if replaced.get(name):
        restore(cf, zone, replaced[name])
        note += f"; restored {len(replaced[name])} replaced record(s)"
    replaced.pop(name, None)
    return note


def release_all(cf: Cloudflare, state: dict, names: list[str], records: dict) -> list[str]:
    """Release `names`; returns the ones that failed, still to be tracked."""
    zones = state.setdefault("zones", {})
    replaced = state.setdefault("replaced", {})
    failed = []
    for name in names:
        try:
            note = release(cf, cf.zone_for(name, zones)["id"], name, replaced)
            print(f"  released  {name} {note}", file=sys.stderr)
        except CloudflareError as exc:
            records[name] = {"ok": False, "message": f"removing: {exc}"}
            failed.append(name)
    return failed


# ── Main ─────────────────────────────────────────────────────────────────────


def _account(cf: Cloudflare, state: dict, creds: dict, hostnames: list[str]) -> str | None:
    if hostnames:
        acct = cf.zone_for(hostnames[0], state.setdefault("zones", {}))["account"]["id"]
        if not acct:
            raise CloudflareError(f"the zone of {hostnames[0]} names no account")
        return acct
    return state.get("accountId") or creds.get("AccountTag")


def apply(cf: Cloudflare, cfg: dict, state: dict, creds_file: Path, status: dict) -> None:
    """enable=true: converge, filling in `status` as it goes so a failure
    part-way still reports what was reached."""
    records = status["records"]
    hostnames = _hostnames(cfg)
    creds = load_json(creds_file)
    if not hostnames and not (state.get("tunnelId") or creds.get("TunnelID")):
        # Nothing to serve and no tunnel to keep: wait for a hostname instead
        # of creating a tunnel that serves nothing. Names a failed teardown
        # left behind are still released.
        dropped = sorted(set(state.get("managed", [])) | set(state.get("replaced", {})))
        state["managed"] = release_all(cf, state, dropped, records)
        status["message"] = IDLE
        print(f"{PROG}: no hostnames and no tunnel — {IDLE}", file=sys.stderr)
        return
    acct = _account(cf, state, creds, hostnames)
    if not acct:
        raise CloudflareError("the tunnel has no recorded account — add a hostname, whose zone names the account")
    state["accountId"] = acct

    tunnel, how = ensure_tunnel(cf, acct, cfg["name"], creds_file)
    state["tunnelId"] = tunnel["id"]
    status["tunnel"] = {"id": tunnel["id"], "name": tunnel.get("name"), "status": tunnel.get("status")}
    print(f"{PROG}: tunnel {tunnel.get('name')} {tunnel['id']} {how}", file=sys.stderr)
    target = f"{tunnel['id']}.{TUNNEL_DOMAIN}"

    zones = state.setdefault("zones", {})
    replaced = state.setdefault("replaced", {})
    for name in hostnames:
        try:
            note = point(cf, cf.zone_for(name, zones)["id"], name, target, replaced)
            records[name] = {"ok": True, "message": note}
        except CloudflareError as exc:
            records[name] = {"ok": False, "message": str(exc)}
        print(f"  {'ok' if records[name]['ok'] else 'error':9} {name} {records[name]['message']}", file=sys.stderr)

    # Dropped names, and replaced records left behind by a lost managed set.
    dropped = sorted((set(state.get("managed", [])) | set(replaced)) - set(hostnames))
    failed = release_all(cf, state, dropped, records)
    state["managed"] = sorted(set(hostnames) | set(failed))

    status["connections"] = connections(cf, acct, tunnel["id"])


def teardown(cf: Cloudflare, state: dict, creds_file: Path, records: dict) -> None:
    """enable=false: remove the records, then the tunnel, then its secret."""
    creds = load_json(creds_file)
    failed = release_all(cf, state, sorted(set(state.get("managed", [])) | set(state.get("replaced", {}))), records)
    state["managed"] = failed
    tid = state.get("tunnelId") or creds.get("TunnelID")
    acct = state.get("accountId") or creds.get("AccountTag")
    if tid:
        if not acct:
            raise CloudflareError(f"tunnel {tid} has no recorded account; delete it in the Cloudflare dashboard")
        delete_tunnel(cf, acct, tid)
        print(f"{PROG}: tunnel {tid} deleted", file=sys.stderr)
    state.pop("tunnelId", None)
    creds_file.unlink(missing_ok=True)


def run(cfg: dict) -> int:
    state_dir = Path(cfg["stateDir"])
    state_file = state_dir / "state.json"
    status_file = state_dir / "status.json"
    creds_file = state_dir / "credentials.json"
    enable = cfg.get("enable", True)

    state = load_json(state_file)
    if not enable and not (
        state.get("tunnelId") or state.get("managed") or state.get("replaced") or creds_file.exists()
    ):
        return 0  # never enabled, or already torn down
    state_dir.mkdir(parents=True, exist_ok=True)

    now = time.time()
    status: dict = {"tunnel": None, "connections": [], "records": {}}
    error: str | None = None
    token = load_token(cfg.get("apiTokenFile"))
    if not token:
        error = "no Cloudflare API token (apiTokenFile)"
    else:
        cf = Cloudflare(token)
        try:
            if enable:
                apply(cf, cfg, state, creds_file, status)
            else:
                teardown(cf, state, creds_file, status["records"])
        except CloudflareError as exc:
            error = str(exc)
        failed = [n for n, r in status["records"].items() if not r["ok"]]
        if failed and not error:
            error = f"{len(failed)} hostname(s) failed"
        write_json(state_file, state, 0o600)
        print(f"{PROG}: {cf.writes} API write(s)", file=sys.stderr)

    write_json(status_file, {"updated": _iso(now), "ok": error is None, "error": error, **status}, 0o644)
    if error:
        print(f"{PROG}: {error}", file=sys.stderr)
        return 1
    return 0


def main() -> None:
    parser = argparse.ArgumentParser(description="Manage the router's Cloudflare Tunnel and its DNS records")
    parser.add_argument("--config", required=True, help="runtime config JSON (Nix-generated)")
    args = parser.parse_args()
    cfg = json.loads(Path(args.config).read_text())["tunnel"]
    sys.exit(run(cfg))


if __name__ == "__main__":
    main()
