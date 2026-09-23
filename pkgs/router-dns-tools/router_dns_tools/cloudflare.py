"""Shared Cloudflare v4 API client for router-ddns and router-cloudflare-tunnel.

Both tools publish DNS records into the operator's Cloudflare zones and must
coexist with records made by hand, so they share:

  • the bearer-auth transport and its error type;
  • token loading — the systemd credential `cf-api-token` first, then the
    configured file path;
  • zone lookup (the longest suffix of a name that is a zone), cached in the
    caller's state.json;
  • the comment that marks a record as this router's, and the take-over /
    restore pair: a configured name belongs to the router, so a conflicting
    hand-made record is deleted — but remembered, and put back once the name
    is dropped, so taking a name over is never a one-way loss.

Environment overrides (the tests point them at a fake API):
  ROUTER_CLOUDFLARE_API_BASE (preferred), ROUTER_DDNS_API_BASE
"""

from __future__ import annotations

import json
import os
import urllib.error
import urllib.parse
import urllib.request
from collections.abc import Callable, Iterable
from pathlib import Path

API_BASE = (
    os.environ.get("ROUTER_CLOUDFLARE_API_BASE")
    or os.environ.get("ROUTER_DDNS_API_BASE")
    or "https://api.cloudflare.com/client/v4"
)
COMMENT = "managed by nixos-router"
CREDENTIAL = "cf-api-token"

# The fields of a replaced record needed to create it again.
RESTORE_FIELDS = ("type", "name", "content", "ttl", "proxied", "comment")


class CloudflareError(Exception):
    """An API call that failed. `status` is the HTTP code when there was one."""

    def __init__(self, message: str, status: int | None = None) -> None:
        super().__init__(message)
        self.status = status


def load_token(path: str | None) -> str | None:
    """The API token: the systemd credential when the unit passes one (a
    DynamicUser cannot read the secret file itself), else the file at `path`."""
    cred_dir = os.environ.get("CREDENTIALS_DIRECTORY")
    if cred_dir and (Path(cred_dir) / CREDENTIAL).exists():
        return (Path(cred_dir) / CREDENTIAL).read_text().strip()
    if path and Path(path).exists():
        return Path(path).read_text().strip()
    return None


class Cloudflare:
    def __init__(self, token: str, base: str = API_BASE) -> None:
        self.token = token
        self.base = base.rstrip("/")
        self.writes = 0

    def call(self, method: str, path: str, params: dict | None = None, body: dict | None = None):
        url = f"{self.base}{path}"
        if params:
            url += "?" + urllib.parse.urlencode(params)
        req = urllib.request.Request(
            url,
            data=None if body is None else json.dumps(body).encode(),
            headers={"Authorization": f"Bearer {self.token}", "Content-Type": "application/json"},
            method=method,
        )
        if method != "GET":
            self.writes += 1
        status = None
        try:
            with urllib.request.urlopen(req, timeout=30) as resp:
                payload = json.loads(resp.read().decode() or "{}")
        except urllib.error.HTTPError as exc:
            status = exc.code
            try:
                payload = json.loads(exc.read().decode() or "{}")
            except ValueError:
                raise CloudflareError(f"{method} {path}: HTTP {exc.code}", status) from exc
        except (urllib.error.URLError, OSError) as exc:
            raise CloudflareError(f"{method} {path}: {exc}") from exc
        if not payload.get("success", False):
            errors = "; ".join(e.get("message", "?") for e in payload.get("errors", [])) or "request failed"
            raise CloudflareError(f"{method} {path}: {errors}", status)
        return payload.get("result")

    def zone_for(self, name: str, cache: dict) -> dict:
        """The zone `name` lives in — the longest suffix that is one — as
        {"id", "name", "account": {"id"}}.

        Needs Zone:Read on the token. Results are cached in the caller's
        state.json; zone ids never change for the life of a zone. An entry in
        the old id-only form is looked up again once to learn the account.
        """
        labels = name.lower().split(".")
        for i in range(len(labels) - 1):
            candidate = ".".join(labels[i:])
            if isinstance(cache.get(candidate), dict):
                return cache[candidate]
            found = self.call("GET", "/zones", {"name": candidate, "status": "active"})
            if found:
                zone = found[0]
                cache[candidate] = {
                    "id": zone["id"],
                    "name": zone.get("name", candidate),
                    "account": {"id": (zone.get("account") or {}).get("id")},
                }
                return cache[candidate]
        raise CloudflareError(f"no Cloudflare zone found for {name} — does the token have Zone:Read on it?")

    def records(self, zone: str, name: str, rtype: str) -> list[dict]:
        return self.call("GET", f"/zones/{zone}/dns_records", {"name": name, "type": rtype}) or []


def take_over(
    cf: Cloudflare,
    zone: str,
    name: str,
    replaced: dict,
    types: Iterable[str] = ("CNAME",),
    keep: Callable[[dict], bool] = lambda r: False,
) -> list[dict]:
    """Delete the records of `types` at `name` that stand in the router's way.

    Records `keep` accepts (the caller's own) are left alone. Each deleted one
    is appended to `replaced[name]` — the caller persists that dict in its
    state.json and hands the list to restore() once the name is dropped — as
    it goes, so a failure part-way loses nothing. Returns this call's
    deletions, reduced to RESTORE_FIELDS.
    """
    removed = []
    for rtype in types:
        for r in cf.records(zone, name, rtype):
            if keep(r):
                continue
            cf.call("DELETE", f"/zones/{zone}/dns_records/{r['id']}")
            saved = {k: r.get(k) for k in RESTORE_FIELDS}
            replaced.setdefault(name, []).append(saved)
            removed.append(saved)
    return removed


def restore(cf: Cloudflare, zone: str, records: list[dict]) -> None:
    """Recreate records take_over replaced. Called only once the router's own
    records at the name are gone, since a CNAME cannot sit beside them."""
    for r in records:
        body = {k: v for k, v in r.items() if v is not None and v != ""}
        cf.call("POST", f"/zones/{zone}/dns_records", body=body)


# ── State files ──────────────────────────────────────────────────────────────


def load_json(path: Path) -> dict:
    try:
        return json.loads(path.read_text())
    except (OSError, ValueError):
        return {}


def write_json(path: Path, payload: dict, mode: int) -> None:
    """Replace `path` atomically; the file never exists with a wider mode."""
    tmp = path.with_suffix(".tmp")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, mode)
    with os.fdopen(fd, "w") as handle:
        json.dump(payload, handle, indent=2)
    os.chmod(tmp, mode)
    tmp.rename(path)
