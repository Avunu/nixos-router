"""Just enough of the Cloudflare v4 API for router-ddns and
router-cloudflare-tunnel, in memory.

Zone lookup, dns_records list/create/patch/delete (a list is by name, and by
type when one is given), the IPv4 trace endpoint, and the one DNS rule that bit
a real deployment: a CNAME cannot share its name with an A, AAAA or other CNAME
record, so Cloudflare refuses the combination.

Tunnels (/accounts/{acct}/cfd_tunnel): create, get, list (?name=,
?is_deleted=), delete — which, like Cloudflare, marks the tunnel deleted_at
and refuses while it has connections — and the connections list/cleanup. A new
tunnel comes up "healthy" with one fake cloudflared connection, as if the
daemon had started, so teardown has to clean connections up first.

GET /__state (no auth) exposes the records, tunnels and the write count to
tests.

Environment:
  FAKE_CF_BIND / FAKE_CF_PORT  listen address (0.0.0.0:8000)
  FAKE_CF_ZONE                 the one zone served (example.com)
  FAKE_CF_TRACE_IP             what /cdn-cgi/trace reports (203.0.113.1)
  FAKE_CF_SEED                 JSON file of records present at start
  FAKE_CF_TOKEN                accepted bearer token (test-token)
"""

import itertools
import json
import os
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

ACCOUNT = "acct1"
ZONE = {"id": "zone-1", "name": os.environ.get("FAKE_CF_ZONE", "example.com"), "account": {"id": ACCOUNT}}
TOKEN = os.environ.get("FAKE_CF_TOKEN", "test-token")
TRACE_IP = os.environ.get("FAKE_CF_TRACE_IP", "203.0.113.1")
RECORDS_PATH = f"/client/v4/zones/{ZONE['id']}/dns_records"
TUNNELS_PATH = f"/client/v4/accounts/{ACCOUNT}/cfd_tunnel"

ids = itertools.count(1)
records: dict[str, dict] = {}
tunnels: dict[str, dict] = {}
tunnel_ids = itertools.count(1)
writes = 0

if os.environ.get("FAKE_CF_SEED"):
    with open(os.environ["FAKE_CF_SEED"]) as seed:
        for rec in json.load(seed):
            rid = f"rec-{next(ids)}"
            records[rid] = {**rec, "id": rid}


def conflict(rec: dict) -> str | None:
    """Cloudflare's refusal for a record that cannot sit beside the others.

    Cloudflare enforces the CNAME rule against A, AAAA and CNAME only (its own
    error message names them) — which is how an apex CNAME can keep MX and TXT
    records beside it there.
    """
    same_name = [r for r in records.values() if r["name"] == rec["name"]]
    if rec["type"] in ("A", "AAAA") and any(r["type"] == "CNAME" for r in same_name):
        return "A CNAME record with that host already exists."
    if rec["type"] == "CNAME" and any(r["type"] in ("A", "AAAA", "CNAME") for r in same_name):
        return "An A, AAAA, or CNAME record with that host already exists."
    return None


def public(tunnel: dict) -> dict:
    """A tunnel as the API shows it: no secret, connections flattened."""
    view = {k: v for k, v in tunnel.items() if k not in ("clients", "tunnel_secret")}
    view["connections"] = [c for client in tunnel["clients"] for c in client["conns"]]
    return view


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *args) -> None:  # keep test logs readable
        pass

    def reply(self, result, code=200, success=True, errors=()):
        body = json.dumps(
            {"success": success, "errors": [{"message": e} for e in errors], "result": result}
        ).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def authorized(self) -> bool:
        if self.headers.get("Authorization") != f"Bearer {TOKEN}":
            self.reply(None, 403, False, ["bad token"])
            return False
        return True

    def body(self) -> dict:
        return json.loads(self.rfile.read(int(self.headers.get("Content-Length", 0))) or b"{}")

    def do_GET(self):
        u = urlparse(self.path)
        q = {k: v[0] for k, v in parse_qs(u.query).items()}
        if u.path == "/__state":
            return self.reply({"records": list(records.values()), "tunnels": list(tunnels.values()), "writes": writes})
        if u.path == "/cdn-cgi/trace":
            body = f"fl=1\nip={TRACE_IP}\nts=0\n".encode()
            self.send_response(200)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return
        if not self.authorized():
            return
        if u.path == "/client/v4/zones":
            return self.reply([ZONE] if q.get("name") == ZONE["name"] else [])
        if u.path == RECORDS_PATH:
            return self.reply(
                [r for r in records.values() if r["name"] == q.get("name") and q.get("type") in (None, r["type"])]
            )
        if u.path == TUNNELS_PATH:
            found = [
                t
                for t in tunnels.values()
                if q.get("name") in (None, t["name"])
                and (q.get("is_deleted") != "false" or t["deleted_at"] is None)
            ]
            return self.reply([public(t) for t in found])
        tid, sub = self.tunnel_path(u.path)
        if tid is not None:
            if tid not in tunnels:
                return self.reply(None, 404, False, ["Tunnel not found"])
            if sub == "":
                return self.reply(public(tunnels[tid]))
            if sub == "connections":
                return self.reply(tunnels[tid]["clients"])
        self.reply(None, 404, False, ["not found"])

    @staticmethod
    def tunnel_path(path: str) -> tuple[str | None, str | None]:
        """(tunnel id, sub-path) for /cfd_tunnel/{id}[/sub], else (None, None)."""
        if not path.startswith(TUNNELS_PATH + "/"):
            return None, None
        tid, _, sub = path[len(TUNNELS_PATH) + 1 :].partition("/")
        return tid, sub

    def do_POST(self):
        global writes
        if not self.authorized():
            return
        if urlparse(self.path).path == TUNNELS_PATH:
            return self.create_tunnel(self.body())
        rec = self.body()
        refusal = conflict(rec)
        if refusal:
            return self.reply(None, 400, False, [refusal])
        writes += 1
        rec["id"] = f"rec-{next(ids)}"
        records[rec["id"]] = rec
        self.reply(rec)

    def do_PATCH(self):
        global writes
        if not self.authorized():
            return
        writes += 1
        rid = self.path.rsplit("/", 1)[1]
        records[rid].update(self.body())
        self.reply(records[rid])

    def do_DELETE(self):
        global writes
        if not self.authorized():
            return
        tid, sub = self.tunnel_path(urlparse(self.path).path)
        if tid is not None:
            return self.delete_tunnel(tid, sub)
        writes += 1
        rid = self.path.rsplit("/", 1)[1]
        records.pop(rid, None)
        self.reply({"id": rid})

    def create_tunnel(self, body: dict):
        global writes
        if not body.get("name") or not body.get("tunnel_secret"):
            return self.reply(None, 400, False, ["name and tunnel_secret are required"])
        if any(t["name"] == body["name"] and t["deleted_at"] is None for t in tunnels.values()):
            return self.reply(None, 409, False, ["You already have a tunnel with this name"])
        writes += 1
        n = next(tunnel_ids)
        tid = f"00000000-0000-4000-8000-{n:012d}"
        tunnels[tid] = {
            "id": tid,
            "account_tag": ACCOUNT,
            "name": body["name"],
            "config_src": body.get("config_src"),
            "created_at": "2026-01-01T00:00:00Z",
            "deleted_at": None,
            "status": "healthy",
            # The secret is kept only so a test can check what was written.
            "tunnel_secret": body["tunnel_secret"],
            "clients": [
                {
                    "id": f"client-{n}",
                    "version": "2026.9.0",
                    "conns": [
                        {
                            "colo_name": "ams01",
                            "origin_ip": "198.51.100.7",
                            "opened_at": "2026-01-01T00:00:05Z",
                            "client_version": "2026.9.0",
                        }
                    ],
                }
            ],
        }
        self.reply(public(tunnels[tid]))

    def delete_tunnel(self, tid: str, sub: str):
        global writes
        tunnel = tunnels.get(tid)
        if tunnel is None or tunnel["deleted_at"] is not None:
            return self.reply(None, 404, False, ["Tunnel not found"])
        if sub == "connections":
            writes += 1
            tunnel["clients"] = []
            tunnel["status"] = "inactive"
            return self.reply(None)
        if tunnel["clients"]:
            return self.reply(None, 400, False, ["Cannot delete tunnel because it has active connections"])
        writes += 1
        tunnel["deleted_at"] = "2026-01-01T01:00:00Z"
        self.reply(public(tunnel))


ThreadingHTTPServer(
    (os.environ.get("FAKE_CF_BIND", "0.0.0.0"), int(os.environ.get("FAKE_CF_PORT", "8000"))), Handler
).serve_forever()
