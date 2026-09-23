"""Just enough of the Cloudflare v4 API for router-ddns, in memory.

Zone lookup, dns_records list/create/patch/delete, the IPv4 trace endpoint, and
the one DNS rule that bit a real deployment: a CNAME cannot share its name with
an A, AAAA or other CNAME record, so Cloudflare refuses the combination.
GET /__state (no auth) exposes the records and the write count to tests.

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

ZONE = {"id": "zone-1", "name": os.environ.get("FAKE_CF_ZONE", "example.com")}
TOKEN = os.environ.get("FAKE_CF_TOKEN", "test-token")
TRACE_IP = os.environ.get("FAKE_CF_TRACE_IP", "203.0.113.1")
RECORDS_PATH = f"/client/v4/zones/{ZONE['id']}/dns_records"

ids = itertools.count(1)
records: dict[str, dict] = {}
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
            return self.reply({"records": list(records.values()), "writes": writes})
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
                [r for r in records.values() if r["name"] == q.get("name") and r["type"] == q.get("type")]
            )
        self.reply(None, 404, False, ["not found"])

    def do_POST(self):
        global writes
        if not self.authorized():
            return
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
        writes += 1
        rid = self.path.rsplit("/", 1)[1]
        records.pop(rid, None)
        self.reply({"id": rid})


ThreadingHTTPServer(
    (os.environ.get("FAKE_CF_BIND", "0.0.0.0"), int(os.environ.get("FAKE_CF_PORT", "8000"))), Handler
).serve_forever()
