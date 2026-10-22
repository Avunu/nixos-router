"""router-logd — the query-log store and portal daemon.

Owns the DuckDB database. DuckDB takes an exclusive lock on the file, so every
read and write flows through this one process — which is already the shape of
the system: router-report does not open the database, it queries the HTTP API
below.

  • POST /ingest                 Log Exporter batches (bearer ingest token);
                                 entries are enriched with device / group /
                                 policy attribution at insert time.
  • GET  /logs, /logs.csv        filtered, paged log search (bearer query token)
  • GET  /stats/top, /stats/summary   SQL aggregates for dashboards/reports
  • POST /portal/request-exception    block-page form target (unauthenticated,
                                      rate-limited; reachable from LAN)
  • GET/POST /portal/requests[...]    exception queue for the Cockpit UI
  • GET  /healthz

With router.fqdn set and the block page on, a second listener serves the
portal over HTTPS at blocked.<fqdn> for the browser extension (PortalHandler):
the block check, the block page, and the exception form, never the token
endpoints. See portal.py.

DuckDB is used for its columnar/analytical engine — nearly everything asked of
this store is an aggregate over a time range (top domains, per-group counts,
blocked ratios) rather than a point lookup."""

from __future__ import annotations

import argparse
import csv
import hmac
import html
import io
import ipaddress
import json
import re
import signal
import socket
import ssl
import sys
import threading
import time
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

# No sqlite3 fallback. It used to be a safe hedge because Turso wrote
# SQLite-format files, but DuckDB's storage is its own — falling back would
# silently create a second, incompatible database at the same path rather than
# failing where an operator can see it.
import duckdb as dbapi

DB_ENGINE = "duckdb"

from . import csvsafe, portal
from .compile_policies import _load_directory, compile_config

BLOCKED_TYPES = ("Blocked", "UpstreamBlocked", "UpstreamBlockedCached")

# Request-body ceilings. /ingest is authenticated and carries Log Exporter
# batches; the portal form is unauthenticated and reachable from the guest
# network, so it gets only what a domain and a 1000-character reason need.
INGEST_BODY_LIMIT = 32 * 1024 * 1024
PORTAL_BODY_LIMIT = 16 * 1024
STATUS_BODY_LIMIT = 4 * 1024

# DuckDB has no SQLite-style implicit rowid: `INTEGER PRIMARY KEY` is just a
# NOT NULL column, and an INSERT that omits it fails the constraint. Ids come
# from explicit sequences instead, which must be created before the tables that
# default to them.
SCHEMA = """
CREATE SEQUENCE IF NOT EXISTS seq_query_log;
CREATE SEQUENCE IF NOT EXISTS seq_exception_requests;
CREATE TABLE IF NOT EXISTS query_log (
  id INTEGER PRIMARY KEY DEFAULT nextval('seq_query_log'),
  ts TEXT NOT NULL,
  client_ip TEXT NOT NULL,
  protocol TEXT,
  response_type TEXT,
  rcode TEXT,
  qname TEXT,
  qtype TEXT,
  answer TEXT,
  device TEXT,
  host_group TEXT,
  policy TEXT
);
CREATE INDEX IF NOT EXISTS idx_log_ts ON query_log (ts);
CREATE INDEX IF NOT EXISTS idx_log_client ON query_log (client_ip);
CREATE INDEX IF NOT EXISTS idx_log_qname ON query_log (qname);
CREATE INDEX IF NOT EXISTS idx_log_rtype ON query_log (response_type);
CREATE INDEX IF NOT EXISTS idx_log_policy ON query_log (policy);
CREATE TABLE IF NOT EXISTS exception_requests (
  id INTEGER PRIMARY KEY DEFAULT nextval('seq_exception_requests'),
  ts TEXT NOT NULL,
  domain TEXT NOT NULL,
  client_ip TEXT NOT NULL,
  device TEXT,
  user TEXT,
  host_group TEXT,
  policy TEXT,
  reason TEXT,
  status TEXT NOT NULL DEFAULT 'pending'
);
"""


def _jget(d: dict, *names, default=None):
    """Tolerant field access — Technitium's serializer casing may vary."""
    for n in names:
        for k in (n, n[0].upper() + n[1:], n[0].lower() + n[1:]):
            if k in d:
                return d[k]
    return default


class Attribution:
    """client IP → (device, group, policy), rebuilt when inputs change."""

    def __init__(self, static_path: str, directory_path: str | None):
        self.static_path = static_path
        self.directory_path = directory_path
        self._stamp = None
        self._lock = threading.Lock()
        self._reload()

    def _mtimes(self):
        def mt(p):
            try:
                return Path(p).stat().st_mtime if p else 0
            except OSError:
                return 0

        return (mt(self.static_path), mt(self.directory_path))

    def _reload(self):
        static = json.loads(Path(self.static_path).read_text())
        directory = _load_directory(self.directory_path)
        compiled = compile_config(static, directory)
        self.hosts_by_ip = {h["staticIp"]: h for h in static["hosts"] if h.get("staticIp")}
        self.networks = []
        for cidr, group in compiled["networkGroupMap"].items():
            # Advanced Blocking brackets IPv6 keys ("[::]/0", "[::1]"); strip()
            # would leave "::]/0" intact because the key ends in a digit.
            try:
                net = ipaddress.ip_network(cidr.replace("[", "").replace("]", ""), strict=False)
            except ValueError:
                continue
            self.networks.append((net, group))
        self._stamp = self._mtimes()

    def resolve(self, ip: str) -> tuple[str | None, str | None, str | None]:
        with self._lock:
            if self._mtimes() != self._stamp:
                try:
                    self._reload()
                except (OSError, ValueError) as exc:
                    print(f"attribution reload failed: {exc}", file=sys.stderr)
            host = self.hosts_by_ip.get(ip)
            try:
                addr = ipaddress.ip_address(ip)
            except ValueError:
                return (None, None, None)
            best = None
            for net, group in self.networks:
                if addr.version == net.version and addr in net:
                    if best is None or net.prefixlen > best[0].prefixlen:
                        best = (net, group)
            policy = best[1] if best else None
            return (
                host["name"] if host else None,
                host.get("group") if host else None,
                policy,
            )


class LogStore:
    """All DB access serialized behind one lock (single connection, one process)."""

    def __init__(self, db_path: str, retention_days: int):
        self.conn = dbapi.connect(db_path)
        self.lock = threading.Lock()
        self.retention_days = retention_days
        with self.lock:
            cur = self.conn.cursor()
            for stmt in SCHEMA.strip().split(";"):
                if stmt.strip():
                    cur.execute(stmt)
            self.conn.commit()

    def insert_entries(self, rows: list[tuple]):
        with self.lock:
            cur = self.conn.cursor()
            cur.executemany(
                "INSERT INTO query_log (ts, client_ip, protocol, response_type, rcode,"
                " qname, qtype, answer, device, host_group, policy)"
                " VALUES (?,?,?,?,?,?,?,?,?,?,?)",
                rows,
            )
            self.conn.commit()

    def query(self, sql: str, params: tuple = ()) -> list[tuple]:
        with self.lock:
            cur = self.conn.cursor()
            cur.execute(sql, params)
            return cur.fetchall()

    def execute(self, sql: str, params: tuple = ()) -> int:
        """Run a statement and return the number of rows it changed.

        DuckDB always reports cursor.rowcount as -1; it returns the affected
        count as a one-row result set instead. That count is load-bearing —
        the exception-queue endpoint reports it to the UI, and prune() logs it.
        """
        with self.lock:
            cur = self.conn.cursor()
            cur.execute(sql, params)
            rows = cur.fetchall()
            self.conn.commit()
            return int(rows[0][0]) if rows and rows[0] else 0

    def prune(self):
        cutoff = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(time.time() - self.retention_days * 86400))
        n = self.execute("DELETE FROM query_log WHERE ts < ?", (cutoff,))
        if n:
            print(f"pruned {n} log rows older than {cutoff}", file=sys.stderr)


LOG_FILTERS = {
    "start": ("ts >= ?", str),
    "end": ("ts <= ?", str),
    "client": ("client_ip = ?", str),
    "group": ("host_group = ?", str),
    "policy": ("policy = ?", str),
}


def _log_where(q: dict) -> tuple[str, list]:
    clauses, params = [], []
    for key, (clause, conv) in LOG_FILTERS.items():
        if q.get(key):
            clauses.append(clause)
            params.append(conv(q[key][0]))
    if q.get("qname"):
        clauses.append("qname LIKE ?")
        params.append(f"%{q['qname'][0]}%")
    if q.get("blocked", ["0"])[0] in ("1", "true"):
        clauses.append(f"response_type IN ({','.join('?' * len(BLOCKED_TYPES))})")
        params.extend(BLOCKED_TYPES)
    return (" WHERE " + " AND ".join(clauses)) if clauses else "", params


LOG_COLUMNS = [
    "ts",
    "client_ip",
    "protocol",
    "response_type",
    "rcode",
    "qname",
    "qtype",
    "answer",
    "device",
    "host_group",
    "policy",
]

PORTAL_RESPONSE = """<!doctype html><html><head><meta charset="utf-8"><title>{title}</title>
<style>body{{font-family:system-ui,sans-serif;max-width:36rem;margin:4rem auto;padding:0 1rem;color:#222}}</style>
</head><body><h1>{heading}</h1><p>{message}</p></body></html>"""


class Handler(BaseHTTPRequestHandler):
    server_version = "router-logd"
    daemon: "Daemon"
    # Socket timeout per connection (StreamRequestHandler applies it): a client
    # that stalls mid-request is dropped instead of holding a thread forever.
    timeout = 30

    # ── helpers ──────────────────────────────────────────────
    def _bearer_ok(self, token: str) -> bool:
        got = self.headers.get("Authorization", "")
        return got.startswith("Bearer ") and hmac.compare_digest(got[7:].strip(), token)

    def _send(self, code: int, body: bytes, ctype: str = "application/json"):
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _json(self, obj, code: int = 200):
        self._send(code, json.dumps(obj).encode())

    def _deny(self):
        self._json({"error": "unauthorized"}, 401)

    def log_message(self, fmt, *args):  # quiet default access log
        pass

    # ── routing ──────────────────────────────────────────────
    def do_GET(self):
        url = urllib.parse.urlparse(self.path)
        q = urllib.parse.parse_qs(url.query)
        d = self.daemon
        if url.path == "/healthz":
            return self._json({"ok": True, "engine": DB_ENGINE})
        if not self._bearer_ok(d.query_token):
            return self._deny()
        if url.path == "/logs":
            return self._logs(q)
        if url.path == "/logs.csv":
            return self._logs_csv(q)
        if url.path == "/stats/top":
            return self._stats_top(q)
        if url.path == "/stats/summary":
            return self._stats_summary(q)
        if url.path == "/portal/requests":
            return self._portal_list(q)
        self._json({"error": "not found"}, 404)

    def do_POST(self):
        url = urllib.parse.urlparse(self.path)
        d = self.daemon
        if url.path == "/ingest":
            if not self._bearer_ok(d.ingest_token):
                return self._deny()
            return self._ingest()
        if url.path == "/portal/request-exception":
            return self._portal_submit()
        m = re.fullmatch(r"/portal/requests/(\d+)/status", url.path)
        if m:
            if not self._bearer_ok(d.query_token):
                return self._deny()
            return self._portal_status(int(m.group(1)))
        self._json({"error": "not found"}, 404)

    def _body(self, limit: int) -> bytes | None:
        """The request body, or None after answering 400/413 when the declared
        length is malformed, negative or over `limit`. A negative length used to
        reach rfile.read(-1), which reads until the client hangs up."""
        try:
            length = int(self.headers.get("Content-Length") or 0)
        except ValueError:
            length = -1
        if length < 0:
            self._send(400, b"Bad Content-Length", "text/plain")
            return None
        if length > limit:
            self._send(413, b"Request body too large", "text/plain")
            return None
        return self.rfile.read(length)

    # ── ingest ───────────────────────────────────────────────
    def _ingest(self):
        body = self._body(INGEST_BODY_LIMIT)
        if body is None:
            return
        try:
            payload = json.loads(body.decode("utf-8", "replace"))
        except ValueError:
            return self._json({"error": "bad json"}, 400)
        events = payload.get("events", payload) if isinstance(payload, dict) else payload
        if not isinstance(events, list):
            return self._json({"error": "unexpected payload"}, 400)

        rows = []
        for event in events:
            entry = event
            if isinstance(event, dict) and "clientIp" not in event and "ClientIp" not in event:
                # Serilog envelope: the LogEntry JSON is the rendered message.
                msg = _jget(event, "renderedMessage") or _jget(event, "messageTemplate") or ""
                try:
                    entry = json.loads(msg)
                except ValueError:
                    continue
            if not isinstance(entry, dict):
                continue
            client_ip = _jget(entry, "clientIp", default="")
            if not client_ip:
                continue
            question = _jget(entry, "question", default={}) or {}
            qname = str(_jget(question, "questionName", default="")).lower().rstrip(".")
            # The portal's own oracle lookups: router-logd asking Technitium,
            # not a device's traffic.
            if any(qname == z or qname.endswith("." + z) for z in self.daemon.ignore_qname_suffixes):
                continue
            answers = _jget(entry, "answers", default=[]) or []
            answer = ", ".join(str(_jget(a, "recordData", default="")) for a in answers if isinstance(a, dict))
            device, group, policy = self.daemon.attribution.resolve(client_ip)
            rows.append(
                (
                    str(_jget(entry, "timestamp", default="")),
                    client_ip,
                    str(_jget(entry, "protocol", default="")),
                    str(_jget(entry, "responseType", default="")),
                    str(_jget(entry, "responseCode", default="")),
                    str(_jget(question, "questionName", default="")).lower(),
                    str(_jget(question, "questionType", default="")),
                    answer,
                    device,
                    group,
                    policy,
                )
            )
        if rows:
            self.daemon.store.insert_entries(rows)
        self._json({"accepted": len(rows)})

    # ── log queries ──────────────────────────────────────────
    def _logs(self, q):
        where, params = _log_where(q)
        page = max(1, int(q.get("page", ["1"])[0]))
        page_size = min(500, max(1, int(q.get("pageSize", ["50"])[0])))
        total = self.daemon.store.query(f"SELECT COUNT(*) FROM query_log{where}", tuple(params))[0][0]
        rows = self.daemon.store.query(
            f"SELECT {', '.join(LOG_COLUMNS)} FROM query_log{where} ORDER BY ts DESC LIMIT ? OFFSET ?",
            tuple(params) + (page_size, (page - 1) * page_size),
        )
        self._json(
            {
                "total": total,
                "page": page,
                "pageSize": page_size,
                "entries": [dict(zip(LOG_COLUMNS, r)) for r in rows],
            }
        )

    def _logs_csv(self, q):
        where, params = _log_where(q)
        rows = self.daemon.store.query(
            f"SELECT {', '.join(LOG_COLUMNS)} FROM query_log{where} ORDER BY ts DESC LIMIT 100000",
            tuple(params),
        )
        buf = io.StringIO()
        writer = csv.writer(buf)
        writer.writerow(LOG_COLUMNS)
        writer.writerows(csvsafe.row(r) for r in rows)
        self._send(200, buf.getvalue().encode(), "text/csv")

    def _stats_top(self, q):
        where, params = _log_where(q)
        by = q.get("by", ["domain"])[0]
        column = {
            "domain": "qname",
            "client": "client_ip",
            "group": "host_group",
            "policy": "policy",
            "device": "device",
            "blocked": "qname",
        }.get(by)
        if column is None:
            return self._json({"error": "bad 'by'"}, 400)
        if by == "blocked":
            blocked_clause = f"response_type IN ({','.join('?' * len(BLOCKED_TYPES))})"
            where = f"{where} AND {blocked_clause}" if where else f" WHERE {blocked_clause}"
            params = list(params) + list(BLOCKED_TYPES)
        limit = min(1000, int(q.get("limit", ["10"])[0]))
        rows = self.daemon.store.query(
            f"SELECT {column} AS k, COUNT(*) AS hits,"
            f" SUM(CASE WHEN response_type IN ({','.join('?' * len(BLOCKED_TYPES))}) THEN 1 ELSE 0 END) AS blocked"
            f" FROM query_log{where} GROUP BY {column} ORDER BY hits DESC LIMIT ?",
            tuple(BLOCKED_TYPES) + tuple(params) + (limit,),
        )
        self._json({"top": [{"name": r[0] or "(unknown)", "hits": r[1], "blocked": r[2]} for r in rows]})

    def _stats_summary(self, q):
        where, params = _log_where(q)
        row = self.daemon.store.query(
            f"SELECT COUNT(*),"
            f" SUM(CASE WHEN response_type IN ({','.join('?' * len(BLOCKED_TYPES))}) THEN 1 ELSE 0 END),"
            f" COUNT(DISTINCT client_ip) FROM query_log{where}",
            tuple(BLOCKED_TYPES) + tuple(params),
        )[0]
        self._json({"total": row[0], "blocked": row[1] or 0, "clients": row[2]})

    # ── portal ───────────────────────────────────────────────
    def _portal_submit(self):
        d = self.daemon
        client_ip = self.client_address[0]
        now = time.time()
        with d.portal_lock:
            recent = [t for t in d.portal_hits.get(client_ip, []) if now - t < 3600]
            limited = len(recent) >= d.portal_rate_limit
            if not limited:
                d.portal_hits[client_ip] = recent + [now]
            # Forget clients idle for an hour, so a guest network cycling
            # through addresses cannot grow the table without bound.
            if len(d.portal_hits) > 1024:
                d.portal_hits = {ip: ts for ip, ts in d.portal_hits.items() if now - ts[-1] < 3600}
        if limited:
            return self._send(429, b"Too many requests", "text/plain")

        body = self._body(PORTAL_BODY_LIMIT)
        if body is None:
            return
        form = urllib.parse.parse_qs(body.decode("utf-8", "replace"))
        domain = (form.get("domain", [""])[0]).strip().lower()[:253]
        reason = (form.get("reason", [""])[0]).strip()[:1000]
        if not re.fullmatch(r"[a-z0-9_.-]{1,253}", domain or ""):
            return self._send(400, b"Invalid domain", "text/plain")

        device, group, policy = d.attribution.resolve(client_ip)
        host = d.attribution.hosts_by_ip.get(client_ip, {})
        d.store.execute(
            "INSERT INTO exception_requests (ts, domain, client_ip, device, user, host_group, policy, reason)"
            " VALUES (?,?,?,?,?,?,?,?)",
            (
                time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                domain,
                client_ip,
                device,
                host.get("user"),
                group,
                policy,
                reason,
            ),
        )
        body = PORTAL_RESPONSE.format(
            title="Request submitted",
            heading="Request submitted",
            message=f"Your request to unblock <strong>{html.escape(domain)}</strong> has been sent to your network administrator.",
        )
        self._send(200, body.encode(), "text/html")

    def _portal_list(self, q):
        status = q.get("status", [None])[0]
        where, params = ("", ())
        if status:
            where, params = " WHERE status = ?", (status,)
        rows = self.daemon.store.query(
            "SELECT id, ts, domain, client_ip, device, user, host_group, policy, reason, status"
            f" FROM exception_requests{where} ORDER BY ts DESC LIMIT 500",
            params,
        )
        cols = ["id", "ts", "domain", "client_ip", "device", "user", "host_group", "policy", "reason", "status"]
        self._json({"requests": [dict(zip(cols, r)) for r in rows]})

    def _portal_status(self, request_id: int):
        raw = self._body(STATUS_BODY_LIMIT)
        if raw is None:
            return
        try:
            body = json.loads(raw.decode() or "{}")
        except ValueError:
            body = {}
        status = body.get("status")
        if status not in ("approved", "denied", "pending"):
            return self._json({"error": "status must be approved|denied|pending"}, 400)
        n = self.daemon.store.execute(
            "UPDATE exception_requests SET status = ? WHERE id = ?", (status, request_id)
        )
        self._json({"updated": n})


def _secret(credential_name: str, path: str) -> str:
    """Prefer systemd LoadCredential (the unit runs as DynamicUser and cannot
    read the root-owned token files directly); fall back to the raw path."""
    import os

    cred_dir = os.environ.get("CREDENTIALS_DIRECTORY")
    if cred_dir and (Path(cred_dir) / credential_name).exists():
        return (Path(cred_dir) / credential_name).read_text().strip()
    return Path(path).read_text().strip()


class Daemon:
    def __init__(self, cfg: dict):
        self.store = LogStore(cfg["dbPath"], cfg.get("retentionDays", 90))
        self.attribution = Attribution(cfg["staticInputs"], cfg.get("directoryState"))
        self.ingest_token = _secret("ingest-token", cfg["ingestTokenFile"])
        self.query_token = _secret("query-token", cfg["queryTokenFile"])
        self.portal_rate_limit = cfg.get("portalRateLimitPerHour", 10)
        self.portal_hits: dict[str, list[float]] = {}
        self.portal_lock = threading.Lock()
        self.ignore_qname_suffixes = [z.lower().rstrip(".") for z in cfg.get("ignoreQnameSuffixes", [])]
        # The HTTPS portal's block check, per client per minute (PortalHandler).
        self.check_rate_limit = (cfg.get("portal") or {}).get("checkRatePerMinute", 60)
        self.check_hits: dict[str, list[float]] = {}
        self.cfg = cfg

    def prune_loop(self):
        while True:
            try:
                self.store.prune()
            except Exception as exc:  # pruning must never kill the daemon
                print(f"prune failed: {exc}", file=sys.stderr)
            time.sleep(24 * 3600)


class BoundedThreadingHTTPServer(ThreadingHTTPServer):
    """ThreadingHTTPServer with a ceiling on concurrent connections. The stock
    server starts a thread per connection with no limit, and the portal is open
    to the guest network; past the ceiling a new connection is closed at once."""

    max_connections = 64

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._slots = threading.BoundedSemaphore(self.max_connections)

    def process_request(self, request, client_address):
        if not self._slots.acquire(blocking=False):
            self.shutdown_request(request)
            return
        try:
            super().process_request(request, client_address)
        except Exception:
            self._slots.release()
            raise

    def process_request_thread(self, request, client_address):
        try:
            super().process_request_thread(request, client_address)
        finally:
            self._slots.release()


class PortalHandler(Handler):
    """The HTTPS portal at blocked.<fqdn> (portal.py). It answers the browser
    extension and the pages it opens, so it serves only the public routes;
    the token endpoints and /ingest are not found here, whatever the token.

    Every response carries headers for a page on the router's own trusted
    origin: no framing, no sniffing, no caching, a strict CSP, and no cookies.
    No HSTS: it is per host, not per port, and would cover every port of
    blocked.<fqdn>. No CORS headers either, so a web page can make the browser
    send a check but never read its answer."""

    server_version = "router-logd-portal"
    portal_cfg: dict
    block_check: portal.BlockCheck
    template: str

    _csp = "default-src 'none'; style-src 'unsafe-inline'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'"

    def end_headers(self):
        self.send_header("Content-Security-Policy", self._csp)
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        # same-origin, not no-referrer: under no-referrer the block page's own
        # form POST would carry "Origin: null" and fail the check in do_POST.
        self.send_header("Referrer-Policy", "same-origin")
        self.send_header("Cache-Control", "no-store")
        super().end_headers()

    def _html(self, code: int, body: str, nonce: str | None = None):
        if nonce:
            self._csp = portal.page_csp(nonce)
        self._send(code, body.encode(), "text/html; charset=utf-8")

    def _api_ok(self) -> bool:
        """The JSON endpoints need a header no cross-site page can send without
        a CORS preflight, which fails here. That keeps pages from using up a
        device's rate limit."""
        if self.headers.get("X-Router-Portal") == "1":
            return True
        self._json({"error": "missing X-Router-Portal header"}, 403)
        return False

    def _check_rate_ok(self) -> bool:
        d = self.daemon
        client_ip = self.client_address[0]
        now = time.time()
        with d.portal_lock:
            recent = [t for t in d.check_hits.get(client_ip, []) if now - t < 60]
            limited = len(recent) >= d.check_rate_limit
            if not limited:
                d.check_hits[client_ip] = recent + [now]
            if len(d.check_hits) > 1024:
                d.check_hits = {ip: ts for ip, ts in d.check_hits.items() if now - ts[-1] < 60}
        return not limited

    def do_GET(self):
        url = urllib.parse.urlparse(self.path)
        q = urllib.parse.parse_qs(url.query)
        if url.path == "/portal/info":
            if not self._api_ok():
                return
            return self._json(
                {"service": "nixos-router-portal", "apiVersion": 1, "name": self.portal_cfg.get("routerName")}
            )
        if url.path == "/portal/check":
            if not self._api_ok():
                return
            return self._check(q)
        if url.path == "/portal/blocked":
            return self._blocked_page(q)
        self._json({"error": "not found"}, 404)

    def do_POST(self):
        url = urllib.parse.urlparse(self.path)
        if url.path == "/portal/request-exception":
            # Only the portal's own block page submits here over HTTPS.
            if self.headers.get("Origin") != self.portal_cfg["origin"]:
                return self._send(403, b"Forbidden", "text/plain")
            return self._portal_submit()
        self._json({"error": "not found"}, 404)

    def _lookup(self, q) -> tuple[str | None, portal.CheckResult | None, int]:
        """(host, result, status): status is 200, or the error to answer."""
        host = portal.normalize_host(q.get("host", [""])[0])
        if host is None:
            return None, None, 400
        if not self._check_rate_ok():
            return host, None, 429
        try:
            return host, self.block_check.check(host, self.client_address[0]), 200
        except portal.OracleError as exc:
            print(f"portal: block check for {host} failed: {exc}", file=sys.stderr)
            return host, None, 503

    def _check(self, q):
        host, result, status = self._lookup(q)
        if status != 200 or result is None:
            error = {400: "invalid host", 429: "too many requests", 503: "block check unavailable"}[status]
            return self._json({"error": error}, status)
        self._json({"blocked": result.show_page, "host": host, "reason": result.reason if result.show_page else None})

    def _blocked_page(self, q):
        nonce = portal.new_nonce()
        _, result, status = self._lookup(q)
        if status == 400:
            return self._send(400, b"Invalid host", "text/plain")
        if status == 429:
            return self._send(429, b"Too many requests", "text/plain")
        if result is None:
            return self._html(503, portal.render_unavailable(nonce), nonce)
        # A page asked for by name shows the truth, NXDOMAIN policies included;
        # only the extension's automatic redirect leaves those alone (_check).
        if not result.blocked:
            return self._html(200, portal.render_not_blocked(nonce, result.host), nonce)
        self._html(200, portal.render_block_page(self.template, nonce, result.host, result.reason), nonce)


class PortalTLSServer(BoundedThreadingHTTPServer):
    """The HTTPS side. The TLS handshake runs in the connection's own thread,
    under the connection ceiling, so a client that connects and never speaks
    cannot stall the accept loop. The context is swapped on reload (SIGHUP after
    a certificate renewal) without dropping the listener."""

    handshake_timeout = 10

    def __init__(self, address, handler, context: ssl.SSLContext):
        self.context = context
        super().__init__(address, handler)

    def finish_request(self, request, client_address):
        request.settimeout(self.handshake_timeout)
        try:
            tls = self.context.wrap_socket(request, server_side=True)
        except (ssl.SSLError, OSError):
            return
        try:
            self.RequestHandlerClass(tls, client_address, self)
        finally:
            try:
                tls.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            tls.close()


class PortalTLS:
    """Owns the HTTPS listener's lifecycle. A missing or unreadable certificate
    (not issued yet, mid-renewal) never takes router-logd down: the listener
    starts on the first reload that finds a usable one, and a failed reload
    keeps serving the previous certificate."""

    def __init__(self, cfg: dict, handler: type):
        self.cfg = cfg
        self.handler = handler
        self.server: PortalTLSServer | None = None
        self.lock = threading.Lock()

    def _context(self) -> ssl.SSLContext:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.minimum_version = ssl.TLSVersion.TLSv1_2
        ctx.load_cert_chain(self.cfg["certFile"], self.cfg["keyFile"])
        return ctx

    def reload(self) -> None:
        with self.lock:
            try:
                ctx = self._context()
            except (OSError, ssl.SSLError) as exc:
                state = "keeps its previous certificate" if self.server else "stays off"
                print(f"portal: cannot load {self.cfg['certFile']}: {exc}; HTTPS {state}", file=sys.stderr)
                return
            if self.server is not None:
                self.server.context = ctx
                print("portal: certificate reloaded", file=sys.stderr)
                return
            try:
                self.server = PortalTLSServer(
                    (self.cfg.get("listenAddress", "0.0.0.0"), self.cfg["tlsPort"]), self.handler, ctx
                )
            except OSError as exc:
                print(f"portal: cannot listen on {self.cfg['tlsPort']}: {exc}", file=sys.stderr)
                return
            threading.Thread(target=self.server.serve_forever, daemon=True).start()
            print(f"portal: HTTPS on {self.server.server_address} for {self.cfg['origin']}", file=sys.stderr)


def main() -> None:
    parser = argparse.ArgumentParser(description="router query-log store and portal daemon")
    parser.add_argument("--config", required=True, help="runtime config JSON (Nix-generated)")
    args = parser.parse_args()
    cfg = json.loads(Path(args.config).read_text())["logd"]

    daemon = Daemon(cfg)
    threading.Thread(target=daemon.prune_loop, daemon=True).start()

    handler = type("BoundHandler", (Handler,), {"daemon": daemon})
    server = BoundedThreadingHTTPServer((cfg.get("listenAddress", "0.0.0.0"), cfg.get("port", 8067)), handler)
    print(f"router-logd listening on {server.server_address} (db engine: {DB_ENGINE})", file=sys.stderr)

    pcfg = cfg.get("portal")
    if pcfg:
        pcfg = {**pcfg, "listenAddress": cfg.get("listenAddress", "0.0.0.0")}
        portal_handler = type(
            "BoundPortalHandler",
            (PortalHandler,),
            {
                "daemon": daemon,
                "portal_cfg": pcfg,
                "template": Path(pcfg["template"]).read_text(),
                "block_check": portal.BlockCheck(
                    pcfg["blockCheckZone"],
                    pcfg.get("listNames", {}),
                    port=pcfg.get("dnsPort", 53),
                    timeout_ms=pcfg.get("dnsTimeoutMs", 1500),
                ),
            },
        )
        tls = PortalTLS(pcfg, portal_handler)
        tls.reload()
        # A certificate renewal (acme reloadServices) and `systemctl reload`
        # send SIGHUP. Unhandled, it would end the process.
        signal.signal(signal.SIGHUP, lambda *_: threading.Thread(target=tls.reload, daemon=True).start())
    else:
        signal.signal(signal.SIGHUP, signal.SIG_IGN)

    server.serve_forever()


if __name__ == "__main__":
    main()
