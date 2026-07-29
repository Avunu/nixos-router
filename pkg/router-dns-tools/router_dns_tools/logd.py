"""router-logd — the query-log store and portal daemon.

Owns the Turso database (Turso does not support multi-process access, so
every read and write flows through this one process):

  • POST /ingest                 Log Exporter batches (bearer ingest token);
                                 entries are enriched with device / group /
                                 policy attribution at insert time.
  • GET  /logs, /logs.csv        filtered, paged log search (bearer query token)
  • GET  /stats/top, /stats/summary   SQL aggregates for dashboards/reports
  • POST /portal/request-exception    block-page form target (unauthenticated,
                                      rate-limited; reachable from LAN)
  • GET/POST /portal/requests[...]    exception queue for the Cockpit UI
  • GET  /healthz

The database is SQLite-format-compatible; `turso` (pyturso) is preferred and
stdlib sqlite3 is the drop-in fallback."""

from __future__ import annotations

import argparse
import csv
import hmac
import html
import io
import ipaddress
import json
import re
import sys
import threading
import time
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

try:
    import turso as dbapi

    DB_ENGINE = "turso"
except ImportError:  # hedge: same file format, same DB-API
    import sqlite3 as dbapi

    DB_ENGINE = "sqlite3"

from .compile_policies import _load_directory, compile_config

BLOCKED_TYPES = ("Blocked", "UpstreamBlocked", "UpstreamBlockedCached")

SCHEMA = """
CREATE TABLE IF NOT EXISTS query_log (
  id INTEGER PRIMARY KEY,
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
  id INTEGER PRIMARY KEY,
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
        with self.lock:
            cur = self.conn.cursor()
            cur.execute(sql, params)
            self.conn.commit()
            return getattr(cur, "rowcount", 0) or 0

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

    def _body(self) -> bytes:
        length = int(self.headers.get("Content-Length") or 0)
        return self.rfile.read(min(length, 32 * 1024 * 1024))

    # ── ingest ───────────────────────────────────────────────
    def _ingest(self):
        try:
            payload = json.loads(self._body().decode("utf-8", "replace"))
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
        writer.writerows(rows)
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
        recent = [t for t in d.portal_hits.get(client_ip, []) if now - t < 3600]
        if len(recent) >= d.portal_rate_limit:
            return self._send(429, b"Too many requests", "text/plain")
        d.portal_hits[client_ip] = recent + [now]

        form = urllib.parse.parse_qs(self._body().decode("utf-8", "replace"))
        domain = (form.get("domain", [""])[0]).strip().lower()[:253]
        reason = (form.get("reason", [""])[0]).strip()[:1000]
        if not re.fullmatch(r"[a-z0-9.-]{1,253}", domain or ""):
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
        try:
            body = json.loads(self._body().decode() or "{}")
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
        self.cfg = cfg

    def prune_loop(self):
        while True:
            try:
                self.store.prune()
            except Exception as exc:  # pruning must never kill the daemon
                print(f"prune failed: {exc}", file=sys.stderr)
            time.sleep(24 * 3600)


def main() -> None:
    parser = argparse.ArgumentParser(description="router query-log store and portal daemon")
    parser.add_argument("--config", required=True, help="runtime config JSON (Nix-generated)")
    args = parser.parse_args()
    cfg = json.loads(Path(args.config).read_text())["logd"]

    daemon = Daemon(cfg)
    threading.Thread(target=daemon.prune_loop, daemon=True).start()

    handler = type("BoundHandler", (Handler,), {"daemon": daemon})
    server = ThreadingHTTPServer((cfg.get("listenAddress", "0.0.0.0"), cfg.get("port", 8067)), handler)
    print(f"router-logd listening on {server.server_address} (db engine: {DB_ENGINE})", file=sys.stderr)
    server.serve_forever()


if __name__ == "__main__":
    main()
