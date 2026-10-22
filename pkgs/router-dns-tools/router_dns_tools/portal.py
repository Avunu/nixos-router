"""The HTTPS portal's block check and pages (served by router-logd).

The browser extension asks the portal whether a site it failed to open is
blocked for this device, and if so sends the tab to the portal's block page.
Advanced Blocking picks a policy from the address a query came from only, and
router-logd's own queries come from loopback (the bypass group), so the answer
comes from the Router Live DNS app's oracle zone instead: a TXT query for
<host>.<client-label>.<zone>, answered from inside Technitium as that client
(pkgs/technitium-apps/RouterLiveDnsApp, ProcessBlockCheckAsync).

Everything here is stdlib and free of router-logd's database, so it can be
tested on its own (tests/test_portal.py)."""

from __future__ import annotations

import html
import ipaddress
import re
import secrets
import socket
import struct
import time
from dataclasses import dataclass

# What the portal accepts as a host: a lowercase DNS name with at least one dot.
# Underscores are allowed because Technitium resolves (and blocks) such names.
_LABEL = r"[a-z0-9_](?:[a-z0-9_-]{0,61}[a-z0-9_])?"
_HOST_RE = re.compile(rf"(?:{_LABEL}\.)+{_LABEL}")

TXT = 16
RCODES = {0: "NoError", 1: "FormatError", 2: "ServerFailure", 3: "NxDomain", 4: "NotImplemented", 5: "Refused"}


class OracleError(Exception):
    """The oracle gave no usable answer: the router can't tell right now."""


def normalize_host(raw: str | None) -> str | None:
    """The host as the oracle is asked about it, or None when it isn't one.
    IP literals are not names a policy blocks, so they are refused too."""
    if not raw:
        return None
    host = raw.strip().lower().removesuffix(".")
    if len(host) > 253 or not _HOST_RE.fullmatch(host):
        return None
    try:
        ipaddress.ip_address(host)
        return None
    except ValueError:
        return host


def client_label(ip: str) -> str:
    """One DNS label for a client address: 10.48.4.50 → 10-48-4-50,
    fd00::1 → fd00--1. The oracle reverses it (ParseClientLabel)."""
    addr = ipaddress.ip_address(ip)
    if isinstance(addr, ipaddress.IPv6Address) and addr.ipv4_mapped is not None:
        addr = addr.ipv4_mapped
    if addr.version == 4:
        return str(addr).replace(".", "-")
    return addr.compressed.replace(":", "-")


def oracle_name(host: str, client_ip: str, zone: str) -> str | None:
    """The oracle's question for `host` as seen by `client_ip`, or None when it
    would not fit in a DNS name (255 bytes on the wire)."""
    name = f"{host}.{client_label(client_ip)}.{zone.rstrip('.')}"
    labels = name.split(".")
    if any(len(label) == 0 or len(label) > 63 for label in labels):
        return None
    if sum(len(label) + 1 for label in labels) + 1 > 255:
        return None
    return name


# ── DNS wire format (just enough for one TXT question) ──────────────
def build_query(name: str, qid: int, qtype: int = TXT) -> bytes:
    header = struct.pack("!HHHHHH", qid, 0x0100, 1, 0, 0, 0)  # RD set
    qname = b"".join(bytes([len(label)]) + label.encode("ascii") for label in name.split(".")) + b"\0"
    return header + qname + struct.pack("!HH", qtype, 1)


def _skip_name(msg: bytes, off: int) -> int:
    """The offset just past the (possibly compressed) name at `off`."""
    while True:
        if off >= len(msg):
            raise OracleError("truncated name")
        length = msg[off]
        if length == 0:
            return off + 1
        if length & 0xC0 == 0xC0:
            return off + 2  # a pointer ends the name
        if length & 0xC0:
            raise OracleError("bad label")
        off += 1 + length


def parse_txt_response(msg: bytes, qid: int) -> tuple[str, list[str]]:
    """(rcode name, the TXT answers with their character-strings joined)."""
    if len(msg) < 12:
        raise OracleError("short response")
    rid, flags, qdcount, ancount, _, _ = struct.unpack("!HHHHHH", msg[:12])
    if rid != qid or not flags & 0x8000:
        raise OracleError("not an answer to this query")
    rcode = RCODES.get(flags & 0xF, str(flags & 0xF))
    off = 12
    for _ in range(qdcount):
        off = _skip_name(msg, off) + 4
    texts = []
    for _ in range(ancount):
        off = _skip_name(msg, off)
        if off + 10 > len(msg):
            raise OracleError("truncated record")
        rtype, _, _, rdlen = struct.unpack("!HHIH", msg[off : off + 10])
        off += 10
        rdata = msg[off : off + rdlen]
        if len(rdata) != rdlen:
            raise OracleError("truncated record data")
        off += rdlen
        if rtype != TXT:
            continue
        parts, i = [], 0
        while i < len(rdata):
            n = rdata[i]
            parts.append(rdata[i + 1 : i + 1 + n])
            i += 1 + n
        texts.append(b"".join(parts).decode("utf-8", "replace"))
    return rcode, texts


def _recv_exact(sock: socket.socket, n: int, deadline: float) -> bytes:
    buf = b""
    while len(buf) < n:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise OracleError("timed out")
        sock.settimeout(remaining)
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise OracleError("connection closed")
        buf += chunk
    return buf


def query_txt(name: str, server: str, port: int, timeout: float) -> tuple[str, list[str]]:
    """One TXT query over TCP: a blocking report carries a list URL or a regex
    and can outgrow a 512-byte UDP answer."""
    qid = secrets.randbelow(0x10000)
    query = build_query(name, qid)
    deadline = time.monotonic() + timeout
    try:
        with socket.create_connection((server, port), timeout=timeout) as sock:
            sock.sendall(struct.pack("!H", len(query)) + query)
            (length,) = struct.unpack("!H", _recv_exact(sock, 2, deadline))
            return parse_txt_response(_recv_exact(sock, length, deadline), qid)
    except OSError as exc:
        raise OracleError(str(exc)) from exc


# ── the oracle's answer ─────────────────────────────────────────────
def parse_report(text: str) -> dict[str, str]:
    """ "rcode=NoError; source=advanced-blocking-app; group=Base;
    blockListUrl=…; domain=…" → a dict. A regex (`regex=`) is always the last
    field and may itself contain "; ", so everything after it is taken whole."""
    fields: dict[str, str] = {}
    head, sep, regex = text.partition("; regex=")
    if not sep and text.startswith("regex="):
        head, regex, sep = "", text[len("regex=") :], "regex="
    for part in head.split("; "):
        key, eq, value = part.partition("=")
        if eq:
            fields[key.strip()] = value.strip()
    if sep:
        fields["regex"] = regex
    return fields


@dataclass(frozen=True)
class CheckResult:
    host: str
    blocked: bool  # blocked for this client at all
    show_page: bool  # …and by a policy that sends the device to the block page
    reason: str | None  # what the page says it was blocked by, if known


class BlockCheck:
    """Asks the oracle and turns its answer into what the portal shows."""

    def __init__(
        self, zone: str, list_names: dict[str, str], server: str = "127.0.0.1", port: int = 53, timeout_ms: int = 1500
    ):
        self.zone = zone
        self.list_names = list_names
        self.server = server
        self.port = port
        self.timeout = timeout_ms / 1000

    def check(self, host: str, client_ip: str) -> CheckResult:
        name = oracle_name(host, client_ip, self.zone)
        if name is None:
            raise OracleError("host too long to ask about")
        rcode, texts = query_txt(name, self.server, self.port, self.timeout)
        # The oracle answers every well-formed question NOERROR (empty when not
        # blocked). Anything else means it is not answering yet: the zone or
        # the app config is still being reconciled, or the probe failed.
        if rcode != "NoError":
            raise OracleError(f"oracle answered {rcode}")
        report = next((parse_report(t) for t in texts if "source=advanced-blocking-app" in t), None)
        if report is None:
            return CheckResult(host, blocked=False, show_page=False, reason=None)
        # NXDOMAIN policies are for devices that should fail fast and quietly
        # (docs/access-policies/block-page.md): blocked, but no page.
        show = report.get("rcode") != "NxDomain"
        return CheckResult(
            host, blocked=True, show_page=show, reason=self.list_names.get(report.get("blockListUrl", ""))
        )


# ── pages ───────────────────────────────────────────────────────────
def new_nonce() -> str:
    return secrets.token_urlsafe(18)


def page_csp(nonce: str) -> str:
    return (
        f"default-src 'none'; style-src 'nonce-{nonce}'; script-src 'nonce-{nonce}'; "
        "form-action 'self'; frame-ancestors 'none'; base-uri 'none'"
    )


def render_block_page(template: str, nonce: str, host: str, reason: str | None) -> str:
    """The block page template (modules/dns-technitium.nix renders it with the
    router's texts) with this response's placeholders filled."""
    details = f'<p class="reason">{html.escape(reason)}</p>' if reason else ""
    return (
        template.replace("@NONCE_ATTR@", f' nonce="{nonce}"')
        .replace("@HEAD_EXTRA@", f'<meta name="blocked-host" content="{html.escape(host)}">')
        .replace("@DETAILS@", details)
    )


_SIMPLE_PAGE = """<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="robots" content="noindex, nofollow">
<title>{title}</title>
<style nonce="{nonce}">
body {{ font-family: system-ui, -apple-system, sans-serif; color: #1b1f23; background: #f4f6f8; margin: 0; }}
main {{ max-width: 34rem; margin: 8vh auto; padding: 2.5rem; background: #fff; border-radius: 10px;
        box-shadow: 0 2px 12px rgba(0,0,0,.08); }}
h1 {{ margin: 0 0 .5rem; font-size: 1.5rem; }}
.domain {{ font-family: ui-monospace, monospace; background: #f0f2f4; padding: .15rem .45rem; border-radius: 4px; }}
p.note {{ color: #57606a; font-size: .9rem; }}
</style></head>
<body><main><h1>{heading}</h1>{body}</main></body></html>"""


def render_not_blocked(nonce: str, host: str) -> str:
    h = html.escape(host)
    return _SIMPLE_PAGE.format(
        title="Not blocked",
        heading="Not blocked",
        nonce=nonce,
        body=(
            f'<p><span class="domain">{h}</span> isn\'t blocked for this device.</p>'
            f'<p><a href="https://{h}/">Go to {h}</a></p>'
            '<p class="note">If your browser still shows a security warning there, the warning '
            "isn't coming from this router's filtering.</p>"
        ),
    )


def render_unavailable(nonce: str) -> str:
    return _SIMPLE_PAGE.format(
        title="Try again",
        heading="The router couldn't check this address",
        nonce=nonce,
        body="<p>It may still be starting up. Reload the page in a moment.</p>",
    )
