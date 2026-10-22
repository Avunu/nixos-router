"""Unit tests for router_dns_tools.portal: the HTTPS portal's block check.

The wire format and the oracle's answers are exercised against a fake DNS
server on loopback, so the TCP path runs for real. The technitium-vm test
covers the portal end to end against the real oracle."""

import socket
import struct
import threading
import unittest

from router_dns_tools import portal


def txt_rdata(text: str) -> bytes:
    raw = text.encode()
    chunks = [raw[i : i + 255] for i in range(0, len(raw), 255)] or [b""]
    return b"".join(bytes([len(c)]) + c for c in chunks)


def answer(query: bytes, rcode: int = 0, texts: tuple[str, ...] = ()) -> bytes:
    """A response to `query`: its question echoed, each TXT answer's owner a
    compression pointer to it (offset 12), the way real servers write it."""
    qid = struct.unpack("!H", query[:2])[0]
    question = query[12:]
    header = struct.pack("!HHHHHH", qid, 0x8180 | rcode, 1, len(texts), 0, 0)
    records = b""
    for text in texts:
        rdata = txt_rdata(text)
        records += b"\xc0\x0c" + struct.pack("!HHIH", portal.TXT, 1, 0, len(rdata)) + rdata
    return header + question + records


class FakeDns:
    """Answers each TCP query with respond(query, qname); None hangs up."""

    def __init__(self, respond):
        self.respond = respond
        self.queries: list[str] = []
        self.sock = socket.socket()
        self.sock.bind(("127.0.0.1", 0))
        self.sock.listen()
        self.port = self.sock.getsockname()[1]
        threading.Thread(target=self._serve, daemon=True).start()

    @staticmethod
    def qname(query: bytes) -> str:
        labels, off = [], 12
        while query[off]:
            n = query[off]
            labels.append(query[off + 1 : off + 1 + n].decode())
            off += 1 + n
        return ".".join(labels)

    def _serve(self):
        while True:
            try:
                conn, _ = self.sock.accept()
            except OSError:
                return
            with conn:
                (length,) = struct.unpack("!H", conn.recv(2))
                query = conn.recv(length)
                self.queries.append(self.qname(query))
                reply = self.respond(query, self.qname(query))
                if reply is None:
                    continue
                conn.sendall(struct.pack("!H", len(reply)) + reply)

    def close(self):
        self.sock.close()


REPORT = "source=advanced-blocking-app; group=Base; blockListUrl=https://lists.example/ads.txt; domain=ads.example.com"


class HostTests(unittest.TestCase):
    def test_normalizes(self):
        self.assertEqual(portal.normalize_host("Ads.Example.COM."), "ads.example.com")
        self.assertEqual(portal.normalize_host(" _dmarc.example.com "), "_dmarc.example.com")
        self.assertEqual(portal.normalize_host("xn--bcher-kva.example"), "xn--bcher-kva.example")

    def test_rejects(self):
        for bad in (
            "",
            None,
            "localhost",
            "10.0.0.1",
            "a..b",
            "-a.com",
            "a-.com",
            "a b.com",
            "a.com/x",
            "x" * 64 + ".com",
        ):
            with self.subTest(bad=bad):
                self.assertIsNone(portal.normalize_host(bad))

    def test_rejects_overlong(self):
        self.assertIsNone(portal.normalize_host(".".join(["a" * 60] * 5)))


class OracleNameTests(unittest.TestCase):
    def test_labels(self):
        self.assertEqual(portal.client_label("10.48.4.50"), "10-48-4-50")
        self.assertEqual(portal.client_label("fd00::1"), "fd00--1")
        self.assertEqual(portal.client_label("::ffff:10.0.0.1"), "10-0-0-1")

    def test_name(self):
        self.assertEqual(
            portal.oracle_name("ads.example.com", "10.48.4.50", "blockcheck.nixos-router.internal."),
            "ads.example.com.10-48-4-50.blockcheck.nixos-router.internal",
        )

    def test_too_long(self):
        host = ".".join(["a" * 60] * 4)  # 243 characters: fine alone, too long with the suffix
        self.assertIsNotNone(portal.normalize_host(host))
        self.assertIsNone(portal.oracle_name(host, "10.48.4.50", "blockcheck.nixos-router.internal"))


class WireTests(unittest.TestCase):
    def test_round_trip_joins_character_strings(self):
        long_text = "rcode=NoError; " + REPORT + "; " + "x" * 400
        query = portal.build_query("a.example.com", 0x1234)
        rcode, texts = portal.parse_txt_response(answer(query, texts=(long_text,)), 0x1234)
        self.assertEqual(rcode, "NoError")
        self.assertEqual(texts, [long_text])

    def test_wrong_id(self):
        query = portal.build_query("a.example.com", 1)
        with self.assertRaises(portal.OracleError):
            portal.parse_txt_response(answer(query), 2)

    def test_truncated(self):
        query = portal.build_query("a.example.com", 7)
        with self.assertRaises(portal.OracleError):
            portal.parse_txt_response(answer(query, texts=("abc",))[:-2], 7)


class ReportTests(unittest.TestCase):
    def test_fields(self):
        fields = portal.parse_report("rcode=NoError; " + REPORT)
        self.assertEqual(fields["rcode"], "NoError")
        self.assertEqual(fields["group"], "Base")
        self.assertEqual(fields["blockListUrl"], "https://lists.example/ads.txt")
        self.assertEqual(fields["domain"], "ads.example.com")

    def test_regex_taken_whole(self):
        fields = portal.parse_report("rcode=NxDomain; source=advanced-blocking-app; group=Kids; regex=(^|\\.)a; b=c$")
        self.assertEqual(fields["regex"], "(^|\\.)a; b=c$")
        self.assertEqual(fields["rcode"], "NxDomain")


class BlockCheckTests(unittest.TestCase):
    zone = "blockcheck.nixos-router.internal"

    def check(self, respond, host="ads.example.com", timeout_ms=1500):
        dns = FakeDns(respond)
        self.addCleanup(dns.close)
        bc = portal.BlockCheck(
            self.zone, {"https://lists.example/ads.txt": "List: Ads"}, port=dns.port, timeout_ms=timeout_ms
        )
        return bc.check(host, "10.48.4.50"), dns

    def test_blocked(self):
        result, dns = self.check(lambda q, _: answer(q, texts=("rcode=NoError; " + REPORT,)))
        self.assertEqual(dns.queries, [f"ads.example.com.10-48-4-50.{self.zone}"])
        self.assertTrue(result.blocked)
        self.assertTrue(result.show_page)
        self.assertEqual(result.reason, "List: Ads")

    def test_nxdomain_policy_gets_no_page(self):
        result, _ = self.check(lambda q, _: answer(q, texts=("rcode=NxDomain; " + REPORT,)))
        self.assertTrue(result.blocked)
        self.assertFalse(result.show_page)

    def test_unknown_list_has_no_reason(self):
        report = "rcode=NoError; source=advanced-blocking-app; group=Base; domain=ads.example.com"
        result, _ = self.check(lambda q, _: answer(q, texts=(report,)))
        self.assertTrue(result.show_page)
        self.assertIsNone(result.reason)

    def test_not_blocked(self):
        result, _ = self.check(lambda q, _: answer(q))
        self.assertFalse(result.blocked)
        self.assertFalse(result.show_page)

    def test_refused_is_an_error(self):
        with self.assertRaises(portal.OracleError):
            self.check(lambda q, _: answer(q, rcode=5))

    def test_nxdomain_answer_is_an_error(self):
        # The oracle answers every good question NOERROR; NXDOMAIN means the
        # zone exists but the app is not answering yet.
        with self.assertRaises(portal.OracleError):
            self.check(lambda q, _: answer(q, rcode=3))

    def test_hang_up_is_an_error(self):
        with self.assertRaises(portal.OracleError):
            self.check(lambda q, _: None)

    def test_no_server_is_an_error(self):
        sock = socket.socket()
        sock.bind(("127.0.0.1", 0))
        port = sock.getsockname()[1]
        sock.close()
        bc = portal.BlockCheck(self.zone, {}, port=port, timeout_ms=500)
        with self.assertRaises(portal.OracleError):
            bc.check("ads.example.com", "10.48.4.50")


class PageTests(unittest.TestCase):
    template = "<head>@HEAD_EXTRA@<style@NONCE_ATTR@></style></head><body>@DETAILS@<script@NONCE_ATTR@></script></body>"

    def test_block_page(self):
        page = portal.render_block_page(self.template, "N0nce", "ads.example.com", "Category: ads & <trackers>")
        self.assertIn('<meta name="blocked-host" content="ads.example.com">', page)
        self.assertEqual(page.count(' nonce="N0nce"'), 2)
        self.assertIn('<p class="reason">Category: ads &amp; &lt;trackers&gt;</p>', page)
        self.assertNotIn("@", page)

    def test_block_page_without_reason(self):
        page = portal.render_block_page(self.template, "n", "ads.example.com", None)
        self.assertNotIn("reason", page)

    def test_csp_carries_nonce(self):
        csp = portal.page_csp("abc")
        self.assertIn("script-src 'nonce-abc'", csp)
        self.assertIn("frame-ancestors 'none'", csp)

    def test_simple_pages(self):
        page = portal.render_not_blocked("n", "ok.example.com")
        self.assertIn('href="https://ok.example.com/"', page)
        self.assertIn('<style nonce="n">', page)
        self.assertIn('<style nonce="n">', portal.render_unavailable("n"))


if __name__ == "__main__":
    unittest.main()
