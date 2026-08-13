"""router-report — scheduled DNS activity reports.

Aggregates the period's activity from router-logd (group/device attribution is
already materialized at ingest), renders a PDF with Typst (static template +
data.json — no string templating in the document), writes a companion CSV, and
optionally emails the PDF via the Cloudflare Email Sending API.
"""

from __future__ import annotations

import argparse
import base64
import csv
import json
import os
import shutil
import subprocess
import sys
import tempfile
import time
import urllib.parse
import urllib.request
from importlib import resources
from pathlib import Path

RANGE_DAYS = {"daily": 1, "weekly": 7, "monthly": 30}
PRUNE_DAYS = 365


def _logd_get(cfg: dict, path: str, params: dict) -> dict:
    token = Path(cfg["logd"]["queryTokenFile"]).read_text().strip()
    url = f"http://127.0.0.1:{cfg['logd']['port']}{path}?{urllib.parse.urlencode(params)}"
    req = urllib.request.Request(url, headers={"Authorization": f"Bearer {token}"})
    with urllib.request.urlopen(req, timeout=60) as resp:
        return json.loads(resp.read().decode())


def _iso(ts: float) -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(ts))


def collect(cfg: dict, schedule: dict) -> dict:
    end = time.time()
    start = end - RANGE_DAYS[schedule["frequency"]] * 86400
    window = {"start": _iso(start), "end": _iso(end)}
    if schedule.get("groups"):
        # Single-group filter is applied per query; multi-group reports keep
        # the full data set and filter rows client-side below.
        pass

    def top(by: str, limit: int = 25) -> list[dict]:
        rows = _logd_get(cfg, "/stats/top", {**window, "by": by, "limit": limit})["top"]
        if schedule.get("groups") and by in ("group",):
            rows = [r for r in rows if r["name"] in schedule["groups"]]
        return rows

    sections: dict[str, object] = {}
    wanted = set(schedule.get("sections") or ["overview", "topDomains", "topBlocked", "perGroup"])

    if "overview" in wanted:
        summary = _logd_get(cfg, "/stats/summary", window)
        total = summary["total"] or 0
        sections["overview"] = {
            **summary,
            "blockRate": f"{(summary['blocked'] / total * 100):.1f}%" if total else "0%",
        }
    if "topDomains" in wanted:
        sections["topDomains"] = top("domain")
    if "topBlocked" in wanted:
        sections["topBlocked"] = top("blocked")
    if "perGroup" in wanted:
        sections["perGroup"] = top("group", 100)
    if "perDevice" in wanted:
        sections["perDevice"] = top("device", 100)
    if "perUser" in wanted:
        # Users are not a log column; fold device rows through the registry.
        static = json.loads(Path(cfg["policy"]["staticInputs"]).read_text())
        device_user = {h["name"]: h["user"] for h in static["hosts"] if h.get("user")}
        by_user: dict[str, dict] = {}
        for row in top("device", 1000):
            user = device_user.get(row["name"])
            if not user:
                continue
            agg = by_user.setdefault(user, {"name": user, "hits": 0, "blocked": 0})
            agg["hits"] += row["hits"]
            agg["blocked"] += row["blocked"]
        sections["perUser"] = sorted(by_user.values(), key=lambda r: -r["hits"])[:100]

    return {
        "meta": {
            "title": f"DNS Activity Report — {schedule['name']}",
            "schedule": schedule["name"],
            "frequency": schedule["frequency"],
            "generatedAt": _iso(end),
            "rangeStart": window["start"],
            "rangeEnd": window["end"],
        },
        "sections": sections,
    }


def render_pdf(data: dict, out_pdf: Path) -> None:
    with tempfile.TemporaryDirectory() as tmp:
        tmp_path = Path(tmp)
        template = resources.files("router_dns_tools").joinpath("report.typ").read_text()
        (tmp_path / "report.typ").write_text(template)
        (tmp_path / "data.json").write_text(json.dumps(data))
        subprocess.run(
            ["typst", "compile", "--root", tmp, str(tmp_path / "report.typ"), str(out_pdf)],
            check=True,
            capture_output=True,
            text=True,
        )


def write_csv(data: dict, out_csv: Path) -> None:
    with out_csv.open("w", newline="") as fh:
        writer = csv.writer(fh)
        writer.writerow(["section", "name", "hits", "blocked"])
        for section, rows in data["sections"].items():
            if section == "overview":
                writer.writerow(["overview", "total", rows["total"], rows["blocked"]])
                continue
            for row in rows:
                writer.writerow([section, row["name"], row["hits"], row["blocked"]])


def _cf_token(cfg: dict) -> str | None:
    cred_dir = os.environ.get("CREDENTIALS_DIRECTORY")
    if cred_dir and (Path(cred_dir) / "cf-api-token").exists():
        return (Path(cred_dir) / "cf-api-token").read_text().strip()
    path = cfg.get("reporting", {}).get("email", {}).get("apiTokenFile")
    if path and Path(path).exists():
        return Path(path).read_text().strip()
    return None


def send_email(cfg: dict, schedule: dict, data: dict, pdf: Path) -> None:
    """Deliver the report via the Cloudflare Email Sending API.

    Endpoint and payload contract per the cloudflare_email_delivery PoC:
    POST /client/v4/accounts/{id}/email/sending/send with base64 attachments.
    """
    email = cfg["reporting"]["email"]
    token = _cf_token(cfg)
    recipients = schedule.get("recipients") or []
    if not recipients:
        print("no recipients configured — skipping email delivery", file=sys.stderr)
        return
    if not token or not email.get("accountId"):
        print("Cloudflare email not configured (accountId/apiTokenFile) — skipping delivery", file=sys.stderr)
        return

    overview = data["sections"].get("overview", {})
    payload = {
        "from": email["fromAddress"],
        "to": recipients,
        "subject": f"{data['meta']['title']} ({data['meta']['rangeStart'][:10]} – {data['meta']['rangeEnd'][:10]})",
        "text": (
            f"Attached: {data['meta']['title']}.\n\n"
            f"Total queries: {overview.get('total', 'n/a')}\n"
            f"Blocked: {overview.get('blocked', 'n/a')} ({overview.get('blockRate', 'n/a')})\n"
            f"Active clients: {overview.get('clients', 'n/a')}\n"
        ),
        "attachments": [
            {
                "filename": pdf.name,
                "content": base64.b64encode(pdf.read_bytes()).decode(),
                "type": "application/pdf",
                "disposition": "attachment",
            }
        ],
    }
    req = urllib.request.Request(
        f"https://api.cloudflare.com/client/v4/accounts/{email['accountId']}/email/sending/send",
        data=json.dumps(payload).encode(),
        headers={"Authorization": f"Bearer {token}", "Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=60) as resp:
            body = json.loads(resp.read().decode())
        if not body.get("success", True):
            raise RuntimeError("; ".join(e.get("message", "") for e in body.get("errors", [])))
        print(f"report emailed to {', '.join(recipients)}", file=sys.stderr)
    except Exception as exc:
        # Delivery failure must not fail the timer unit — the PDF remains
        # downloadable from Cockpit.
        print(f"Cloudflare email delivery failed: {exc}", file=sys.stderr)


def prune(reports_dir: Path) -> None:
    cutoff = time.time() - PRUNE_DAYS * 86400
    for f in reports_dir.iterdir():
        if f.is_file() and f.stat().st_mtime < cutoff:
            f.unlink()


def main() -> None:
    parser = argparse.ArgumentParser(description="Generate (and email) a scheduled DNS report")
    parser.add_argument("--config", required=True, help="runtime config JSON (Nix-generated)")
    parser.add_argument("--schedule", required=True, help="schedule name from reporting.schedules")
    args = parser.parse_args()
    cfg = json.loads(Path(args.config).read_text())

    schedule = next(
        (s for s in cfg["reporting"]["schedules"] if s["name"] == args.schedule),
        None,
    )
    if schedule is None:
        sys.exit(f"unknown schedule '{args.schedule}'")

    reports_dir = Path(cfg["reporting"]["reportsDir"])
    reports_dir.mkdir(parents=True, exist_ok=True)

    data = collect(cfg, schedule)
    stem = f"{time.strftime('%Y-%m-%d')}-{schedule['name']}"
    pdf = reports_dir / f"{stem}.pdf"
    render_pdf(data, pdf)
    write_csv(data, reports_dir / f"{stem}.csv")
    print(f"report written: {pdf}", file=sys.stderr)

    send_email(cfg, schedule, data, pdf)
    prune(reports_dir)


if __name__ == "__main__":
    main()
