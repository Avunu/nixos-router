"""Microsoft Entra ID (Azure AD) provider via Microsoft Graph.

Requires an app registration with application permissions User.Read.All and
GroupMember.Read.All (admin-consented), authenticating with client credentials.
"""

from __future__ import annotations

import json
import urllib.parse
import urllib.request

GRAPH = "https://graph.microsoft.com/v1.0"


def _token(cfg: dict, client_secret: str) -> str:
    body = urllib.parse.urlencode(
        {
            "client_id": cfg["clientId"],
            "client_secret": client_secret,
            "scope": "https://graph.microsoft.com/.default",
            "grant_type": "client_credentials",
        }
    ).encode()
    req = urllib.request.Request(
        f"https://login.microsoftonline.com/{cfg['tenantId']}/oauth2/v2.0/token",
        data=body,
        headers={"Content-Type": "application/x-www-form-urlencoded"},
    )
    with urllib.request.urlopen(req, timeout=60) as resp:
        return json.loads(resp.read().decode())["access_token"]


def _paged(url: str, token: str):
    while url:
        req = urllib.request.Request(url, headers={"Authorization": f"Bearer {token}"})
        with urllib.request.urlopen(req, timeout=60) as resp:
            page = json.loads(resp.read().decode())
        yield from page.get("value", [])
        url = page.get("@odata.nextLink")


def fetch(cfg: dict, client_secret: str | None) -> tuple[list[dict], list[dict]]:
    if not client_secret:
        raise RuntimeError("entra: clientSecretFile is missing or unreadable")
    token = _token(cfg, client_secret)

    groups = [
        {"id": g["id"], "name": g.get("displayName") or g["id"]}
        for g in _paged(f"{GRAPH}/groups?$select=id,displayName&$top=999", token)
    ]

    membership: dict[str, list[str]] = {}
    for group in groups:
        for member in _paged(
            f"{GRAPH}/groups/{group['id']}/members?$select=id&$top=999",
            token,
        ):
            membership.setdefault(member["id"], []).append(group["id"])

    users = [
        {
            "id": u["id"],
            "name": u.get("displayName") or "",
            "email": (u.get("mail") or u.get("userPrincipalName") or "").lower(),
            "groups": membership.get(u["id"], []),
        }
        for u in _paged(
            f"{GRAPH}/users?$select=id,displayName,mail,userPrincipalName&$top=999",
            token,
        )
    ]
    return users, groups
