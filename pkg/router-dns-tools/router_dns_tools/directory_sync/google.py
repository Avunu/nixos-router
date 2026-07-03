"""Google Workspace provider via the Admin SDK Directory API.

Requires a service account with domain-wide delegation impersonating a
Workspace admin (cfg.adminEmail), with the readonly directory scopes granted.
"""

from __future__ import annotations

import json

SCOPES = [
    "https://www.googleapis.com/auth/admin.directory.user.readonly",
    "https://www.googleapis.com/auth/admin.directory.group.readonly",
]


def fetch(cfg: dict, service_account_key: str | None) -> tuple[list[dict], list[dict]]:
    if not service_account_key:
        raise RuntimeError("google: serviceAccountKeyFile is missing or unreadable")

    from google.oauth2 import service_account
    from googleapiclient.discovery import build

    credentials = service_account.Credentials.from_service_account_info(
        json.loads(service_account_key), scopes=SCOPES
    ).with_subject(cfg["adminEmail"])
    directory = build("admin", "directory_v1", credentials=credentials, cache_discovery=False)

    def paged(request_fn, key: str, **kwargs):
        token = None
        while True:
            resp = request_fn(pageToken=token, **kwargs).execute()
            yield from resp.get(key, [])
            token = resp.get("nextPageToken")
            if not token:
                return

    groups = [
        {"id": g["id"], "name": g.get("name") or g.get("email") or g["id"]}
        for g in paged(directory.groups().list, "groups", domain=cfg["domain"], maxResults=200)
    ]

    membership: dict[str, list[str]] = {}
    for group in groups:
        for member in paged(directory.members().list, "members", groupKey=group["id"], maxResults=200):
            if member.get("type") == "USER":
                membership.setdefault(member["id"], []).append(group["id"])

    users = [
        {
            "id": u["id"],
            "name": (u.get("name") or {}).get("fullName") or "",
            "email": (u.get("primaryEmail") or "").lower(),
            "groups": membership.get(u["id"], []),
        }
        for u in paged(
            directory.users().list,
            "users",
            domain=cfg["domain"],
            maxResults=200,
            projection="basic",
        )
    ]
    return users, groups
