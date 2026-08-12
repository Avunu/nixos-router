"""Minimal Technitium DNS Server HTTP API client.

Used by the reconcile and policy-push services. Every call returns the
`response` object from Technitium's `{status, response|errorMessage}`
envelope and raises TechnitiumError on non-ok status.
"""

from __future__ import annotations

import time
import urllib.error
import urllib.parse
import urllib.request


class TechnitiumError(RuntimeError):
    pass


class TechnitiumClient:
    def __init__(self, base_url: str, token: str | None = None, timeout: int = 30):
        self.base_url = base_url.rstrip("/")
        self.token = token
        self.timeout = timeout

    # ── transport ────────────────────────────────────────────
    def _call(self, path: str, params: dict | None = None, post: bool = False) -> dict:
        params = {k: v for k, v in (params or {}).items() if v is not None}
        query = urllib.parse.urlencode(params)
        url = f"{self.base_url}{path}"
        headers = {}
        if self.token:
            headers["Authorization"] = f"Bearer {self.token}"
        if post:
            req = urllib.request.Request(
                url,
                data=query.encode(),
                headers={**headers, "Content-Type": "application/x-www-form-urlencoded"},
                method="POST",
            )
        else:
            req = urllib.request.Request(f"{url}?{query}" if query else url, headers=headers)
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                import json

                body = json.loads(resp.read().decode())
        except urllib.error.URLError as exc:
            raise TechnitiumError(f"{path}: {exc}") from exc
        status = body.get("status")
        if status != "ok":
            raise TechnitiumError(f"{path}: {status}: {body.get('errorMessage', 'unknown error')}")
        return body.get("response", body)

    def wait_ready(self, timeout_s: int = 120) -> None:
        """Wait until the web service answers (any response counts)."""
        deadline = time.monotonic() + timeout_s
        while True:
            try:
                urllib.request.urlopen(f"{self.base_url}/api/user/login", timeout=5).read()
                return
            except urllib.error.HTTPError:
                return  # got an HTTP answer — service is up
            except OSError:
                if time.monotonic() > deadline:
                    raise TechnitiumError("timed out waiting for Technitium web service")
                time.sleep(2)

    # ── auth ─────────────────────────────────────────────────
    def login(self, user: str, password: str) -> str:
        resp = self._call("/api/user/login", {"user": user, "pass": password})
        self.token = resp.get("token") or resp["token"]
        return self.token

    def change_password(self, current_password: str, new_password: str) -> None:
        self._call(
            "/api/user/changePassword",
            {"pass": current_password, "newPass": new_password},
            post=True,
        )

    def create_api_token(self, user: str, password: str, token_name: str) -> str:
        resp = self._call(
            "/api/user/createToken",
            {"user": user, "pass": password, "tokenName": token_name},
        )
        return resp["token"]

    # ── settings / zones / apps ──────────────────────────────
    def get_settings(self) -> dict:
        return self._call("/api/settings/get")

    def set_settings(self, settings: dict) -> dict:
        return self._call("/api/settings/set", settings, post=True)

    def list_zones(self) -> list[dict]:
        return self._call("/api/zones/list").get("zones", [])

    def create_zone(self, zone: str, zone_type: str = "Primary") -> None:
        self._call("/api/zones/create", {"zone": zone, "type": zone_type})

    def delete_zone(self, zone: str) -> None:
        self._call("/api/zones/delete", {"zone": zone})

    def get_records(self, domain: str, zone: str) -> list[dict]:
        resp = self._call("/api/zones/records/get", {"domain": domain, "zone": zone, "listZone": "true"})
        return resp.get("records", [])

    def add_record(self, zone: str, domain: str, rtype: str, ttl: int = 3600, **rdata) -> None:
        self._call(
            "/api/zones/records/add",
            {"domain": domain, "zone": zone, "type": rtype, "ttl": ttl, "overwrite": "true", **rdata},
        )

    def get_app_config(self, name: str) -> str | None:
        resp = self._call("/api/apps/config/get", {"name": name})
        return resp.get("config")

    def set_app_config(self, name: str, config: str) -> None:
        self._call("/api/apps/config/set", {"name": name, "config": config}, post=True)

    def list_apps(self) -> list[dict]:
        return self._call("/api/apps/list").get("apps", [])

    # ── admin (users / groups / permissions) ─────────────────
    def list_users(self) -> list[dict]:
        return self._call("/api/admin/users/list").get("users", [])

    def create_user(self, user: str, password: str, display_name: str | None = None) -> None:
        self._call(
            "/api/admin/users/create",
            {"user": user, "pass": password, "displayName": display_name or user},
        )

    def set_user_password(self, user: str, password: str) -> None:
        self._call("/api/admin/users/set", {"user": user, "newPass": password})

    def list_groups(self) -> list[dict]:
        return self._call("/api/admin/groups/list").get("groups", [])

    def create_group(self, group: str, description: str = "") -> None:
        self._call("/api/admin/groups/create", {"group": group, "description": description})

    def set_user_groups(self, user: str, groups: list[str]) -> None:
        self._call("/api/admin/users/set", {"user": user, "memberOfGroups": ",".join(groups)})

    def get_permission(self, section: str) -> dict:
        return self._call(
            "/api/admin/permissions/get",
            {"section": section, "includeUsersAndGroups": "true"},
        )

    def grant_user_view(self, section: str, user: str) -> None:
        """Grant view-only access on a section to a user, preserving existing rows.

        permissions/set overwrites the whole table, so read-modify-write.
        """
        current = self.get_permission(section)
        user_rows = [
            (u["username"], u["canView"], u["canModify"], u["canDelete"])
            for u in current.get("userPermissions", [])
            if u["username"] != user
        ] + [(user, True, False, False)]
        group_rows = [
            (g["name"], g["canView"], g["canModify"], g["canDelete"])
            for g in current.get("groupPermissions", [])
        ]
        fmt = lambda rows: "|".join(
            "|".join([name] + [str(b).lower() for b in flags]) for name, *flags in rows
        )
        self._call(
            "/api/admin/permissions/set",
            {
                "section": section,
                "userPermissions": fmt(user_rows),
                "groupPermissions": fmt(group_rows),
            },
            post=True,
        )

    def list_sessions(self, user: str | None = None) -> list[dict]:
        return self._call("/api/admin/sessions/list").get("sessions", [])

    def delete_session(self, partial_token: str) -> None:
        self._call("/api/admin/sessions/delete", {"partialToken": partial_token})
