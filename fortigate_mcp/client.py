"""FortiOS REST API client with API-token and session (username/password) auth."""

from __future__ import annotations

import os
import sys
from typing import Any

import httpx
from dotenv import load_dotenv

# Load .env before reading the settings below; they are read once, at import time.
load_dotenv()

FORTIGATE_HOST = os.getenv("FORTIGATE_HOST", "")
FORTIGATE_PORT = os.getenv("FORTIGATE_PORT", "443")
FORTIGATE_API_TOKEN = os.getenv("FORTIGATE_API_TOKEN", "")
FORTIGATE_USERNAME = os.getenv("FORTIGATE_USERNAME", "")
FORTIGATE_PASSWORD = os.getenv("FORTIGATE_PASSWORD", "")
FORTIGATE_VDOM = os.getenv("FORTIGATE_VDOM", "root")
FORTIGATE_VERIFY_SSL = os.getenv("FORTIGATE_VERIFY_SSL", "false").lower() == "true"
FORTIGATE_READ_ONLY = os.getenv("FORTIGATE_READ_ONLY", "false").lower() == "true"
FORTIGATE_TIMEOUT = float(os.getenv("FORTIGATE_TIMEOUT", "30"))


def _validate_config() -> None:
    if not FORTIGATE_HOST:
        print("Error: FORTIGATE_HOST must be set", file=sys.stderr)
        sys.exit(1)
    if not FORTIGATE_API_TOKEN and not (FORTIGATE_USERNAME and FORTIGATE_PASSWORD):
        print(
            "Error: set FORTIGATE_API_TOKEN, or FORTIGATE_USERNAME + FORTIGATE_PASSWORD",
            file=sys.stderr,
        )
        sys.exit(1)


class FortiGateAPIError(Exception):
    """A non-2xx FortiOS response, keeping the details FortiOS sends back.

    FortiOS explains most failures in the JSON body (``cli_error``, ``error``),
    so the message includes them instead of only the HTTP status.
    """

    def __init__(self, method: str, path: str, status: int, body: Any) -> None:
        self.method = method
        self.path = path
        self.status = status
        self.body = body
        detail = ""
        if isinstance(body, dict):
            parts = []
            if body.get("cli_error"):
                cli = body["cli_error"]
                parts.append("; ".join(cli) if isinstance(cli, list) else str(cli))
            if body.get("error") not in (None, 0):
                parts.append(f"error={body['error']}")
            for key in ("status_message", "error_message", "forticare_error_message"):
                if body.get(key):
                    parts.append(str(body[key]))
            detail = " | ".join(p for p in parts if p)
        elif body:
            detail = str(body)[:300]
        super().__init__(f"{method} {path} -> HTTP {status}" + (f": {detail}" if detail else ""))


class FortiGateClient:
    def __init__(self) -> None:
        self.base_url = f"https://{FORTIGATE_HOST}:{FORTIGATE_PORT}"
        self.client = httpx.AsyncClient(verify=FORTIGATE_VERIFY_SSL, timeout=FORTIGATE_TIMEOUT)
        self.csrf_token: str | None = None
        self.session_auth = False

    async def authenticate(self) -> None:
        if FORTIGATE_API_TOKEN:
            print("✓ API token auth", file=sys.stderr)
            return
        await self._session_login()
        print(f"✓ Session auth: {FORTIGATE_USERNAME}", file=sys.stderr)

    async def _session_login(self) -> None:
        # FortiOS 7.6 removed form-based /logincheck; the GUI logs in with JSON here.
        response = await self.client.post(
            f"{self.base_url}/api/v2/authentication",
            json={"username": FORTIGATE_USERNAME, "password": FORTIGATE_PASSWORD},
        )
        body = _json(response)
        if not isinstance(body, dict) or body.get("status_message") != "LOGIN_SUCCESS":
            raise FortiGateAPIError("POST", "/api/v2/authentication", response.status_code, body)
        # The CSRF cookie is named ccsrf_token_<port>_<hash> on 7.6 (ccsrftoken on older builds).
        self.csrf_token = next(
            (v for k, v in self.client.cookies.items() if k.startswith(("ccsrf_token", "ccsrftoken"))),
            None,
        )
        if self.csrf_token:
            self.csrf_token = self.csrf_token.strip('"')
        self.session_auth = True

    def _headers(self, method: str) -> dict[str, str]:
        headers: dict[str, str] = {}
        if FORTIGATE_API_TOKEN:
            headers["Authorization"] = f"Bearer {FORTIGATE_API_TOKEN}"
        elif self.csrf_token and method != "GET":
            headers["X-CSRFTOKEN"] = self.csrf_token
        return headers

    async def request(
        self,
        method: str,
        path: str,
        params: dict[str, Any] | None = None,
        body: Any | None = None,
        vdom: str | None = None,
        read_only_safe: bool = False,
    ) -> Any:
        # read_only_safe marks the few POST endpoints that only read (e.g. config backup).
        if FORTIGATE_READ_ONLY and method != "GET" and not read_only_safe:
            raise PermissionError(f"Read-only mode (FORTIGATE_READ_ONLY): refusing {method} {path}")
        query = {k: v for k, v in (params or {}).items() if v is not None}
        query.setdefault("vdom", vdom or FORTIGATE_VDOM)
        url = f"{self.base_url}{path}"

        response = await self._send(method, url, query, body)
        if response.status_code == 401 and self.session_auth:
            # Session expired (FortiOS idle timeout): log in again once and retry.
            await self._session_login()
            response = await self._send(method, url, query, body)

        data = _json(response)
        if response.status_code >= 400:
            raise FortiGateAPIError(method, path, response.status_code, data)
        return data

    async def _send(
        self, method: str, url: str, query: dict[str, Any], body: Any | None
    ) -> httpx.Response:
        return await self.client.request(
            method, url, params=query, json=body, headers=self._headers(method)
        )

    async def get(self, path: str, params: dict[str, Any] | None = None) -> Any:
        return await self.request("GET", path, params)

    async def post(
        self, path: str, body: Any | None = None, params: dict[str, Any] | None = None
    ) -> Any:
        return await self.request("POST", path, params, body)

    async def put(
        self, path: str, body: Any | None = None, params: dict[str, Any] | None = None
    ) -> Any:
        return await self.request("PUT", path, params, body)

    async def delete(self, path: str, params: dict[str, Any] | None = None) -> Any:
        return await self.request("DELETE", path, params)

    async def close(self) -> None:
        if self.session_auth:
            try:
                await self.client.delete(
                    f"{self.base_url}/api/v2/authentication", headers=self._headers("DELETE")
                )
            except httpx.HTTPError:
                pass
        await self.client.aclose()


def _json(response: httpx.Response) -> Any:
    try:
        return response.json()
    except ValueError:
        return response.text
