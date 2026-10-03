"""A FortiGateClient wired to an httpx MockTransport that records every request."""

import json

import httpx
import pytest

from fortigate_mcp import client as client_mod


class Recorder:
    def __init__(self) -> None:
        self.requests: list[httpx.Request] = []
        self.responses: dict[tuple[str, str], httpx.Response] = {}

    def respond(self, method: str, path: str, status: int = 200, payload=None, **kw) -> None:
        self.responses[(method, path)] = httpx.Response(status, json=payload or {"status": "success"}, **kw)

    def handler(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(request)
        return self.responses.get(
            (request.method, request.url.path), httpx.Response(200, json={"status": "success", "results": []})
        )

    def body(self, i: int = -1):
        return json.loads(self.requests[i].content or b"null")


@pytest.fixture
def fgt(monkeypatch):
    monkeypatch.setattr(client_mod, "FORTIGATE_HOST", "fgt.test")
    monkeypatch.setattr(client_mod, "FORTIGATE_API_TOKEN", "tok")
    monkeypatch.setattr(client_mod, "FORTIGATE_READ_ONLY", False)
    rec = Recorder()
    c = client_mod.FortiGateClient()
    c.client = httpx.AsyncClient(transport=httpx.MockTransport(rec.handler))
    return c, rec
