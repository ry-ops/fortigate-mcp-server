"""Client behaviour: read-only mode, auth headers, VDOM, error details, session login."""

import httpx
import pytest

from fortigate_mcp import client as client_mod
from fortigate_mcp.client import FortiGateAPIError


@pytest.mark.parametrize("method", ["POST", "PUT", "DELETE"])
async def test_read_only_blocks_writes(monkeypatch, fgt, method):
    c, rec = fgt
    monkeypatch.setattr(client_mod, "FORTIGATE_READ_ONLY", True)
    with pytest.raises(PermissionError, match="Read-only mode"):
        await c.request(method, "/api/v2/cmdb/firewall/policy/1")
    assert rec.requests == []


async def test_read_only_allows_get(monkeypatch, fgt):
    c, rec = fgt
    monkeypatch.setattr(client_mod, "FORTIGATE_READ_ONLY", True)
    await c.get("/api/v2/cmdb/firewall/policy")
    assert [r.method for r in rec.requests] == ["GET"]


async def test_token_header_and_default_vdom(fgt):
    c, rec = fgt
    await c.get("/api/v2/monitor/system/status")
    req = rec.requests[0]
    assert req.headers["Authorization"] == "Bearer tok"
    assert req.url.params["vdom"] == "root"


async def test_explicit_vdom_and_none_params_dropped(fgt):
    c, rec = fgt
    await c.get("/api/v2/cmdb/firewall/address", {"vdom": "lab", "filter": None})
    params = rec.requests[0].url.params
    assert params["vdom"] == "lab"
    assert "filter" not in params


async def test_error_includes_fortios_cli_error(fgt):
    c, rec = fgt
    rec.respond(
        "POST", "/api/v2/cmdb/system/dns-database", 500,
        {"status": "error", "error": -651, "cli_error": ["hostname is not a valid dns name."]},
    )
    with pytest.raises(FortiGateAPIError) as exc:
        await c.post("/api/v2/cmdb/system/dns-database", {"name": "lab"})
    assert exc.value.status == 500
    assert "hostname is not a valid dns name" in str(exc.value)
    assert "error=-651" in str(exc.value)


async def test_session_login_uses_json_auth_and_csrf_cookie(monkeypatch):
    monkeypatch.setattr(client_mod, "FORTIGATE_HOST", "fgt.test")
    monkeypatch.setattr(client_mod, "FORTIGATE_API_TOKEN", "")
    monkeypatch.setattr(client_mod, "FORTIGATE_USERNAME", "admin")
    monkeypatch.setattr(client_mod, "FORTIGATE_PASSWORD", "pw")
    monkeypatch.setattr(client_mod, "FORTIGATE_READ_ONLY", False)
    seen: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        if request.url.path == "/api/v2/authentication" and request.method == "POST":
            return httpx.Response(
                200,
                json={"status": 6, "status_message": "LOGIN_SUCCESS"},
                headers={"set-cookie": 'ccsrf_token_443_abc="CSRF123"; path=/'},
            )
        return httpx.Response(200, json={"status": "success"})

    c = client_mod.FortiGateClient()
    c.client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    await c.authenticate()
    await c.put("/api/v2/cmdb/firewall/policy/1", {"status": "disable"})
    assert seen[0].url.path == "/api/v2/authentication"
    assert seen[1].headers["X-CSRFTOKEN"] == "CSRF123"
    assert "Authorization" not in seen[1].headers


async def test_session_login_failure_raises(monkeypatch):
    monkeypatch.setattr(client_mod, "FORTIGATE_HOST", "fgt.test")
    monkeypatch.setattr(client_mod, "FORTIGATE_API_TOKEN", "")
    monkeypatch.setattr(client_mod, "FORTIGATE_USERNAME", "admin")
    monkeypatch.setattr(client_mod, "FORTIGATE_PASSWORD", "wrong")
    c = client_mod.FortiGateClient()
    c.client = httpx.AsyncClient(
        transport=httpx.MockTransport(
            lambda r: httpx.Response(200, json={"status": -1, "status_message": "LOGIN_FAILED"})
        )
    )
    with pytest.raises(FortiGateAPIError, match="LOGIN_FAILED"):
        await c.authenticate()


@pytest.mark.parametrize(
    "value, expected",
    [(None, True), ("", True), ("true", True), ("1", True), ("false", False), ("FALSE", False),
     ("0", False), ("off", False), ("/etc/fgt-ca.pem", "/etc/fgt-ca.pem")],
)
def test_tls_verify_defaults_on(monkeypatch, value, expected):
    if value is None:
        monkeypatch.delenv("X_VERIFY_SSL", raising=False)
    else:
        monkeypatch.setenv("X_VERIFY_SSL", value)
    assert client_mod.tls_verify("X_VERIFY_SSL") == expected


def test_ssl_verify_warns_when_off(capsys):
    assert client_mod.ssl_verify(False, "X_VERIFY_SSL") is False
    assert "X_VERIFY_SSL=false" in capsys.readouterr().err
    assert client_mod.ssl_verify(True, "X_VERIFY_SSL") is True
    assert capsys.readouterr().err == ""


def test_ssl_verify_ca_bundle(tmp_path):
    import certifi

    ctx = client_mod.ssl_verify(certifi.where(), "X_VERIFY_SSL")
    assert ctx.verify_mode.name == "CERT_REQUIRED" and ctx.check_hostname
    with pytest.raises(ValueError, match="CA bundle not found"):
        client_mod.ssl_verify(str(tmp_path / "missing.pem"), "X_VERIFY_SSL")
