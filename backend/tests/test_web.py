import json
import socket
from unittest.mock import Mock

import pytest
from app.web import transport, api
from app.web.checks import inspect
from app.web.transport import Page, TargetError, normalize_url, public_addresses


def page(headers=None, body=b"", status=200, url="https://example.com/"):
    return Page(url, status, headers or [("Content-Type", "text/html")], body, False, [], [])


@pytest.fixture(autouse=True)
def clear_limits():
    api.recent.clear()
    yield
    api.recent.clear()


@pytest.mark.parametrize(
    "url",
    [
        "file:///etc/passwd",
        "https://user:pass@example.com",
        "https://example.com:8000",
        "https://example.com\\@localhost",
        "https://example.com/\n",
        "https://[fe80::1%25eth0]/",
    ],
)
def test_reject_unsafe_url(url):
    with pytest.raises(TargetError):
        normalize_url(url)


def test_url_strips_tokens_and_encodes_path():
    assert normalize_url("https://Example.com/é?q=secret#token").url == "https://example.com/%C3%A9"


@pytest.mark.parametrize(
    "address", ["127.0.0.1", "10.0.0.1", "169.254.169.254", "::1", "::ffff:127.0.0.1", "224.0.0.1", "2002:0808:0808::"]
)
def test_private_and_transition_dns_blocked(monkeypatch, address):
    monkeypatch.setattr(socket, "getaddrinfo", lambda *a, **k: [(0, 0, 0, "", (address, 443))])
    with pytest.raises(TargetError):
        public_addresses(normalize_url("https://example.com"))


def test_mixed_dns_blocked(monkeypatch):
    monkeypatch.setattr(
        socket, "getaddrinfo", lambda *a, **k: [(0, 0, 0, "", (v, 443)) for v in ("8.8.8.8", "10.0.0.1")]
    )
    with pytest.raises(TargetError):
        public_addresses(normalize_url("https://example.com"))


def test_connect_pins_ip_and_checks_original_hostname(monkeypatch):
    sock = Mock()
    context = Mock()
    context.wrap_socket.return_value = sock
    monkeypatch.setattr(socket, "socket", lambda *a: sock)
    monkeypatch.setattr(transport.ssl, "create_default_context", lambda: context)
    conn = transport.PinnedConnection(normalize_url("https://example.com"), "8.8.8.8", 1)
    conn.connect()
    sock.connect.assert_called_once_with(("8.8.8.8", 443))
    context.wrap_socket.assert_called_once_with(sock, server_hostname="example.com")


def test_findings_do_not_retain_secrets():
    report = inspect(
        page(
            [("Content-Type", "text/html"), ("Set-Cookie", "session=SECRET_VALUE; Path=/")],
            b'<script src="http://example.net/a"></script>-----BEGIN PRIVATE KEY-----SECRET_KEY',
        )
    )
    text = json.dumps(report)
    assert "SECRET_VALUE" not in text and "SECRET_KEY" not in text
    assert report["summary"]["high"] == 1
    assert report["cookies"][0]["name"] == "session"
    assert any(f["id"] == "mixed-content" for f in report["findings"])
    assert all(f["location"] and f["recommendation"] and f["verification"] for f in report["findings"])


def test_controls_and_applicability():
    headers = [
        ("Content-Type", "text/html"),
        ("Strict-Transport-Security", "max-age=31536000"),
        ("Content-Security-Policy", "default-src 'self'; frame-ancestors 'none'"),
        ("X-Content-Type-Options", "nosniff"),
        ("Referrer-Policy", "strict-origin"),
        ("Set-Cookie", "session=SECRET; Secure; HttpOnly; SameSite=Lax"),
    ]
    assert inspect(page(headers))["findings"] == []
    report = inspect(page([("Content-Type", "application/json")]))
    assert not any(f["id"] in ("csp", "framing", "referrer") for f in report["findings"])
    assert not any(f["id"] in ("csp", "framing", "hsts") for f in inspect(page(status=302))["findings"])


def test_cross_host_redirect_not_fetched(monkeypatch):
    response = Mock(status=302)
    response.getheaders.return_value = [("Location", "https://other.example/path?secret=1")]
    response.getheader.return_value = "https://other.example/path?secret=1"
    response.read1.return_value = b""
    connection = Mock(sock=None)
    connection.getresponse.return_value = response
    monkeypatch.setattr(transport, "public_addresses", lambda *a: ["8.8.8.8"])
    factory = Mock(return_value=connection)
    monkeypatch.setattr(transport, "PinnedConnection", factory)
    result = transport.fetch_page("https://example.com")
    assert factory.call_count == 1
    assert result.redirects[0]["followed"] is False
    assert result.redirects[0]["to"] == "https://other.example/path"


def test_api_persists_report_and_requires_authorization(client, monkeypatch):
    monkeypatch.setattr(api, "fetch_page", lambda value: page())
    assert (
        client.post("/api/web/assessments", json={"url": "https://example.com", "authorized": False}).status_code == 422
    )
    result = client.post("/api/web/assessments", json={"url": "https://example.com", "authorized": True})
    assert result.status_code == 201
    report = result.json()
    assert client.get("/api/web/assessments/" + report["id"]).json() == report
    assert client.get("/api/web/assessments").json()[0]["id"] == report["id"]
    assert client.get("/api/web/assessments/missing").status_code == 404
    monkeypatch.setenv("CYVRA_API_KEY", "test-key")
    assert client.get("/api/web/assessments").status_code == 401


def test_rate_limit_and_error(client, monkeypatch):
    def fail(value):
        raise TargetError("blocked target")

    monkeypatch.setattr(api, "fetch_page", fail)
    for _ in range(10):
        assert (
            client.post("/api/web/assessments", json={"url": "https://example.com", "authorized": True}).status_code
            == 422
        )
    result = client.post("/api/web/assessments", json={"url": "https://example.com", "authorized": True})
    assert result.status_code == 429 and result.headers["retry-after"] == "60"
    assert client.get("/api/web/assessments").json() == []


def test_untrusted_large_hsts_does_not_crash():
    report = inspect(page([("Content-Type", "text/html"), ("Strict-Transport-Security", "max-age=" + "9" * 5000)]))
    assert any(f["id"] == "hsts" for f in report["findings"])


def test_body_markers_include_line_without_raw_content():
    report = inspect(page(body=b"<html>\n-----BEGIN PRIVATE KEY-----\nPRIVATE_VALUE"))
    finding = next(f for f in report["findings"] if f["id"] == "private-key-marker")
    assert finding["location"].endswith("HTML line 2")
    assert "PRIVATE_VALUE" not in json.dumps(report)
