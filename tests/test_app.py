"""auth-gateway with n8n replaced by a fake: no test reaches the real login flow or Telegram."""

from urllib.parse import parse_qs, unquote, urlsplit

import pytest
import requests

import app as gateway

ORIGIN = "https://jarllindquist.com"


class FakeResponse:
    def __init__(self, status=200, body=None):
        self.status_code = status
        self._body = body if body is not None else {}

    def json(self):
        return self._body


class FakeN8n:
    """Records each call and answers per webhook path."""

    def __init__(self):
        self.calls = []
        self.valid_sessions = {"good-session"}
        self.approved = set()
        self.magic_link_status = 200

    def __call__(self, url, json=None, headers=None, timeout=None):
        path = url.rsplit("/", 1)[-1]
        self.calls.append((path, json, headers or {}))
        if path == "session-check":
            ok = (headers or {}).get("X-Admin-Session") in self.valid_sessions and json == {"app": "ops"}
            return FakeResponse(200, {"valid": ok})
        if path == "request-magic-link":
            if self.magic_link_status != 200:
                return FakeResponse(self.magic_link_status, {})
            return FakeResponse(200, {"sessionId": "pending-123"})
        if path == "check-login-status":
            return FakeResponse(200, {"authenticated": json["sessionId"] in self.approved})
        if path == "session-end":
            sid = (headers or {}).get("X-Admin-Session")
            ended = sid in self.valid_sessions and json == {"app": "ops"}
            self.valid_sessions.discard(sid)
            return FakeResponse(200, {"ended": ended})
        raise AssertionError("unexpected n8n call " + path)


@pytest.fixture
def n8n(monkeypatch):
    fake = FakeN8n()
    monkeypatch.setattr(gateway.requests, "post", fake)
    gateway._checks.clear()
    return fake


@pytest.fixture
def client():
    # Cookies are given as headers in each test, so the client keeps no cookie jar of its own
    return gateway.app.test_client(use_cookies=False)


def forwarded(host="grafana.jarllindquist.com", uri="/d/abc?x=1", method="GET", cookie=None):
    headers = {"X-Forwarded-Proto": "https", "X-Forwarded-Host": host, "X-Forwarded-Uri": uri,
               "X-Forwarded-Method": method}
    if cookie:
        headers["Cookie"] = f"ops_session={cookie}"
    return headers


# --- /auth/verify: what Traefik asks before every request ---

def test_no_cookie_goes_to_login_with_the_way_back(client, n8n):
    r = client.get("/auth/verify", headers=forwarded())
    assert r.status_code == 302
    loc = urlsplit(r.headers["Location"])
    assert f"{loc.scheme}://{loc.netloc}{loc.path}" == ORIGIN + "/auth/login"
    assert unquote(parse_qs(loc.query)["rd"][0]) == "https://grafana.jarllindquist.com/d/abc?x=1"
    assert "X-WEBAUTH-USER" not in r.headers


def test_valid_session_passes_and_names_the_user(client, n8n):
    r = client.get("/auth/verify", headers=forwarded(cookie="good-session"))
    assert r.status_code == 200
    assert r.headers["X-WEBAUTH-USER"] == "admin"
    assert n8n.calls == [("session-check", {"app": "ops"}, {"X-Admin-Session": "good-session"})]


def test_a_yes_is_cached_so_n8n_is_not_asked_on_every_request(client, n8n):
    for _ in range(5):
        assert client.get("/auth/verify", headers=forwarded(cookie="good-session")).status_code == 200
    assert len(n8n.calls) == 1


def test_unknown_session_does_not_pass(client, n8n):
    r = client.get("/auth/verify", headers=forwarded(cookie="made-up"))
    assert r.status_code == 302
    assert "X-WEBAUTH-USER" not in r.headers


def test_other_methods_get_401_not_a_redirect(client, n8n):
    assert client.get("/auth/verify", headers=forwarded(method="POST")).status_code == 401


def test_n8n_down_lets_nobody_in(client, monkeypatch):
    def down(*args, **kwargs):
        raise requests.ConnectionError("n8n is down")

    monkeypatch.setattr(gateway.requests, "post", down)
    gateway._checks.clear()
    assert client.get("/auth/verify", headers=forwarded(cookie="good-session")).status_code == 302


def test_a_foreign_host_is_not_used_as_the_way_back(client, n8n):
    r = client.get("/auth/verify", headers=forwarded(host="evil.example"))
    assert r.status_code == 302
    assert r.headers["Location"] == ORIGIN + "/auth/login"


@pytest.mark.parametrize("url, ok", [
    ("https://grafana.jarllindquist.com/d/x", True),
    ("https://jarllindquist.com/cv", True),
    ("http://grafana.jarllindquist.com/", False),          # not https
    ("https://jarllindquist.com.evil.example/", False),    # our name as a prefix of another domain
    ("https://evil.example/?next=jarllindquist.com", False),
    ("https://jarllindquist.com@evil.example/", False),    # user info trick
    ("https://notjarllindquist.com/", False),
    ("https://grafana.jarllindquist.com:8443/", False),
    ("//evil.example/", False),
    ("javascript:alert(1)", False),
    ("", False),
    (None, False),
])
def test_safe_return(url, ok):
    result = gateway.safe_return(url)
    assert (result is not None and result == url) is ok


# --- login: request, poll, cookie ---

def test_login_request_needs_our_origin(client, n8n):
    assert client.post("/auth/login").status_code == 403
    assert client.post("/auth/login", headers={"Origin": "https://evil.example"}).status_code == 403
    assert n8n.calls == []  # nothing reached Telegram


def test_login_request_asks_n8n_for_app_ops_and_keeps_the_pending_id(client, n8n):
    r = client.post("/auth/login", headers={"Origin": ORIGIN, "X-Real-Ip": "203.0.113.9"})
    assert r.status_code == 200
    code = r.get_json()["code"]
    assert n8n.calls == [("request-magic-link", {"app": "ops", "code": code, "ip": "203.0.113.9"}, {})]
    cookie = r.headers["Set-Cookie"]
    assert cookie.startswith("ops_pending=pending-123")
    for part in ("HttpOnly", "Secure", "SameSite=Strict", "Path=/auth"):
        assert part in cookie


def test_login_request_passes_on_too_many(client, n8n):
    n8n.magic_link_status = 429
    assert client.post("/auth/login", headers={"Origin": ORIGIN}).status_code == 429


def test_status_without_a_request_is_400(client, n8n):
    assert client.get("/auth/login/status").status_code == 400


def test_status_before_approval_sets_no_session(client, n8n):
    r = client.get("/auth/login/status", headers={"Cookie": "ops_pending=pending-123"})
    assert r.get_json() == {"authenticated": False}
    assert "ops_session" not in r.headers.get("Set-Cookie", "")


def test_approval_sets_the_domain_cookie_and_returns_the_safe_way_back(client, n8n):
    n8n.approved.add("pending-123")
    rd = "https://grafana.jarllindquist.com/d/abc"
    r = client.get("/auth/login/status", query_string={"rd": rd}, headers={"Cookie": "ops_pending=pending-123"})
    assert r.get_json() == {"authenticated": True, "next": rd}
    cookies = r.headers.getlist("Set-Cookie")
    session = next(c for c in cookies if c.startswith("ops_session="))
    assert session.startswith("ops_session=pending-123")
    for part in ("Domain=jarllindquist.com", "HttpOnly", "Secure", "SameSite=Lax", "Path=/"):
        assert part in session
    assert any(c.startswith("ops_pending=;") for c in cookies)  # the pending id is cleared


def test_approval_never_sends_you_to_a_foreign_site(client, n8n):
    n8n.approved.add("pending-123")
    r = client.get("/auth/login/status", query_string={"rd": "https://evil.example/"},
                   headers={"Cookie": "ops_pending=pending-123"})
    assert r.get_json()["next"] == "/auth/login"


def test_login_page_sends_a_logged_in_user_straight_back(client, n8n):
    rd = "https://grafana.jarllindquist.com/"
    r = client.get("/auth/login", query_string={"rd": rd}, headers={"Cookie": "ops_session=good-session"})
    assert r.status_code == 302 and r.headers["Location"] == rd


def test_login_page_shows_the_button(client, n8n):
    r = client.get("/auth/login")
    assert r.status_code == 200
    assert b"Skicka inloggning till Telegram" in r.data


def test_logout_clears_the_cookie(client, n8n):
    assert client.post("/auth/logout").status_code == 403
    r = client.post("/auth/logout", headers={"Origin": ORIGIN, "Cookie": "ops_session=good-session"})
    assert r.status_code == 303
    cookie = r.headers["Set-Cookie"]
    assert cookie.startswith("ops_session=;") and "Domain=jarllindquist.com" in cookie


# --- headers ---

def test_security_headers_on_every_answer(client, n8n):
    for path in ("/auth/login", "/auth/health", "/auth/static/login.js"):
        r = client.get(path)
        assert "frame-ancestors 'none'" in r.headers["Content-Security-Policy"]
        assert "unsafe-inline" not in r.headers["Content-Security-Policy"]
        assert r.headers["Cache-Control"] == "no-store"
        assert r.headers["X-Content-Type-Options"] == "nosniff"


# --- the tools on the page ---

def test_logged_in_page_links_the_tools(client, n8n, monkeypatch):
    monkeypatch.setattr(gateway, "TOOLS", "Grafana=/grafana/;Prometheus=/prometheus/")
    r = client.get("/auth/login", headers={"Cookie": "ops_session=good-session"})
    assert b'href="/grafana/"' in r.data and b'href="/prometheus/"' in r.data


def test_tools_are_not_shown_before_login(client, n8n, monkeypatch):
    monkeypatch.setattr(gateway, "TOOLS", "Grafana=/grafana/")
    assert b"/grafana/" not in client.get("/auth/login").data


def test_tool_links_keep_only_our_own_addresses():
    links = gateway.tool_links(
        "Grafana=/grafana/; ChirpStack=https://chirpstack.jarllindquist.com/ ;Evil=https://evil.example/;"
        "Scheme=//evil.example/;Js=javascript:alert(1);=/nameless/;Empty="
    )
    assert links == [{"name": "Grafana", "url": "/grafana/"},
                     {"name": "ChirpStack", "url": "https://chirpstack.jarllindquist.com/"}]


def test_no_tools_configured_shows_no_list(client, n8n, monkeypatch):
    monkeypatch.setattr(gateway, "TOOLS", "")
    r = client.get("/auth/login", headers={"Cookie": "ops_session=good-session"})
    assert b'class="tools"' not in r.data and b"Logga ut" in r.data


# --- the code shown on the page and in Telegram ---

def test_the_code_is_four_unambiguous_characters_and_new_each_time(client, n8n):
    codes = {client.post("/auth/login", headers={"Origin": ORIGIN}).get_json()["code"] for _ in range(20)}
    assert len(codes) > 15  # random, not repeated
    for code in codes:
        assert len(code) == 4 and all(c in gateway.CODE_ALPHABET for c in code)
        assert not set(code) & set("01OI")


def test_a_strange_ip_header_is_not_passed_on(client, n8n):
    client.post("/auth/login", headers={"Origin": ORIGIN, "X-Real-Ip": "1.2.3.4; <b>"})
    assert n8n.calls[-1][1]["ip"] == ""


def test_no_ip_header_sends_an_empty_ip(client, n8n):
    client.post("/auth/login", headers={"Origin": ORIGIN})
    assert n8n.calls[-1][1]["ip"] == ""


# --- logout ends the session in n8n ---

def test_logout_ends_the_session_in_n8n(client, n8n):
    client.post("/auth/logout", headers={"Origin": ORIGIN, "Cookie": "ops_session=good-session"})
    assert ("session-end", {"app": "ops"}, {"X-Admin-Session": "good-session"}) in n8n.calls
    # the same cookie, copied before the logout, no longer gets through
    r = client.get("/auth/verify", headers=forwarded(cookie="good-session"))
    assert r.status_code == 302


def test_logout_without_a_cookie_asks_n8n_nothing(client, n8n):
    client.post("/auth/logout", headers={"Origin": ORIGIN})
    assert n8n.calls == []


def test_logout_works_when_n8n_is_down(client, monkeypatch):
    def down(*args, **kwargs):
        raise requests.ConnectionError("n8n is down")

    monkeypatch.setattr(gateway.requests, "post", down)
    r = client.post("/auth/logout", headers={"Origin": ORIGIN, "Cookie": "ops_session=good-session"})
    assert r.status_code == 303 and r.headers["Set-Cookie"].startswith("ops_session=;")


# --- service tokens: machine access, GET only, one host and prefix, until a date ---

import hashlib as _hashlib
from datetime import datetime as _dt, timezone as _tz

TOKEN = "a-long-random-test-token-0123456789abcdef"
SPEC = ("claude-heim|" + _hashlib.sha256(TOKEN.encode()).hexdigest()
        + "|2099-01-01T00:00:00Z|jarllindquist.com|/heim/api/")


@pytest.fixture
def tokens(monkeypatch):
    monkeypatch.setattr(gateway, "SERVICE_TOKENS", gateway.parse_service_tokens(SPEC))


def bearer(uri="/heim/api/summary", host="jarllindquist.com", method="GET", token=TOKEN):
    return {"Authorization": "Bearer " + token, "X-Forwarded-Host": host, "X-Forwarded-Uri": uri,
            "X-Forwarded-Method": method, "X-Forwarded-Proto": "https"}


def test_service_token_reads_its_prefix(client, n8n, tokens):
    r = client.get("/auth/verify", headers=bearer())
    assert r.status_code == 200 and r.headers["X-WEBAUTH-USER"] == "service:claude-heim"
    assert n8n.calls == []  # no session check, no Telegram


@pytest.mark.parametrize("headers", [
    bearer(uri="/grafana/"),                       # outside the prefix
    bearer(uri="/heim/"),                          # the page itself, not the API
    bearer(uri="/heim/api/../../grafana/"),        # dot segments
    bearer(uri="/heim/api/%2e%2e/x"),              # encoded dots
    bearer(uri="/heim/api//x"),                    # double slash
    bearer(method="POST"),                         # not a read
    bearer(host="pb.jarllindquist.com"),           # another host
    bearer(token="wrong-token"),                   # unknown token
])
def test_service_token_refused(client, n8n, tokens, headers):
    r = client.get("/auth/verify", headers=headers)
    assert r.status_code == 401
    assert "X-WEBAUTH-USER" not in r.headers


def test_expired_service_token_is_refused(tokens):
    later = _dt(2099, 1, 2, tzinfo=_tz.utc)
    assert gateway.service_token_user("Bearer " + TOKEN, "jarllindquist.com", "/heim/api/x", "GET", now=later) is None
    earlier = _dt(2098, 12, 31, tzinfo=_tz.utc)
    assert gateway.service_token_user("Bearer " + TOKEN, "jarllindquist.com", "/heim/api/x", "GET", now=earlier) == "claude-heim"


def test_no_service_tokens_configured_means_no_machine_access(client, n8n, monkeypatch):
    monkeypatch.setattr(gateway, "SERVICE_TOKENS", [])
    assert client.get("/auth/verify", headers=bearer()).status_code == 401


def test_malformed_token_lines_are_ignored():
    bad = ["only|three|parts", "x|nothex|2099-01-01T00:00:00Z|h|/p/", "x|" + "a" * 64 + "|not-a-date|h|/p/",
           "x|" + "a" * 64 + "|2099-01-01T00:00:00|h|/p/",  # no timezone
           "x|" + "a" * 64 + "|2099-01-01T00:00:00Z|h|no-slash",
           "x|" + "a" * 64 + "|2099-01-01T00:00:00Z|h|/p/|maybe"]  # unknown flag
    parsed = gateway.parse_service_tokens(";".join(bad + [SPEC]))
    assert [t["name"] for t in parsed] == ["claude-heim"]


def test_a_cookie_login_still_works_next_to_tokens(client, n8n, tokens):
    r = client.get("/auth/verify", headers=forwarded(cookie="good-session"))
    assert r.status_code == 200 and r.headers["X-WEBAUTH-USER"] == "admin"


# --- ?key= in the URL, for the phone widget ---

WIDGET = "another-long-random-widget-token-98765"
WIDGET_SPEC = ("phone-widget|" + _hashlib.sha256(WIDGET.encode()).hexdigest()
               + "|2099-01-01T00:00:00Z|jarllindquist.com|/heim/api/widget|query")


@pytest.fixture
def widget_tokens(monkeypatch):
    monkeypatch.setattr(gateway, "SERVICE_TOKENS", gateway.parse_service_tokens(SPEC + ";" + WIDGET_SPEC))


def by_url(uri, method="GET", host="jarllindquist.com"):
    return {"X-Forwarded-Host": host, "X-Forwarded-Uri": uri, "X-Forwarded-Method": method, "X-Forwarded-Proto": "https"}


def test_widget_key_in_the_url_reads_exactly_its_path(client, n8n, widget_tokens):
    r = client.get("/auth/verify", headers=by_url("/heim/api/widget?key=" + WIDGET))
    assert r.status_code == 200 and r.headers["X-WEBAUTH-USER"] == "service:phone-widget"


@pytest.mark.parametrize("uri", [
    "/heim/api/latest?key=" + WIDGET,          # another endpoint (has occupancy)
    "/heim/api/widgetx?key=" + WIDGET,         # exact path, not a prefix
    "/heim/api/widget/?key=" + WIDGET,
    "/heim/api/hourly?key=" + WIDGET,
    "/heim/api/widget?key=" + WIDGET + "&key=" + WIDGET,  # two keys
])
def test_widget_key_refused_elsewhere(client, n8n, widget_tokens, uri):
    assert client.get("/auth/verify", headers=by_url(uri)).status_code != 200


def test_a_header_only_token_is_refused_in_the_url(client, n8n, widget_tokens):
    # claude-heim may read /heim/api/ with a header, but not with ?key= (it isn't marked "query")
    r = client.get("/auth/verify", headers=by_url("/heim/api/latest?key=" + TOKEN))
    assert r.status_code == 401


def test_the_widget_key_also_works_as_a_header(client, n8n, widget_tokens):
    r = client.get("/auth/verify", headers=bearer(uri="/heim/api/widget", token=WIDGET))
    assert r.status_code == 200


def test_the_key_never_reaches_the_log(client, n8n, widget_tokens, capsys):
    client.get("/auth/verify", headers=by_url("/heim/api/widget?key=" + WIDGET))
    assert WIDGET not in capsys.readouterr().out
