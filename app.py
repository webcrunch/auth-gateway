"""auth-gateway: the magic-link login in front of the server's tools (Grafana, ChirpStack, ...).

Traefik asks /auth/verify before every request to a protected service (the forwardAuth middleware
ops-auth@docker). A valid "ops" session answers 200 and names the user in X-WEBAUTH-USER, which
Traefik passes on (Grafana logs that user in). Anything else is sent to the login page, where n8n
sends an approval request to Telegram: the same shared flow as the other systems, with app "ops".

The session cookie holds the n8n session id and nothing else; n8n decides whether it is valid
(session-check), so there is no signing key to keep. It is set for the whole domain, so one login
covers every subdomain.
"""

import os
import secrets
import threading
import time
from urllib.parse import quote, urlsplit

import requests
from flask import Flask, jsonify, make_response, redirect, render_template, request

N8N_WEBHOOK_URL = os.environ.get("N8N_WEBHOOK_URL", "https://jarllindquist.com/n8n/webhook")
MAGIC_LINK_APP = os.environ.get("MAGIC_LINK_APP", "ops")
# The cookie is sent to this domain and every subdomain of it
COOKIE_DOMAIN = os.environ.get("COOKIE_DOMAIN", "jarllindquist.com")
# Where the login page lives; a POST from any other origin is refused
PUBLIC_ORIGIN = os.environ.get("PUBLIC_ORIGIN", "https://jarllindquist.com")
# The user name the protected services see (Grafana: the existing admin account)
OPS_USER = os.environ.get("OPS_USER", "admin")
# The tools behind the login, linked from the page once logged in: "Name=/path/;Name=/path/".
# Set in docker-compose.prod.yml, next to the rest of the setup; none when unset.
TOOLS = os.environ.get("TOOLS", "")


def tool_links(spec: str) -> list[dict]:
    """Name and address per tool; only paths on this site or https on our own domain."""
    links = []
    for part in spec.split(";"):
        name, _, url = part.partition("=")
        name, url = name.strip(), url.strip()
        if not name or not url:
            continue
        if (url.startswith("/") and not url.startswith("//")) or safe_return(url):
            links.append({"name": name, "url": url})
    return links

SESSION_COOKIE = "ops_session"
PENDING_COOKIE = "ops_pending"
SESSION_MAX_AGE = 12 * 3600  # the cookie; n8n ends the session after 15 idle minutes anyway
PENDING_MAX_AGE = 5 * 60  # n8n's approval request lives 5 minutes

SECURITY_HEADERS = {
    "Content-Security-Policy": "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self'; "
    "connect-src 'self'; object-src 'none'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'",
    "X-Frame-Options": "DENY",
    "X-Content-Type-Options": "nosniff",
    "Referrer-Policy": "no-referrer",
    "Cache-Control": "no-store",
}

app = Flask(__name__, static_url_path="/auth/static")

# n8n's answers per session: {session_id: (valid, checked_at)}. One process (gunicorn with threads),
# so every request shares it.
_checks: dict[str, tuple[bool, float]] = {}
_checks_lock = threading.Lock()


def n8n(path: str, timeout: float = 5, **kwargs) -> requests.Response:
    return requests.post(f"{N8N_WEBHOOK_URL}/{path}", timeout=timeout, **kwargs)


def session_valid(session_id: str | None) -> bool:
    if not session_id or len(session_id) > 200:
        return False
    now = time.time()
    with _checks_lock:
        cached = _checks.get(session_id)
    # A yes is trusted for a minute, a no for ten seconds; n8n renews the session on each check,
    # so a session stays alive while it is used
    if cached and now - cached[1] < (60 if cached[0] else 10):
        return cached[0]
    try:
        response = n8n("session-check", json={"app": MAGIC_LINK_APP}, headers={"X-Admin-Session": session_id})
        valid = response.status_code == 200 and response.json().get("valid") is True
    except (requests.RequestException, ValueError):
        valid = False  # n8n unreachable: nobody gets in
    with _checks_lock:
        if len(_checks) > 1000:
            _checks.clear()
        _checks[session_id] = (valid, now)
    return valid


def safe_return(url: str | None) -> str | None:
    """The address to go back to after login, only if it is https on our own domain."""
    if not url:
        return None
    try:
        parts = urlsplit(url)
    except ValueError:
        return None
    host = (parts.hostname or "").lower()
    if parts.scheme != "https" or "@" in parts.netloc or parts.port not in (None, 443):
        return None
    if host != COOKIE_DOMAIN and not host.endswith("." + COOKIE_DOMAIN):
        return None
    return url


# The code shown on the login page and in the Telegram message: 4 characters, no look-alikes (0/O, 1/I)
CODE_ALPHABET = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"


def new_code() -> str:
    return "".join(secrets.choice(CODE_ALPHABET) for _ in range(4))


def client_ip() -> str:
    """The visitor's address as Traefik saw it (X-Real-Ip), for the Telegram message."""
    ip = request.headers.get("X-Real-Ip", "").strip()
    return ip if 3 <= len(ip) <= 45 and all(c in "0123456789abcdefABCDEF:." for c in ip) else ""


def same_origin() -> bool:
    return request.headers.get("Origin") == PUBLIC_ORIGIN


@app.after_request
def security_headers(response):
    for name, value in SECURITY_HEADERS.items():
        response.headers[name] = value
    return response


@app.get("/auth/health")
def health():
    return "ok"


@app.get("/auth/verify")
def verify():
    if session_valid(request.cookies.get(SESSION_COOKIE)):
        response = make_response("", 200)
        response.headers["X-WEBAUTH-USER"] = OPS_USER
        return response
    # Only a page load can be sent on to the login page; anything else just gets a no
    if request.headers.get("X-Forwarded-Method", "GET") not in ("GET", "HEAD"):
        return "", 401
    target = safe_return(
        f"{request.headers.get('X-Forwarded-Proto', 'https')}://"
        f"{request.headers.get('X-Forwarded-Host', '')}{request.headers.get('X-Forwarded-Uri', '/')}"
    )
    login = f"{PUBLIC_ORIGIN}/auth/login"
    if target:
        login += "?rd=" + quote(target, safe="")
    return redirect(login, 302)


@app.get("/auth/login")
def login_page():
    target = safe_return(request.args.get("rd"))
    logged_in = session_valid(request.cookies.get(SESSION_COOKIE))
    if logged_in and target:
        return redirect(target, 302)
    return render_template("login.html", logged_in=logged_in, rd=target or "",
                           tools=tool_links(TOOLS) if logged_in else [])


@app.post("/auth/login")
def login_request():
    if not same_origin():
        return jsonify({"error": "origin"}), 403
    try:
        code = new_code()
        # The code and IP are shown in Telegram, so a request you didn't make stands out
        response = n8n("request-magic-link", timeout=10,
                       json={"app": MAGIC_LINK_APP, "code": code, "ip": client_ip()})
        if response.status_code == 429:
            return jsonify({"error": "too_many"}), 429
        session_id = response.json().get("sessionId")
    except (requests.RequestException, ValueError):
        session_id = None
    if not session_id:
        return jsonify({"error": "failed"}), 502
    result = jsonify({"sent": True, "code": code})
    result.set_cookie(PENDING_COOKIE, session_id, max_age=PENDING_MAX_AGE, path="/auth",
                      secure=True, httponly=True, samesite="Strict")
    return result


@app.get("/auth/login/status")
def login_status():
    session_id = request.cookies.get(PENDING_COOKIE)
    if not session_id:
        return jsonify({"authenticated": False, "error": "no_request"}), 400
    try:
        response = n8n("check-login-status", timeout=10, json={"sessionId": session_id})
        authenticated = response.json().get("authenticated") is True
    except (requests.RequestException, ValueError):
        authenticated = False
    if not authenticated:
        return jsonify({"authenticated": False})
    result = jsonify({"authenticated": True, "next": safe_return(request.args.get("rd")) or "/auth/login"})
    result.set_cookie(SESSION_COOKIE, session_id, max_age=SESSION_MAX_AGE, domain=COOKIE_DOMAIN, path="/",
                      secure=True, httponly=True, samesite="Lax")
    result.delete_cookie(PENDING_COOKIE, path="/auth", secure=True, httponly=True, samesite="Strict")
    return result


@app.post("/auth/logout")
def logout():
    if not same_origin():
        return "", 403
    session_id = request.cookies.get(SESSION_COOKIE)
    with _checks_lock:
        _checks.pop(session_id, None)
    # End the session in n8n too, so a copied cookie stops working at once (not only after 15 idle minutes)
    if session_id and len(session_id) <= 200:
        try:
            n8n("session-end", json={"app": MAGIC_LINK_APP}, headers={"X-Admin-Session": session_id})
        except requests.RequestException:
            pass  # the cookie is removed anyway; n8n ends the session after 15 idle minutes
    result = redirect("/auth/login", 303)
    result.delete_cookie(SESSION_COOKIE, domain=COOKIE_DOMAIN, path="/", secure=True, httponly=True, samesite="Lax")
    return result
