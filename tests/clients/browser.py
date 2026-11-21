#!/usr/bin/env python3
"""Local CI browser substitute for the production passwordless and consent forms."""

from http.cookies import SimpleCookie
from html.parser import HTMLParser
import os
import re
import subprocess
import sys
from urllib.parse import parse_qs, urlencode, urljoin, urlsplit
from urllib.request import build_opener, HTTPRedirectHandler, ProxyHandler, Request
from urllib.error import HTTPError


class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        return None


class ConsentFields(HTMLParser):
    def __init__(self, body):
        super().__init__()
        self.fields = {}
        self.feed(body)

    def handle_starttag(self, tag, attrs):
        attrs = dict(attrs)
        if tag == "input" and attrs.get("name") in {"ticket", "csrf"}:
            self.fields[attrs["name"]] = attrs["value"]


def postgres_command(env, statement):
    container = env["OAUTH_TEST_POSTGRES_CONTAINER"]
    assert re.fullmatch(r"[a-f0-9]{64}", container), "disposable PG service id"
    return [
        "docker", "exec", container, "psql", "-U", "postgres", "-d", "humaux_thread_ci",
        "-XAt", "-v", "ON_ERROR_STOP=1", "-c", statement,
    ]


def open_authorization(url):
    origin = os.environ["OAUTH_TEST_ORIGIN"]
    parsed = urlsplit(url)
    assert f"{parsed.scheme}://{parsed.netloc}" == origin and parsed.path == "/oauth/authorize"
    params = parse_qs(parsed.query)
    expected_callback = urlsplit(params["redirect_uri"][0])
    assert expected_callback.scheme == "http" and expected_callback.hostname in {"127.0.0.1", "localhost", "::1"}
    assert expected_callback.port and not expected_callback.username and not expected_callback.fragment
    cookies = {}
    http = build_opener(ProxyHandler({}), NoRedirect())

    def request(path, values=None):
        encoded = urlencode(values).encode() if values is not None else None
        headers = {
            "Cookie": "; ".join(f"{name}={value}" for name, value in cookies.items()),
            "Origin": origin,
            "Sec-Fetch-Site": "same-origin",
        }
        try:
            response = http.open(Request(origin + path, data=encoded, headers=headers), timeout=10)
        except HTTPError as error:
            response = error
        with response:
            for value in response.headers.get_all("Set-Cookie", []):
                for name, morsel in SimpleCookie(value).items():
                    cookies[name] = morsel.value
            return response.status, response.headers.get("Location"), response.read().decode()

    auth_path = parsed.path + "?" + parsed.query
    status, location, _ = request(auth_path)
    assert (status, location) == (303, "/auth/login"), "authorize login redirect"
    status, _, _ = request("/auth/login", {"email": os.environ["OAUTH_TEST_EMAIL"]})
    assert status == 303, "login request"
    user = os.environ["OAUTH_TEST_USER"]
    assert re.fullmatch(r"[a-f0-9-]{36}", user)
    code = subprocess.check_output(
        postgres_command(os.environ, f"SELECT payload->>'code' FROM ops.email_outbox WHERE user_id='{user}' "
                         "ORDER BY created_at DESC LIMIT 1"),
        stderr=subprocess.DEVNULL,
        text=True,
        timeout=10,
    ).strip()
    assert re.fullmatch(r"[0-9]{6}", code), "outbox login code"
    status, continuation, _ = request("/auth/code", {"code": code})
    assert (status, continuation) == (303, auth_path), "login continuation"
    status, _, body = request(auth_path)
    assert status == 200, "authenticated consent page"
    fields = ConsentFields(body).fields
    assert fields.keys() == {"ticket", "csrf"}, "consent hidden fields"
    decision = "deny" if os.environ["OAUTH_CLIENT_FAULT"] == "consent" else "allow"
    status, location, _ = request("/oauth/authorize", {**fields, "decision": decision})
    assert status == 303 and location, "consent redirect"
    actual = urlsplit(location)
    assert (actual.scheme, actual.netloc, actual.path) == (
        expected_callback.scheme, expected_callback.netloc, expected_callback.path
    ), "callback address"
    callback = parse_qs(actual.query)
    assert callback.get("state") == params.get("state"), "callback state"
    assert callback.get("iss") == [origin], "callback issuer"
    if decision == "deny":
        assert callback.get("error") == ["access_denied"] and "code" not in callback
    else:
        assert callback.get("code") and "error" not in callback
    # Never forward the login cookie to the client callback.
    with http.open(Request(urljoin(origin, location)), timeout=10) as response:
        assert response.status == 200, "loopback callback status"


if __name__ == "__main__":
    try:
        open_authorization(sys.argv[1])
    except Exception:
        # HTTP and subprocess exceptions can include URLs, OTPs, codes or cookies.
        sys.exit("CI browser failed a login, consent or callback assertion")
