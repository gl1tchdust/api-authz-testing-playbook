"""Tests for how the probe acquires a credential for each identity.

These run against a real token endpoint on localhost rather than a stubbed
`requests.post`. The mistakes this code can make are wire-format mistakes:
sending JSON where RFC 6749 requires `application/x-www-form-urlencoded`,
putting client credentials in the body when the server wants HTTP Basic,
dropping `scope`. A monkeypatch that returns a canned dict hides every one of
them, so the server records what it actually received and the tests assert on
that.

The server is `http.server` from the standard library. No new dependency for a
fixture that exists to make twenty lines of HTTP honest.
"""

from __future__ import annotations

import base64
import json
import threading
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from authzprobe.probe import Identity, Probe, ProbeError


class _TokenHandler(BaseHTTPRequestHandler):
    """Records the last token request and replies with whatever is configured."""

    def do_POST(self) -> None:  # noqa: N802 - BaseHTTPRequestHandler's naming
        length = int(self.headers.get("Content-Length") or 0)
        raw = self.rfile.read(length).decode("utf-8")
        self.server.last = {  # type: ignore[attr-defined]
            "path": self.path,
            "content_type": self.headers.get("Content-Type", ""),
            "authorization": self.headers.get("Authorization"),
            "form": {k: v[0] for k, v in urllib.parse.parse_qs(raw).items()},
            "raw": raw,
        }
        status, payload = self.server.reply  # type: ignore[attr-defined]
        body = payload if isinstance(payload, str) else json.dumps(payload)
        encoded = body.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(encoded)))
        self.end_headers()
        self.wfile.write(encoded)

    def log_message(self, *args) -> None:  # keep pytest output readable
        pass


@pytest.fixture
def token_server():
    server = ThreadingHTTPServer(("127.0.0.1", 0), _TokenHandler)
    server.last = None
    server.reply = (200, {"access_token": "tok-abc", "token_type": "Bearer"})
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield server
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


def _url(server) -> str:
    host, port = server.server_address[:2]
    return f"http://{host}:{port}"


def _probe(server, *, mode: str, identities: list[dict], **auth) -> Probe:
    spec = {
        "target": {
            "base_url": _url(server),
            "auth": {"mode": mode, "token_url": "/oauth/token", **auth},
        },
        "identities": identities,
        "cases": [],
    }
    return Probe(spec)


# ---------------------------------------------------------------------------
# anonymous, the property the whole differential rests on
# ---------------------------------------------------------------------------

def test_an_identity_with_only_a_client_id_is_not_anonymous():
    """Regression for the bug this feature would otherwise have introduced.

    `anonymous` was `username is None`, which is right while form login is the
    only way in. A client-credentials principal has no username, so it would
    have been treated as the anonymous arm, and a differential comparing
    anonymous against anonymous reports no finding however broken the target
    is. That failure is silent and looks like a clean run.
    """
    assert Identity(id="svc", client_id="abc").anonymous is False
    assert Identity(id="static", token="tok").anonymous is False
    assert Identity(id="user", username="u", password="p").anonymous is False
    assert Identity(id="anon").anonymous is True


# ---------------------------------------------------------------------------
# client credentials, RFC 6749 section 4.4
# ---------------------------------------------------------------------------

def test_client_credentials_sends_a_form_encoded_grant(token_server):
    p = _probe(token_server, mode="oauth2_client_credentials",
               identities=[{"id": "svc", "client_id": "cid", "client_secret": "sec"}])
    p.authenticate()

    assert p.identities["svc"].token == "tok-abc"
    sent = token_server.last
    assert sent["path"] == "/oauth/token"
    assert "application/x-www-form-urlencoded" in sent["content_type"]
    assert sent["form"]["grant_type"] == "client_credentials"
    assert "{" not in sent["raw"], "body must be form-encoded, not JSON"


def test_client_credentials_in_the_body_by_default(token_server):
    p = _probe(token_server, mode="oauth2_client_credentials",
               identities=[{"id": "svc", "client_id": "cid", "client_secret": "sec"}])
    p.authenticate()

    sent = token_server.last
    assert sent["form"]["client_id"] == "cid"
    assert sent["form"]["client_secret"] == "sec"
    assert sent["authorization"] is None


def test_client_credentials_as_http_basic_when_asked(token_server):
    """RFC 6749 section 2.3.1 allows either, and servers disagree on which."""
    p = _probe(token_server, mode="oauth2_client_credentials", credentials="basic",
               identities=[{"id": "svc", "client_id": "cid", "client_secret": "sec"}])
    p.authenticate()

    sent = token_server.last
    expected = base64.b64encode(b"cid:sec").decode()
    assert sent["authorization"] == f"Basic {expected}"
    assert "client_secret" not in sent["form"], "secret must not be sent twice"


def test_scope_is_forwarded_when_set(token_server):
    p = _probe(token_server, mode="oauth2_client_credentials",
               identities=[{"id": "svc", "client_id": "cid", "scope": "read:orders"}])
    p.authenticate()
    assert token_server.last["form"]["scope"] == "read:orders"


def test_scope_is_omitted_when_unset(token_server):
    p = _probe(token_server, mode="oauth2_client_credentials",
               identities=[{"id": "svc", "client_id": "cid"}])
    p.authenticate()
    assert "scope" not in token_server.last["form"]


# ---------------------------------------------------------------------------
# password grant, RFC 6749 section 4.3
# ---------------------------------------------------------------------------

def test_password_grant_sends_the_user_credentials(token_server):
    p = _probe(token_server, mode="oauth2_password",
               identities=[{"id": "owner", "username": "u1", "password": "p1",
                            "client_id": "cid"}])
    p.authenticate()

    sent = token_server.last
    assert sent["form"]["grant_type"] == "password"
    assert sent["form"]["username"] == "u1"
    assert sent["form"]["password"] == "p1"
    assert p.identities["owner"].token == "tok-abc"


def test_password_grant_without_a_username_is_rejected(token_server):
    p = _probe(token_server, mode="oauth2_password",
               identities=[{"id": "broken", "client_id": "cid"}])
    with pytest.raises(ProbeError, match="no username"):
        p.authenticate()


def test_client_credentials_without_a_client_id_is_rejected(token_server):
    p = _probe(token_server, mode="oauth2_client_credentials",
               identities=[{"id": "broken", "username": "u"}])
    with pytest.raises(ProbeError, match="no client_id"):
        p.authenticate()


# ---------------------------------------------------------------------------
# identities that need no acquisition
# ---------------------------------------------------------------------------

def test_a_supplied_token_skips_the_token_endpoint(token_server):
    """Static bearer tokens and API keys need no grant and no mode of their own."""
    p = _probe(token_server, mode="oauth2_client_credentials",
               identities=[{"id": "static", "token": "preset-token"}])
    p.authenticate()

    assert p.identities["static"].token == "preset-token"
    assert token_server.last is None, "no token request should have been made"


def test_anonymous_stays_anonymous_and_sends_no_request(token_server):
    p = _probe(token_server, mode="oauth2_client_credentials",
               identities=[{"id": "anon"}])
    p.authenticate()

    assert p.identities["anon"].token is None
    assert token_server.last is None


def test_the_auth_header_is_built_for_an_acquired_token(token_server):
    p = _probe(token_server, mode="oauth2_client_credentials",
               identities=[{"id": "svc", "client_id": "cid"}])
    p.authenticate()
    assert p._auth_header(p.identities["svc"]) == {"Authorization": "Bearer tok-abc"}
    assert p._auth_header(p.identities["svc"]) != {}


# ---------------------------------------------------------------------------
# token_url resolution
# ---------------------------------------------------------------------------

def test_an_absolute_token_url_is_used_as_given(token_server):
    """Authorization servers usually live on a different host to the API."""
    spec = {
        "target": {
            "base_url": "http://192.0.2.1:9999",  # RFC 5737, unroutable on purpose
            "auth": {"mode": "oauth2_client_credentials",
                     "token_url": f"{_url(token_server)}/oauth/token"},
        },
        "identities": [{"id": "svc", "client_id": "cid"}],
        "cases": [],
    }
    p = Probe(spec)
    p.authenticate()
    assert p.identities["svc"].token == "tok-abc"


def test_a_missing_token_url_is_rejected(token_server):
    spec = {
        "target": {"base_url": _url(token_server),
                   "auth": {"mode": "oauth2_client_credentials"}},
        "identities": [{"id": "svc", "client_id": "cid"}],
        "cases": [],
    }
    with pytest.raises(ProbeError, match="no token_url"):
        Probe(spec).authenticate()


# ---------------------------------------------------------------------------
# failures must stop the run, never silently produce a tokenless identity
# ---------------------------------------------------------------------------

def test_a_rejected_token_request_raises_with_the_status(token_server):
    token_server.reply = (401, {"error": "invalid_client"})
    p = _probe(token_server, mode="oauth2_client_credentials",
               identities=[{"id": "svc", "client_id": "cid"}])
    with pytest.raises(ProbeError, match="401"):
        p.authenticate()


def test_a_token_response_without_the_field_raises(token_server):
    token_server.reply = (200, {"token_type": "Bearer"})
    p = _probe(token_server, mode="oauth2_client_credentials",
               identities=[{"id": "svc", "client_id": "cid"}])
    with pytest.raises(ProbeError, match="access_token"):
        p.authenticate()


def test_an_empty_token_raises_rather_than_authenticating_as_nobody(token_server):
    """A 200 carrying an empty token would otherwise produce an identity that
    looks authenticated and sends no credential, which reads as a clean run."""
    token_server.reply = (200, {"access_token": ""})
    p = _probe(token_server, mode="oauth2_client_credentials",
               identities=[{"id": "svc", "client_id": "cid"}])
    with pytest.raises(ProbeError, match="empty"):
        p.authenticate()


def test_a_non_json_token_response_raises(token_server):
    token_server.reply = (200, "<html>gateway error</html>")
    p = _probe(token_server, mode="oauth2_client_credentials",
               identities=[{"id": "svc", "client_id": "cid"}])
    with pytest.raises(ProbeError, match="access_token"):
        p.authenticate()


def test_a_custom_token_field_is_honoured(token_server):
    token_server.reply = (200, {"id_token": "tok-xyz"})
    p = _probe(token_server, mode="oauth2_client_credentials", token_field="id_token",
               identities=[{"id": "svc", "client_id": "cid"}])
    p.authenticate()
    assert p.identities["svc"].token == "tok-xyz"


# ---------------------------------------------------------------------------
# configuration validation, at load time
# ---------------------------------------------------------------------------

def test_an_unknown_mode_is_rejected_when_the_spec_loads():
    """Better than discovering it after the seed step has already run."""
    spec = {
        "target": {"base_url": "http://x", "auth": {"mode": "saml-somehow"}},
        "identities": [], "cases": [],
    }
    with pytest.raises(ProbeError, match="unknown auth mode"):
        Probe(spec)


def test_an_unknown_credentials_placement_is_rejected(token_server):
    p = _probe(token_server, mode="oauth2_client_credentials", credentials="querystring",
               identities=[{"id": "svc", "client_id": "cid", "client_secret": "s"}])
    with pytest.raises(ProbeError, match="body.*basic"):
        p.authenticate()


def test_the_original_login_key_still_configures_form_mode():
    """The VAmPI case file and its committed captures use `login:`."""
    spec = {
        "target": {
            "base_url": "http://x",
            "login": {"method": "POST", "path": "/users/v1/login",
                      "body": {"username": "$username"}, "token_field": "auth_token"},
        },
        "identities": [{"id": "owner", "username": "u", "password": "p"}],
        "cases": [],
    }
    p = Probe(spec)
    assert p.auth_mode == "form"
    assert p.login_cfg["token_field"] == "auth_token"


# ---------------------------------------------------------------------------
# credentials come from the environment, not the case file
# ---------------------------------------------------------------------------

def test_identity_fields_expand_environment_variables(monkeypatch):
    """A case file is committed to a repository; a client secret is not."""
    monkeypatch.setenv("PROBE_TEST_SECRET", "s3cr3t")
    monkeypatch.setenv("PROBE_TEST_KEY", "key-123")
    spec = {
        "target": {"base_url": "http://x"},
        "identities": [{"id": "svc", "client_id": "cid",
                        "client_secret": "${PROBE_TEST_SECRET}",
                        "token": "$PROBE_TEST_KEY"}],
        "cases": [],
    }
    svc = Probe(spec).identities["svc"]
    assert svc.client_secret == "s3cr3t"
    assert svc.token == "key-123"


def test_an_unset_environment_variable_is_an_error_not_a_literal(monkeypatch):
    """`expandvars` leaves an undefined name alone, so the literal string
    '${CLIENT_SECRET}' would be sent as the secret and come back as an
    ordinary 401. That is a confusing way to learn you forgot an export."""
    monkeypatch.delenv("PROBE_TEST_MISSING", raising=False)
    spec = {
        "target": {"base_url": "http://x"},
        "identities": [{"id": "svc", "client_id": "cid",
                        "client_secret": "${PROBE_TEST_MISSING}"}],
        "cases": [],
    }
    with pytest.raises(ProbeError, match="unset environment variable"):
        Probe(spec)


def test_a_literal_value_without_a_placeholder_is_untouched():
    spec = {
        "target": {"base_url": "http://x"},
        "identities": [{"id": "owner", "username": "name1", "password": "pass1"}],
        "cases": [],
    }
    owner = Probe(spec).identities["owner"]
    assert (owner.username, owner.password) == ("name1", "pass1")
