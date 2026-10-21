"""Tests for the authorization probe.

The thing worth testing hard is the violation decision. A probe that
under-reports tells you an endpoint is safe when it is not, which is worse
than having no probe at all. So every branch that can return "ok" gets a test.

Network calls are stubbed by replacing `Probe._send`, except for one
end-to-end case against a stdlib HTTP server so the real request path stays
exercised.
"""

from __future__ import annotations

import json
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

import pytest

from authzprobe.probe import Exchange, Probe, ProbeError

SPEC = {
    "target": {
        "name": "stub",
        "base_url": "http://stub.invalid",
        "login": {
            "method": "POST",
            "path": "/login",
            "body": {"username": "$username", "password": "$password"},
            "token_field": "auth_token",
            "header_name": "Authorization",
            "header_value": "Bearer {token}",
        },
    },
    "identities": [
        {"id": "owner", "username": "a", "password": "a"},
        {"id": "other", "username": "b", "password": "b"},
        {"id": "anon"},
    ],
    "cases": [],
}


def probe_with(statuses: dict[str, int], body: str = "{}") -> Probe:
    """A probe whose every request returns a canned status per identity."""
    p = Probe(SPEC)
    for ident in p.identities.values():
        if not ident.anonymous:
            ident.token = "t"

    def fake_send(method, path, body_, identity=None):
        who = identity.id if identity else "-"
        return Exchange(
            identity=who, method=method, url=p.base + path, request_body=body_,
            status=statuses.get(who, 500), response_body=body,
        )

    p._send = fake_send  # noqa: SLF001
    return p


ACCESS_CASE = {
    "id": "T-1", "type": "access", "title": "t",
    "owasp": "API1:2023", "cwe": "CWE-639", "severity": "HIGH",
    "request": {"method": "GET", "path": "/thing/1"},
    "authorized": ["other"],
    "run_as": ["owner", "other", "anon"],
}


# --- the violation decision -------------------------------------------------


def test_unauthorized_identity_with_2xx_is_a_violation():
    p = probe_with({"owner": 200, "other": 200, "anon": 401})
    _, findings = p.run_access_case(ACCESS_CASE)
    assert [f.case_id for f in findings] == ["T-1"]
    assert "owner" in findings[0].detail


def test_authorized_identity_with_2xx_is_not_a_violation():
    p = probe_with({"owner": 404, "other": 200, "anon": 401})
    _, findings = p.run_access_case(ACCESS_CASE)
    assert findings == []


def test_unauthorized_identity_denied_is_not_a_violation():
    p = probe_with({"owner": 403, "other": 200, "anon": 401})
    _, findings = p.run_access_case(ACCESS_CASE)
    assert findings == []


def test_anonymous_access_is_reported_as_unauthenticated():
    p = probe_with({"owner": 404, "other": 200, "anon": 200})
    _, findings = p.run_access_case(ACCESS_CASE)
    assert len(findings) == 1
    assert "unauthenticated" in findings[0].detail


def test_every_unauthorized_identity_is_reported_separately():
    p = probe_with({"owner": 200, "other": 200, "anon": 200})
    _, findings = p.run_access_case(ACCESS_CASE)
    assert len(findings) == 2  # owner and anon; other is authorized


@pytest.mark.parametrize("status,is_violation",
                         [(200, True), (201, True), (204, True), (299, True),
                          (300, False), (304, False), (400, False), (401, False),
                          (403, False), (404, False), (500, False)])
def test_only_2xx_counts_as_access_granted(status, is_violation):
    p = probe_with({"owner": status, "other": 200, "anon": 401})
    _, findings = p.run_access_case(ACCESS_CASE)
    assert bool(findings) is is_violation


def test_case_with_no_authorized_identities_flags_everyone_who_succeeds():
    case = {**ACCESS_CASE, "authorized": []}
    p = probe_with({"owner": 200, "other": 200, "anon": 403})
    _, findings = p.run_access_case(case)
    assert len(findings) == 2
    assert "nobody" in findings[0].detail


def test_unknown_identity_in_a_case_is_an_error_not_a_pass():
    case = {**ACCESS_CASE, "run_as": ["owner", "ghost"]}
    p = probe_with({"owner": 404})
    with pytest.raises(ProbeError, match="unknown identity"):
        p.run_access_case(case)


# --- record selection, used for discovery and for verification --------------


LIST_BODY = json.dumps({"Books": [
    {"book_title": "t1", "user": "a"},
    {"book_title": "t2", "user": "b"},
]})


def test_pick_matches_on_a_field_and_returns_another():
    assert Probe._pick(LIST_BODY, "Books", {"user": "b"}, "book_title") == "t2"


def test_pick_returns_none_when_nothing_matches():
    assert Probe._pick(LIST_BODY, "Books", {"user": "zzz"}, "book_title") is None


def test_pick_compares_as_strings_so_yaml_ints_still_match():
    body = json.dumps({"rows": [{"id": 7, "name": "x"}]})
    assert Probe._pick(body, "rows", {"id": "7"}, "name") == "x"


def test_pick_rejects_non_json():
    with pytest.raises(ProbeError, match="expected JSON"):
        Probe._pick("<html>nope</html>", "Books", {}, "x")


def test_pick_rejects_a_missing_list():
    with pytest.raises(ProbeError, match="no list at key"):
        Probe._pick(json.dumps({"other": 1}), "Books", {}, "x")


def test_pick_rejects_a_matched_record_without_the_field():
    with pytest.raises(ProbeError, match="no field"):
        Probe._pick(LIST_BODY, "Books", {"user": "b"}, "nonexistent")


# --- mass assignment --------------------------------------------------------


MA_CASE = {
    "id": "T-2", "type": "mass_assignment", "title": "t",
    "owasp": "API3:2023", "cwe": "CWE-915", "severity": "HIGH",
    "request": {"method": "POST", "path": "/register", "body": {"username": "m"}},
    "inject": {"admin": True},
    "verify": {"request": {"method": "GET", "path": "/debug"},
               "list": "users", "where": {"username": "m"}, "take": "admin"},
    "violation_when_equals": True,
}


def ma_probe(readback):
    p = Probe(SPEC)
    body = json.dumps({"users": [{"username": "m", "admin": readback}]})

    def fake_send(method, path, body_, identity=None):
        return Exchange(identity="-", method=method, url=p.base + path,
                        request_body=body_, status=200, response_body=body)

    p._send = fake_send  # noqa: SLF001
    return p


def test_injected_field_that_persists_is_a_violation():
    _, findings = ma_probe(True).run_mass_assignment_case(MA_CASE)
    assert len(findings) == 1
    assert "client-writable" in findings[0].detail


def test_injected_field_the_server_ignored_is_not_a_violation():
    """A 200 on the write proves nothing. Only the read-back decides."""
    _, findings = ma_probe(False).run_mass_assignment_case(MA_CASE)
    assert findings == []


def test_injected_field_is_merged_over_the_base_body():
    p = ma_probe(True)
    sent = []
    inner = p._send

    def spy(method, path, body_, identity=None):
        sent.append(body_)
        return inner(method, path, body_, identity)

    p._send = spy  # noqa: SLF001
    p.run_mass_assignment_case(MA_CASE)
    assert sent[0] == {"username": "m", "admin": True}


# --- placeholder substitution ----------------------------------------------


def test_path_placeholders_are_resolved_from_discovered_variables():
    p = Probe(SPEC)
    p.variables = {"other_book": "bookTitle42"}
    assert p._resolve("/books/v1/{other_book}") == "/books/v1/bookTitle42"


def test_unknown_placeholder_is_left_alone_rather_than_crashing():
    p = Probe(SPEC)
    assert p._resolve("/books/v1/{nope}") == "/books/v1/{nope}"


def test_missing_base_url_is_an_error():
    with pytest.raises(ProbeError, match="no base_url"):
        Probe({"target": {}, "identities": []})


# --- one end-to-end run against a real socket ------------------------------


class _Handler(BaseHTTPRequestHandler):
    def do_GET(self):  # noqa: N802
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(b'{"ok": true}')

    def log_message(self, *args):
        pass


@pytest.fixture
def live_server():
    server = HTTPServer(("127.0.0.1", 0), _Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    yield f"http://127.0.0.1:{server.server_port}"
    server.shutdown()
    server.server_close()


def test_real_request_path_reports_a_violation_end_to_end(live_server):
    """Exercises requests, not a stub: everyone gets 200, nobody is authorized."""
    spec = {
        "target": {"name": "live", "base_url": live_server},
        "identities": [{"id": "anon"}],
        "cases": [{
            "id": "E2E", "type": "access", "title": "t",
            "owasp": "API1:2023", "cwe": "CWE-639", "severity": "HIGH",
            "request": {"method": "GET", "path": "/anything"},
            "authorized": [], "run_as": ["anon"],
        }],
    }
    probe = Probe(spec)
    findings = probe.run()
    assert len(findings) == 1
    assert probe.exchanges[0][1].status == 200


def test_unreachable_target_raises_rather_than_reporting_clean():
    probe = Probe({**SPEC, "target": {"name": "x", "base_url": "http://127.0.0.1:59998"}})
    with pytest.raises(ProbeError, match="failed"):
        probe._send("GET", "/x", None)


# --- effect confirmation on mutating cases ---------------------------------
#
# This is the one piece of logic that can SUPPRESS a finding, so it gets the
# hardest tests in the file. It exists because a status-code-only comparison
# reported a violation against VAmPI's fixed build: that build returns 204
# from the password endpoint and updates the caller's own record instead of
# the path target. Correct code, flagged.
#
# The risk now runs the other way. A confirmation step that wrongly fails
# hides a real account takeover.

MUTATING_CASE = {
    "id": "T-3", "type": "access", "title": "t",
    "owasp": "API1:2023", "cwe": "CWE-639", "severity": "CRITICAL",
    "request": {"method": "PUT", "path": "/users/v1/victim/password",
                "body": {"password": "set-by-probe"}},
    "authorized": ["other"],
    "run_as": ["owner"],
    "confirm_effect": {
        "request": {"method": "POST", "path": "/login",
                    "body": {"username": "victim", "password": "set-by-probe"}},
        "expect_contains": "auth_token",
    },
}


def probe_with_confirm(write_status: int, confirm_body: str) -> Probe:
    """Write returns `write_status`; the confirmation returns `confirm_body`."""
    p = Probe(SPEC)
    for ident in p.identities.values():
        if not ident.anonymous:
            ident.token = "t"

    def fake_send(method, path, body_, identity=None):
        is_confirm = path == "/login"
        return Exchange(
            identity=identity.id if identity else "-", method=method,
            url=p.base + path, request_body=body_,
            status=200 if is_confirm else write_status,
            response_body=confirm_body if is_confirm else "",
        )

    p._send = fake_send  # noqa: SLF001
    return p


def test_confirmed_effect_reports_the_violation():
    p = probe_with_confirm(204, '{"auth_token": "eyJ..."}')
    _, findings = p.run_access_case(MUTATING_CASE)
    assert len(findings) == 1
    assert "confirmed" in findings[0].detail


def test_unconfirmed_effect_suppresses_the_violation():
    """The fixed build: 204, but the victim's password never changed."""
    p = probe_with_confirm(204, '{"status": "fail", "message": "Password is not correct"}')
    _, findings = p.run_access_case(MUTATING_CASE)
    assert findings == []


def test_unconfirmed_effect_is_recorded_on_the_exchange():
    """So the matrix can print 'no effect on target' instead of a bare ok."""
    p = probe_with_confirm(204, '{"status": "fail"}')
    exchanges, _ = p.run_access_case(MUTATING_CASE)
    assert exchanges[0].effect_confirmed is False


def test_confirmation_matches_content_not_status():
    """VAmPI returns 200 on a FAILED login, so status is no signal at all.

    Both branches below see HTTP 200 from the confirmation request. Only the
    body distinguishes a real takeover from a no-op.
    """
    assert probe_with_confirm(204, '{"auth_token": "x"}').run_access_case(MUTATING_CASE)[1]
    assert not probe_with_confirm(204, '{"message": "fail"}').run_access_case(MUTATING_CASE)[1]


def test_a_denied_write_never_runs_the_confirmation():
    """No 2xx, no finding, and no wasted mutation of the target."""
    calls = []
    p = probe_with_confirm(403, '{"auth_token": "x"}')
    inner = p._send

    def spy(method, path, body_, identity=None):
        calls.append(path)
        return inner(method, path, body_, identity)

    p._send = spy  # noqa: SLF001
    _, findings = p.run_access_case(MUTATING_CASE)
    assert findings == []
    assert "/login" not in calls


def test_authorized_identity_never_runs_the_confirmation():
    """Confirming for the legitimate owner would mutate state for nothing."""
    case = {**MUTATING_CASE, "run_as": ["other"]}
    calls = []
    p = probe_with_confirm(204, '{"auth_token": "x"}')
    inner = p._send

    def spy(method, path, body_, identity=None):
        calls.append(path)
        return inner(method, path, body_, identity)

    p._send = spy  # noqa: SLF001
    _, findings = p.run_access_case(case)
    assert findings == []
    assert "/login" not in calls


def test_case_without_confirm_effect_is_unchanged():
    """A GET needs no confirmation: the response body IS the evidence."""
    p = probe_with({"owner": 200, "other": 200, "anon": 401})
    _, findings = p.run_access_case(ACCESS_CASE)
    assert len(findings) == 1
    assert "confirmed" not in findings[0].detail


# --- credential redaction in captures --------------------------------------
#
# Captures are committed and read by strangers. An earlier version redacted
# only the Authorization request header, so the BOLA-02 confirmation, which
# logs in as the victim, wrote a live JWT from the RESPONSE body straight into
# the capture file. The gitleaks pre-commit hook caught it. These tests mean
# the hook does not have to catch it twice.


def _jwt_shaped() -> str:
    """Build a JWT-shaped string at runtime.

    Deliberately not a literal. A hardcoded `eyJ...` fixture is what secret
    scanners are built to find, and a test file full of suppressions teaches
    the next person that gitleaks findings are noise. Base64url of a JSON
    header starts with `eyJ` on its own, so this exercises the real regex
    without putting a credential-shaped string in the source.
    """
    import base64

    def seg(text: str) -> str:
        return base64.urlsafe_b64encode(text.encode()).decode().rstrip("=")

    return f'{seg(chr(123) + '"alg":"none"' + chr(125))}.{seg(chr(123) + '"sub":"test"' + chr(125))}.{seg("not-a-real-signature")}'


def test_jwt_in_a_response_body_is_redacted():
    from authzprobe.probe import redact_tokens

    token = _jwt_shaped()
    body = f'{{"auth_token": "{token}", "status": "success"}}'
    out = redact_tokens(body)
    assert token not in out
    assert "<redacted-jwt>" in out
    assert '"status": "success"' in out, "non-credential fields must survive"


def test_named_token_fields_are_redacted_even_when_not_jwt_shaped():
    from authzprobe.probe import redact_tokens

    # Low-entropy on purpose: the point is the field NAME, and a
    # realistic-looking opaque token here would just be another secret
    # scanners have to be told to ignore.
    token = "placeholder-" + "x" * 20
    body = f'{{"access_token": "{token}", "expires_in": 3600}}'
    out = redact_tokens(body, ("access_token",))
    assert token not in out
    assert "3600" in out


def test_redaction_leaves_ordinary_bodies_alone():
    from authzprobe.probe import redact_tokens

    body = '{"book_title": "bookTitle66", "owner": "name2", "secret": "s"}'
    assert redact_tokens(body, ("auth_token",)) == body


def test_short_values_are_not_mangled():
    """Redacting a 2-character value would destroy evidence for no gain."""
    from authzprobe.probe import redact_tokens

    body = '{"token": "no"}'
    assert redact_tokens(body, ("token",)) == body


def test_written_captures_contain_no_jwt(tmp_path):
    """End to end: a capture written from a token-bearing exchange is clean."""
    p = Probe(SPEC)
    p.exchanges = [("T-1", Exchange(
        identity="anon", method="POST", url="http://x/login", request_body=None,
        status=200,
        response_body=f'{{"auth_token": "{_jwt_shaped()}"}}',
    ))]
    written = p.write_captures(tmp_path).read_text(encoding="utf-8")
    assert _jwt_shaped() not in written
    assert "<redacted" in written
