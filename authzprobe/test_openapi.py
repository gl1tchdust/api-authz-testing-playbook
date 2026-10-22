"""Tests for reading the authorization model an OpenAPI document declares.

The last test in this file is the one that matters. It pins the result against
VAmPI's real published specification, where the module recovers both documented
object-level findings, excludes the ones the specification itself declares
public, and surfaces two operations the handwritten playbook never covered.
"""

from __future__ import annotations

import pathlib

import pytest
import yaml

from authzprobe.openapi import (
    Operation,
    bola_candidates,
    declared_scopes,
    emit_cases,
    load,
    render,
    scope_conflicts,
)

VAMPI_SPEC = pathlib.Path(".target/vampi/openapi_specs/openapi3.yml")


def _write(tmp_path: pathlib.Path, doc: dict, name: str = "openapi.yml") -> pathlib.Path:
    path = tmp_path / name
    path.write_text(yaml.safe_dump(doc), encoding="utf-8")
    return path


def _doc(paths: dict, **extra) -> dict:
    return {"openapi": "3.0.0", "info": {"title": "t", "version": "1"},
            "paths": paths, **extra}


# ---------------------------------------------------------------------------
# security resolution
# ---------------------------------------------------------------------------

def test_operation_level_security_is_read(tmp_path):
    spec = _write(tmp_path, _doc({
        "/a": {"get": {"security": [{"oauth2": ["read"]}]}},
    }))
    _, ops = load(spec)
    assert len(ops) == 1
    assert ops[0].authenticated is True
    assert ops[0].schemes == ["oauth2"]
    assert ops[0].scopes == ["read"]
    assert ops[0].security_inherited is False


def test_an_operation_without_security_inherits_the_document_default(tmp_path):
    spec = _write(tmp_path, _doc(
        {"/a": {"get": {}}},
        security=[{"bearerAuth": []}],
    ))
    _, ops = load(spec)
    assert ops[0].authenticated is True
    assert ops[0].security_inherited is True


def test_an_empty_security_list_is_an_explicit_public_override(tmp_path):
    """`security: []` is not missing configuration.

    It makes the operation public even when the document declares a default.
    Reading it as authenticated would report every deliberately public endpoint
    as unenforced, which is the fastest way to make the output ignorable.
    """
    spec = _write(tmp_path, _doc(
        {"/login": {"post": {"security": []}}},
        security=[{"bearerAuth": []}],
    ))
    _, ops = load(spec)
    assert ops[0].authenticated is False
    assert ops[0].security_inherited is False


def test_a_requirement_of_empty_dicts_is_not_authentication(tmp_path):
    """`security: [{}]` means the operation may be called with nothing."""
    spec = _write(tmp_path, _doc({"/a": {"get": {"security": [{}]}}}))
    _, ops = load(spec)
    assert ops[0].authenticated is False


def test_non_operation_keys_in_a_path_item_are_ignored(tmp_path):
    spec = _write(tmp_path, _doc({
        "/a": {"summary": "not an operation",
               "parameters": [{"name": "x", "in": "query"}],
               "get": {"security": [{"k": []}]}},
    }))
    _, ops = load(spec)
    assert [str(o) for o in ops] == ["GET /a"]


def test_scopes_are_unioned_across_alternative_requirements(tmp_path):
    spec = _write(tmp_path, _doc({
        "/a": {"get": {"security": [{"oauth2": ["read"]}, {"oauth2": ["admin"]}]}},
    }))
    _, ops = load(spec)
    assert ops[0].scopes == ["admin", "read"]


def test_a_document_without_a_version_key_is_rejected(tmp_path):
    spec = _write(tmp_path, {"paths": {"/a": {"get": {}}}})
    with pytest.raises(ValueError, match="openapi or swagger"):
        load(spec)


def test_a_json_document_loads(tmp_path):
    """JSON is a subset of YAML, so one loader covers both file types."""
    import json
    path = tmp_path / "openapi.json"
    path.write_text(json.dumps(_doc({"/a": {"get": {"security": [{"k": []}]}}})),
                    encoding="utf-8")
    _, ops = load(path)
    assert ops[0].authenticated is True


# ---------------------------------------------------------------------------
# declared scopes
# ---------------------------------------------------------------------------

def test_scopes_are_collected_from_oauth2_flows(tmp_path):
    spec = _write(tmp_path, _doc({}, components={"securitySchemes": {"oauth2": {
        "type": "oauth2",
        "flows": {
            "clientCredentials": {"tokenUrl": "/t", "scopes": {"a:read": "A"}},
            "authorizationCode": {"tokenUrl": "/t", "authorizationUrl": "/a",
                                  "scopes": {"a:write": "B"}},
        },
    }}}))
    doc, _ = load(spec)
    assert declared_scopes(doc) == {"oauth2": {"a:read": "A", "a:write": "B"}}


def test_swagger2_scopes_on_the_scheme_are_collected(tmp_path):
    path = tmp_path / "swagger.yml"
    path.write_text(yaml.safe_dump({
        "swagger": "2.0", "paths": {},
        "securityDefinitions": {"oauth": {"type": "oauth2",
                                          "scopes": {"legacy": "L"}}},
    }), encoding="utf-8")
    doc, _ = load(path)
    assert declared_scopes(doc) == {"oauth": {"legacy": "L"}}


def test_a_scheme_without_scopes_is_omitted(tmp_path):
    spec = _write(tmp_path, _doc({}, components={"securitySchemes": {
        "bearerAuth": {"type": "http", "scheme": "bearer"}}}))
    doc, _ = load(spec)
    assert declared_scopes(doc) == {}


# ---------------------------------------------------------------------------
# scope enforcement, the conformance test the document itself defines
# ---------------------------------------------------------------------------

def _scoped_ops() -> list[Operation]:
    return [
        Operation("get", "/orders", None, [{"o": ["orders:read"]}], False),
        Operation("post", "/orders", None, [{"o": ["orders:write"]}], False),
        Operation("get", "/health", None, [], False),
    ]


def test_an_operation_requiring_a_scope_the_principal_lacks_is_a_conflict():
    conflicts = scope_conflicts(_scoped_ops(), ["orders:read"])
    assert [(str(op), missing) for op, missing in conflicts] == [
        ("POST /orders", ["orders:write"]),
    ]


def test_a_principal_holding_everything_has_no_conflicts():
    assert scope_conflicts(_scoped_ops(), ["orders:read", "orders:write"]) == []


def test_a_principal_holding_nothing_conflicts_with_every_scoped_operation():
    conflicts = scope_conflicts(_scoped_ops(), [])
    assert {str(op) for op, _ in conflicts} == {"GET /orders", "POST /orders"}


def test_operations_requiring_no_scope_are_never_conflicts():
    """An operation with a scheme but no scopes cannot be scope-tested."""
    ops = [Operation("get", "/a", None, [{"bearerAuth": []}], False)]
    assert scope_conflicts(ops, []) == []


# ---------------------------------------------------------------------------
# object-level candidates
# ---------------------------------------------------------------------------

def test_an_authenticated_operation_with_an_identifier_is_a_candidate():
    ops = [Operation("put", "/users/{username}/email", None, [{"b": []}], False)]
    assert [str(o) for o in bola_candidates(ops)] == ["PUT /users/{username}/email"]
    assert ops[0].identifier_params == ["username"]


def test_a_public_operation_with_an_identifier_is_not_a_candidate():
    """The probe's BOLA-03 lives here: VAmPI's spec declares
    GET /users/v1/{username} public, so the specification agrees with the
    implementation and conformance has nothing to say. That case has to be
    written by hand, which is why this module emits stubs rather than verdicts.
    """
    ops = [Operation("get", "/users/{username}", None, [], False)]
    assert bola_candidates(ops) == []


def test_an_authenticated_operation_with_no_path_parameter_is_not_a_candidate():
    ops = [Operation("get", "/me", None, [{"b": []}], False)]
    assert bola_candidates(ops) == []


@pytest.mark.parametrize("param,is_identifier", [
    ("username", True), ("userId", True), ("book_title", True), ("orderId", True),
    ("uuid", True), ("account", True), ("file_key", True),
    ("page", False), ("limit", False), ("offset", False), ("sort", False),
])
def test_identifier_parameters_are_distinguished_from_pagination(param, is_identifier):
    op = Operation("get", f"/a/{{{param}}}", None, [{"b": []}], False)
    assert bool(op.identifier_params) is is_identifier


# ---------------------------------------------------------------------------
# emitted stubs
# ---------------------------------------------------------------------------

def test_emitted_stubs_are_valid_yaml_and_assert_nothing():
    ops = [Operation("put", "/users/{username}/email", "updateEmail",
                     [{"b": []}], False)]
    text = emit_cases(ops)
    parsed = yaml.safe_load(text)
    assert len(parsed["cases"]) == 1
    case = parsed["cases"][0]
    # The point of a stub: it must not pretend to know who is authorized.
    assert case["authorized"] == []
    assert "TODO" in case["id"]
    # The path keeps OpenAPI's `{name}` templating, which is also the probe's
    # placeholder syntax, so the stub already points at the variable the author
    # must declare. An earlier version escaped these to `{{name}}`, producing a
    # path that was neither a template nor a literal.
    assert case["request"]["path"] == "/users/{username}/email"


def test_no_candidates_emits_a_comment_not_an_empty_cases_key():
    """An empty `cases:` list would be a valid file that silently tests
    nothing, which is worse than a file that says so."""
    text = emit_cases([])
    assert yaml.safe_load(text) is None
    assert "No authenticated operations" in text


def test_render_names_what_the_document_cannot_express():
    doc = _doc({})
    text = render(doc, [Operation("put", "/u/{id}", None, [{"b": []}], False)], None)
    assert "cannot express who owns" in text
    assert "PUT /u/{id}" in text


# ---------------------------------------------------------------------------
# against the real published specification
# ---------------------------------------------------------------------------

@pytest.mark.skipif(not VAMPI_SPEC.exists(),
                    reason="run ./scripts/vampi.sh fetch first")
def test_vampi_spec_yields_the_documented_authorization_model():
    """Pins the real-world result, measured 2026-10-23.

    All six declared-authenticated operations were verified by hand to return
    401 to an unauthenticated caller, so VAmPI enforces the model it publishes
    and a conformance checker finds nothing. Its real flaws are elsewhere:

      BOLA-01  GET /books/v1/{book_title}      -> a candidate below
      BOLA-02  PUT /users/v1/{username}/pass.. -> a candidate below
      BOLA-03  GET /users/v1/{username}        -> declared PUBLIC, so absent
      BFLA-01  GET /users/v1/_debug            -> declared PUBLIC, so absent

    The two absences are the finding, not a gap: object-level and
    function-level authorization are not expressible in an OpenAPI security
    block, so no amount of conformance testing reaches them.
    """
    doc, ops = load(VAMPI_SPEC)
    assert len(ops) == 14

    public = {str(o) for o in ops if not o.authenticated}
    authed = {str(o) for o in ops if o.authenticated}
    assert len(public) == 8 and len(authed) == 6

    # The specification is complicit in the worst endpoint in the target.
    assert "GET /users/v1/_debug" in public
    assert "GET /users/v1/{username}" in public

    candidates = {str(o) for o in bola_candidates(ops)}
    assert candidates == {
        "DELETE /users/v1/{username}",
        "GET /books/v1/{book_title}",
        "PUT /users/v1/{username}/email",
        "PUT /users/v1/{username}/password",
    }

    # Recovers both documented object-level findings.
    assert "GET /books/v1/{book_title}" in candidates
    assert "PUT /users/v1/{username}/password" in candidates

    # VAmPI declares no scopes, so there is nothing to conformance-test.
    assert declared_scopes(doc) == {}
