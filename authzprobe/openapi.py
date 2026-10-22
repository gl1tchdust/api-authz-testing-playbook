#!/usr/bin/env python3
"""Read the authorization model an OpenAPI document declares, and say what it
cannot declare.

    python -m authzprobe.openapi path/to/openapi.yml
    python -m authzprobe.openapi path/to/openapi.yml --emit-cases

Three outputs, in increasing order of usefulness.

1. The declared model. Which operations require a credential, which are
   public, and which scopes each one asks for. Printing this is not
   impressive, but a permission model spread across forty operation objects
   is one nobody has read end to end, and "these eight endpoints are public"
   is a sentence worth putting in front of a human.

2. Scope enforcement candidates. If the document declares OAuth2 scopes, then
   for a principal holding one scope every operation requiring a *different*
   scope must be refused. That is a conformance test the document itself
   defines, and `authzprobe` can run it.

3. BOLA candidates. This is the output that earns its keep, and it is not a
   conformance test at all.

On the third point, measured against VAmPI, whose spec declares six
operations as requiring a credential: all six correctly return 401 to an
unauthenticated caller, so a conformance checker finds nothing. Its real
authorization flaws are invisible to conformance for two different reasons.

`GET /users/v1/_debug` dumps every user record including passwords, and the
spec declares it public. Specification and implementation agree. The
specification is complicit, so conformance passes.

`PUT /users/v1/{username}/password` lets one authenticated user change
another's password. The spec says `security: [{bearerAuth: []}]`, which means
"a credential is required" and is satisfied. OpenAPI has no vocabulary for
"only the owner of {username} may call this", so object-level authorization
cannot be expressed, which means it cannot be checked.

What the document does do is tell you exactly where to look. Every real
authorization flaw in that target sits on an operation that the spec marks
as authenticated and that carries an object identifier in its path. That set
is small, mechanical to extract, and is the shortlist a human should write
cases against. So this module ends by emitting case stubs rather than
verdicts: the spec picks the targets, a person decides who should be allowed
to reach them.
"""

from __future__ import annotations

import argparse
import dataclasses
import json
import pathlib
import re
import sys

import yaml

METHODS = ("get", "put", "post", "delete", "patch", "head", "options", "trace")

# Path parameters whose name suggests they address a specific object rather
# than page, filter or shape the response. A false positive here costs a human
# ten seconds of reading; a false negative loses the case entirely, so the list
# leans inclusive.
IDENTIFIER_HINTS = (
    "id", "uuid", "guid", "key", "slug", "name", "title", "user", "username",
    "email", "account", "order", "invoice", "customer", "tenant", "org",
    "project", "file", "document", "record", "ref", "number", "code",
)

# Parameters that address a collection rather than one object.
NOT_IDENTIFIERS = ("page", "limit", "offset", "size", "sort", "order_by", "format")


@dataclasses.dataclass
class Operation:
    method: str
    path: str
    operation_id: str | None
    # Resolved: the operation's own `security`, or the document default.
    requirements: list[dict]
    security_inherited: bool

    @property
    def authenticated(self) -> bool:
        """True when at least one credential is required.

        An empty `security: []` on an operation is not missing configuration,
        it is an explicit override making the operation public even when the
        document declares a default. Treating those as authenticated would
        report every public endpoint as unenforced.
        """
        return bool(self.requirements) and any(self.requirements)

    @property
    def schemes(self) -> list[str]:
        return sorted({name for req in self.requirements for name in req})

    @property
    def scopes(self) -> list[str]:
        return sorted({s for req in self.requirements for scopes in req.values()
                       for s in (scopes or [])})

    @property
    def path_params(self) -> list[str]:
        return re.findall(r"\{([^}/]+)\}", self.path)

    @property
    def identifier_params(self) -> list[str]:
        out = []
        for param in self.path_params:
            low = param.lower()
            if any(bad in low for bad in NOT_IDENTIFIERS):
                continue
            if any(hint in low for hint in IDENTIFIER_HINTS):
                out.append(param)
        return out

    def __str__(self) -> str:
        return f"{self.method.upper()} {self.path}"


def load(path: pathlib.Path) -> tuple[dict, list[Operation]]:
    """Parse a document and resolve each operation's security requirement."""
    text = path.read_text(encoding="utf-8")
    # json is a subset of yaml, so one loader covers .json and .yaml alike.
    doc = yaml.safe_load(text)
    if not isinstance(doc, dict):
        raise ValueError(f"{path} is not an OpenAPI document")
    if not (doc.get("openapi") or doc.get("swagger")):
        raise ValueError(f"{path} has no openapi or swagger version key")

    default = doc.get("security")
    operations: list[Operation] = []
    for route, item in (doc.get("paths") or {}).items():
        if not isinstance(item, dict):
            continue
        for method, op in item.items():
            if method.lower() not in METHODS or not isinstance(op, dict):
                continue
            own = op.get("security")
            inherited = own is None
            operations.append(Operation(
                method=method.lower(),
                path=route,
                operation_id=op.get("operationId"),
                requirements=(default if inherited else own) or [],
                security_inherited=inherited,
            ))
    return doc, operations


def declared_scopes(doc: dict) -> dict[str, dict[str, str]]:
    """scheme name -> {scope: description}, across every OAuth2 flow."""
    schemes = ((doc.get("components") or {}).get("securitySchemes")
               or doc.get("securityDefinitions") or {})
    out: dict[str, dict[str, str]] = {}
    for name, scheme in schemes.items():
        if not isinstance(scheme, dict):
            continue
        scopes: dict[str, str] = {}
        for flow in (scheme.get("flows") or {}).values():
            if isinstance(flow, dict):
                scopes.update(flow.get("scopes") or {})
        # Swagger 2 put scopes directly on the scheme.
        scopes.update(scheme.get("scopes") or {})
        if scopes:
            out[name] = scopes
    return out


def scope_conflicts(operations: list[Operation],
                    held: list[str]) -> list[tuple[Operation, list[str]]]:
    """Operations a principal holding exactly `held` must be refused.

    The document defines this test, not the tester: an operation requiring
    `orders:write` must refuse a token that carries only `orders:read`. If it
    answers 2xx, the API is not enforcing the model it publishes.
    """
    have = set(held)
    out = []
    for op in operations:
        if not op.scopes:
            continue
        missing = [s for s in op.scopes if s not in have]
        if missing:
            out.append((op, missing))
    return out


def bola_candidates(operations: list[Operation]) -> list[Operation]:
    """Authenticated operations addressing a specific object by path.

    Not findings. The shortlist worth writing cases against, because
    object-level authorization is the thing OpenAPI cannot express and
    therefore the thing a conformance checker can never test.
    """
    return [op for op in operations if op.authenticated and op.identifier_params]


def render(doc: dict, operations: list[Operation], held: list[str] | None) -> str:
    scopes = declared_scopes(doc)
    auth = [op for op in operations if op.authenticated]
    public = [op for op in operations if not op.authenticated]
    lines: list[str] = []

    title = (doc.get("info") or {}).get("title") or "untitled"
    version = (doc.get("info") or {}).get("version") or "?"
    lines += [f"{title} {version}", f"{len(operations)} operations", ""]

    lines.append("DECLARED PUBLIC")
    if public:
        for op in sorted(public, key=str):
            note = "" if not op.security_inherited else "  (no security key)"
            lines.append(f"  {op}{note}")
    else:
        lines.append("  (none)")
    lines.append("")

    lines.append("DECLARED AUTHENTICATED")
    for op in sorted(auth, key=str):
        detail = ",".join(op.schemes)
        if op.scopes:
            detail += "  scopes: " + ",".join(op.scopes)
        lines.append(f"  {op}  [{detail}]")
    if not auth:
        lines.append("  (none)")
    lines.append("")

    if scopes:
        lines.append("DECLARED SCOPES")
        for scheme, defined in sorted(scopes.items()):
            lines.append(f"  {scheme}")
            for scope, desc in sorted(defined.items()):
                lines.append(f"    {scope:<28} {desc}")
        used = {s for op in operations for s in op.scopes}
        orphans = sorted({s for d in scopes.values() for s in d} - used)
        if orphans:
            lines += ["", "  declared but required by no operation:"]
            lines += [f"    {s}" for s in orphans]
        undeclared = sorted(used - {s for d in scopes.values() for s in d})
        if undeclared:
            # A scope an operation demands but the scheme never defines cannot
            # be granted, so the operation is unreachable rather than lax.
            lines += ["", "  required but declared by no scheme:"]
            lines += [f"    {s}" for s in undeclared]
        lines.append("")

    if held is not None:
        conflicts = scope_conflicts(operations, held)
        lines.append(f"SCOPE ENFORCEMENT, for a principal holding: "
                     f"{', '.join(held) or '(nothing)'}")
        if conflicts:
            lines.append("  these must all be refused:")
            for op, missing in sorted(conflicts, key=lambda c: str(c[0])):
                lines.append(f"    {op}  missing: {','.join(missing)}")
        else:
            lines.append("  no operation requires a scope this principal lacks")
        lines.append("")

    candidates = bola_candidates(operations)
    lines.append("OBJECT-LEVEL AUTHORIZATION CANDIDATES")
    lines.append("  Authenticated, and addressing one object by path. OpenAPI")
    lines.append("  cannot express who owns that object, so conformance cannot")
    lines.append("  test these. They are where to write cases by hand.")
    lines.append("")
    if candidates:
        for op in sorted(candidates, key=str):
            lines.append(f"  {op}  identifier: {','.join(op.identifier_params)}")
    else:
        lines.append("  (none)")
    return "\n".join(lines)


def emit_cases(operations: list[Operation]) -> str:
    """Case stubs for the object-level candidates, in cases.yml shape.

    Stubs, not cases. `authorized` is left as a placeholder on purpose: who
    should reach an object is the one thing neither the document nor this
    module knows, and a generated file that guessed would look like coverage
    while asserting whatever the generator assumed.
    """
    candidates = bola_candidates(operations)
    if not candidates:
        return "# No authenticated operations address an object by path.\n"

    out = [
        "# Generated by `python -m authzprobe.openapi --emit-cases`.",
        "# One stub per authenticated operation that addresses an object by",
        "# path. These are NOT cases yet. Set `authorized` to the identities",
        "# that should legitimately reach each object, and fill the path",
        "# parameter from a discovered variable. Until then every stub asserts",
        "# nothing.",
        "",
        "cases:",
    ]
    for op in sorted(candidates, key=str):
        slug = re.sub(r"[^a-z0-9]+", "-",
                      (op.operation_id or f"{op.method}-{op.path}").lower()).strip("-")
        out += [
            f"  - id: TODO-{slug}",
            f"    title: TODO who may {op.method.upper()} {op.path}",
            "    owasp: \"API1:2023 Broken Object Level Authorization\"",
            "    cwe: CWE-639",
            "    request:",
            f"      method: {op.method.upper()}",
            # OpenAPI path templating and the probe's variable placeholder are
            # the same `{name}` syntax, which is a convenience rather than a
            # coincidence worth relying on: emitting the parameter name as-is
            # means the stub already points at the variable the author has to
            # declare under `variables:`. An earlier version escaped these to
            # `{{name}}` to avoid substitution, which produced a path that was
            # neither a template nor a literal.
            f"      path: {op.path}  "
            f"# TODO declare {','.join(op.identifier_params)} under variables:",
            "    authorized: []  # TODO, an empty list asserts nothing",
            "",
        ]
    return "\n".join(out)


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("spec", type=pathlib.Path)
    ap.add_argument("--held-scopes", default=None,
                    help="comma-separated scopes a principal holds, to list "
                         "the operations that must refuse it")
    ap.add_argument("--emit-cases", action="store_true",
                    help="print cases.yml stubs for the object-level candidates")
    ap.add_argument("--json", action="store_true")
    args = ap.parse_args()

    try:
        doc, operations = load(args.spec)
    except (OSError, ValueError, yaml.YAMLError) as exc:
        print(f"could not read {args.spec}: {exc}", file=sys.stderr)
        return 2

    held = args.held_scopes.split(",") if args.held_scopes is not None else None
    held = [h.strip() for h in held if h.strip()] if held is not None else None

    if args.emit_cases:
        print(emit_cases(operations))
        return 0

    if args.json:
        print(json.dumps({
            "operations": [
                {"method": op.method, "path": op.path,
                 "operation_id": op.operation_id,
                 "authenticated": op.authenticated,
                 "schemes": op.schemes, "scopes": op.scopes,
                 "identifier_params": op.identifier_params}
                for op in operations
            ],
            "declared_scopes": declared_scopes(doc),
            "bola_candidates": [str(op) for op in bola_candidates(operations)],
        }, indent=1))
        return 0

    print(render(doc, operations, held))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
