#!/usr/bin/env python3
"""Differential authorization probe.

Replays one request as several identities and reports where authorization
failed to distinguish between them.

    python -m authzprobe.probe --cases authzprobe/cases.yml
    python -m authzprobe.probe --cases authzprobe/cases.yml --capture captures/

The technique, in one sentence: an authorization bug is never visible in a
single response. `200 OK` is correct for the owner and a critical finding for
anybody else, so the only way to see it is to send the same request as two
principals and compare.

That is also why this is a tool and not a list of curl commands. Keeping the
identities, the token handling and the expected-access matrix in one place is
what makes the comparison routine instead of something you eyeball.

Exit codes:
    0  every case behaved as its definition says it should
    1  at least one authorization violation
    2  could not run: target unreachable, bad case file, login failed
"""

from __future__ import annotations

import argparse
import dataclasses
import datetime as dt
import json
import os
import pathlib
import re
import sys

import requests
import yaml

TIMEOUT = 15

# How the probe gets a credential for each identity.
#
#   form   POST a JSON body to a login path and read a token out of the
#          response. What VAmPI and most teaching targets do.
#   oauth2_password            RFC 6749 section 4.3
#   oauth2_client_credentials  RFC 6749 section 4.4
#
# An identity that carries `token` directly needs none of these, which covers
# static bearer tokens and API keys without a mode of its own.
AUTH_MODES = frozenset({"form", "oauth2_password", "oauth2_client_credentials"})


class ProbeError(Exception):
    """Something stopped the run. Never used to report a finding."""


@dataclasses.dataclass
class Identity:
    id: str
    username: str | None = None
    password: str | None = None
    # Supplied directly for a target that hands out long-lived tokens or API
    # keys. An identity that already has one skips acquisition entirely.
    token: str | None = None
    # OAuth2 client credentials, for the two grants in RFC 6749 this supports.
    client_id: str | None = None
    client_secret: str | None = None
    scope: str | None = None

    @property
    def anonymous(self) -> bool:
        """No credential of any kind, so the probe sends the request bare.

        This used to be `username is None`, which was right while form login
        was the only way in. It silently misclassifies every token-based
        identity: a client-credentials principal has no username, so it was
        treated as the anonymous arm and the whole differential collapsed into
        comparing anonymous against anonymous.
        """
        return not (self.username or self.token or self.client_id)


@dataclasses.dataclass
class Exchange:
    """One request/response pair, kept verbatim so captures are real."""

    identity: str
    method: str
    url: str
    request_body: dict | None
    status: int
    response_body: str
    # None for a non-mutating case, where the response is the evidence.
    # False means the write returned 2xx but did not affect the target.
    effect_confirmed: bool | None = None

    def pretty_request(self, header: str | None) -> str:
        lines = [f"{self.method} {self.url}"]
        if header:
            lines.append(header)
        if self.request_body is not None:
            lines.append("Content-Type: application/json")
            lines.append("")
            lines.append(json.dumps(self.request_body, indent=2))
        return "\n".join(lines)


# A JWT, or any long opaque token, appearing anywhere in a captured response.
#
# Captures redact the Authorization header on requests, which is the obvious
# place a credential appears and the only one an earlier version handled. It is
# not the only one: the BOLA-02 confirmation logs in as the victim, so the
# *response* carries a live token straight into the committed capture file.
# The gitleaks pre-commit hook caught that before it was committed, which is
# the entire reason the hook is installed.
_JWT = re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}")


def _expand_env(value, identity_id: str, field: str):
    """Expand `$VAR` and `${VAR}` in an identity field.

    A case file is committed to a repository; a client secret is not. Reading
    credentials from the environment is the only arrangement where those two
    facts coexist.

    `expandvars` leaves an undefined name untouched, which would send the
    literal string `${CLIENT_SECRET}` as the secret and fail at the token
    endpoint as an ordinary 401. That is a confusing way to learn you forgot an
    export, so an unexpanded placeholder is an error here instead.
    """
    if not isinstance(value, str):
        return value
    expanded = os.path.expandvars(value)
    if "$" in expanded and re.search(r"\$\{?\w+\}?", expanded):
        raise ProbeError(
            f"identity {identity_id!r} field {field!r} references an unset "
            f"environment variable: {value!r}"
        )
    return expanded


def redact_tokens(body: str, extra_fields: tuple[str, ...] = ()) -> str:
    """Strip credential material out of a response body before it is written.

    Captures are committed to the repository and read by strangers. A token
    that is only valid against a local throwaway target is still a credential
    in a public file, and treating it as harmless is how the habit forms.
    """
    redacted = _JWT.sub("<redacted-jwt>", body)
    for field in extra_fields:
        redacted = re.sub(
            rf'("{re.escape(field)}"\s*:\s*")([^"]{{8,}})(")',
            r"\1<redacted>\3",
            redacted,
        )
    return redacted


@dataclasses.dataclass
class Finding:
    case_id: str
    title: str
    owasp: str
    cwe: str
    severity: str
    detail: str


class Probe:
    def __init__(self, spec: dict, base_url: str | None = None):
        self.target = spec.get("target") or {}
        self.base = (base_url or self.target.get("base_url") or "").rstrip("/")
        if not self.base:
            raise ProbeError("no base_url in the case file and none passed on the command line")
        # `auth` is the current spelling; `login` is the original one and still
        # works, because the VAmPI case file and its captures are written
        # against it. An unrecognised mode is rejected at load time rather than
        # part-way through a run.
        self.login_cfg = self.target.get("auth") or self.target.get("login") or {}
        self.auth_mode = self.login_cfg.get("mode", "form")
        if self.auth_mode not in AUTH_MODES:
            raise ProbeError(
                f"unknown auth mode {self.auth_mode!r}, expected one of "
                f"{', '.join(sorted(AUTH_MODES))}"
            )
        self.identities = {
            i["id"]: Identity(**{k: _expand_env(v, i.get("id", "?"), k)
                                 for k, v in i.items()})
            for i in (spec.get("identities") or [])
        }
        self.variables_spec = spec.get("variables") or {}
        self.cases = spec.get("cases") or []
        self.variables: dict[str, str] = {}
        self.exchanges: list[tuple[str, Exchange]] = []

    # -- plumbing ----------------------------------------------------------

    def _auth_header(self, identity: Identity) -> dict[str, str]:
        if identity.anonymous or not identity.token:
            return {}
        name = self.login_cfg.get("header_name", "Authorization")
        value = self.login_cfg.get("header_value", "Bearer {token}")
        return {name: value.format(token=identity.token)}

    def _send(self, method: str, path: str, body: dict | None,
              identity: Identity | None = None) -> Exchange:
        url = self.base + path
        headers = self._auth_header(identity) if identity else {}
        try:
            resp = requests.request(
                method.upper(), url, json=body, headers=headers, timeout=TIMEOUT
            )
        except requests.RequestException as exc:
            raise ProbeError(f"{method} {url} failed: {exc}") from exc
        return Exchange(
            identity=identity.id if identity else "-",
            method=method.upper(),
            url=url,
            request_body=body,
            status=resp.status_code,
            response_body=resp.text,
        )

    def _resolve(self, text: str) -> str:
        """Substitute {var} placeholders from discovered variables."""
        for key, value in self.variables.items():
            text = text.replace("{" + key + "}", str(value))
        return text

    @staticmethod
    def _pick(payload: str, list_key: str, where: dict, take: str):
        """Find one record in a JSON list response and return one of its fields."""
        try:
            doc = json.loads(payload)
        except json.JSONDecodeError as exc:
            raise ProbeError(f"expected JSON, got: {payload[:120]!r}") from exc
        items = doc.get(list_key)
        if not isinstance(items, list):
            raise ProbeError(f"no list at key {list_key!r} in response")
        for item in items:
            if all(str(item.get(k)) == str(v) for k, v in where.items()):
                if take not in item:
                    raise ProbeError(f"matched record has no field {take!r}")
                return item[take]
        return None

    # -- setup -------------------------------------------------------------

    def seed(self) -> None:
        for step in self.target.get("seed") or []:
            self._send(step["method"], step["path"], step.get("body"))

    def _acquire_form(self, identity: Identity) -> str:
        """POST a JSON login body and read the token out of the response."""
        body = {
            k: str(v).replace("$username", identity.username or "")
                       .replace("$password", identity.password or "")
            for k, v in (self.login_cfg.get("body") or {}).items()
        }
        ex = self._send(self.login_cfg["method"], self.login_cfg["path"], body)
        if ex.status != 200:
            raise ProbeError(
                f"login failed for {identity.id!r}: HTTP {ex.status} {ex.response_body[:160]}"
            )
        try:
            return json.loads(ex.response_body)[self.login_cfg["token_field"]]
        except (json.JSONDecodeError, KeyError) as exc:
            raise ProbeError(f"no token for {identity.id!r} in login response") from exc

    def _acquire_oauth2(self, identity: Identity, mode: str) -> str:
        """Run an OAuth2 token request for one identity.

        Deliberately not routed through `_send`. The token endpoint is
        form-encoded rather than JSON, frequently lives on a different host to
        the API under test, and the request body carries a client secret. None
        of that belongs in the method that records evidence.
        """
        token_url = self.login_cfg.get("token_url") or self.login_cfg.get("path")
        if not token_url:
            raise ProbeError("auth mode is oauth2 but no token_url is configured")
        if not token_url.startswith(("http://", "https://")):
            token_url = self.base + token_url

        if mode == "oauth2_client_credentials":
            data = {"grant_type": "client_credentials"}
            if not identity.client_id:
                raise ProbeError(f"{identity.id!r} has no client_id for client_credentials")
        else:
            data = {"grant_type": "password",
                    "username": identity.username or "",
                    "password": identity.password or ""}
            if not identity.username:
                raise ProbeError(f"{identity.id!r} has no username for the password grant")
        if identity.scope:
            data["scope"] = identity.scope

        # RFC 6749 section 2.3.1 permits either HTTP Basic or the request body
        # for client credentials, and servers differ on which they accept.
        auth = None
        placement = self.login_cfg.get("credentials", "body")
        if identity.client_id:
            if placement == "basic":
                auth = (identity.client_id, identity.client_secret or "")
            elif placement == "body":
                data["client_id"] = identity.client_id
                if identity.client_secret:
                    data["client_secret"] = identity.client_secret
            else:
                raise ProbeError(
                    f"credentials must be 'body' or 'basic', not {placement!r}"
                )

        try:
            resp = requests.post(token_url, data=data, auth=auth, timeout=TIMEOUT)
        except requests.RequestException as exc:
            raise ProbeError(f"token request to {token_url} failed: {exc}") from exc

        if resp.status_code != 200:
            # The body of a failed token response is an RFC 6749 error object,
            # not a credential, so it is safe and useful to surface.
            raise ProbeError(
                f"token request for {identity.id!r} returned HTTP "
                f"{resp.status_code}: {resp.text[:160]}"
            )
        field = self.login_cfg.get("token_field", "access_token")
        try:
            token = resp.json()[field]
        except (ValueError, KeyError) as exc:
            raise ProbeError(
                f"no {field!r} in the token response for {identity.id!r}"
            ) from exc
        if not token:
            raise ProbeError(f"empty {field!r} in the token response for {identity.id!r}")
        return token

    def authenticate(self) -> None:
        if not self.login_cfg:
            return
        for identity in self.identities.values():
            if identity.anonymous or identity.token:
                # Nothing to acquire: no credential at all, or one was supplied
                # in the case file, which is how a static bearer or API key
                # identity works.
                continue
            if self.auth_mode == "form":
                identity.token = self._acquire_form(identity)
            else:
                identity.token = self._acquire_oauth2(identity, self.auth_mode)

    def discover(self) -> None:
        for name, spec in self.variables_spec.items():
            req = spec["request"]
            ex = self._send(req["method"], req["path"], req.get("body"))
            value = self._pick(ex.response_body, spec["list"], spec["where"], spec["take"])
            if value is None:
                raise ProbeError(f"could not discover {name!r} from {req['path']}")
            self.variables[name] = value

    # -- the two case types ------------------------------------------------

    def _effect_confirmed(self, case: dict, case_id: str) -> tuple[bool, str]:
        """For a mutating case, did the write actually land on the victim?

        A 2xx on a write is not evidence. VAmPI's fixed build returns 204 from
        the password endpoint and quietly updates the *caller's* record instead
        of the path target, so a status-code comparison reports a violation
        against code that is correct. This is the same trap the mass-assignment
        cases avoid by reading the object back, and access cases that mutate
        need the same discipline.

        Confirmation matches on response content, not status: VAmPI returns 200
        on a failed login too, so the status code carries no signal here
        either.
        """
        confirm = case.get("confirm_effect")
        if not confirm:
            return True, ""  # non-mutating case; the response itself is the evidence

        req = confirm["request"]
        ex = self._send(req["method"], self._resolve(req["path"]), req.get("body"))
        self.exchanges.append((case_id, ex))

        needle = confirm["expect_contains"]
        if needle in ex.response_body:
            return True, f"confirmed: {needle!r} present in the follow-up response"
        return False, f"not confirmed: {needle!r} absent, so the write did not affect the target"

    def run_access_case(self, case: dict) -> tuple[list[Exchange], list[Finding]]:
        req = case["request"]
        path = self._resolve(req["path"])
        authorized = set(case.get("authorized") or [])
        exchanges, findings = [], []

        for ident_id in case.get("run_as") or list(self.identities):
            identity = self.identities.get(ident_id)
            if identity is None:
                raise ProbeError(f"case {case['id']}: unknown identity {ident_id!r}")
            ex = self._send(req["method"], path, req.get("body"), identity)
            exchanges.append(ex)
            self.exchanges.append((case["id"], ex))

            allowed = 200 <= ex.status < 300
            if not (allowed and ident_id not in authorized):
                continue

            # Confirm immediately, before another identity runs the same
            # mutation and muddies the result.
            confirmed, note = self._effect_confirmed(case, case["id"])
            ex.effect_confirmed = confirmed
            if not confirmed:
                continue

            who = "an unauthenticated caller" if identity.anonymous else f"identity {ident_id!r}"
            detail = (f"{who} received HTTP {ex.status} on "
                      f"{req['method'].upper()} {path}, which only "
                      f"{sorted(authorized) or ['nobody']} should reach")
            if note:
                detail += f". {note}"
            findings.append(Finding(
                case_id=case["id"], title=case["title"], owasp=case["owasp"],
                cwe=case["cwe"], severity=case.get("severity", "-"), detail=detail,
            ))
        return exchanges, findings

    def run_mass_assignment_case(self, case: dict) -> tuple[list[Exchange], list[Finding]]:
        req = case["request"]
        inject = case.get("inject") or {}
        body = {**(req.get("body") or {}), **inject}

        exchanges = [self._send(req["method"], self._resolve(req["path"]), body)]
        self.exchanges.append((case["id"], exchanges[0]))

        verify = case["verify"]
        vreq = verify["request"]
        vex = self._send(vreq["method"], self._resolve(vreq["path"]), vreq.get("body"))
        exchanges.append(vex)
        self.exchanges.append((case["id"], vex))

        observed = self._pick(vex.response_body, verify["list"], verify["where"], verify["take"])
        field = verify["take"]
        expected = case.get("violation_when_equals")

        findings = []
        if observed is not None and observed == expected:
            findings.append(Finding(
                case_id=case["id"], title=case["title"], owasp=case["owasp"],
                cwe=case["cwe"], severity=case.get("severity", "-"),
                detail=(f"field {field!r} was sent as {expected!r} by the client and "
                        f"read back as {observed!r}, so it is client-writable"),
            ))
        return exchanges, findings

    def run(self) -> list[Finding]:
        self.seed()
        self.authenticate()
        self.discover()

        all_findings: list[Finding] = []
        for case in self.cases:
            kind = case.get("type", "access")
            print(f"\n[{case['id']}] {case['title']}")
            if case.get("destructive"):
                print("  note: this case mutates the target")

            if kind == "access":
                exchanges, findings = self.run_access_case(case)
                authorized = set(case.get("authorized") or [])
                for ex in exchanges:
                    allowed = 200 <= ex.status < 300
                    suspect = allowed and ex.identity not in authorized
                    if suspect and ex.effect_confirmed is False:
                        # 2xx, but the write never reached the target object.
                        mark = "ok (2xx, no effect on target)"
                    elif suspect:
                        mark = "VIOLATION"
                    else:
                        mark = "ok"
                    print(f"  {ex.identity:<8} HTTP {ex.status:<4} {mark}")
            elif kind == "mass_assignment":
                _, findings = self.run_mass_assignment_case(case)
                print(f"  injected {case.get('inject')} -> "
                      f"{'persisted, VIOLATION' if findings else 'rejected, ok'}")
            else:
                raise ProbeError(f"case {case['id']}: unknown type {kind!r}")

            all_findings.extend(findings)
        return all_findings

    # -- capture -----------------------------------------------------------

    def write_captures(self, out: pathlib.Path) -> pathlib.Path:
        out.mkdir(parents=True, exist_ok=True)
        stamp = dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%d")
        path = out / f"{self.target.get('name', 'target').lower()}-{stamp}.md"

        lines = [
            f"# Captured exchanges: {self.target.get('name')}",
            "",
            f"Target: {self.target.get('repo')} at `{str(self.target.get('commit'))[:8]}`",
            f"Captured: {stamp} against `{self.base}`",
            "",
            "Generated by `authzprobe`. Every request and response below is a",
            "verbatim capture from a live run, not a hand-written example.",
            "Bearer tokens are omitted; re-run the probe to mint your own.",
            "",
        ]
        # Whatever the target calls its token, plus the usual suspects.
        token_fields = tuple({
            self.login_cfg.get("token_field", "auth_token"),
            "auth_token", "access_token", "refresh_token", "id_token", "token",
        })

        current = None
        for case_id, ex in self.exchanges:
            if case_id != current:
                lines += ["", f"## {case_id}", ""]
                current = case_id
            lines += [
                f"### as `{ex.identity}`",
                "",
                "```http",
                ex.pretty_request("Authorization: Bearer <redacted>"
                                  if ex.identity not in ("-", "anon") else None),
                "```",
                "",
                "```http",
                f"HTTP/1.1 {ex.status}",
                "",
                redact_tokens(ex.response_body.strip()[:1200], token_fields),
                "```",
                "",
            ]
        path.write_text("\n".join(lines), encoding="utf-8")
        return path


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--cases", type=pathlib.Path, default=pathlib.Path("authzprobe/cases.yml"))
    ap.add_argument("--base-url", default=None, help="override the target in the case file")
    ap.add_argument("--capture", type=pathlib.Path, default=None,
                    help="directory to write verbatim request/response captures into")
    ap.add_argument("--json-out", type=pathlib.Path, default=None,
                    help="write findings as JSON, for asserting on them in CI")
    args = ap.parse_args()

    if not args.cases.exists():
        print(f"case file not found: {args.cases}", file=sys.stderr)
        return 2

    try:
        spec = yaml.safe_load(args.cases.read_text(encoding="utf-8")) or {}
        probe = Probe(spec, base_url=args.base_url)
        print(f"target: {probe.target.get('name')} at {probe.base}")
        findings = probe.run()
        if args.capture:
            print(f"\ncaptures written to {probe.write_captures(args.capture)}")
    except ProbeError as exc:
        print(f"\nprobe could not complete: {exc}", file=sys.stderr)
        return 2

    if args.json_out:
        args.json_out.parent.mkdir(parents=True, exist_ok=True)
        args.json_out.write_text(
            json.dumps(
                {
                    "target": probe.target.get("name"),
                    "commit": probe.target.get("commit"),
                    "violations": len(findings),
                    "findings": [dataclasses.asdict(f) for f in findings],
                },
                indent=2,
            ),
            encoding="utf-8",
        )

    print(f"\n{'=' * 68}")
    if not findings:
        print("no authorization violations found")
        return 0

    print(f"{len(findings)} authorization violation(s)\n")
    for f in findings:
        print(f"  {f.severity:<9} {f.case_id:<14} {f.title}")
        print(f"  {'':<9} {f.owasp} / {f.cwe}")
        print(f"  {'':<9} {f.detail}\n")
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
