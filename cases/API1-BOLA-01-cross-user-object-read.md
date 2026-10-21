# API1-BOLA-01: Cross-user object read via a path parameter

| | |
|---|---|
| **OWASP** | [API1:2023 Broken Object Level Authorization](https://owasp.org/API-Security/editions/2023/en/0xa1-broken-object-level-authorization/) |
| **CWE** | [CWE-639: Authorization Bypass Through User-Controlled Key](https://cwe.mitre.org/data/definitions/639.html) |
| **Severity** | High |
| **Validated against** | VAmPI at `f16052dc`, `GET /books/v1/{book_title}` |
| **Runnable** | `python -m authzprobe.probe` case `API1-BOLA-01` |

## Purpose

Establish whether the API authorizes the *object* or merely the *caller*. The
endpoint checks a bearer token and then looks the record up by an identifier
taken from the URL, so any authenticated caller can address any record.

This is the single most common API finding and the one most often missed in
testing, because every request involved returns a perfectly ordinary `200 OK`.
A scanner replaying one session sees nothing wrong. The bug only exists in the
*relationship* between two sessions' responses.

## Identification

1. Enumerate object identifiers and their owners. Look for a list endpoint
   that returns both. In VAmPI, `GET /books/v1` is unauthenticated and returns
   exactly that mapping, which hands you the input for the attack:

   ```json
   { "Books": [ { "book_title": "bookTitle66", "user": "name2" } ] }
   ```

   Where no such endpoint exists, identifiers are often sequential, or appear
   in notification emails, exports, or a sibling object's response.

2. Confirm the identifier is in the request rather than derived from the token.
   A path segment, a query parameter, or a body field are all request-controlled.
   A value read out of the JWT `sub` claim is not.

3. Register or obtain two accounts at the same privilege level. Two *peers*,
   not an admin and a user: an admin succeeding proves nothing about
   object-level authorization.

4. Send the identical request as both, and compare status and body.

## Implementation

Authenticate as the non-owner and request the owner's object:

```bash
TOKEN=$(curl -s -X POST http://127.0.0.1:5000/users/v1/login \
  -H 'Content-Type: application/json' \
  -d '{"username":"name1","password":"pass1"}' | jq -r .auth_token)

curl -i -H "Authorization: Bearer $TOKEN" \
  http://127.0.0.1:5000/books/v1/bookTitle66
```

Or run the whole matrix at once:

```bash
python -m authzprobe.probe --cases authzprobe/cases.yml
```

## Success criteria

The finding is confirmed when **two different principals receive the same
successful response to the same request**, and at least one of them does not
own the object.

Specifically:

- Non-owner receives `2xx` with the owner's data. Confirmed.
- Non-owner receives `403`, or `404` with no body difference. Correctly
  authorized. Prefer `404`, since `403` confirms the object exists.
- Anonymous caller receives `401`. That is authentication working, and says
  nothing either way about authorization. Do not stop here.

That last point is the trap. VAmPI returns `401` without a token, which makes
the endpoint look guarded.

## Original and modified exchange

Both captures below are verbatim from `captures/vampi-2026-10-21.md`. The book
belongs to `name2`.

**Original** — the owner, `name2`, reading their own book. Legitimate.

```http
GET /books/v1/bookTitle66 HTTP/1.1
Authorization: Bearer <name2 token>
```

```http
HTTP/1.1 200

{"book_title": "bookTitle66", "owner": "name2", "secret": "secret for bookTitle66"}
```

**Modified** — the same request, with `name1`'s token substituted. The only
change is the credential.

```http
GET /books/v1/bookTitle66 HTTP/1.1
Authorization: Bearer <name1 token>
```

```http
HTTP/1.1 200

{"book_title": "bookTitle66", "owner": "name2", "secret": "secret for bookTitle66"}
```

Byte-identical responses to two different principals. The response even names
the owner as `name2` while answering `name1`, which is the clearest possible
evidence and is worth quoting directly in a report.

**Control** — no credential, to show authentication is in fact enforced:

```http
GET /books/v1/bookTitle66 HTTP/1.1
```

```http
HTTP/1.1 401

{"detail": "No authorization token provided", "status": 401, "title": "Unauthorized"}
```

## Remediation

Scope the query to the authenticated principal. Do not fetch and then compare,
fetch with the constraint applied, so a missing ownership check cannot fall
through to a successful read:

```python
# Vulnerable: loads by request-controlled key, ownership never consulted
book = Book.query.filter_by(book_title=book_title).first()

# Fixed: the caller's identity is part of the lookup
owner = User.query.filter_by(username=claims["sub"]).first()
book = Book.query.filter_by(user=owner, book_title=book_title).first()
```

Supporting controls:

- Enforce scoping in a shared data-access layer, not in each handler. A rule
  that every handler must remember is a rule that will be forgotten.
- Return `404`, not `403`, for objects outside the caller's scope.
- Prefer unguessable identifiers (UUIDv4) over sequential integers. This
  raises the cost of enumeration; it is not an authorization control and does
  not fix the bug.

## Notes

Detectable statically. `semgrep/rules/python/bola-missing-object-authorization.yaml`
in [devsecops-pipeline-lab](https://github.com/gl1tchdust/devsecops-pipeline-lab)
flags this exact line in VAmPI at `books.py:51`, where Semgrep's registry
rulesets flag nothing.
