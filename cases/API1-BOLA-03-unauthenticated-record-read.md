# API1-BOLA-03: Unauthenticated read of any user record

| | |
|---|---|
| **OWASP** | [API1:2023 Broken Object Level Authorization](https://owasp.org/API-Security/editions/2023/en/0xa1-broken-object-level-authorization/) |
| **CWE** | [CWE-639](https://cwe.mitre.org/data/definitions/639.html), with [CWE-306](https://cwe.mitre.org/data/definitions/306.html) |
| **Severity** | Medium |
| **Validated against** | VAmPI at `f16052dc`, `GET /users/v1/{username}` |
| **Runnable** | `python -m authzprobe.probe` case `API1-BOLA-03` |

## Purpose

Catch the endpoint that was never wired to the auth middleware at all. Distinct
from BOLA-01: there the check existed and was incomplete, here there is no
check. It appears when one route is added to a controller whose siblings are
all guarded, so the omission is invisible in review.

Rated Medium rather than High here because VAmPI's response exposes only a
username and email. The severity of this case is entirely a function of what
the record contains, so re-rate it per target rather than copying this number.

## Identification

1. Replay every endpoint with the `Authorization` header removed. This is the
   cheapest authorization test that exists and should be the first one run.
2. Compare against the API's own contract. VAmPI's `openapi3.yml` declares
   `bearerAuth` on 6 of its 14 operations; this route is not one of them, so
   the specification and the implementation agree and *both* are wrong.
3. Note that a declared-public endpoint is not automatically a finding. The
   question is whether the data is public, not whether the route is.
4. Vary the identifier to show it is not a fixed public profile.

Useful inversion: do not ask "is this endpoint authenticated". Ask "what is the
least privileged caller who gets a 2xx". Then decide whether that is right.

## Implementation

```bash
# No credential at all
curl -i http://127.0.0.1:5000/users/v1/name1

# And a peer's record, to show it is not a self-service route
curl -i http://127.0.0.1:5000/users/v1/name2
```

Compare the full matrix:

```bash
python -m authzprobe.probe --cases authzprobe/cases.yml
```

## Success criteria

Confirmed when an anonymous caller receives `2xx` with another principal's
data. Observed matrix:

| Identity | Status |
|---|---|
| `owner` (the record's subject) | `200` |
| `other` (a peer) | `200` |
| `anon` (no credential) | `200` |

Three identities, one response. There is no authorization boundary here at all.

Not a finding where the endpoint is a deliberate public profile *and* the
response contains only data the owner published. An email address does not
usually qualify.

## Original and modified exchange

Verbatim from `captures/vampi-2026-10-21.md`.

**Original** — the subject reading their own record:

```http
GET /users/v1/name1 HTTP/1.1
Authorization: Bearer <name1 token>
```

```http
HTTP/1.1 200

{"username": "name1", "email": "mail1@mail.com"}
```

**Modified** — the `Authorization` header deleted. Nothing else changed.

```http
GET /users/v1/name1 HTTP/1.1
```

```http
HTTP/1.1 200

{"username": "name1", "email": "mail1@mail.com"}
```

## Remediation

```python
# Vulnerable: no credential consulted, no scoping
def get_by_username(username):
    return Response(str(User.get_user(username)), 200)

# Fixed: authenticate, then authorize, then project
def get_by_username(username):
    claims = token_validator(request.headers.get("Authorization"))
    if "error" in claims:
        return Response(..., 401)
    if claims["sub"] != username and not is_admin(claims):
        return Response(..., 404)
    user = User.query.filter_by(username=username).first()
    return jsonify({"username": user.username})
```

- Make authentication the default and public routes the explicit exception.
  Deny-by-default turns a forgotten route into a `401` instead of a breach.
- Keep the OpenAPI document and the implementation in agreement, and test the
  document. Here both were wrong in the same direction, so neither caught it.
- Project responses through an explicit serialiser. Returning the model means
  every future column is published automatically.

## Notes

This case is a known **false negative** for the static rule in
[devsecops-pipeline-lab](https://github.com/gl1tchdust/devsecops-pipeline-lab):
the lookup goes through a custom accessor (`User.get_user`) rather than an ORM
query the rule recognises, so it is recorded there as a miss. A good example of
why the dynamic probe and the static rules are not substitutes for one another.
