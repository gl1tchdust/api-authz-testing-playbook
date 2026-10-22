# api-authz-testing-playbook

[![ci](https://github.com/gl1tchdust/api-authz-testing-playbook/actions/workflows/ci.yml/badge.svg)](https://github.com/gl1tchdust/api-authz-testing-playbook/actions/workflows/ci.yml)

Test cases for OWASP API Security authorization flaws, written so they can be
**run** rather than only read. Every request and response quoted here was
captured from a live target, and CI re-runs every case on every push to prove
the write-ups still reproduce.

Target: [OWASP VAmPI](https://github.com/erev0s/VAmPI), pinned at `f16052dc`.
Fetched at run time, never vendored. Only public, deliberately vulnerable
targets are used.

## 60-second quickstart

```bash
git clone https://github.com/gl1tchdust/api-authz-testing-playbook
cd api-authz-testing-playbook
pip install -r requirements.txt
./scripts/vampi.sh fetch
./scripts/vampi.sh run &          # target on :5000
./scripts/vampi.sh wait           # blocks until up, then seeds
python -m authzprobe.probe --cases authzprobe/cases.yml
```

Output:

```
[API1-BOLA-01] Cross-user object read via a path parameter
  owner    HTTP 200  VIOLATION
  other    HTTP 200  ok
  anon     HTTP 401  ok
```

Three lines that contain the entire technique. `owner` and `other` received the
same response to the same request, and only one of them owns the object.

## The cases

| ID | Class | Severity | Title |
|---|---|---|---|
| [API1-BOLA-01](cases/API1-BOLA-01-cross-user-object-read.md) | API1:2023 / CWE-639 | High | Cross-user object read via a path parameter |
| [API1-BOLA-02](cases/API1-BOLA-02-account-takeover-via-path-parameter.md) | API1:2023 / CWE-639 | Critical | Account takeover by rewriting another user's password |
| [API1-BOLA-03](cases/API1-BOLA-03-unauthenticated-record-read.md) | API1:2023 / CWE-639 | Medium | Unauthenticated read of any user record |
| [API3-MA-01](cases/API3-MA-01-privilege-escalation-on-registration.md) | API3:2023 / CWE-915 | High | Self-granted admin role on registration |
| [API5-BFLA-01](cases/API5-BFLA-01-unauthenticated-debug-dump.md) | API5:2023 / CWE-862 | Critical | Unauthenticated dump of every user record including passwords |

Each case carries purpose, identification steps, implementation, success
criteria, the original and modified exchange, OWASP and CWE mappings, and
remediation.

API1 and API3 were the two classes this set out to cover. API5 is included
because the probe's identity matrix detects function-level and object-level
failures by the same mechanism, so the marginal cost was one case definition.

## Why a tool and not a list of curl commands

An authorization bug is not visible in any single response. `200 OK` is the
correct answer for the owner and a critical finding for anyone else. The only
way to see it is to send the same request as two principals and compare, which
means the comparison, not the request, is the test.

So `authzprobe` keeps the identities, the token handling, and the
expected-access matrix in one place and replays each case across all of them:

```yaml
- id: API1-BOLA-01
  request:
    method: GET
    path: "/books/v1/{other_book}"
  authorized: [other]            # only `other` owns this object
  run_as: [owner, other, anon]
```

Anyone outside `authorized` who receives a `2xx` is the finding. That inverts
the usual shape of a security test: the case declares what *should* be true,
and deviations are reported, rather than the test asserting a known bug.

Mass assignment needs a second shape, because the question is not who can
reach an object but which of its properties a client may write. Those cases
inject a property and then read the object back:

```yaml
- id: API3-MA-01
  inject: { admin: true }
  verify:
    request: { method: GET, path: /users/v1/_debug }
    list: users
    where: { username: "probe-mallory" }
    take: admin
  violation_when_equals: true
```

The read-back is the whole point and the step most often skipped. A `200` on
the write proves nothing: most APIs silently discard unknown properties, so a
successful response and a rejected property look identical from outside.

## The negative control, and the false positive it caught

"The probe found 8 violations" is unfalsifiable on its own. A tool that reports
findings against every target it sees looks identical to one that works, right
up until it matters.

VAmPI gates three of its five authorization flaws behind `vulnerable=0`, which
makes it a free control. Same cases, same probe, both builds:

| Case | `vulnerable=1` | `vulnerable=0` | Gated in source |
|---|---|---|---|
| API1-BOLA-01 | VIOLATION | clean | yes, `books.py:50` |
| API1-BOLA-02 | VIOLATION | clean, no effect | yes, `users.py:186` |
| API1-BOLA-03 | 2 violations | 2 violations | **no** |
| API5-BFLA-01 | 3 violations | 3 violations | **no** |
| API3-MA-01 | VIOLATION | rejected | yes, `users.py:60` |
| | **8** | **5** | |

Three cases go quiet and two do not, and the two that do not are provably
ungated upstream: `get_by_username` and `debug` have no `if vuln:` branch at
all, so they are broken in both builds. The probe's output tracks the guards in
the source exactly. `scripts/negative_control.py` asserts that in CI, and each
case declares its expected behaviour with `fixed_in_secure_mode` so a drift in
either direction fails the build.

### The false positive

Running that control the first time, **API1-BOLA-02 still reported a violation
against the fixed build**. The probe was wrong, not the target.

VAmPI's fixed `update_password` returns `204` either way. What changes is the
subject: the vulnerable branch writes to the account named in the path, the
fixed branch writes to the caller's own. Both are successes, and a comparison
that looks only at status codes cannot tell "you rewrote the victim's password"
from "you rewrote your own".

Which is the exact rule this playbook states for mass assignment, broken by its
own access cases. The fix was to apply the same discipline: a mutating case now
declares a confirmation step, and a `2xx` is only reported when the effect is
confirmed on the target.

```yaml
confirm_effect:
  request:
    method: POST
    path: /users/v1/login
    body: { username: name2, password: "probe-set-this" }
  expect_contains: auth_token
```

Note it matches on content, not status. VAmPI returns `200` on a *failed* login
too, so even the confirmation step has no usable status code. The probe now
prints the distinction:

```
owner    HTTP 204  ok (2xx, no effect on target)
```

Seven tests cover this logic, more than any other part of the probe, because it
is the only path that can *suppress* a finding. The original bug cost precision.
A confirmation step that wrongly fails would cost a critical account takeover,
so both directions are tested: that a confirmed effect is always reported, that
an unconfirmed one never is, that a denied write never runs the confirmation,
and that the legitimately authorized identity never triggers it either.

## Three things that will cost you findings

Collected from building this, and the reason the cases are structured the way
they are.

**A `401` without a credential tells you nothing about authorization.** VAmPI
returns `401` on `/books/v1/{title}` with no token, which makes the endpoint
look guarded. It is not: any authenticated user reads any user's object.
Authentication proves who is calling. Authorization decides what they may
touch. A test that stops at the `401` reports the endpoint as fine.

**Test as peers, not as an admin and a user.** An administrator succeeding
proves nothing about object-level authorization, because they are supposed to
succeed. The comparison has to be between two principals at the same privilege
level, which is why `cases.yml` defines `owner` and `other` as equals and keeps
`admin` separate for the function-level cases.

**A `2xx` on a write is not evidence.** For mass assignment, verify by reading
the object back, then by exercising something gated on the property. For this
playbook's API3 case all three levels were reached: the property persisted, and
an account created with `"admin": true` could then delete another user, while
the same request from a non-admin peer returned `401 "Only Admins may delete
users!"`. That control is what turns "the field was accepted" into "privilege
escalation", and it is one extra request.

## Captures

`captures/` holds verbatim request and response pairs from a live run,
generated by the probe rather than written by hand:

```bash
python -m authzprobe.probe --cases authzprobe/cases.yml --capture captures/
```

Bearer tokens are omitted; re-run the probe to mint your own. CI regenerates
the captures and `scripts/check_captures.py` fails the build if a defined case
has no exchange behind it, which is the specific way a playbook rots: still
readable, quietly wrong.

## Wordlists

`wordlists/mass-assignment-params.txt` collects property names worth injecting,
grouped by what they change rather than alphabetically, because the names that
flip an authorization decision are the only ones that turn a shrug into a
finding. Role and privilege first, then account state, then ownership and
tenancy, then money.

It is deliberately short. A list of every field name in existence costs more
requests than it is worth. Send one name per request, try each in camelCase,
snake_case and PascalCase, and read the object back every time.

## Using it against your own API

```bash
cp authzprobe/cases.yml my-api.yml
# edit target.base_url, target.auth, identities, and the cases
python -m authzprobe.probe --cases my-api.yml --base-url https://staging.example.com
```

### Getting a credential for each identity

The whole differential depends on holding several principals at once, so the
probe has to be able to obtain a credential the way your API actually issues
one. `target.auth.mode` selects how.

**`form`**, the default, and what the VAmPI case file uses. POST a JSON body
to a login path and read a token out of the response. Common in teaching
targets and internal APIs, rare in production.

```yaml
target:
  auth:
    mode: form
    method: POST
    path: /users/v1/login
    body: { username: "$username", password: "$password" }
    token_field: auth_token
identities:
  - { id: owner, username: name1, password: pass1 }
```

**`oauth2_client_credentials`** ([RFC 6749 §4.4](https://www.rfc-editor.org/rfc/rfc6749#section-4.4))
and **`oauth2_password`** ([§4.3](https://www.rfc-editor.org/rfc/rfc6749#section-4.3)).
`token_url` may be absolute, because the authorization server usually is not
the API under test. `credentials` places the client id and secret in the body
or in HTTP Basic, which [§2.3.1](https://www.rfc-editor.org/rfc/rfc6749#section-2.3.1)
permits either way and servers disagree about.

```yaml
target:
  auth:
    mode: oauth2_client_credentials
    token_url: https://auth.example.com/oauth2/token
    credentials: basic          # or body, the default
    token_field: access_token   # the default
identities:
  - { id: owner,  client_id: svc-a, client_secret: ${A}, scope: "orders:write" }
  - { id: other,  client_id: svc-b, client_secret: ${B}, scope: "orders:write" }
  - { id: reader, client_id: svc-c, client_secret: ${C}, scope: "orders:read" }
  - { id: anon }
```

**A credential you already hold** needs no mode. Give the identity a `token`
and acquisition is skipped, which covers static bearers and API keys. Change
`header_name` and `header_value` for a key that does not go in
`Authorization`:

```yaml
target:
  auth:
    header_name: X-API-Key
    header_value: "{token}"
identities:
  - { id: owner, token: ${OWNER_KEY} }
  - { id: other, token: ${OTHER_KEY} }
  - { id: anon }
```

Two deliberate behaviours. A token request that fails **stops the run** with
exit 2 rather than continuing with a tokenless identity, because an identity
that silently sends no credential turns the owner arm into a second anonymous
arm and the differential then reports nothing however broken the target is.
And a 200 carrying an empty token is treated as a failure for the same reason.

Secrets belong in the environment, not the case file. Nothing about token
acquisition is written to captures: the token endpoint is not routed through
the method that records evidence, precisely because its request body carries a
client secret.

Exit codes make it usable as a CI gate against your own staging environment:

| Code | Meaning |
|---|---|
| 0 | every case behaved as its definition says it should |
| 1 | at least one authorization violation |
| 2 | could not run: target unreachable, bad case file, login failed |

Note the deliberate split between 1 and 2. A probe that cannot log in must not
report "no violations found", for the same reason an unparseable scan report
must never be read as a clean one.

## Reading the model a spec declares

An OpenAPI document already contains a permission model. `security` on each
operation says whether a credential is required, and OAuth2 schemes name the
scopes. That model is worth printing, because one spread across forty
operation objects is one nobody has read end to end.

```bash
python -m authzprobe.openapi .target/vampi/openapi_specs/openapi3.yml
python -m authzprobe.openapi spec.yml --held-scopes orders:read   # what must be refused
python -m authzprobe.openapi spec.yml --emit-cases                # case stubs
```

With `--held-scopes`, the document defines its own conformance test: an
operation requiring `orders:write` must refuse a token carrying only
`orders:read`. A 2xx there means the API does not enforce the model it
publishes.

### What a spec cannot declare, and why that is the useful part

Against VAmPI, conformance testing finds **nothing**. Its spec declares six
operations as requiring a credential, and all six were verified by hand to
return 401 to an unauthenticated caller. The implementation matches the
document.

Its real authorization flaws are invisible to conformance for two separate
reasons:

| Case | Why conformance misses it |
|---|---|
| `GET /users/v1/_debug` dumps every password | the spec declares it **public**, so spec and code agree |
| `PUT /users/v1/{username}/password` lets anyone change anyone's | `security: [{bearerAuth: []}]` means "a credential is required", which is satisfied |

The second is the structural one. **OpenAPI has no vocabulary for "only the
owner of `{username}` may call this."** Object-level authorization cannot be
expressed, so it cannot be checked, which is exactly why BOLA stays the
top-ranked API risk while schema validation is a solved problem.

So this module does not issue verdicts on those. It produces the shortlist:
authenticated operations that address one object by path.

On VAmPI that is four operations, and testing all four by hand gave:

- `GET /books/v1/{book_title}` and `PUT /users/v1/{username}/password` are the
  two documented findings in this playbook, recovered from the spec alone.
- `DELETE /users/v1/{username}` is correctly gated: `401 Only Admins may
  delete users!`. A negative result, which is what a shortlist is for.
- `PUT /users/v1/{username}/email` returns **204** to a cross-user write and
  is **not** a finding. It updates the caller's own record. That is precisely
  the false positive `_effect_confirmed` exists to suppress, arrived at from a
  different direction.

Which is the honest summary: the spec picks the targets, a human decides who
should be allowed to reach them, and the probe checks whether the write landed
on the victim. `--emit-cases` leaves `authorized: []` unset on purpose,
because a generated file that guessed would look like coverage while asserting
whatever the generator assumed.

## What this does not do

- **No authorization testing of flows.** It compares single requests. A
  multi-step workflow where step 3 can be reached without step 2 needs state
  the case format does not model.
- **No identifier discovery.** Object ids come from a declared discovery
  request. It will not find the endpoint that leaks them for you.
- **No session or token analysis.** JWT algorithm confusion, token lifetime,
  and revocation are out of scope. The probe treats a token as opaque.
- **Not a scanner.** It tests cases you wrote. Pointing it at an API it has no
  case definitions for will report nothing, correctly.

## Tests

```bash
python -m pytest authzprobe/ -q                              # 102, no target needed
AUTHZPROBE_TARGET=http://127.0.0.1:5000 python -m pytest -q  # 107, with a live target
```

The unit tests concentrate on the violation decision, because a probe that
under-reports tells you an endpoint is safe when it is not, which is worse than
having no probe. Both directions are covered: that an unauthorized `2xx` is
always reported, and that the legitimately authorized identity never is.

The live tests assert that every documented case still reproduces against the
pinned commit, and that the target is in fact that commit. CI runs both.

## Layout

```
cases/                  the playbook, one file per test case
authzprobe/probe.py     differential authorization probe
authzprobe/cases.yml    machine-readable case definitions, read by both
authzprobe/openapi.py   reads the authorization model a spec declares
authzprobe/test_*.py    unit tests, plus live reproduction tests
captures/               verbatim exchanges, generated
wordlists/              property names for mass-assignment probing
scripts/vampi.sh        fetch, run and seed the target
scripts/check_captures.py  fails the build when captures drift from cases
```

The playbook and the probe read the same `cases.yml` on purpose. A document
that drifts from the tool that runs it is a document with footnotes.

## Related

Static detection of these same bug classes, with measured precision and recall,
is in [devsecops-pipeline-lab](https://github.com/gl1tchdust/devsecops-pipeline-lab).
The two are not substitutes. API1-BOLA-03 here is a documented false negative
for the static rules, because the lookup goes through a custom accessor; the
API3 case is a documented false negative too, because the request value
controls a branch rather than a value and taint analysis cannot follow it.
Both take one request to find dynamically.

## License

MIT. See [LICENSE](LICENSE).

Shivam Mahajan, https://linkedin.com/in/shivam-mahajan-a8005a205
