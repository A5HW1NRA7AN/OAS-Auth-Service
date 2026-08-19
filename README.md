# OAS Auth Service

Token issuance, validation and revocation for the OpenAgriStack catalogue services, backed by Keycloak
and Redis.

**The split of responsibilities:** the user-catalogue owns users and their passwords. Keycloak holds an
identity shell per user — the catalogue's `userId` plus `org_id` and `entity_type` — and issues tokens
for it, storing **no credential of any kind**. This service owns those tokens and their revocation, and
administers the Keycloak users the catalogue publishes.

Spring Boot 3.3.5, Java 17, no database of its own.

> **This service does not authenticate its callers, and credential verification is flag-gated and off
> by default.** With `catalogue.validate-enabled=false`, `auth_token_create` issues a token for
> whatever `userId` it is handed. Every endpoint here is for service-to-service use inside the cluster
> and none may be routed through Kong or any ingress.
> See [§4](#4-credential-verification-flag-gated) and [§6](#6-security-posture).

> **⚠️ TEMPORARY (UAT):** for a limited UAT integration window this service **is** exposed through Kong
> at the shared nginx host (`/auth/v1/*`), gated only by the existing catalogue API keys — no real
> caller authentication. This deliberately relaxes the "never routed through Kong" rule above and
> **must be reverted to strictly private before prod** — see the revert checklist in the OAS-Infra repo
> (`kong/kong.decK.yaml`, block marked `TEMP/UAT`).

## Contents

1. [Architecture](#1-architecture)
2. [Quick start](#2-quick-start)
3. [API reference](#3-api-reference)
4. [Credential verification (flag-gated)](#4-credential-verification-flag-gated)
5. [Catalogue integration contract](#5-catalogue-integration-contract)
6. [Security posture](#6-security-posture)
7. [Redis keys](#7-redis-keys)
8. [Configuration](#8-configuration)
9. [Deployment](#9-deployment)
10. [Testing](#10-testing)
11. [Project structure](#11-project-structure)
12. [Known pitfalls](#12-known-pitfalls)
13. [Not implemented](#13-not-implemented)

---

## 1. Architecture

### Provisioning

A user exists in Keycloak only because the catalogue published them.

```
catalogue record -> ACTIVE
        |
        v
POST /auth/v1/auth_user_create  { userId, orgId, entityType,
                                  email?, firstName?, lastName?, registries? }
        |
        v
Keycloak user:  username = userId
                enabled  = true
                attributes = { user_id, org_id, entity_type, registries[] }
                credentials = (none)
```

The push happens **before** the catalogue persists `ACTIVE`, so a failure here leaves the record at its
previous status and retryable. The reverse order can leave a user the catalogue believes is live but who
cannot obtain a token, with no clean way to detect it afterwards.

### Issuing a token

With `catalogue.validate-enabled=false` (the default):

```
caller -> POST /auth/v1/auth_token_create { userId }
              |
              v
        Keycloak direct grant, no password field
              |
        flow: direct-grant-validate-username  (REQUIRED)
              -> resolves the user, enforces `enabled`
              -> no credential is checked, because Keycloak holds none
              |
              v
        access_token + refresh_token
```

The realm's direct grant flow contains no password step at all. `setup-realm.sh` removes it and asserts
it is gone. That is what makes a password-less grant possible, and it is also why the client secret and
network isolation are the only things protecting this endpoint — see [§6](#6-security-posture).

With the flag on, one step is added in front: the service asks the user-catalogue to verify the
username and password, and only the `userId` the catalogue returns reaches Keycloak. Keycloak's own
role is unchanged, because it still holds no credential. See [§4](#4-credential-verification-flag-gated).

### Validation

Entirely local. The signature is verified against Keycloak's published JWKS (cached), then the claims
and the Redis denylist are checked. There is no call to Keycloak on the hot path.

```
signature (RS256, pinned)  ->  iss  ->  exp / nbf  ->  typ == Bearer
    ->  azp == client id  ->  jti present  ->  Redis denylist
```

RS256 is pinned in code rather than read from the token header. Trusting the header would allow the
algorithm-confusion attack, where a token is signed with the published public key used as an HMAC
secret. There is a test for exactly that.

If Redis cannot answer, validation falls back to Keycloak introspection, which knows about logouts and
disabled users. If neither can answer it fails closed.

### Revocation

A JWT is a self-contained signed string, so Keycloak cannot recall one it has already issued. Blocking
an account therefore takes two actions, and neither alone is sufficient:

| Action | What it does | What it cannot do |
|---|---|---|
| Redis denylist | kills tokens already in circulation | wears off when the entries expire |
| Keycloak `enabled=false` | stops all future tokens, permanently | cannot touch an issued token |

`auth_user_revoke` does both. `auth_user_create` reverses it.

---

## 2. Quick start

```bash
docker compose up -d              # Redis on 6380, Keycloak on 8180
./setup-realm.sh                  # realm, client, service account, flow, hardening; writes .env
./mvnw clean package
set -a; . ./.env; set +a           # KEYCLOAK_CLIENT_SECRET
java -jar target/svc-auth-0.0.1-SNAPSHOT.jar
```

Ordering matters in one place: `setup-realm.sh` generates the client secret, so the application must
start **after** it with `.env` sourced. Start it first and every call fails with `invalid_client`. The
script waits for Keycloak itself (about 10 seconds from a cold container), so it is safe to run
immediately after `docker compose up -d`.

Verify:

```bash
curl -s localhost:8080/actuator/health/readiness

curl -s -X POST localhost:8080/auth/v1/auth_user_create \
  -H 'Content-Type: application/json' \
  -d '{"userId":"user-000000000001","orgId":"org-000000000001","entityType":"MAKER"}'

curl -s -X POST localhost:8080/auth/v1/auth_token_create \
  -H 'Content-Type: application/json' -d '{"userId":"user-000000000001"}'
```

### Ports

| Service | Port | Notes |
|---|---|---|
| auth-service | 8080 | `SERVER_PORT` at run time |
| Keycloak | 8180 | bound to `127.0.0.1` in compose, deliberately |
| Redis | 6380 | 6379 is left to the catalogue's own stack |

The user-catalogue's stack is untouched by anything here, so no `docker compose down -v` in this
repository can reach its data.

---

## 3. API reference

All six endpoints are `POST /auth/v1/<action>` with a JSON body, returning the standard envelope
(`result`, `params`, `responseCode`) on success and `{code, message, httpStatusCode}` on failure.

### POST /auth/v1/auth_user_create

Creates or updates the Keycloak user. Idempotent, and also the re-enable path after a revoke.

```json
{ "userId": "user-000000000001", "orgId": "org-000000000001", "entityType": "MAKER",
  "email": "user@example.com", "firstName": "Season", "lastName": "Field Agent",
  "registries": ["cropCatalogue", "seasonCatalogue"] }
```

```json
{ "result": { "userId": "user-000000000001", "created": true, "enabled": true } }
```

`orgId` and `entityType` are required. `email`, `firstName`, `lastName` and `registries` are optional.

`firstName` and `lastName` need no mapper: the client keeps Keycloak's built-in `profile` scope, so
`given_name`, `family_name` and `name` appear in the token as soon as the fields are stored.

**`registries` is the user's list of accessible catalogues, and it is three-state:**

| Sent | Effect |
|---|---|
| omitted | whatever is stored is kept — an unrelated republish never wipes the list |
| `[]` | cleared, and the claim disappears from the token entirely |
| `["a","b"]` | replaced |

Blank entries and duplicates are dropped; a non-array value is a `400`. Values come from whoever owns
the permission matrix — this service only carries what it is given and has no opinion about who
computes it. **Once the catalogue manages registries it must send the key on every publish, and send
`[]` to revoke:** a caller that stops sending it keeps the previous list forever.

`email`, `firstName` and `lastName` are likewise carried forward when omitted. An existing user returns `200` with
`created: false` rather than a conflict — the caller is a catalogue whose publish is "push here, then
persist ACTIVE", so every way this response can be lost leaves it believing the push did not happen. A
409 there would wedge the record permanently. The update rewrites `enabled` and all three attributes, so
a republish repairs drift.

`409 AUTH_USER_CONFLICT` means a **different** username already holds that email. Retrying will not fix
it; the data has to change.

### POST /auth/v1/auth_token_create

The body depends on `catalogue.validate-enabled`, and **the flag alone selects the path** — never the
shape of the body.

```json
{ "userId": "user-000000000001" }                      // flag off (default): trusts the caller
{ "username": "asha@example.org", "password": "..." }  // flag on: verified by the catalogue
```

Returns Keycloak's token response verbatim (`access_token`, `refresh_token`, `expires_in`, …).

With the flag on, a `userId` in the body is **ignored**: the token is issued for the `userId` the
catalogue returned. Honouring the body's value would let one valid password mint a token for any other
account. Sending only `{userId}` while the flag is on is a `400`, not a fallback — otherwise any caller
could downgrade out of verification. See [§4](#4-credential-verification-flag-gated).

### POST /auth/v1/auth_token_validate

```json
{ "token": "<access token>" }
```

```json
{ "result": { "active": true, "sub": "…", "preferred_username": "user-000000000001",
              "user_id": "user-000000000001", "org_id": "org-000000000001",
              "entity_type": "MAKER", "registries": ["cropCatalogue", "seasonCatalogue"],
              "given_name": "Season", "family_name": "Field Agent",
              "email": "user@example.com", "exp": 1786968521, "jti": "…", "sid": "…" } }
```

The token is never echoed back.

`registries` is `null`, never `[]`, when the user holds none — Keycloak omits an empty attribute
entirely, and `[]` would assert "this user holds no registries" on a token that never said so. If it
ever comes back as a bare string, the realm's mapper is not multi-valued and Keycloak is sending only
the first value; re-run `setup-realm.sh`, which asserts against exactly that.

### POST /auth/v1/auth_token_invalidate

```json
{ "token": "<access token>", "refreshToken": "<refresh token>" }
```

```json
{ "result": { "localRevocation": "ok", "idpLogout": "ok" } }
```

`refreshToken` is optional; supplying it also ends the Keycloak session. Accepts an already-expired
token so the rest of its session can still be killed.

### POST /auth/v1/auth_user_revoke

```json
{ "userId": "user-000000000001" }
```

```json
{ "result": { "userId": "user-000000000001", "revoked": true, "keycloakDisabled": "ok" } }
```

Denylists the user and every indexed session, then disables the user in Keycloak. The revocation is
load-bearing and fails the request; the Keycloak disable is best-effort and reported in the body, because
the catalogue's own status already blocks new logins and a Keycloak blip must not fail the block.

### POST /auth/v1/auth_user_delete

```json
{ "userId": "user-000000000001" }
```

```json
{ "result": { "userId": "user-000000000001", "revoked": true, "deleted": true } }
```

Revokes first, then deletes. An already-absent user returns `200` with `deleted: false`, not a 404 — a
caller retrying a half-finished cleanup has to be able to complete it.

### Token shape

```json
{
  "iss": "http://localhost:8180/realms/OAS",
  "aud": ["oas-auth-service", "account"],
  "azp": "oas-auth-service",
  "typ": "Bearer",
  "sub": "8f204b4c-bcfa-4719-8a35-f192baed5c76",
  "sid": "WVTqfj5U6u5oALw73ZKr1Ynm",
  "jti": "onrtro:c57fab42-3442-18be-261e-c8c3ba3e1257",
  "preferred_username": "user-000000000001",
  "user_id": "user-000000000001",
  "org_id": "org-000000000001",
  "entity_type": "MAKER",
  "registries": ["cropCatalogue", "seasonCatalogue"],
  "given_name": "Season",
  "family_name": "Field Agent",
  "name": "Season Field Agent",
  "email": "user@example.com",
  "email_verified": true
}
```

`user_id`, `org_id`, `entity_type` and `registries` are projected from the Keycloak user attributes that
`auth_user_create` wrote. `given_name`, `family_name`, `name`, `email` and `email_verified` come from
Keycloak's built-in `profile` and `email` scopes, with no mapper of ours involved.

`entity_type` and `registries` are both **data, not permissions** — there is no RBAC, and nothing here
or in Keycloak enforces either. A consumer that wants to gate on `registries` must do so itself.
Nothing caps the list length, and a few hundred entries would produce a JWT large enough to hit proxy
header limits downstream.

### Errors

| Code | Status | Meaning | Caller action |
|---|---|---|---|
| `AUTH_INVALID_REQUEST` | 400 | a required field is missing | fix the request |
| `AUTH_TOKEN_INVALID` | 401 | signature, issuer, `typ` or `azp` wrong, or malformed | re-authenticate |
| `AUTH_TOKEN_EXPIRED` | 401 | past `exp` | refresh |
| `AUTH_TOKEN_REVOKED` | 401 | denylisted | re-authenticate |
| `AUTH_INVALID_CREDENTIALS` | 401 | the catalogue answered `valid:false` | re-authenticate |
| `AUTH_USER_DISABLED` | 403 | blocked in Keycloak | `auth_user_create` re-enables |
| `AUTH_USER_NOT_FOUND` | 404 | never provisioned | call `auth_user_create` |
| `AUTH_USER_CONFLICT` | 409 | another username holds that email | change the data |
| `AUTH_IDP_OPERATION_FAILED` | 502 | Keycloak rejected the call | configuration fault; alert |
| `AUTH_UPSTREAM_UNAVAILABLE` | 503 | Keycloak or the catalogue unreachable, or the catalogue answered something unparseable | retry |
| `AUTH_REVOCATION_FAILED` | 503 | Redis unreachable | retry |

The 404/403 split on `auth_token_create` is deliberate and safe: there is no password in play, so
nothing can be enumerated, and the distinction is the difference between "your publish never landed" and
"this account is blocked". It costs one admin lookup, on the failure path only.

### Failure behaviour

| Dependency | Effect |
|---|---|
| Redis down | validation falls back to Keycloak introspection; revocation fails loudly with 503 |
| Keycloak down | token creation and user administration return 503; validation keeps working from cached JWKS until the denylist is also unreachable |
| Both down | fails closed |

---

## 4. Credential verification (flag-gated)

The client is built and unit-tested. It is **off by default** because the catalogue endpoint it calls
does not exist yet — switching it on later is configuration, not development.

```properties
catalogue.validate-enabled=false            # default: auth_token_create takes {userId}, trusts caller
catalogue.base-url=http://localhost:8082    # in-cluster Service DNS, never the public host
catalogue.verify-path=/user/v1/verify
```

With the flag on, `auth_token_create` takes `{username, password}`, calls the catalogue, and issues a
token only for the `userId` the catalogue returns.

**Confirm the mode after enabling it.** Anything Spring does not read as `true` — unset, misspelled,
`0`, `False`, `"true "` — silently means `false`, and passwords then stop being checked with no error
anywhere. Two things make that visible: every call logs `mode=VERIFIED` or `mode=TRUSTED`, and the audit
line records `SUCCESS` or `SUCCESS_UNVERIFIED`, so an audit stream proves which path served each token.

### What the catalogue must expose

```
POST /user/v1/verify     { "username": "...", "password": "<plaintext>" }

200  { "result": { "valid": true, "userId": "user-000000000001" } }
200  { "result": { "valid": false } }        // never 401
```

The path is `/user/v1/verify` rather than something like `/validate-credentials` because that repo has
no multi-word path anywhere — every action is a single lowercase verb (`create`, `approve`, `review`,
`toggle`, `search`, `read`). It is configurable via `catalogue.verify-path` either way.

Response contract, as this service parses it:

| Rule | Why |
|---|---|
| `valid` is **always present**, on success and failure alike | A body with no `valid` is treated as an outage (503), not a rejection. If rejections omit it, every wrong password becomes a 503 |
| `userId` accompanies `valid:true` | `valid:true` with no userId is a 503. This service will never fall back to the submitted username |
| Payload flat at `result` | Nested at `result.result` also works, since that repo's own handlers disagree — but pick flat |
| HTTP 2xx for both verdicts | Any other status is a 503 and the body is not parsed |

Five rules for whoever implements it, all security-relevant:

1. **Compare with bcrypt.** The stored `password` is already a bcrypt hash — the catalogue's schema
   documents it as hashed by the portal before submission. `BCryptPasswordEncoder.matches(plaintext,
   storedHash)`. The salt is inside the hash. Note that repo currently has **no** hashing dependency, so
   one has to be added, and nothing enforces that stored values really are bcrypt.
2. **Require `status == ACTIVE`.** This is what makes blocking effective at source. Note `DELETED`
   records keep their hash in Postgres, so a naive `findById` + `matches` would authenticate a
   soft-deleted user.
3. **Return a byte-identical body for every failure** — unknown user, wrong password and non-ACTIVE must
   be indistinguishable. Anything else allows account enumeration, and "this account is blocked" tells an
   attacker their guessing is working. Run a bcrypt comparison against a dummy hash even for unknown
   users, so response time does not reveal which accounts exist.
4. **Never log the request body.** It contains a plaintext password. This one needs saying explicitly:
   that repo's `UserServiceImpl` logs its entire request payload at **INFO** on the create path, so an
   endpoint written to the house pattern would write every plaintext password to the log. Its
   `OutboundRequestHandlerServiceImpl` is worse — it logs bodies at DEBUG *and* returns 4xx bodies as
   though they were successes, so do not route this through it.
5. **Do not answer HTTP 200 for "not found".** That repo's `read` handler does, with the real status only
   in the body. This service treats a 200 it cannot parse as an outage rather than a rejection, which is
   the safe reading but makes such a response a 503.

It must not be routed through Kong: it accepts plaintext passwords and returns a credential verdict.
Kong routes by path convention, and this path is neither `read` nor `search`, so default rules would
classify it as a public write action.

There is no `username` column in that schema — only `email` (required, non-unique, not indexed) and the
generated `userId`. Whatever the user typed is forwarded verbatim for the catalogue to resolve, and the
`userId` it returns is what reaches Keycloak, so the catalogue can accept an email as the login
identifier without any change here. A lookup by email will need a native jsonb query and an index.

---

## 5. Catalogue integration contract

The catalogue makes three calls, plus one endpoint it exposes ([§4](#4-credential-verification-flag-gated)).
Nothing in the catalogue talks to Keycloak, and Keycloak does not call the catalogue.

| Catalogue event | Call | Notes |
|---|---|---|
| publish, status becomes `ACTIVE` | `auth_user_create` | **before** persisting ACTIVE; on failure leave the record retryable |
| `ACTIVE -> INACTIVE` | `auth_user_revoke` | |
| `INACTIVE -> ACTIVE` | `auth_user_create` | re-enables and clears the block |
| record deleted | `auth_user_delete` | |
| login | `auth_token_create` with `{username, password}` | only when `catalogue.validate-enabled=true` |

**If the catalogue takes ownership of `registries`, it must send the key on every `auth_user_create`,
and send `[]` to revoke access.** Omitting it means "keep what is stored", which is right for a caller
that does not manage the list but wrong for one that does — a revocation made in the catalogue's own
database would otherwise leave the old claim in every token issued afterwards.

Use a `RestTemplate` **with timeouts** — a shared bean usually has none, and a hung call would hold the
request thread indefinitely. Do not report the raw exception on failure: a connection error message
contains this service's internal host and port.

Revoked tokens stay dead after a re-enable. `auth_user_create` clears the user-level block so logins work
again immediately, but the per-session entries are left in place on purpose.

---

## 6. Security posture

Read this before deploying.

**Nothing here authenticates its caller.** There is no interceptor, no API key, no mTLS. Access control
is entirely network-level, by decision. All six endpoints, and Keycloak's token endpoint, must be
unreachable from outside the cluster.

**`auth_token_create` mints a token for any `userId`** while `catalogue.validate-enabled` is `false`,
which is the default. A single misconfigured Kong route is then a full authentication bypass for every
account. Turning the flag on is the fix; until then the network is the only control.

**The flag is silent when it is wrong.** A missing or misspelled `CATALOGUE_VALIDATE_ENABLED` reverts to
trusting the caller and still returns a token — the only failure in this service whose wrong outcome is a
200. Grep the log for `mode=VERIFIED` after any deployment that expects verification.

**The `oas-auth-service` client secret is the boundary.** Because the realm's direct grant flow checks
no credential, anyone holding that secret can obtain a token for any user in the realm. Treat it as a
root credential: `setup-realm.sh` writes it to `.env` (gitignored) and regenerating it is a re-run away.

**Keycloak's `admin-cli` is the trap to know about.** `directGrantFlow` is a realm-wide binding, and
Keycloak auto-creates a **public** `admin-cli` client with direct access grants enabled in every realm.
With no password step in the flow, this issues a live token for any user with no secret and no password:

```
POST /realms/OAS/protocol/openid-connect/token
grant_type=password&client_id=admin-cli&username=<any userId>
```

Verified against Keycloak 26.7 — it really does return a token. `setup-realm.sh` disables direct access
grants on every client except `oas-auth-service` and then **fails loudly** if any other client still has
it, because a rebuilt realm recreates `admin-cli` with the flag back on. Do not remove that assertion.

**MFA is structurally impossible in this realm** while Keycloak holds no credentials.

---

## 7. Redis keys

| Key | Type | TTL | Purpose |
|---|---|---|---|
| `auth:denylist:jti:<jti>` | string `1` | token's remaining life | one revoked token |
| `auth:denylist:sid:<sid>` | string `1` | `denylist-sid-ttl-seconds` | a revoked session |
| `auth:denylist:user:<userId>` | string `1` | `denylist-sid-ttl-seconds` | a blocked user |
| `auth:session:<sid>` | string (JSON) | `denylist-sid-ttl-seconds` | session record |
| `auth:user:<userId>:sessions` | set of sids | `denylist-sid-ttl-seconds` | session index |

Values are a constant `1`, never the token — a Redis dump must not hand anyone a usable credential.

The session index is not part of the security decision; validation remains signature + claims +
denylist. Its purpose is that "clear everything for this user" is an enumeration rather than a hope that
one TTL covers every outstanding token.

---

## 8. Configuration

Everything is environment-driven with a local default.

| Variable | Local default | In-cluster |
|---|---|---|
| `SERVER_PORT` | 8080 | 8080 |
| `SPRING_REDIS_HOST` / `_PORT` | `localhost` / `6380` | the Redis host |
| `KEYCLOAK_BASE_URL` | `http://localhost:8180` | `http://keycloak:8080` (Service DNS) |
| `KEYCLOAK_ISSUER` | `http://localhost:8180/realms/OAS` | the **public** ingress URL |
| `KEYCLOAK_REALM` | `OAS` | `OAS` |
| `KEYCLOAK_CLIENT_ID` | `oas-auth-service` | same |
| `KEYCLOAK_CLIENT_SECRET` | from `.env` | from a Secret |
| `KEYCLOAK_CONNECT_TIMEOUT_MS` / `_READ_TIMEOUT_MS` | 2000 / 5000 | tune as needed |
| `KEYCLOAK_CLOCK_SKEW_SECONDS` | 30 | 30 |
| `KEYCLOAK_DENYLIST_SID_TTL_SECONDS` | 900 | at least the SSO session max |
| `CATALOGUE_VALIDATE_ENABLED` | `false` | `true` once the catalogue exposes `/user/v1/verify` |
| `CATALOGUE_BASE_URL` | `http://localhost:8082` | `http://user-catalogue:8080` (Service DNS, **not** the public host) |
| `CATALOGUE_VERIFY_PATH` | `/user/v1/verify` | same |
| `CATALOGUE_CONNECT_TIMEOUT_MS` / `_READ_TIMEOUT_MS` | 2000 / 5000 | the read timeout is the login latency ceiling |

`KEYCLOAK_BASE_URL` (how this service reaches Keycloak) and `KEYCLOAK_ISSUER` (what Keycloak stamps into
tokens) are separate on purpose. See [§12](#12-known-pitfalls).

The service authenticates to Keycloak's admin API using its **own client's service account**
(`client_credentials`), holding only `manage-users` and `view-users`. There are no admin credentials
anywhere in the application.

---

## 9. Deployment

### Platform contract

| Requirement | Status |
|---|---|
| `/actuator/health/liveness`, `/actuator/health/readiness` | yes |
| `/v3/api-docs` | yes, all six endpoints |
| Port 8080 via `SERVER_PORT` | yes |
| Env-driven config, no hardcoded hosts | yes |
| `./mvnw clean package -DskipTests` | yes |
| Stateless (no local disk, no session affinity) | yes |
| `/<domain>/v1/<action>` routing | yes |

The `Dockerfile` builds the jar and runs it as a non-root user. Jenkins builds this Dockerfile directly;
there is no separate Maven stage.

Readiness intentionally does **not** depend on Keycloak or Redis. A green readiness probe therefore does
not mean logins work — those failures surface as 503 on the endpoints instead.

### Keycloak

The stock `quay.io/keycloak/keycloak:26.7` image, with no custom provider and no `kc.sh build`. For a
real environment: run `start --optimized` rather than `start-dev`, attach a real database, set
`KC_HOSTNAME` to the public URL, `KC_HOSTNAME_STRICT=true`, and `KC_PROXY_HEADERS=xforwarded` behind an
ingress. Do not expose the token endpoint publicly.

### Realm provisioning

`setup-realm.sh` is idempotent and environment-driven (`KC`, `REALM`, `CLIENT`, `ADMIN_USER`,
`ADMIN_PASS`, `KC_WAIT_SECONDS`). Run it once against a deployed Keycloak after its database is
attached. It creates the realm and client, enables the service account and grants it `manage-users` and
`view-users`, declares the three custom attributes in the User Profile, creates the `oas-profile` scope
with its mappers and the audience mapper, strips the password step from the direct grant flow, disables
direct access grants on every other client, turns off email login, and verifies all of it.

The realm lives only in the `kcdata` volume, so `docker compose down -v` destroys it and this script is
how you rebuild it. Re-run it after any upgrade that recreates the realm.

---

## 10. Testing

```bash
./mvnw test        # 93 tests
```

| Class | Covers |
|---|---|
| `KeycloakServiceImplTest` | token verification: algorithm confusion, wrong key, tampering, issuer, `azp`, `typ`, expiry, denylist by jti/sid/user, introspection fallback, fail-closed |
| `KeycloakServiceImplAdminTest` | service-account token caching and invalidation, upsert create/update/conflict, disable, delete idempotency, no password in the grant, the 404/403 split |
| `AuthServiceImplTest` | the JSON contract the catalogue integrates against, required fields, the revoke-before-delete ordering, both flag paths, and the two bypass guards |
| `CatalogueServiceImplTest` | the credential check: which responses issue a token, which are 401, which are 503, and that the password never reaches a log |

All container-free: an RSA key pair is generated in-process, tokens are minted with java-jwt, and
Keycloak and Redis are mocked. The suite runs in a few seconds, so there is no excuse not to run it.

Two Postman collections, for different purposes:

| File | Style | Run it with |
|---|---|---|
| `OAS_Auth_Service.postman_collection.json` | manual walkthrough, `PASTE_...` placeholders | Postman, top to bottom, with `OAS_Auth_Service.postman_environment.json` |
| `postman/OAS_Auth_Service.postman_collection.json` | automated, chained, 11 assertions | `newman`, against a deployed stack — fill in `base_url`, `api_key` and `userId` |

The manual one ends with a `Create Token (verified mode)` request that returns 400 on a default stack;
it is there to document the body, not to pass.

The automated one carries the single most valuable assertion in the suite:

```js
pm.expect(r.registries).to.eql(["cropCatalogue", "seasonCatalogue"]);
```

It fails if either the protocol mapper or the User Profile declaration is single-valued — the one bug in
this area that is otherwise silent, because Keycloak then sends only the first value and logs nothing but
a warning.

Two behaviours worth verifying by hand after any change to revocation:

```bash
# 1. a block outlasts the denylist TTL, i.e. the Keycloak disable really happened
#    revoke, then delete the denylist key to simulate its expiry — login must STILL fail 403
docker exec acs-auth-redis redis-cli DEL "auth:denylist:user:<userId>"

# 2. a re-enable takes effect immediately
#    auth_user_create the same user — login must succeed at once, not after 900s
```

---

## 11. Project structure

```
src/main/java/com/catalogue/verg/
  auth/controller/AuthController              the six endpoints
  auth/service/AuthService                    interface
  auth/service/impl/AuthServiceImpl           orchestration and audit logging
  core/keycloak/config/KeycloakConfig         RestTemplate and JwkProvider beans
  core/keycloak/service/KeycloakService       interface
  core/keycloak/service/KeycloakServiceImpl   tokens, verification, denylist, user administration
  core/catalogue/config/CatalogueConfig       RestTemplate bean for the credential check
  core/catalogue/service/CatalogueService     interface
  core/catalogue/service/CatalogueServiceImpl the credential check, flag-gated
  core/dto/{CustomResponse,RespParam}         response envelope
  core/exception/...                          error handling
  core/util/{Constants,VergProperties}        codes and tunables

setup-realm.sh                                provisions the realm; idempotent, waits for Keycloak
```

This follows the verg layout used across the catalogue services: domain modules as
`controller` / `service` / `service/impl`, and `core` integrations as `config` plus interface and
implementation in `service`.

`auth/` has no `entity` or `repository` package because this service owns no database.

---

## 12. Known pitfalls

Each of these was hit during development. The symptom is misleading in every case.

**The issuer trap.** Keycloak stamps `iss` with whatever URL was used to reach it. If this service calls
Keycloak by one hostname but expects another, every token fails with `AUTH_TOKEN_INVALID`, which reads
like a signature problem and is not. Reproduced: reaching Keycloak at `host.docker.internal:8180` while
`KEYCLOAK_ISSUER` said `localhost:8180`. Pin `KC_HOSTNAME` on Keycloak so it always stamps the same
public issuer, and point `KEYCLOAK_ISSUER` at that value.

**Undeclared user attributes are silently dropped.** On Keycloak 24+ writing an attribute the realm's
User Profile does not declare returns `201 Created` with the attribute simply absent — no error, no log
line. If tokens arrive without `user_id`, `org_id` or `entity_type`, this is the first thing to check.
`setup-realm.sh` declares all three and asserts them.

**A required profile attribute breaks token issuance.** Keycloak declares `email`, `firstName` and
`lastName` as required for the `user` role by default. An incomplete profile raises a `VERIFY_PROFILE`
required action, and the token request then fails with:

```json
{"error":"invalid_grant","error_description":"Account is not fully set up"}
```

which surfaces here as a bare `502` with the user visibly present and enabled. These Keycloak records are
machine-provisioned identity shells and `auth_user_create` is not obliged to supply a name, so
`setup-realm.sh` clears `required` on all three.

**Introspection needs the client in the token's audience.** Without the audience mapper, Keycloak 26
answers a bare `{"active": false}` for a perfectly valid token. The Redis-outage fallback would then
reject everything, turning a Redis outage into a total auth outage. `setup-realm.sh` adds the mapper.

**Keycloak 26.7 answers `400`, not `401`, for a refused direct grant.** Unknown user and disabled user
both come back as `400 invalid_grant`. This service collapses all 4xx before mapping them, so its own
responses are unaffected — but anything asserting on Keycloak's raw status will be wrong.

**A single-valued mapper silently truncates `registries`.** If the protocol mapper's `multivalued` is
`"false"` while the attribute holds several values, Keycloak 26.7 puts **only the first** in the token and
logs nothing but a `KC-SERVICES0046` warning. A wrong access list, invisible to every caller. Two related
traps: `multivalued: false` in the User Profile installs an implicit `max: 1` validator that rejects a
two-value write with a 400, and declaring the `multivalued` *validator* explicitly makes `max` mandatory
or the profile `PUT` itself is rejected. `setup-realm.sh` sets all of this and asserts both halves.

**An admin `PUT` that includes `attributes` but omits a key deletes that attribute.** This is why
omitting `registries` from `auth_user_create` means "keep" rather than "clear" — the payload always emits
an `attributes` object, so a request that simply did not mention the list would wipe it. Clearing is
`[]`, which omits the key and is exactly how Keycloak represents "none".

**An empty attribute means the claim is absent, never `[]`.** A consumer must treat "no `registries` key"
and "empty access list" as the same thing.

**A stale `.env` presents as a 401 on every call.** `setup-realm.sh` regenerates the client secret when
it recreates the client. Re-source `.env` and restart afterwards.

**`docker compose down -v` destroys the realm.** The `kcdata` volume is the only copy. Re-run
`setup-realm.sh`, then restart the service to pick up the new secret.

---

## 13. Not implemented

- **The catalogue's `/user/v1/verify` endpoint.** Our side is built and tested; the catalogue team owns
  that endpoint, and it needs a password-hashing dependency that repo does not currently have. Until it
  exists, `catalogue.validate-enabled` stays `false` and no password is checked anywhere —
  see [§4](#4-credential-verification-flag-gated).
- **The permission matrix.** Who computes a user's `registries` is not decided here. Today it is static
  data in the UI; this service carries whatever list it is handed.
- **Nothing enforces these tokens.** Catalogue endpoints are still open. This service gives you a way to
  *get* and *check* a token, not a requirement to *have* one. The interceptor that calls
  `auth_token_validate` on protected paths is the next piece of work, and is what will finally let
  catalogue audit rows carry a real actor instead of `ANONYMOUS`.
- **No caller authentication on these endpoints.** Network isolation only — see [§6](#6-security-posture).
- **No RBAC.** `entity_type` is a claim, not a permission.
- **No MFA**, and it cannot be added while Keycloak holds no credentials.
- **No refresh endpoint.** Callers use Keycloak's token endpoint directly, or re-authenticate.
- **No k8s manifests.** The Dockerfile plus environment-driven configuration is the deliverable.
