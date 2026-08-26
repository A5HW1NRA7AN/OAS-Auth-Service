# OAS Auth Service

Token issuance, validation and revocation for the OpenAgriStack catalogue services, backed by Keycloak
and Redis.

Spring Boot 3.3.5, Java 17, no database of its own.

## Responsibilities

The user-catalogue owns users and their passwords. Keycloak holds an identity shell per user — the
catalogue's `userId` plus `org_id` and `functional_role` — and issues tokens for it, storing no credential
of any kind. This service owns those tokens and their revocation, and administers the Keycloak users
the catalogue publishes.

This service does not authenticate its callers. Access control is network-level only, so every endpoint
here is intended for service-to-service use inside the cluster. Credential verification of the *end
user* is a separate concern, and it is on by default: `auth_token_create` takes `{email, password}`
and verifies them against the user-catalogue. It can be turned off with
`CATALOGUE_VALIDATE_ENABLED=false`, which makes the endpoint take `{userId}` and trust its caller —
useful only for running this service without a catalogue. See
[§4](#4-credential-verification-flag-gated) and [§6](#6-security-posture).

For the duration of the UAT integration window this service is reachable through Kong at the shared
nginx host (`/auth/v1/*`), gated only by the existing catalogue API keys. That is a temporary
relaxation of the rule above and is tracked for revert in the OAS-Infra repository
(`kong/kong.decK.yaml`, block marked `TEMP/UAT`); see [§6](#6-security-posture).

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
POST /auth/v1/auth_user_create  { userId, orgId, functionalRole, email,
                                  firstName?, lastName?, orgName?, displayName? }
        |
        v
Keycloak user:  username = userId
                enabled  = true
                attributes = { user_id, org_id, functional_role, org_name, display_name }
                firstName / lastName (top-level, projected as first_name / last_name)
                credentials = (none)
```

The push happens before the catalogue persists `ACTIVE`, so a failure here leaves the record at its
previous status and retryable. The reverse order can leave a user the catalogue believes is live but who
cannot obtain a token, with no clean way to detect it afterwards.

### Issuing a token

With `catalogue.validate-enabled=false` — no longer the default, and only for running this service
without a catalogue:

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

By default one step is added in front: the service asks the user-catalogue to verify the email
and password, and only the `userId` the catalogue returns reaches Keycloak. Keycloak's own role is
unchanged, because it still holds no credential. See [§4](#4-credential-verification-flag-gated).

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
CATALOGUE_VALIDATE_ENABLED=false java -jar target/svc-auth-0.0.1-SNAPSHOT.jar
```

The override is what makes this a standalone run. Credential verification is on by default and needs
the user-catalogue reachable; without it `auth_token_create` returns `503`. Drop the override once the
catalogue is running and log in with `{email, password}` instead — see
[§4](#4-credential-verification-flag-gated).

Ordering matters in one place: `setup-realm.sh` generates the client secret, so the application must
start after it with `.env` sourced. Start it first and every call fails with `invalid_client`. The
script waits for Keycloak itself (about 10 seconds from a cold container), so it is safe to run
immediately after `docker compose up -d`.

Verify:

```bash
curl -s localhost:8080/actuator/health/readiness

curl -s -X POST localhost:8080/auth/v1/auth_user_create \
  -H 'Content-Type: application/json' \
  -d '{"userId":"user-000000000001","orgId":"org-000000000001","functionalRole":"MAKER",
       "email":"user@example.com"}'

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
{ "userId": "user-000000000001", "orgId": "org-000000000001", "functionalRole": "MAKER",
  "email": "user@example.com", "firstName": "Season", "lastName": "Field Agent",
  "orgName": "Bharat Agri", "displayName": "FIELD_OFFICER" }
```

```json
{ "result": { "userId": "user-000000000001", "created": true, "enabled": true } }
```

`userId`, `orgId`, `functionalRole` and `email` are required. `firstName`, `lastName`, `orgName` and
`displayName` are optional.

`functionalRole` was called `entityType` until the catalogue collapsed its per-catalogue `registry[]`
array to a single scalar role. The rename is hard: sending `entityType` is a `400`, not a fallback.

`email` is required because it is the login identifier the catalogue verifies a password against — a
user published without one could never authenticate. Keycloak's own User Profile must NOT mark it
required, though; that raises `VERIFY_PROFILE` and fails the grant with "Account is not fully set up",
which is why `setup-realm.sh` deletes `required` from it.

**Every optional field carries forward.** Omitting one — or sending an explicit `null` — keeps whatever
is stored, so a republish that knows only the identifiers never wipes a name. There is deliberately no
"clear" signal: this endpoint is called from retry paths, and a stray `null` must not erase a value the
caller did not mean to touch. The consequence is that an `orgName` or `displayName` set once cannot be
unset through this API; `auth_user_delete` followed by `auth_user_create` is the escape hatch.

An existing user returns `200` with `created: false` rather than a conflict — the caller is a catalogue
whose publish is "push here, then persist ACTIVE", so every way this response can be lost leaves it
believing the push did not happen. A 409 there would wedge the record permanently. The update rewrites
`enabled` and every attribute, so a republish repairs drift.

`409 AUTH_USER_CONFLICT` means a different Keycloak username already holds that email. Retrying will
not fix it; the data has to change.

### POST /auth/v1/auth_token_create

The body depends on `catalogue.validate-enabled`, and the flag alone selects the path — never the shape
of the body.

```json
{ "email": "asha@example.org", "password": "..." }     // flag on (default): verified by the catalogue
{ "userId": "user-000000000001" }                      // flag off: trusts the caller
```

Returns Keycloak's token response verbatim (`access_token`, `refresh_token`, `expires_in`, …).

With the flag on, a `userId` in the body is ignored: the token is issued for the `userId` the catalogue
returned. Honouring the body's value would let one valid password mint a token for any other account.
Sending only `{userId}` while the flag is on is a `400`, not a fallback — otherwise any caller could
downgrade out of verification. See [§4](#4-credential-verification-flag-gated).

### POST /auth/v1/auth_token_validate

```json
{ "token": "<access token>" }
```

```json
{ "result": { "active": true, "sub": "…", "preferred_username": "user-000000000001",
              "user_id": "user-000000000001", "org_id": "org-000000000001",
              "org_name": "Bharat Agri", "functional_role": "MAKER",
              "display_name": "FIELD_OFFICER",
              "first_name": "Season", "last_name": "Field Agent",
              "email": "user@example.com", "exp": 1786968521, "jti": "…", "sid": "…" } }
```

The token is never echoed back.

Every key is always present; an optional claim the token does not carry comes back as `null`. A key
that is simply missing would be indistinguishable from one this service forgot to surface.

If `functional_role`, `org_name` or `display_name` is `null` on a user you know has them, the realm's
mappers are the first thing to check — see [§9](#9-things-that-will-bite-you).

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

Denylists the user and every indexed session, then disables the user in Keycloak.

This takes the `userId`, not the email — unlike `auth_token_create`, which takes the email because that
is what the catalogue matches on. Passing an email here revokes nothing, so it returns
`404 AUTH_USER_NOT_FOUND` rather than a misleading success.

A genuine Keycloak failure is different: it returns `200` with `keycloakDisabled: "failed"`, because the
Redis revocation already stopped anyone holding a live token and a Keycloak blip must not fail the
block. Absent means nothing happened; failed means half of it did.

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
  "org_name": "Bharat Agri",
  "functional_role": "MAKER",
  "display_name": "FIELD_OFFICER",
  "first_name": "Season",
  "last_name": "Field Agent",
  "name": "Season Field Agent",
  "email": "user@example.com",
  "email_verified": true
}
```

All seven of `user_id`, `org_id`, `functional_role`, `org_name`, `display_name`, `first_name` and
`last_name` are projected by the `oas-profile` client scope's mappers. The first five read custom user
attributes `auth_user_create` wrote; `first_name` and `last_name` read Keycloak's own `firstName` and
`lastName` fields.

**`first_name` / `last_name`, not `given_name` / `family_name`.** Keycloak's built-in `profile` scope
emits the OIDC-standard pair by default; `setup-realm.sh` deletes those two mappers so every claim in
this token follows one naming convention. That costs interoperability with an off-the-shelf OIDC
consumer, and it edits a scope shared by the whole realm — acceptable only because the realm is locked
to a single client. `preferred_username` and `name` still come from that scope untouched, and
`preferred_username` must stay: revocation falls back to it when `user_id` is absent.

`functional_role` and `display_name` are data, not permissions — there is no RBAC, and nothing here or
in Keycloak enforces either. `display_name` is the human-readable label for the role (e.g.
`FIELD_OFFICER`); `functional_role` is the value to branch on. A consumer that wants to gate on either
must do so itself.

### Errors

| Code | Status | Meaning | Caller action |
|---|---|---|---|
| `AUTH_INVALID_REQUEST` | 400 | a required field is missing | fix the request |
| `AUTH_TOKEN_INVALID` | 401 | signature, issuer, `typ` or `azp` wrong, or malformed | re-authenticate |
| `AUTH_TOKEN_EXPIRED` | 401 | past `exp` | refresh |
| `AUTH_TOKEN_REVOKED` | 401 | denylisted | re-authenticate |
| `AUTH_INVALID_CREDENTIALS` | 401 | the catalogue rejected the credentials (its 401 or 403) | re-authenticate |
| `AUTH_USER_DISABLED` | 403 | blocked in Keycloak | `auth_user_create` re-enables |
| `AUTH_USER_NOT_FOUND` | 404 | never provisioned, or a wrong identifier on revoke/delete | call `auth_user_create`, or check you sent the userId |
| `AUTH_USER_CONFLICT` | 409 | another Keycloak username holds that email | change the data |
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

`catalogue.validate-enabled` is `true` by default, so credentials are verified unless someone turns
that off. The deployed environment also sets it explicitly in OAS-Infra via
`services/oas-auth-service.config.yaml`.

The cost of the safe default is that this service no longer starts useful without a reachable
catalogue: with no catalogue, `auth_token_create` returns `503`. Set `CATALOGUE_VALIDATE_ENABLED=false`
to run it standalone — it then takes `{userId}` and trusts its caller completely.

```properties
catalogue.validate-enabled=true             # default: {email, password}, verified by the catalogue
catalogue.base-url=http://localhost:8082    # the user-catalogue. In-cluster:
                                            #   http://org-user-notification-services.app.svc.cluster.local:8080
catalogue.verify-path=/user/v1/verify
```

With the flag on, `auth_token_create` takes `{email, password}`, calls the catalogue, and issues a token
only for the `userId` the catalogue returns.

Confirm the mode after enabling it. Anything Spring does not read as `true` — unset, misspelled, `0`,
`False`, `"true "` — silently means `false`, and passwords then stop being checked with no error
anywhere. Two things make that visible: every call logs `mode=VERIFIED` or `mode=TRUSTED`, and the audit
line records `SUCCESS` or `SUCCESS_UNVERIFIED`, so an audit stream proves which path served each token.

### The catalogue's contract

As deployed:

```
POST /user/v1/verify     { "email": "...", "password": "<plaintext>" }

200  { "result": { "userId": "user-000000000001", "email": "...", "status": "ACTIVE" },
       "message": "successfully verified" }
401  { "message": "Invalid credentials" }     // unknown email, or wrong password
403  { "message": "User is not active" }      // credentials fine, record not ACTIVE
400  { "message": "Email and password are required" }
```

How this service maps it:

| Catalogue answers | This service returns |
|---|---|
| `200` with `result.userId` | the token, issued for that userId |
| `401` or `403` | `401 AUTH_INVALID_CREDENTIALS` — collapsed, so a caller cannot tell a blocked account from a wrong password |
| `200` with no `userId` | `503`, and never a token for the submitted email |
| `400`, `404`, `5xx`, unreachable, unparseable | `503`, fail closed |

Two deliberate choices. Only `401`/`403` count as a rejection — everything else is an outage, because
reporting `401` for an unreadable response would blame the user's password and hide the fault, and a
missing Kong route produces exactly that `404`. And the login identifier is the email: the catalogue's
schema has no username column, only `email` and the generated `userId`, so the email is forwarded
verbatim and the catalogue decides how to resolve it.

The catalogue is reached in-cluster, so the request never traverses Kong and needs no API key.

`/user/v1/verify` has no Kong route, deliberately. It accepts plaintext passwords and returns a
credential verdict, and with the in-cluster path nothing external needs it. Kong's route regexes list
actions explicitly and `verify` is in neither list, so an external call gets `404 no Route matched` and
never reaches the pod — the intended posture, not a bug. Test it with
`kubectl -n app port-forward deploy/org-user-notification-services 8082:8080`.

Three things the catalogue owns that are worth tracking:

1. It reads the password hash from Elasticsearch, not Postgres, so a user with a missing or stale index
   document cannot log in even with the right password — and the failure looks like a wrong password.
2. Its `401` vs `403` split tells a direct caller whether an account exists. This service collapses the
   two, but anything calling the catalogue directly still sees it.
3. `password` and `pin` are indexed in Elasticsearch, and `/user/v1/search` takes `requestedFields` from
   the request body with no denylist — so a read-scoped API key can retrieve every user's stored hashes.

---

## 5. Catalogue integration contract

The catalogue makes three calls, plus one endpoint it exposes ([§4](#4-credential-verification-flag-gated)).
Nothing in the catalogue talks to Keycloak, and Keycloak does not call the catalogue.

| Catalogue event | Call | Notes |
|---|---|---|
| publish, status becomes `ACTIVE` | `auth_user_create` | before persisting ACTIVE; on failure leave the record retryable |
| `ACTIVE -> INACTIVE` | `auth_user_revoke` | |
| `INACTIVE -> ACTIVE` | `auth_user_create` | re-enables and clears the block |
| record deleted | `auth_user_delete` | |
| login | `auth_token_create` with `{email, password}` | unless `catalogue.validate-enabled` is turned off |

Every optional field on `auth_user_create` carries forward when omitted, so a republish that knows only
the identifiers never wipes a stored name. The flip side is that a value the catalogue *changes* only
reaches the token on a republish: this service holds a snapshot taken at publish time, and nothing
refreshes it. A catalogue that edits a user's `orgName`, `displayName` or `functionalRole` must call
`auth_user_create` again, or every token issued afterwards carries the old value.

Use a `RestTemplate` with timeouts. A shared bean usually has none, and a hung call would hold the
request thread indefinitely. Do not report the raw exception on failure: a connection error message
contains this service's internal host and port.

Revoked tokens stay dead after a re-enable. `auth_user_create` clears the user-level block so logins work
again immediately, but the per-session entries are left in place on purpose.

---

## 6. Security posture

Nothing here authenticates its caller. There is no interceptor, no API key, no mTLS. Access control is
entirely network-level, by decision. All six endpoints, and Keycloak's token endpoint, must be
unreachable from outside the cluster.

During the UAT integration window that property does not hold: the service is routed through Kong at
the shared nginx host (`/auth/v1/*`) behind the existing catalogue API keys, which authenticate a
client but not an end user. The revert is tracked in OAS-Infra (`kong/kong.decK.yaml`, block marked
`TEMP/UAT`) and must be completed before production.

`auth_token_create` mints a token for any `userId` whenever `catalogue.validate-enabled` is `false`.
A single misconfigured Kong route is then a full authentication bypass for every account. The default
is `true`, so this requires someone to actively turn verification off.

The flag is silent when it is wrong. `CATALOGUE_VALIDATE_ENABLED` set to anything Spring does not read
as `true` — `0`, `False`, `"true "` — means `false`, drops back to trusting the caller and still returns
a token: the only failure in this service whose wrong outcome is a 200. An unset variable is now safe,
because the default is `true`. Grep the log for `mode=VERIFIED` after any deployment.

The `oas-auth-service` client secret is the boundary. Because the realm's direct grant flow checks no
credential, anyone holding that secret can obtain a token for any user in the realm. Treat it as a root
credential: `setup-realm.sh` writes it to `.env` (gitignored) and regenerating it is a re-run away.

Keycloak's `admin-cli` client needs specific attention. `directGrantFlow` is a realm-wide binding, and
Keycloak auto-creates a public `admin-cli` client with direct access grants enabled in every realm. With
no password step in the flow, this issues a live token for any user with no secret and no password:

```
POST /realms/OAS/protocol/openid-connect/token
grant_type=password&client_id=admin-cli&username=<any userId>
```

Verified against Keycloak 26.7 — it does return a token. `setup-realm.sh` disables direct access grants
on every client except `oas-auth-service` and then fails loudly if any other client still has it,
because a rebuilt realm recreates `admin-cli` with the flag back on. Do not remove that assertion.

MFA is structurally impossible in this realm while Keycloak holds no credentials.

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
| `KEYCLOAK_ISSUER` | `http://localhost:8180/realms/OAS` | the public ingress URL |
| `KEYCLOAK_REALM` | `OAS` | `OAS` |
| `KEYCLOAK_CLIENT_ID` | `oas-auth-service` | same |
| `KEYCLOAK_CLIENT_SECRET` | from `.env` | from a Secret |
| `KEYCLOAK_CONNECT_TIMEOUT_MS` / `_READ_TIMEOUT_MS` | 2000 / 5000 | tune as needed |
| `KEYCLOAK_CLOCK_SKEW_SECONDS` | 30 | 30 |
| `KEYCLOAK_DENYLIST_SID_TTL_SECONDS` | 900 | at least the SSO session max |
| `CATALOGUE_VALIDATE_ENABLED` | `true` | `true` |
| `CATALOGUE_BASE_URL` | `http://localhost:8082` | `http://org-user-notification-services.app.svc.cluster.local:8080` (Service DNS, not the public host) |
| `CATALOGUE_VERIFY_PATH` | `/user/v1/verify` | same |
| `CATALOGUE_CONNECT_TIMEOUT_MS` / `_READ_TIMEOUT_MS` | 2000 / 5000 | the read timeout is the login latency ceiling |

`KEYCLOAK_BASE_URL` (how this service reaches Keycloak) and `KEYCLOAK_ISSUER` (what Keycloak stamps into
tokens) are separate on purpose. See [§12](#12-known-pitfalls).

The service authenticates to Keycloak's admin API using its own client's service account
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

Readiness intentionally does not depend on Keycloak or Redis. A green readiness probe therefore does not
mean logins work — those failures surface as 503 on the endpoints instead.

### Keycloak

The stock `quay.io/keycloak/keycloak:26.7` image, with no custom provider and no `kc.sh build`. For a
real environment: run `start --optimized` rather than `start-dev`, attach a real database, set
`KC_HOSTNAME` to the public URL, `KC_HOSTNAME_STRICT=true`, and `KC_PROXY_HEADERS=xforwarded` behind an
ingress. Do not expose the token endpoint publicly.

### Realm provisioning

`setup-realm.sh` is idempotent and environment-driven (`KC`, `REALM`, `CLIENT`, `ADMIN_USER`,
`ADMIN_PASS`, `KC_WAIT_SECONDS`). Run it once against a deployed Keycloak after its database is
attached. It creates the realm and client, enables the service account and grants it `manage-users` and
`view-users`, declares the custom attributes in the User Profile, creates the `oas-profile` scope with
its mappers and the audience mapper, strips the password step from the direct grant flow, disables
direct access grants on every other client, turns off email login, and verifies all of it.

The realm lives only in the `kcdata` volume, so `docker compose down -v` destroys it and this script is
how you rebuild it. Re-run it after any upgrade that recreates the realm.

---

## 10. Testing

```bash
./mvnw test        # 90 tests
```

| Class | Covers |
|---|---|
| `KeycloakServiceImplTest` | token verification: algorithm confusion, wrong key, tampering, issuer, `azp`, `typ`, expiry, denylist by jti/sid/user, introspection fallback, fail-closed |
| `KeycloakServiceImplAdminTest` | service-account token caching and invalidation, upsert create/update/conflict, disable, delete idempotency, no password in the grant, the 404/403 split |
| `AuthServiceImplTest` | the JSON contract the catalogue integrates against, required fields, the revoke-before-delete ordering, both flag paths, and the two bypass guards |
| `CatalogueServiceImplTest` | the credential check: which responses issue a token, which are 401, which are 503, and that the password never reaches a log |

All container-free: an RSA key pair is generated in-process, tokens are minted with java-jwt, and
Keycloak and Redis are mocked. The suite runs in a few seconds.

Two Postman collections, for manual walkthroughs of the same ten-step lifecycle:

```
postman/OAS_Auth_Service.postman_collection.json             deployed, behind the shared nginx host
postman/OAS_Auth_Service_local_test.postman_collection.json  auth-service :8080, catalogue :8082 (gitignored)
```

Import a collection and run it. There is no environment file and nothing is captured automatically:
each collection carries its own service URLs as collection variables, and the deployed one adds
`api_key`, sent as the `apikey` header. Set it to an editors-scoped key, because Create User uses the
catalogue's write route.

Everything else is typed by hand. Edit the user details in Create User, then copy the `userId` and the
tokens out of each response into the requests that need them — the placeholders are `PASTE_USER_ID`,
`PASTE_ACCESS_TOKEN` and `PASTE_REFRESH_TOKEN`.

The order is: Create User, Read User, Verify Credentials, Create Token, Validate Token, Invalidate
Token, Revoke User, Enable User, Delete User, Delete Catalogue Record. Re-running Validate Token after
Invalidate Token, and Create Token after each of Revoke, Enable and Delete, is what shows the
transitions — `401` revoked, `403` disabled, `200` again, then `404` not provisioned.

Create User logs in with `{email, password}`, so it needs a reachable catalogue. That is the default
behaviour; if someone has set `CATALOGUE_VALIDATE_ENABLED=false`, the login step returns `400`, because
the flag alone selects the path ([§4](#4-credential-verification-flag-gated)).

Create User is also an integration test of both services: it only succeeds if the catalogue's own call
to `auth_user_create` succeeded, so a green Create User means the two are talking. Keep the email
unique — Keycloak allows one user per email, so re-using one returns `409` until the previous user is
removed by the last two requests.

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
like a signature problem and is not. Reproduced by reaching Keycloak at `host.docker.internal:8180`
while `KEYCLOAK_ISSUER` said `localhost:8180`. Pin `KC_HOSTNAME` on Keycloak so it always stamps the
same public issuer, and point `KEYCLOAK_ISSUER` at that value.

**Undeclared user attributes are silently dropped.** On Keycloak 24+ writing an attribute the realm's
User Profile does not declare returns `201 Created` with the attribute simply absent — no error, no log
line. If tokens arrive without `user_id`, `org_id` or `functional_role`, this is the first thing to check.
`setup-realm.sh` declares all of them and asserts them.

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

**A client scope's mappers are only created when the scope is.** The original `setup-realm.sh` built
`oas-profile`'s mappers inside `if [ -z "$SCOPE_ID" ]`, so re-running it against a realm that already
had the scope printed `skip` and touched nothing. Adding a claim that way appears to work — the script
exits `0` — while no mapper is ever created and every token silently omits it. `auth_token_create` still
returns `200` and Keycloak logs nothing. Every mapper is now created through an upsert that runs
unconditionally and is asserted in step 6; anything added later must go through the same loop.

**An admin `PUT` that includes `attributes` but omits a key deletes that attribute.** The payload always
emits an `attributes` object, so a request that simply did not mention `org_name` would wipe it. That is
why `updateUser` merges the stored values in before building the payload, and why every optional field
carries forward rather than clearing. Note the asymmetry it has to respect: `email`, `firstName` and
`lastName` are top-level Keycloak fields, while `org_name` and `display_name` are attributes — reading
either through the other's accessor compiles fine and silently wipes the value on every republish.

**An empty attribute means the claim is absent, never empty.** Keycloak omits an attribute with no
value entirely, so a consumer must treat "no `display_name` key" and "no display name" as the same
thing. `auth_token_validate` normalises this: every key is always present, `null` when the token does
not carry it.

**A `length` validator that is too short reads as an outage.** The User Profile declares `max: 255` on
`org_name` and `display_name`, not the 64 the identifiers use, because a real organisation name exceeds
64 routinely. Over the limit Keycloak answers `400`, `adminFailure` has no branch for it, and the caller
sees a bare `502 AUTH_IDP_OPERATION_FAILED` with the real reason only in Keycloak's own log.

**`auth_token_create` takes the email; every other endpoint takes the userId.** That asymmetry is the
easiest thing here to get wrong, because the catalogue has no username column and matches on `email`,
while Keycloak's username is the catalogue's `userId`. Revoking with an email used to look like a success
while blocking nobody; it now returns 404.

**A stale `.env` presents as a 401 on every call.** `setup-realm.sh` regenerates the client secret when
it recreates the client. Re-source `.env` and restart afterwards.

**`docker compose down -v` destroys the realm.** The `kcdata` volume is the only copy. Re-run
`setup-realm.sh`, then restart the service to pick up the new secret.

---

## 13. Not implemented

- **Nothing enforces these tokens.** Catalogue endpoints are still open. This service gives you a way to
  get and check a token, not a requirement to have one. An interceptor calling `auth_token_validate` on
  protected paths is the piece that would let catalogue audit rows carry a real actor instead of
  `ANONYMOUS`.
- **Revocation is not yet wired from the catalogue.** The catalogue calls `auth_user_create` on publish,
  but its status toggle and delete paths do not yet call `auth_user_revoke` and `auth_user_delete`, so
  blocking a user leaves their existing tokens valid until they expire. Both endpoints here are built
  and tested; only the calls are missing.
- **No caller authentication on these endpoints.** Network isolation only — see [§6](#6-security-posture).
- **No RBAC.** `functional_role` is a claim, not a permission.
- **No MFA**, and it cannot be added while Keycloak holds no credentials.
- **No refresh endpoint.** Callers use Keycloak's token endpoint directly, or re-authenticate.
- **No k8s manifests.** The Dockerfile plus environment-driven configuration is the deliverable.
