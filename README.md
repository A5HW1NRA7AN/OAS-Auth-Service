# OAS Auth Service

Token issuance, validation and revocation for the OpenAgriStack catalogue services, backed by Keycloak
and Redis. Spring Boot 3.3.5, Java 17, no database of its own.

## Responsibilities

The user-catalogue owns users, passwords and PINs. Keycloak holds an identity shell per user (the
catalogue's `userId`, `org_id`, `functional_role`) and issues tokens for it, storing no credential.
This service owns those tokens, their revocation, PIN-login devices, and the Keycloak users the
catalogue publishes.

It does not authenticate its callers: every endpoint is for service-to-service use inside the
cluster. End-user credentials are verified by default: `auth_token_create` takes `{email, password}`
and checks them against the catalogue. `CATALOGUE_VALIDATE_ENABLED=false` makes it take `{userId}`
and trust the caller, for running without a catalogue only ([§4](#4-credential-verification),
[§6](#6-security-posture)).

For the UAT window the service is reachable through Kong at the shared nginx host (`/auth/v1/*`),
gated only by the catalogue API keys. The revert is tracked in OAS-Infra (`kong/kong.decK.yaml`,
block marked `TEMP/UAT`).

## Contents

1. [Architecture](#1-architecture)
2. [Quick start](#2-quick-start)
3. [API reference](#3-api-reference)
4. [Credential verification](#4-credential-verification)
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

A user exists in Keycloak only because the catalogue published them, before it persists `ACTIVE`,
so a failure leaves the record retryable.

```
POST /auth/v1/auth_user_create  { userId, orgId, functionalRole, email,
                                  firstName?, lastName?, orgName?, displayName? }
  -> Keycloak user: username = userId, enabled = true, no credentials
     attributes { user_id, org_id, functional_role, org_name, display_name }
     firstName / lastName (top-level, projected as first_name / last_name)
```

### Issuing a token

```
{ email, password } -> catalogue /user/v1/verify -> userId      (default; skipped when the flag is off)
userId -> Keycloak direct grant, no password field -> access_token + refresh_token
```

The realm's direct grant flow has no password step (`setup-realm.sh` removes it and asserts it), so
Keycloak only resolves the user and enforces `enabled`. The client secret and network isolation are
what protect that grant ([§6](#6-security-posture)).

### Validation

Entirely local, with no Keycloak call on the hot path:

```
signature (RS256, pinned) -> iss -> exp / nbf -> typ == Bearer -> azp == client -> jti -> Redis denylist
```

RS256 is pinned in code, never read from the header, which blocks algorithm confusion (the published
key used as an HMAC secret); a test covers it. If Redis cannot answer, validation falls back to
Keycloak introspection; if neither can, it fails closed.

### Revocation

Keycloak cannot recall an issued JWT, so blocking takes both halves:

| Action | Does | Cannot |
|---|---|---|
| Redis denylist | kills tokens in circulation | outlast its TTL |
| Keycloak `enabled=false` | stops all future tokens | touch an issued token |

`auth_user_revoke` does both and removes the user's PIN devices. `auth_user_create` reverses the
block, but not the device removal: the user logs in with a password and enrols again.

### PIN login

After a password login the app can enrol its device, then log in with a 6-digit PIN for 30 days.

```
auth_token_create      { email, password, pinLogin: true } -> tokens + deviceHandle
auth_token_create_pin  { deviceHandle, pin }               -> tokens
```

Neither half works alone: the handle proves the device, the catalogue checks the PIN for the device's
user, and five wrong PINs remove the device. A user-chosen 6-digit PIN is at most 20 bits, so it could
never stand alone; with the device required, a stolen handle buys 5 guesses in a million. The handle
is 32 random bytes and Redis holds only its SHA-256. Tokens come from the same issuance path as a
password login, so all revocation covers them.

---

## 2. Quick start

```bash
docker compose up -d              # Redis on 6380, Keycloak on 8180
./setup-realm.sh                  # realm, client, service account, flow, hardening; writes .env
./mvnw clean package
set -a; . ./.env; set +a           # KEYCLOAK_CLIENT_SECRET
CATALOGUE_VALIDATE_ENABLED=false java -jar target/svc-auth-0.0.1-SNAPSHOT.jar
```

The override makes this a standalone run; with a catalogue running, drop it and log in with
`{email, password}`. Start the service after `setup-realm.sh` with `.env` sourced, or every call fails
with `invalid_client`. The script waits for Keycloak itself.

```bash
curl -s localhost:8080/actuator/health/readiness
curl -s -X POST localhost:8080/auth/v1/auth_user_create -H 'Content-Type: application/json' \
  -d '{"userId":"user-000000000001","orgId":"org-000000000001","functionalRole":"MAKER","email":"user@example.com"}'
curl -s -X POST localhost:8080/auth/v1/auth_token_create -H 'Content-Type: application/json' \
  -d '{"userId":"user-000000000001"}'
```

| Service | Port | Notes |
|---|---|---|
| auth-service | 8080 | `SERVER_PORT` |
| Keycloak | 8180 | bound to `127.0.0.1` in compose |
| Redis | 6380 | 6379 is left to the catalogue's stack |

---

## 3. API reference

All nine endpoints are `POST /auth/v1/<action>` with a JSON body. Success returns the standard
envelope (`result`, `params`, `responseCode`); failure returns `{code, message, httpStatusCode}`.

### auth_user_create

```json
{ "userId": "user-000000000001", "orgId": "org-000000000001", "functionalRole": "MAKER",
  "email": "user@example.com", "firstName": "Season", "lastName": "Field Agent",
  "orgName": "Bharat Agri", "displayName": "FIELD_OFFICER" }
```

```json
{ "result": { "userId": "user-000000000001", "created": true, "enabled": true } }
```

- Creates or updates the user. Idempotent, and the re-enable path after a revoke: an existing user is
  `200` with `created: false`, never a 409 that would wedge the caller's retry.
- `userId`, `orgId`, `functionalRole`, `email` are required. `email` is the login identifier; sending
  the old `entityType` instead of `functionalRole` is a `400`.
- **Optional fields carry forward:** an omitted or `null` value keeps the stored one, because this is
  called from retry paths. A value set here cannot be unset here; use `auth_user_update`.
- `409 AUTH_USER_CONFLICT`: another Keycloak user holds the email. Retrying will not help.

### auth_user_update

Same body and required fields as `auth_user_create`; returns `{ "userId": ..., "updated": true }`.

- **Replace, not merge:** an omitted optional field is cleared, since the catalogue is the source of truth.
- Never re-enables and never clears the denylist (`enabled` is not sent), so editing a revoked user
  leaves them revoked.
- `404 AUTH_USER_NOT_FOUND` if never published: an update must not create.
- Always send `displayName`: the agri catalogues reject tokens without a `display_name` claim.

### auth_token_create

```json
{ "email": "asha@example.org", "password": "..." }   // default: verified by the catalogue
{ "userId": "user-000000000001" }                    // CATALOGUE_VALIDATE_ENABLED=false: trusted
```

- Returns Keycloak's token response verbatim, plus `deviceHandle` and `deviceId` when `pinLogin` was sent.
- The flag alone selects the path, never the body: in verified mode a body `userId` is ignored, and a
  bare `{userId}` is a `400` rather than a downgrade.
- `pinLogin: true` (optional `deviceLabel`) enrols the device, only after the password was verified and
  never in trusted mode. The app keeps `deviceHandle` in secure storage; it is returned only once.

### auth_token_create_pin

```json
{ "deviceHandle": "<from auth_token_create with pinLogin>", "pin": "482913" }
```

Returns the same token response as `auth_token_create`, whatever the flag says.

| Outcome | Response |
|---|---|
| a field missing | `400 AUTH_INVALID_REQUEST`, no attempt spent |
| unknown, expired or removed device | `401 AUTH_TOKEN_INVALID`, catalogue not called |
| wrong PIN, attempts 1–4 | `401 AUTH_INVALID_CREDENTIALS` |
| wrong PIN, attempt 5 | `401 AUTH_TOKEN_REVOKED`, device removed; log in with a password |
| Redis or the catalogue unavailable | `503`, no token, no attempt spent |

Each attempt is counted (atomic `INCR`) before the PIN is checked, so parallel requests cannot share
one; a correct PIN resets the count. It fails closed on Redis: the counter is the control. It is a
separate endpoint because `auth_token_create` never lets the body choose the path.

### auth_token_refresh

```json
{ "refreshToken": "<from auth_token_create>" }
```

- Returns a new token pair verbatim. Access tokens live 5 minutes; sessions 30 minutes idle and up to
  10 hours (Keycloak defaults, unset by `setup-realm.sh`).
- Forwarded unexamined: only Keycloak knows whether the session lives. Every refusal is Keycloak's
  `400 invalid_grant`, returned as one `401 AUTH_TOKEN_INVALID`.
- The session is re-indexed (same `sid`, new `jti`) so revocation still finds it; a revoked user's
  refreshed token is rejected by `auth_token_validate`.

### auth_token_validate

```json
{ "token": "<access token>" }
```

```json
{ "result": { "active": true, "sub": "…", "preferred_username": "user-000000000001",
              "user_id": "user-000000000001", "org_id": "org-000000000001", "org_name": "Bharat Agri",
              "functional_role": "MAKER", "display_name": "FIELD_OFFICER", "first_name": "Season",
              "last_name": "Field Agent", "email": "user@example.com", "exp": 1786968521,
              "jti": "…", "sid": "…" } }
```

The token is never echoed. Every key is always present, `null` when the token lacks the claim. Null
claims for a user who has them usually mean a realm mapper problem ([§12](#12-known-pitfalls)).

### auth_token_invalidate

```json
{ "token": "<access token>", "refreshToken": "<optional; also ends the Keycloak session>" }
```

Returns `{ "localRevocation": "ok", "idpLogout": "ok" }`. Accepts an expired token so its session can
still be killed. Logout does not remove a PIN device.

### auth_user_revoke

```json
{ "userId": "user-000000000001" }
```

Returns `{ "userId": ..., "revoked": true, "keycloakDisabled": "ok" }`.

- Denylists the user and every indexed session, deletes every PIN device, then disables the user in
  Keycloak.
- Devices are deleted, not denylisted: a republish clears the user denylist and would revive them.
- Takes the `userId`, not the email: an unknown id is `404 AUTH_USER_NOT_FOUND`, never a false success.
- A Keycloak failure is `200` with `keycloakDisabled: "failed"`: Redis already stopped the tokens.

### auth_user_delete

```json
{ "userId": "user-000000000001" }
```

Returns `{ "userId": ..., "revoked": true, "deleted": true }`. Revokes first (devices included), then
deletes; an absent user is `200` with `deleted: false`, so a retried cleanup can finish.

### Token shape

```json
{ "iss": "http://localhost:8180/realms/OAS", "aud": ["oas-auth-service", "account"],
  "azp": "oas-auth-service", "typ": "Bearer", "sub": "8f204b4c-…", "sid": "WVTq…", "jti": "onrtro:…",
  "preferred_username": "user-000000000001", "user_id": "user-000000000001",
  "org_id": "org-000000000001", "org_name": "Bharat Agri", "functional_role": "MAKER",
  "display_name": "FIELD_OFFICER", "first_name": "Season", "last_name": "Field Agent",
  "name": "Season Field Agent", "email": "user@example.com", "email_verified": true }
```

- The seven OAS claims come from the `oas-profile` scope's mappers: five from custom attributes,
  `first_name`/`last_name` from Keycloak's own fields.
- `setup-realm.sh` deletes the built-in `given_name`/`family_name` mappers so all claims share one
  naming convention (acceptable because the realm has a single client).
- `preferred_username` must stay: revocation falls back to it without `user_id`.
- `functional_role` and `display_name` are data, not permissions: there is no RBAC here.

### Errors

| Code | Status | Meaning | Caller action |
|---|---|---|---|
| `AUTH_INVALID_REQUEST` | 400 | a required field is missing | fix the request |
| `AUTH_TOKEN_INVALID` | 401 | bad signature, issuer, `typ` or `azp`, malformed; or an unknown PIN device | re-authenticate |
| `AUTH_TOKEN_EXPIRED` | 401 | past `exp` | refresh |
| `AUTH_TOKEN_REVOKED` | 401 | denylisted; or a device removed after five wrong PINs | log in with a password |
| `AUTH_INVALID_CREDENTIALS` | 401 | the catalogue rejected the password or PIN (its 401 or 403) | re-authenticate |
| `AUTH_USER_DISABLED` | 403 | blocked in Keycloak | `auth_user_create` re-enables |
| `AUTH_USER_NOT_FOUND` | 404 | never provisioned, or a wrong id on revoke/delete/update | publish, or send the userId |
| `AUTH_USER_CONFLICT` | 409 | another Keycloak user holds that email | change the data |
| `AUTH_IDP_OPERATION_FAILED` | 502 | Keycloak rejected the call | configuration fault; alert |
| `AUTH_UPSTREAM_UNAVAILABLE` | 503 | Keycloak or the catalogue unreachable or unparseable | retry |
| `AUTH_REVOCATION_FAILED` | 503 | Redis unreachable | retry |

The 404/403 split on a refused grant is safe (no password is in play) and costs one admin lookup on
the failure path only.

| Dependency down | Effect |
|---|---|
| Redis | validation falls back to introspection; revocation, PIN enrolment and PIN login return 503 |
| Keycloak | token issuance and user administration return 503; validation continues on cached JWKS |
| Both | fails closed |

---

## 4. Credential verification

`catalogue.validate-enabled` defaults to `true`, and OAS-Infra also sets it explicitly
(`services/oas-auth-service.config.yaml`). Without a reachable catalogue `auth_token_create` returns
`503`; set `CATALOGUE_VALIDATE_ENABLED=false` to run standalone.

Anything Spring does not read as `true` (`0`, `False`, `"true "`) silently means `false`. Every call
logs `mode=VERIFIED` or `mode=TRUSTED` and audits `SUCCESS` or `SUCCESS_UNVERIFIED`; check after a
deploy.

### The catalogue's contract

```
POST /user/v1/verify      { "email": "...", "password": "<plaintext>" }
POST /user/v1/verify_pin  { "userId": "...", "pin": "<plaintext>" }

200  { "result": { "userId": "user-000000000001", "status": "ACTIVE" } }
401  wrong or unknown credential        403  record not ACTIVE        400  missing field
```

| Catalogue answers | This service returns |
|---|---|
| `200` with `result.userId` | a token for that userId |
| `401` or `403` | `401 AUTH_INVALID_CREDENTIALS`, collapsed so a blocked account looks like a wrong password |
| `200` without a `userId`, or a PIN verdict for a different `userId` | `503`, never a token |
| `400`, `404`, `5xx`, unreachable, unparseable | `503`, fail closed |

- Only `401`/`403` are rejections: calling an outage a `401` would blame the user and hide the fault.
- `verify_pin` takes the `userId`, never an email, so a stolen handle cannot target another account.
- Both are called in-cluster and have no Kong route by design (Kong lists actions explicitly), so an
  external call gets `404 no Route matched`. Test with
  `kubectl -n app port-forward deploy/org-user-notification-services 8082:8080`.
- **Deploy the catalogue's credential-hardening change before enabling PIN login:** a 6-digit PIN
  behind BCrypt falls in minutes once its hash is readable.

---

## 5. Catalogue integration contract

| Catalogue event | Call | Notes |
|---|---|---|
| publish, becomes `ACTIVE` | `auth_user_create` | before persisting; on failure stay retryable |
| `ACTIVE -> INACTIVE` | `auth_user_revoke` | |
| `INACTIVE -> ACTIVE` | `auth_user_create` | re-enables and clears the block |
| profile edited | `auth_user_update` | best-effort; never `auth_user_create`, which would un-revoke |
| record deleted | `auth_user_delete` | |
| login | `auth_token_create` with `{email, password}` | |
| PIN login | `auth_token_create_pin` | called by the app, not the catalogue |

Nothing in the catalogue talks to Keycloak. This service holds a snapshot taken at publish, so an edit
reaches tokens only through `auth_user_update`. Call it with a timeout-bounded `RestTemplate`, and never
surface the raw exception (it contains this service's internal host). A re-enable clears the user-level
block, but tokens revoked before it stay dead.

---

## 6. Security posture

- **No caller authentication.** No interceptor, API key or mTLS: all nine endpoints and Keycloak's
  token endpoint must be unreachable from outside the cluster. The UAT Kong route is the tracked
  exception.
- **The flag is a bypass switch.** With `catalogue.validate-enabled=false`, `auth_token_create` mints a
  token for any `userId`, so one misrouted request is a full authentication bypass.
- **The client secret is a root credential.** The direct grant checks nothing, so its holder can get a
  token for any user. `setup-realm.sh` writes it to `.env` (gitignored).
- **`admin-cli`.** Keycloak auto-creates this public client with direct access grants, and with no
  password step it would issue a token for any username with no secret (verified on 26.7).
  `setup-realm.sh` disables direct grants on every other client and fails loudly if one remains; keep
  that assertion.
- **No MFA**, structurally, while Keycloak holds no credentials.

---

## 7. Redis keys

| Key | Type | TTL | Purpose |
|---|---|---|---|
| `auth:denylist:jti:<jti>` | `1` | token's remaining life | one revoked token |
| `auth:denylist:sid:<sid>` | `1` | `denylist-sid-ttl-seconds` | a revoked session |
| `auth:denylist:user:<userId>` | `1` | `denylist-sid-ttl-seconds` | a blocked user |
| `auth:session:<sid>` | JSON | `denylist-sid-ttl-seconds` | session record |
| `auth:user:<userId>:sessions` | set of sids | `denylist-sid-ttl-seconds` | session index |
| `auth:device:<sha256(handle)>` | JSON `user_id`, `device_id`, `label`, `created_at` | `pin.device-ttl-seconds` | a PIN device |
| `auth:user:<userId>:devices` | hash deviceId -> digest | `pin.device-ttl-seconds` | device index |
| `auth:pin:fail:<sha256(handle)>` | counter | `pin.device-ttl-seconds` | attempts spent; 5 removes the device |

A dump holds no usable credential: values are `1` or metadata, and devices are keyed by digest. The
session index only makes "revoke this user" an enumeration; validation never reads it.

---

## 8. Configuration

| Variable | Local default | In-cluster |
|---|---|---|
| `SERVER_PORT` | 8080 | 8080 |
| `SPRING_REDIS_HOST` / `_PORT` | `localhost` / `6380` | the Redis host |
| `KEYCLOAK_BASE_URL` | `http://localhost:8180` | `http://keycloak:8080` (Service DNS) |
| `KEYCLOAK_ISSUER` | `http://localhost:8180/realms/OAS` | the public ingress URL |
| `KEYCLOAK_REALM` / `KEYCLOAK_CLIENT_ID` | `OAS` / `oas-auth-service` | same |
| `KEYCLOAK_CLIENT_SECRET` | from `.env` | from a Secret |
| `KEYCLOAK_CONNECT_TIMEOUT_MS` / `_READ_TIMEOUT_MS` | 2000 / 5000 | tune as needed |
| `KEYCLOAK_CLOCK_SKEW_SECONDS` | 30 | 30 |
| `KEYCLOAK_DENYLIST_SID_TTL_SECONDS` | 900 | at least the SSO session max |
| `CATALOGUE_VALIDATE_ENABLED` | `true` | `true` |
| `CATALOGUE_BASE_URL` | `http://localhost:8082` | `http://org-user-notification-services.app.svc.cluster.local:8080` |
| `CATALOGUE_VERIFY_PATH` / `_VERIFY_PIN_PATH` | `/user/v1/verify` / `/user/v1/verify_pin` | same |
| `CATALOGUE_CONNECT_TIMEOUT_MS` / `_READ_TIMEOUT_MS` | 2000 / 5000 | read timeout caps login latency |
| `PIN_DEVICE_TTL_SECONDS` | 2592000 (30 days) | absolute device life |

`KEYCLOAK_BASE_URL` (where we call Keycloak) and `KEYCLOAK_ISSUER` (what it stamps) are separate on
purpose ([§12](#12-known-pitfalls)). The admin API is reached through the client's own service account
(`manage-users`, `view-users` only); there are no admin credentials in the application.

---

## 9. Deployment

- Platform contract: liveness/readiness probes, `/v3/api-docs` (all nine endpoints), port 8080 via
  `SERVER_PORT`, env-driven config, `./mvnw clean package -DskipTests`, stateless,
  `/<domain>/v1/<action>` routing.
- The `Dockerfile` builds the jar and runs it as non-root; Jenkins builds it directly.
- Readiness does not depend on Keycloak or Redis, so a green probe does not mean logins work.
- **Keycloak:** stock `quay.io/keycloak/keycloak:26.7`. In a real environment run `start --optimized`
  with a real database, `KC_HOSTNAME` set to the public URL, `KC_HOSTNAME_STRICT=true`, and
  `KC_PROXY_HEADERS=xforwarded`. Never expose its token endpoint.
- **Realm:** `setup-realm.sh` is idempotent and env-driven (`KC`, `REALM`, `CLIENT`, `ADMIN_USER`,
  `ADMIN_PASS`, `KC_WAIT_SECONDS`). It creates and asserts:
  - the realm, client and service-account roles;
  - the User Profile attributes;
  - `oas-profile` with its mappers and the audience mapper;
  - the password-less direct grant, with direct grants disabled on every other client;
  - email login turned off.

  Re-run it after anything that recreates the realm.

---

## 10. Testing

```bash
./mvnw test        # 128 tests, container-free: in-process RSA keys, java-jwt, mocked Keycloak and Redis
```

| Class | Covers |
|---|---|
| `KeycloakServiceImplTest` | algorithm confusion, wrong key, tampering, issuer, `azp`, `typ`, expiry, jti/sid/user denylist, introspection fallback, fail-closed; PIN devices: digest-only storage, attempt before check, five strikes, Redis fail-closed, removal on revoke |
| `KeycloakServiceImplAdminTest` | service-account token caching, upsert create/update/conflict, replace (clears, never re-enables), disable, delete idempotency, no password in the grant, the 404/403 split |
| `AuthServiceImplTest` | the JSON contract, required fields, revoke-before-delete, both flag paths, bypass guards, PIN enrolment only after a verified password, PIN outcomes, logout keeping devices, update never upserting |
| `CatalogueServiceImplTest` | which catalogue answers issue a token, 401 or 503; the password and PIN never reach a log |

Two Postman collections, both without scripts or environment files. Service URLs are collection
variables, and the deployed one adds `api_key`, which needs an editors-scoped key:

```
postman/OAS_Auth_Service.postman_collection.json             deployed, behind the shared nginx host
postman/OAS_Auth_Service_local_test.postman_collection.json  auth-service :8080, catalogue :8082 (gitignored)
```

The order is:

1. Create User
2. Read User
3. Verify Credentials
4. Create Token, then Create Token (PIN enrolment), Create Token with PIN, and its wrong-PIN variant
5. Refresh Token
6. Validate Token
7. Invalidate Token
8. Update User
9. Revoke User
10. Enable User
11. Toggle User (the catalogue's toggle; run twice to deactivate, then reactivate)
12. Delete User
13. Delete Catalogue Record

Paste the `PASTE_USER_ID`, `PASTE_ACCESS_TOKEN`, `PASTE_REFRESH_TOKEN` and `PASTE_DEVICE_HANDLE` values
by hand. Re-running Validate or Create Token between the later steps shows each transition: `401`
revoked, `403` disabled, `200` again, `404` not provisioned.

Create User only succeeds if the catalogue's call to `auth_user_create` did, so it tests both services.
Keep the email unique, or it is a `409`. The PIN requests need the catalogue's `verify_pin` and a
6-digit PIN.

After any change to revocation, check by hand:

1. **A block outlasts the denylist.** Revoke, run
   `docker exec acs-auth-redis redis-cli DEL "auth:denylist:user:<userId>"`, and login must still
   return 403.
2. **A re-enable works at once.** `auth_user_create` the user, and login must succeed immediately.

---

## 11. Project structure

```
src/main/java/com/catalogue/verg/
  auth/controller/AuthController              the nine endpoints
  auth/service/AuthService(Impl)              orchestration and audit logging
  core/keycloak/config/KeycloakConfig         RestTemplate and JwkProvider beans
  core/keycloak/service/KeycloakService(Impl) tokens, verification, denylist, PIN devices, user admin
  core/catalogue/config/CatalogueConfig       RestTemplate for the credential checks
  core/catalogue/service/CatalogueService(Impl) the password and PIN checks
  core/dto, core/exception                    response envelope and error handling
  core/util/{Constants,VergProperties}        codes and tunables
setup-realm.sh                                provisions the realm
```

The verg layout of the catalogue services: `controller` / `service` / `service/impl` per domain, and
`core` integrations as `config` plus `service`. No `entity` or `repository`: there is no database.

---

## 12. Known pitfalls

Each was hit during development, and each symptom misleads.

- **Issuer mismatch.** Keycloak stamps `iss` with the URL it was reached on, so calling it by another
  host fails every token as `AUTH_TOKEN_INVALID`, like a signature error. Pin `KC_HOSTNAME` and point
  `KEYCLOAK_ISSUER` at it.
- **Undeclared attributes vanish.** On Keycloak 24+ an attribute the User Profile does not declare is
  dropped with a `201`. Missing `user_id`/`org_id`/`functional_role` claims mean check the profile.
- **Required profile fields break the grant.** Required `email`/`firstName`/`lastName` raise
  `VERIFY_PROFILE` ("Account is not fully set up"), seen here as a bare `502`; `setup-realm.sh` clears
  `required`.
- **Introspection needs the audience mapper.** Without it Keycloak answers `active: false` for valid
  tokens, and a Redis outage becomes a total auth outage.
- **Refused direct grants are `400`, not `401`** on Keycloak 26.7. This service collapses 4xx first;
  raw-status assertions will be wrong.
- **Scope mappers must be upserted.** `setup-realm.sh` once created them only with a new scope, so an
  added claim silently never appeared. Every mapper now goes through the unconditional, asserted loop.
- **An admin `PUT` with `attributes` deletes omitted keys.** Hence the carry-forward merge in the
  upsert (and the deliberate clear in `auth_user_update`). Names are top-level fields, while
  `org_name`/`display_name` are attributes: mixing the accessors wipes a value silently.
- **Absent attribute = absent claim.** Keycloak omits empty attributes; `auth_token_validate` returns
  `null` for them.
- **`length` limits read as outages.** Over the profile's `max` (255 for `org_name`/`display_name`)
  Keycloak answers `400`, surfaced as a bare `502`.
- **Email in, userId everywhere else.** `auth_token_create` takes the email; every other endpoint takes
  the userId. Revoking by email returns `404`.
- **A stale `.env` gives `401` everywhere.** `setup-realm.sh` regenerates the secret with the client;
  re-source and restart.
- **`docker compose down -v` destroys the realm.** Re-run `setup-realm.sh`, then restart.

---

## 13. Not implemented

- **The user catalogue does not validate tokens** (the agri catalogues do, via `auth_token_validate`).
- **The catalogue does not call `auth_user_update` yet.** Its revoke and delete wiring shipped with its
  credential-hardening change; the update call and `verify_pin` come with its PIN change.
- **No caller authentication** on these endpoints: network isolation only.
- **No RBAC:** `functional_role` is a claim, not a permission.
- **No MFA**, and none is possible while Keycloak holds no credentials.
- **No k8s manifests:** the Dockerfile and environment-driven configuration are the deliverable.
