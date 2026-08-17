# OAS Auth Service

Authentication for OpenAgriStack. Issues, validates and revokes JWTs for the catalogue
microservices.

The design rule everything follows: **the user-catalogue owns users and credentials, Keycloak owns
identity, this service owns tokens.** The catalogue holds the bcrypt hash and performs the password
comparison; Keycloak stores no password at all and calls back to the catalogue on every login.
Credential material therefore exists in exactly one database.

This service owns no database. Its only datastore is Redis, holding the token denylist and a session
index.

---

## Contents

1. [Architecture](#1-architecture)
2. [Quick start](#2-quick-start)
3. [API reference](#3-api-reference)
4. [Redis keys](#4-redis-keys)
5. [Catalogue integration contract](#5-catalogue-integration-contract)
6. [Configuration](#6-configuration)
7. [Deployment](#7-deployment)
8. [Testing](#8-testing)
9. [Project structure](#9-project-structure)
10. [Known pitfalls](#10-known-pitfalls)
11. [Not implemented](#11-not-implemented)

---

## 1. Architecture

### Login

```
                     1. username + plaintext password
   client ──────────────────────> auth-service :8080
                                       |
                                       | 2. password grant
                                       v
                                  Keycloak :8180
                                  users, sessions, signing keys - NO password
                                       |
                                       | 3. Direct Grant flow ->
                                       |    CatalogueAuthenticator (custom provider)
                                       v
                                  user-catalogue :8082
                                  POST /user/v1/verify_credentials
                                  bcrypt compare + status must be ACTIVE
                                       |
                     4. signed JWT <---+
                        user_id, org_id, entity_type
```

Keycloak resolves the user and enforces its `enabled` flag, then delegates the password check to the
catalogue. Because the catalogue also requires `status == ACTIVE`, its record is always authoritative.

### Provisioning

Runs in the opposite direction. The catalogue pushes a user into Keycloak at publish time, and does so
**before** persisting `ACTIVE`:

```
create --> PENDING --approve--> APPROVED --review--> [push to Keycloak] --> ACTIVE
                                                            |
                                                       fails? stays APPROVED, returns 502
```

If Keycloak is unavailable the publish fails and the record stays `APPROVED`. There is no state in
which the catalogue reports a user as live but that user cannot log in.

### Validation

`auth_token_validate` makes no network calls. A JWT is a self-contained signed document, so the
service verifies it locally against Keycloak's published signing key (cached JWKS). Checks run in
order:

1. RS256 signature. The algorithm is **pinned in code**, never read from the token header.
2. `iss` matches the configured issuer exactly.
3. `exp` / `nbf`, allowing the configured clock skew.
4. `typ` is `Bearer`. Refresh tokens are signed with the same key and pass every other check.
5. `azp` is this client. Realms are shared between applications.
6. `jti` is present, since the denylist keys on it.
7. Not present in the Redis denylist.

Keycloak is contacted only when Redis is unavailable, via token introspection.

### Revocation

Keycloak cannot recall an access token it has already issued: logout ends the session and the refresh
token, but the access token keeps verifying until it expires. The Redis denylist is what makes
revocation real.

---

## 2. Quick start

Two stacks run side by side. The user-catalogue's stack is left untouched; this repository's ports
were moved instead, so nothing here can reach its data.

```bash
# 1. user-catalogue (its own repository, unchanged)
cd ../OrgUserNotificationServices
docker compose up -d
SERVER_PORT=8082 java -jar target/svc-ctlg-0.0.1-SNAPSHOT.jar

# 2. this repository
cd ../OAS-Auth-Service
docker compose up -d --build     # Redis + Keycloak
./setup-realm.sh                 # realm, client, attributes, login flow; writes .env
./mvnw clean package
set -a; . ./.env; set +a         # KEYCLOAK_CLIENT_SECRET
java -jar target/svc-auth-0.0.1-SNAPSHOT.jar
```

Verify:

```bash
curl -s localhost:8080/actuator/health/readiness
curl -s localhost:8082/actuator/health
curl -s localhost:8180/realms/OAS/.well-known/openid-configuration | jq -r .issuer
```

### Ports

| | user-catalogue | this repository |
|---|---|---|
| application | 8082 (`SERVER_PORT`) | 8080 |
| Keycloak | - | 8180, admin console at `/admin` |
| Postgres | 5433 | not used |
| Redis | 6379 | 6380 |
| Elasticsearch | 9200 / 9300 | not used |

`docker compose down -v` here destroys only this repository's volumes. It costs the Keycloak realm,
which `./setup-realm.sh` rebuilds. The catalogue's data is in its own stack and is never touched.

---

## 3. API reference

All endpoints are `POST` and accept and return JSON.

### POST /auth/v1/auth_token_create

```json
{ "username": "user-340256581511", "password": "<plaintext>" }
```

Returns Keycloak's token response unchanged: `access_token`, `refresh_token`, `expires_in`,
`token_type`, `scope`, `session_state`.

### POST /auth/v1/auth_token_validate

```json
{ "token": "<access_token>" }
```

```json
{
  "active": true,
  "sub": "8ac798e2-e0d8-4bb6-a26e-573cf38dfa40",
  "preferred_username": "user-340256581511",
  "user_id": "user-340256581511",
  "org_id": "org-000000000001",
  "entity_type": "MAKER",
  "exp": 1786945358,
  "jti": "onrtro:5abd6dea-e9b6-145b-c67d-ed7fe68ff923",
  "sid": "tP27_5XKwnbWzklfHilSYiCO"
}
```

The token itself is never echoed back.

### POST /auth/v1/auth_token_invalidate

```json
{ "token": "<access_token>", "refreshToken": "<refresh_token>" }
```

Denylists the token and its session, clears the session record, then ends the Keycloak session.
`refreshToken` is optional. Returns `{"localRevocation": "ok", "idpLogout": "ok"}`.

### POST /auth/v1/auth_user_revoke

```json
{ "userId": "user-340256581511" }
```

Blocks the user for `keycloak.denylist-sid-ttl-seconds` (900 by default). Every token for that user is
rejected, **including tokens issued after this call**, because the denylist is keyed on the user rather
than on a token. Keycloak will still issue a token on a fresh login, since it knows nothing about this
denylist; that token is refused by `auth_token_validate`. To block permanently rather than for the TTL,
the catalogue record must also be set to `INACTIVE`.

### Token shape

```json
{
  "iss": "http://localhost:8180/realms/OAS",
  "aud": ["oas-auth-service", "account"],
  "azp": "oas-auth-service",
  "typ": "Bearer",
  "sub": "8ac798e2-e0d8-4bb6-a26e-573cf38dfa40",
  "sid": "tP27_5XKwnbWzklfHilSYiCO",
  "jti": "onrtro:5abd6dea-e9b6-145b-c67d-ed7fe68ff923",
  "preferred_username": "user-340256581511",
  "user_id": "user-340256581511",
  "org_id": "org-000000000001",
  "entity_type": "MAKER"
}
```

`user_id`, `org_id` and `entity_type` originate in the catalogue. `entity_type` is carried as data,
not as a permission; there is no RBAC.

### Errors

| Situation | Status | Code |
|---|---|---|
| Missing required field | 400 | `AUTH_INVALID_REQUEST` |
| Wrong password, unknown user, or blocked account | 401 | `AUTH_INVALID_CREDENTIALS` |
| Bad signature, wrong issuer or client, wrong token type | 401 | `AUTH_TOKEN_INVALID` |
| Expired | 401 | `AUTH_TOKEN_EXPIRED` |
| Revoked | 401 | `AUTH_TOKEN_REVOKED` |
| Keycloak unreachable | 503 | `AUTH_UPSTREAM_UNAVAILABLE` |
| Redis and Keycloak both unreachable | 503 | `AUTH_REVOCATION_FAILED` |

The three credential failures return byte-identical responses by design. Distinguishing them would
allow username enumeration, and "account is locked" tells an attacker their guessing is working.

### Failure behaviour

| Situation | Behaviour |
|---|---|
| Catalogue unreachable | Login fails closed with 503; never an accidental success |
| Redis down, token otherwise valid | Falls back to Keycloak introspection, returns 200 |
| Redis down, session logged out or user disabled | Introspection reports inactive, returns 401 |
| Redis and Keycloak both down | Fails closed with 503 |
| User revoked | All that user's sessions cleared and denylisted immediately |

---

## 4. Redis keys

```
auth:session:<sid>            {user_id, org_id, entity_type, username}   TTL = denylist TTL
auth:user:<user_id>:sessions  SET of sids
auth:denylist:jti:<jti>       one revoked token
auth:denylist:sid:<sid>       one revoked session
auth:denylist:user:<user_id>  every token for one user
```

The session index exists so that disabling a user is an enumeration rather than a hope that one TTL
covers every outstanding token: `auth_user_revoke` reads the set, denylists each sid and deletes each
record.

The session record is deliberately not part of the security decision. Validation remains signature
plus claims plus denylist, so a Redis outage degrades to introspection instead of logging everyone
out.

Denylist values are the constant `"1"`, never the token, so a Redis dump never yields a usable
credential.

Auth events are written to the application log rather than a database, because the `audit` catalogue
belongs to `agri-catalogue-service`:

```
AUDIT operation=auth_token_create userId=user-340256581511 entityType=MAKER outcome=SUCCESS
```

---

## 5. Catalogue integration contract

What the user-catalogue must implement. A working reference implementation exists in
`OrgUserNotificationServices`.

### 5.1 Expose POST /user/v1/verify_credentials

Keycloak calls this on every login.

Request, plaintext password:

```json
{ "username": "user-340256581511", "password": "<plaintext>" }
```

Success, HTTP 200:

```json
{ "result": { "valid": true, "userId": "user-340256581511",
              "orgId": "org-000000000001", "entityType": "MAKER" } }
```

Failure, also HTTP 200:

```json
{ "result": { "valid": false } }
```

Four rules, all security-relevant:

1. Compare with bcrypt. The stored password is already a bcrypt hash, since the portal hashes before
   submission. The salt is embedded in the hash.
2. Require `status == ACTIVE`. This is what makes blocking effective at source.
3. Return an identical body for every failure. Unknown user, wrong password and non-ACTIVE status must
   be indistinguishable.
4. Never log the request body; it contains a plaintext password.

Run a bcrypt comparison even when the user does not exist, against a dummy hash, so response time does
not reveal which accounts are real.

**This endpoint must not be routed through Kong.** Kong routes by path convention, and
`verify_credentials` is neither `read` nor `search`, so default rules classify it as a write action and
expose it publicly behind an API key alone. It accepts plaintext passwords. Exclude it explicitly.

### 5.2 Push to Keycloak before the record becomes ACTIVE

When the target status is `ACTIVE`, create or update the Keycloak user **before** saving the record.
If the push fails, return an error and do not persist `ACTIVE`.

```json
{
  "username": "<userId>", "email": "...", "firstName": "...", "lastName": "...",
  "enabled": true, "emailVerified": true,
  "attributes": { "user_id": ["<userId>"], "org_id": ["<orgId>"], "entity_type": ["<entityType>"] }
}
```

`POST /admin/realms/OAS/users` to create, `PUT /admin/realms/OAS/users/{id}` to update. Obtain an admin
token from `/realms/master/protocol/openid-connect/token` using `grant_type=password` and
`client_id=admin-cli`. No credentials array is sent; Keycloak stores no password.

Do not return the raw exception on failure. A connection error message contains the identity provider's
internal host and port.

### 5.3 Blocking requires three actions

| Action | Why it is insufficient alone |
|---|---|
| Set `INACTIVE` in the catalogue | Stops new logins; tokens already issued keep working |
| Disable the Keycloak user and log out its sessions | Ends sessions and refresh tokens; cannot recall an issued access token |
| `POST /auth/v1/auth_user_revoke` | Kills tokens already in circulation |

Make the Keycloak and auth-service calls best-effort. The catalogue status alone already blocks every
new login, so a transient outage must not fail the block request.

---

## 6. Configuration

Every value is an environment variable with a local default. No infrastructure endpoint is hardcoded.

| Variable | Local default | Purpose |
|---|---|---|
| `SERVER_PORT` | 8080 | Listening port |
| `SPRING_REDIS_HOST` / `_PORT` | localhost / 6380 | Denylist and session index |
| `KEYCLOAK_BASE_URL` | `http://localhost:8180` | Where this service calls Keycloak |
| `KEYCLOAK_ISSUER` | `http://localhost:8180/realms/OAS` | What Keycloak stamps into `iss` |
| `KEYCLOAK_REALM` | `OAS` | |
| `KEYCLOAK_CLIENT_ID` | `oas-auth-service` | |
| `KEYCLOAK_CLIENT_SECRET` | empty | Supplied via `.env`, never committed |
| `KEYCLOAK_CONNECT_TIMEOUT_MS` | 2000 | |
| `KEYCLOAK_READ_TIMEOUT_MS` | 5000 | |
| `KEYCLOAK_CLOCK_SKEW_SECONDS` | 30 | |
| `KEYCLOAK_DENYLIST_SID_TTL_SECONDS` | 900 | Must be at least the access token lifespan |

`KEYCLOAK_BASE_URL` and `KEYCLOAK_ISSUER` are separate on purpose. Keycloak derives the issuer from the
URL used to reach it, so in a cluster the service calls Keycloak by Service name while tokens must carry
the public ingress URL. See [section 10](#10-known-pitfalls).

---

## 7. Deployment

Built by the OAS-Infra Jenkins pipeline, which checks this repository out and builds its `Dockerfile`
directly; there is no separate Maven stage.

### Platform contract

Verified against a running container with every setting supplied by environment variable.

| Requirement | Status |
|---|---|
| `GET /actuator/health/liveness` returns 200 | Met |
| `GET /actuator/health/readiness` returns 200 | Met |
| `GET /v3/api-docs` returns valid OpenAPI 3 | Met, `openapi 3.0.1`, 4 paths |
| Listens on 8080, overridable via `SERVER_PORT` | Met, verified on 9090 |
| Fully environment-configurable | Met, verified with all URLs overridden |
| `./mvnw clean package -DskipTests` | Met |
| Stateless, no local-disk writes | Met; owns no database |
| Routing `/<domain>/v1/<action>` | Met, `/auth/v1/...` |

No database or Elasticsearch index is required, so the onboarding step that provisions a database on the
DB host and a `db-password-<service>` Jenkins credential does not apply. Redis and Keycloak only.

The standard smoke test calls `/<prefix>/v1/read/smoketest`; this service has no `read` endpoint. Point
it at `/actuator/health/readiness` or record an exception.

Kong splits `read` and `search` from all other actions. All four endpoints fall into the write bucket,
including `auth_token_validate`, which is semantically a read. `auth_token_create` is the login endpoint,
so whatever credential Kong requires in front of it must be available before a user holds a token.

### Keycloak is not yet production-ready

Keycloak currently runs `start-dev` against a dev-mode H2 file in the `kcdata` volume. In a pod the
realm, users and client secret would live in ephemeral storage.

| | Current | Required |
|---|---|---|
| Command | `start-dev` | `start --optimized` |
| Database | H2 file in a volume | Postgres via `KC_DB`, `KC_DB_URL`, `KC_DB_USERNAME`, `KC_DB_PASSWORD` |
| Hostname | Derived from the request | `KC_HOSTNAME` pinned, `KC_HOSTNAME_STRICT=true` |
| Proxy | None | `KC_PROXY_HEADERS=xforwarded` behind an ingress |
| Admin | `admin`/`admin` bootstrap | Real credentials from a Secret |
| TLS | None | Terminated at the ingress |

Keycloak also does not fit the shared `oas-catalogue` Helm chart: it has no Spring Actuator endpoints and
no `/v3/api-docs`, and its health endpoints are on management port 9000 (`/health/ready`, `/health/live`,
enabled by `KC_HEALTH_ENABLED`). It needs its own manifest.

The image itself is ECR-ready. `keycloak/Dockerfile` copies the provider jar into
`/opt/keycloak/providers/` and runs `kc.sh build`, which is what makes a provider visible.

### Realm provisioning

`setup-realm.sh` is idempotent and environment-driven (`KC`, `REALM`, `CLIENT`, `ADMIN_USER`,
`ADMIN_PASS`, `CATALOGUE_URL`). Run it once against a deployed Keycloak after its database is attached.
It creates the realm and client, declares the three custom attributes in the User Profile, creates the
`oas-profile` scope with its mappers and the audience mapper, and rewires the Direct Grant flow.

`CATALOGUE_URL` must resolve from inside the Keycloak container, so a Service name in a cluster, never
`localhost`.

---

## 8. Testing

```bash
./mvnw test                                              # 25 tests
newman run OAS_Auth_Service.postman_collection.json \
  -e OAS_Auth_Service.postman_environment.json \
  --folder "6. Regression (Automated)"                   # 21 requests, 48 assertions
```

The Postman collection covers the full lifecycle across all three services:

| Folder | Requests | Covers |
|---|---|---|
| 0. Preflight | 3 | all three services reachable; realm exists |
| 1. User Lifecycle (catalogue side) | 6 | create, the approval gate, publish, verify credentials |
| 2. Auth Service API | 4 | the four token endpoints |
| 3. Credential Rejections | 4 | wrong password, unknown user and inactive user are indistinguishable |
| 4. Token Rejections | 5 | refresh token, tampered, malformed, missing fields |
| 5. Block Lifecycle | 6 | revoke, block, blocked token, blocked login, unblock |
| 6. Regression (Automated) | 21 | all of the above, unattended |

Folders 0 to 5 are for stepping through by hand. Request bodies carry literal placeholders such as
`PASTE_USER_ID_HERE`, replaced with values copied from the previous response; each request description
says what to copy and what to expect. Folder 6 is self-chaining and creates its own user on each run,
so it is repeatable and needs nothing pasted.

Run folder 5 last. It leaves the user blocked for the length of the revocation TTL.

`KeycloakServiceImplTest` runs without containers: it generates an RSA key pair in-process, mints tokens
with java-jwt and stubs the JwkProvider. It covers the algorithm-confusion attack, in which a token is
signed using the published public key as an HMAC secret; that case is the difference between working
authentication and an authentication bypass.

---

## 9. Project structure

```
src/main/java/com/catalogue/verg/
  auth/controller/AuthController              REST endpoints
  auth/service/AuthService                    interface
  auth/service/impl/AuthServiceImpl           orchestration and audit logging
  core/keycloak/config/KeycloakConfig         RestTemplate and JwkProvider beans
  core/keycloak/service/KeycloakService       interface
  core/keycloak/service/KeycloakServiceImpl   verification, denylist, sessions
  core/dto/{CustomResponse,RespParam}         response envelope
  core/exception/...                          error handling
  core/util/{Constants,VergProperties}        codes and tunables

keycloak/
  Dockerfile                                  bakes the provider into the Keycloak image
  authenticator/                              the Keycloak provider, a separate Maven artifact
```

This follows the verg layout used across the catalogue services: domain modules as
`controller` / `service` / `service/impl`, and `core` integrations as `config` plus interface and
implementation in `service`, matching `core/elasticsearch` there.

`auth/` has no `entity` or `repository` package because this service owns no database.

The Keycloak provider is a separate Maven artifact by necessity, not by preference. It is loaded by
Keycloak's classloader from `/opt/keycloak/providers/`, which requires classes at the jar root, whereas
Spring Boot repackaging places them under `BOOT-INF/classes/`. It also compiles against Keycloak SPI
dependencies at `provided` scope, which must not appear on this service's classpath.

---

## 10. Known pitfalls

**Undeclared user attributes are silently dropped.** On Keycloak 24 and later, writing an attribute not
declared in the realm's User Profile returns `201 Created` and discards it, with no error and no log
entry. `setup-realm.sh` declares `user_id`, `org_id` and `entity_type`. If tokens arrive without those
claims, check this first.

**Introspection requires the client in the token audience.** Keycloak 26 refuses to introspect a token
whose `aud` excludes the introspecting client and answers a bare `{"active": false}`. Since validation
falls back to introspection when Redis is down, without the `oas-auth-service-audience` mapper that
fallback would reject every token, turning a Redis outage into a total authentication outage.

**Base URL and issuer must agree.** Keycloak stamps `iss` with whatever URL was used to reach it. If the
service calls Keycloak by one hostname but expects another in `KEYCLOAK_ISSUER`, every token fails with
`AUTH_TOKEN_INVALID`, which reads like a signature problem. In a deployed environment pin `KC_HOSTNAME`
so Keycloak always stamps the public issuer, and set `KEYCLOAK_ISSUER` to that same value.

**A new provider jar requires `kc.sh build`.** Placing a jar in `/opt/keycloak/providers/` without
rebuilding leaves the provider invisible, with no error. After changing the authenticator:

```bash
./mvnw -f keycloak/authenticator/pom.xml package
docker compose up -d --build keycloak
```

**`docker compose down -v` destroys the realm.** It exists only in the `kcdata` volume. Recover with
`./setup-realm.sh`, then restart the service, since the client secret is regenerated into `.env`.

**A stale `.env` presents as a 401 on every login.** `setup-realm.sh` regenerates the client secret each
time it creates the client.

---

## 11. Not implemented

- **Nothing enforces these tokens.** Catalogue endpoints remain open. This service provides a way to
  obtain a token, not a requirement to present one. The next step is an interceptor in each catalogue
  calling `auth_token_validate` on protected paths.
- **Catalogue audit rows still record `ANONYMOUS`**, since catalogues cannot yet supply a caller
  identity.
- **No RBAC.** `entity_type` is a claim, not a permission.
- **No browser login flow.** Only the Direct Grant flow is rewired.
- **No Kubernetes manifests or ECR build scripts**; those live in OAS-Infra.
