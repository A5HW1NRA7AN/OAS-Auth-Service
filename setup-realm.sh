#!/usr/bin/env bash
#
# setup-realm.sh — configure the OAS realm. Idempotent; re-run any time.
#
# The realm lives only in the `kcdata` docker volume, so `docker compose down -v` wipes it
# and this script is how you rebuild it.
#
# Usage:  ./setup-realm.sh
set -euo pipefail

KC="${KC:-http://localhost:8180}"
REALM="${REALM:-OAS}"
CLIENT="${CLIENT:-oas-auth-service}"
ADMIN_USER="${ADMIN_USER:-admin}"
ADMIN_PASS="${ADMIN_PASS:-admin}"

# How Keycloak reaches the user-catalogue. The authenticator runs INSIDE the Keycloak
# container, so this is never plain localhost.
#   local : the catalogue runs on the host      -> host.docker.internal:8082
#   k8s   : the catalogue is a Service          -> http://user-catalogue:8080
CATALOGUE_URL="${CATALOGUE_URL:-http://host.docker.internal:8082}"

AUTHENTICATOR_ID="catalogue-validate-password"
FLOW_NAME="catalogue direct grant"

GRN=$'\033[0;32m'; YEL=$'\033[0;33m'; CYN=$'\033[0;36m'; RED=$'\033[0;31m'; RST=$'\033[0m'
step() { printf '\n%s==> %s%s\n' "$CYN" "$*" "$RST"; }
ok()   { printf '  %sok%s   %s\n' "$GRN" "$RST" "$*"; }
skip() { printf '  %sskip%s %s\n' "$YEL" "$RST" "$*"; }
die()  { printf '%sFATAL%s %s\n' "$RED" "$RST" "$*" >&2; exit 1; }

command -v jq >/dev/null || die "jq not found"

# Prints a token, or nothing if Keycloak is not up yet. Must never return non-zero: under
# `set -e` with `pipefail` a failing curl here would kill the script before the wait below.
admin_token() {
  curl -sf -X POST "$KC/realms/master/protocol/openid-connect/token" \
    -d "username=$ADMIN_USER" -d "password=$ADMIN_PASS" \
    -d 'grant_type=password' -d 'client_id=admin-cli' 2>/dev/null \
    | jq -r '.access_token // empty' 2>/dev/null || true
}

# Keycloak needs ~10s after the container starts before it answers. Running this immediately
# after `docker compose up -d` otherwise fails on a healthy stack, so wait rather than die.
TOKEN=$(admin_token)
if [ -z "$TOKEN" ]; then
  printf '  waiting for Keycloak at %s ' "$KC"
  for _ in $(seq 1 "${KC_WAIT_SECONDS:-90}"); do
    sleep 1; printf '.'
    TOKEN=$(admin_token)
    [ -n "$TOKEN" ] && break
  done
  printf '\n'
fi
[ -n "$TOKEN" ] || die "cannot reach Keycloak at $KC (waited ${KC_WAIT_SECONDS:-90}s)"
[ -n "$TOKEN" ] && [ "$TOKEN" != "null" ] || die "could not obtain admin token"

A=(-H "Authorization: Bearer $TOKEN")
J=(-H "Content-Type: application/json")
api() { curl -sf "${A[@]}" "$@"; }

# ---------------------------------------------------------------------------------
step "0. Realm and client"
# ---------------------------------------------------------------------------------
if api "$KC/admin/realms/$REALM" >/dev/null 2>&1; then
  skip "realm $REALM already exists"
else
  api -X POST "$KC/admin/realms" "${J[@]}" \
    -d "{\"realm\":\"$REALM\",\"displayName\":\"OpenAgriStack\",\"enabled\":true}" >/dev/null
  ok "created realm $REALM"
fi

if [ -z "$(api "$KC/admin/realms/$REALM/clients?clientId=$CLIENT" | jq -r '.[0].id // empty')" ]; then
  # Direct Access Grants (password grant) is dev-only: it cannot do MFA or a forced
  # password change. Turn it off in production.
  api -X POST "$KC/admin/realms/$REALM/clients" "${J[@]}" -d "{
    \"clientId\": \"$CLIENT\",
    \"name\": \"OAS Auth Service\",
    \"enabled\": true,
    \"protocol\": \"openid-connect\",
    \"publicClient\": false,
    \"standardFlowEnabled\": true,
    \"directAccessGrantsEnabled\": true,
    \"implicitFlowEnabled\": false,
    \"serviceAccountsEnabled\": false,
    \"redirectUris\": [\"http://localhost:3000/*\"],
    \"webOrigins\": [\"http://localhost:3000\"]
  }" >/dev/null
  ok "created client $CLIENT"
fi

# Keycloak generates the secret; keep .env (gitignored) in step with it.
CLIENT_UUID=$(api "$KC/admin/realms/$REALM/clients?clientId=$CLIENT" | jq -r '.[0].id')
SECRET=$(api "$KC/admin/realms/$REALM/clients/$CLIENT_UUID/client-secret" | jq -r .value)
ENV_FILE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/.env"
if [ -f "$ENV_FILE" ] && grep -q "^KEYCLOAK_CLIENT_SECRET=${SECRET}$" "$ENV_FILE"; then
  skip ".env already holds the current client secret"
else
  printf 'KEYCLOAK_CLIENT_SECRET=%s\n' "$SECRET" > "$ENV_FILE"
  ok "wrote the client secret to .env (restart the auth-service to pick it up)"
fi

# ---------------------------------------------------------------------------------
step "1. Declaring custom attributes in the User Profile"
# ---------------------------------------------------------------------------------
# Fetch the current profile and add our three attributes if absent, preserving whatever
# is already declared (username/email/firstName/lastName come as standard).
PROFILE=$(api "$KC/admin/realms/$REALM/users/profile")

# Attributes are admin-edit-only: a user must never be able to change their own org_id and
# read another org's data. (`label` is reserved in jq, hence the `display` parameter name.)
NEW_PROFILE=$(echo "$PROFILE" | jq '
  def attr(n; display):
    {
      name: n,
      displayName: display,
      multivalued: false,
      permissions: { view: ["admin","user"], edit: ["admin"] },
      validations: { length: { min: 1, max: 64 } },
      annotations: {}
    };
  .unmanagedAttributePolicy = "ADMIN_EDIT"
  | .attributes = (
      .attributes
      + (if any(.attributes[]; .name == "user_id")     then [] else [attr("user_id";     "OAS user id")]     end)
      + (if any(.attributes[]; .name == "org_id")      then [] else [attr("org_id";      "OAS organisation id")] end)
      + (if any(.attributes[]; .name == "entity_type") then [] else [attr("entity_type"; "OAS entity type")] end)
    )
')

api -X PUT "$KC/admin/realms/$REALM/users/profile" "${J[@]}" -d "$NEW_PROFILE" >/dev/null
DECLARED=$(api "$KC/admin/realms/$REALM/users/profile" | jq -r '[.attributes[].name] | join(", ")')
ok "declared: $DECLARED"

for a in user_id org_id entity_type; do
  echo "$DECLARED" | grep -q "$a" || die "attribute $a was not declared — tokens will have no $a claim"
done

# ---------------------------------------------------------------------------------
step "2. Client scope 'oas-profile' with attribute mappers"
# ---------------------------------------------------------------------------------
SCOPE_ID=$(api "$KC/admin/realms/$REALM/client-scopes" | jq -r '.[] | select(.name=="oas-profile") | .id')

if [ -z "$SCOPE_ID" ]; then
  # One oidc-usermodel-attribute-mapper per attribute, copying it into the access token,
  # the ID token and userinfo.
  mapper() {
    jq -n --arg n "$1" '{
      name: $n, protocol: "openid-connect",
      protocolMapper: "oidc-usermodel-attribute-mapper",
      consentRequired: false,
      config: {
        "user.attribute": $n, "claim.name": $n, "jsonType.label": "String",
        "access.token.claim": "true", "id.token.claim": "true",
        "userinfo.token.claim": "true", "introspection.token.claim": "true",
        "multivalued": "false", "aggregate.attrs": "false"
      }
    }'
  }
  BODY=$(jq -n --argjson m "[$(mapper user_id),$(mapper org_id),$(mapper entity_type)]" '{
    name: "oas-profile",
    description: "OAS identifiers (user_id, org_id, entity_type) projected from the catalogue",
    protocol: "openid-connect",
    attributes: { "include.in.token.scope": "true", "display.on.consent.screen": "false" },
    protocolMappers: $m
  }')
  api -X POST "$KC/admin/realms/$REALM/client-scopes" "${J[@]}" -d "$BODY" >/dev/null
  SCOPE_ID=$(api "$KC/admin/realms/$REALM/client-scopes" | jq -r '.[] | select(.name=="oas-profile") | .id')
  ok "created oas-profile ($SCOPE_ID)"
else
  skip "oas-profile already exists"
fi

# Audience mapper — required for token introspection to work at all.
#
# Keycloak 26 refuses to introspect a token whose audience does not include the client doing
# the introspecting: it answers a bare {"active": false} and logs
#   "Client 'oas-auth-service' is not in the token audience".
# By default these tokens carry aud=["account"] only, so without this mapper the
# Redis-outage fallback in KeycloakService would reject EVERY token — turning the outage it
# exists to survive into a complete authentication outage.
MAPPER_NAME="$CLIENT-audience"
if api "$KC/admin/realms/$REALM/client-scopes/$SCOPE_ID/protocol-mappers/models" \
   | jq -e --arg n "$MAPPER_NAME" '.[] | select(.name == $n)' >/dev/null; then
  skip "audience mapper already present"
else
  api -X POST "$KC/admin/realms/$REALM/client-scopes/$SCOPE_ID/protocol-mappers/models" "${J[@]}" -d "$(
    jq -n --arg n "$MAPPER_NAME" --arg c "$CLIENT" '{
      name: $n, protocol: "openid-connect", protocolMapper: "oidc-audience-mapper",
      consentRequired: false,
      config: {
        "included.client.audience": $c,
        "access.token.claim": "true",
        "id.token.claim": "false",
        "introspection.token.claim": "true"
      }
    }')" >/dev/null
  ok "added audience mapper ($CLIENT in aud)"
fi

CID=$(api "$KC/admin/realms/$REALM/clients?clientId=$CLIENT" | jq -r '.[0].id')
[ -n "$CID" ] && [ "$CID" != "null" ] || die "client $CLIENT not found — run the Phase 1 setup first"

if api "$KC/admin/realms/$REALM/clients/$CID/default-client-scopes" | jq -e '.[] | select(.name=="oas-profile")' >/dev/null; then
  skip "oas-profile already attached to $CLIENT"
else
  api -X PUT "$KC/admin/realms/$REALM/clients/$CID/default-client-scopes/$SCOPE_ID" >/dev/null
  ok "attached oas-profile to $CLIENT"
fi

# ---------------------------------------------------------------------------------
step "3. Direct Grant flow -> validate passwords against the catalogue"
# ---------------------------------------------------------------------------------
# Only possible once the provider jar is in the image. Checked rather than assumed, so
# this script is still useful before the jar is built.
if ! api "$KC/admin/realms/$REALM/authentication/authenticator-providers" \
     | jq -e --arg id "$AUTHENTICATOR_ID" '.[] | select(.id == $id)' >/dev/null; then
  skip "provider '$AUTHENTICATOR_ID' not deployed yet — build the jar, then re-run this script"
  printf '\n%sRealm configured (steps 1-2). Re-run after building the authenticator.%s\n' "$GRN" "$RST"
  exit 0
fi

if api "$KC/admin/realms/$REALM/authentication/flows" | jq -e --arg n "$FLOW_NAME" '.[] | select(.alias == $n)' >/dev/null; then
  skip "flow '$FLOW_NAME' already exists"
else
  # Copy rather than edit: the built-in flow stays as a fallback you can rebind.
  api -X POST "$KC/admin/realms/$REALM/authentication/flows/direct%20grant/copy" \
    "${J[@]}" -d "{\"newName\":\"$FLOW_NAME\"}" >/dev/null
  ok "copied 'direct grant' -> '$FLOW_NAME'"
fi

# Idempotent from here, so an interrupted run gets repaired rather than skipped.
FLOW_URI=$(printf %s "$FLOW_NAME" | jq -sRr @uri)
executions() { api "$KC/admin/realms/$REALM/authentication/flows/$FLOW_URI/executions"; }

# Drop Keycloak's own password check. direct-grant-validate-username stays, so Keycloak
# still resolves the user and enforces the `enabled` flag before our authenticator runs.
PW_EXEC=$(executions | jq -r '.[] | select(.providerId=="direct-grant-validate-password") | .id')
if [ -n "$PW_EXEC" ]; then
  api -X DELETE "$KC/admin/realms/$REALM/authentication/executions/$PW_EXEC" >/dev/null
  ok "removed built-in password validation"
else
  skip "built-in password validation already removed"
fi

if [ -z "$(executions | jq -r --arg p "$AUTHENTICATOR_ID" '.[] | select(.providerId==$p) | .id')" ]; then
  api -X POST "$KC/admin/realms/$REALM/authentication/flows/$FLOW_URI/executions/execution" \
    "${J[@]}" -d "{\"provider\":\"$AUTHENTICATOR_ID\"}" >/dev/null
  ok "added $AUTHENTICATOR_ID"
else
  skip "$AUTHENTICATOR_ID already present"
fi

# Must use the FLOW-SCOPED endpoint with the full execution representation; the bare
# /authentication/executions path returns 404 for updates.
EXEC_INFO=$(executions | jq -c --arg p "$AUTHENTICATOR_ID" '.[] | select(.providerId==$p)')
EXEC_ID=$(echo "$EXEC_INFO" | jq -r .id)
api -X PUT "$KC/admin/realms/$REALM/authentication/flows/$FLOW_URI/executions" "${J[@]}" \
  -d "$(echo "$EXEC_INFO" | jq '.requirement = "REQUIRED"')" >/dev/null
ok "requirement REQUIRED"

# A new execution is APPENDED, landing after the conditional-OTP subflow; raise it. Only
# top-level entries count — the listing is flattened and includes subflow children.
toplevel_index() {
  executions | jq --arg p "$AUTHENTICATOR_ID" \
    '[.[] | select(.level == 0)] | map(.providerId == $p) | index(true)'
}
for _ in 1 2 3 4 5; do
  [ "$(toplevel_index)" = "1" ] && break
  api -X POST "$KC/admin/realms/$REALM/authentication/executions/$EXEC_ID/raise-priority" >/dev/null
done
ok "positioned at top-level index $(toplevel_index) (directly after username validation)"

# Point it at the catalogue.
if [ "$(echo "$EXEC_INFO" | jq -r '.authenticationConfig // empty')" = "" ]; then
  CFG=$(jq -n --arg u "$CATALOGUE_URL" '{alias:"catalogue-config", config:{catalogueUrl:$u, connectTimeoutMs:"2000", readTimeoutMs:"5000"}}')
  if api -X POST "$KC/admin/realms/$REALM/authentication/executions/$EXEC_ID/config" "${J[@]}" -d "$CFG" >/dev/null; then
    ok "configured catalogueUrl=$CATALOGUE_URL"
  else
    skip "config POST failed — provider falls back to its built-in default URL"
  fi
else
  skip "already configured"
fi

# Bind the copy as the realm's direct grant flow.
CURRENT=$(api "$KC/admin/realms/$REALM" | jq -r '.directGrantFlow')
if [ "$CURRENT" = "$FLOW_NAME" ]; then
  skip "realm already bound to '$FLOW_NAME'"
else
  api -X PUT "$KC/admin/realms/$REALM" "${J[@]}" \
    -d "$(api "$KC/admin/realms/$REALM" | jq --arg f "$FLOW_NAME" '.directGrantFlow = $f')" >/dev/null
  ok "bound realm directGrantFlow -> $FLOW_NAME"
fi

printf '\n%sRealm configured.%s\n' "$GRN" "$RST"
api "$KC/admin/realms/$REALM/authentication/flows/$(printf %s "$FLOW_NAME" | jq -sRr @uri)/executions" \
  | jq -r '.[] | "  \(.index)  \(.displayName)  [\(.requirement)]"'
