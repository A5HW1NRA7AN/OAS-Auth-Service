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

FLOW_NAME="catalogue direct grant"

# The retired custom authenticator. Still referenced here only so an existing realm gets
# repaired: once the provider jar is gone from the image, a flow that still names it fails
# every login with an unresolvable authenticator.
RETIRED_AUTHENTICATOR="catalogue-validate-password"

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
  # This is the ONLY client in the realm allowed Direct Access Grants — step 5 turns it off
  # everywhere else. serviceAccountsEnabled gives the auth-service its own admin identity for
  # the user CRUD in step 3, so no admin username/password ever reaches the application.
  api -X POST "$KC/admin/realms/$REALM/clients" "${J[@]}" -d "{
    \"clientId\": \"$CLIENT\",
    \"name\": \"OAS Auth Service\",
    \"enabled\": true,
    \"protocol\": \"openid-connect\",
    \"publicClient\": false,
    \"standardFlowEnabled\": true,
    \"directAccessGrantsEnabled\": true,
    \"implicitFlowEnabled\": false,
    \"serviceAccountsEnabled\": true,
    \"redirectUris\": [\"http://localhost:3000/*\"],
    \"webOrigins\": [\"http://localhost:3000\"]
  }" >/dev/null
  ok "created client $CLIENT"
fi

CLIENT_UUID=$(api "$KC/admin/realms/$REALM/clients?clientId=$CLIENT" | jq -r '.[0].id')

# Realms created before the service account was needed have it switched off; repair in place.
CLIENT_JSON=$(api "$KC/admin/realms/$REALM/clients/$CLIENT_UUID")
if [ "$(echo "$CLIENT_JSON" | jq -r '.serviceAccountsEnabled')" = "true" ]; then
  skip "service account already enabled on $CLIENT"
else
  api -X PUT "$KC/admin/realms/$REALM/clients/$CLIENT_UUID" "${J[@]}" \
    -d "$(echo "$CLIENT_JSON" | jq '.serviceAccountsEnabled = true')" >/dev/null
  ok "enabled the service account on $CLIENT"
fi

# Keycloak generates the secret; keep .env (gitignored) in step with it.
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

# Admin-edit-only: a user must never change their own org_id. (`label` is reserved in jq.)
# email/firstName/lastName lose `required`: Keycloak requires them by default, and an incomplete
# profile raises VERIFY_PROFILE, failing the grant with "Account is not fully set up".
NEW_PROFILE=$(echo "$PROFILE" | jq '
  def attr(n; display; multi):
    {
      name: n,
      displayName: display,
      multivalued: multi,
      permissions: { view: ["admin","user"], edit: ["admin"] },
      validations: { length: { min: 1, max: 64 } },
      annotations: {}
    };
  .unmanagedAttributePolicy = "ADMIN_EDIT"
  | .attributes = (
      .attributes
      + (if any(.attributes[]; .name == "user_id")     then [] else [attr("user_id";     "OAS user id"; false)]     end)
      + (if any(.attributes[]; .name == "org_id")      then [] else [attr("org_id";      "OAS organisation id"; false)] end)
      + (if any(.attributes[]; .name == "entity_type") then [] else [attr("entity_type"; "OAS entity type"; false)] end)
      + (if any(.attributes[]; .name == "registries")  then [] else [attr("registries";  "OAS registries"; true)]  end)
    )
  # Self-healing: the append checks NAMES only, and multivalued:false installs an implicit max:1
  # validator that 400s a two-registry write. BOOLEAN here, STRING "true" in the mapper.
  # The multivalued VALIDATOR is deliberately not declared: it would make `max` mandatory.
  | .attributes = [ .attributes[]
      | if .name == "registries" then .multivalued = true else . end ]
  | .attributes = [ .attributes[]
      | if (.name == "email" or .name == "firstName" or .name == "lastName")
        then del(.required) else . end ]
')

api -X PUT "$KC/admin/realms/$REALM/users/profile" "${J[@]}" -d "$NEW_PROFILE" >/dev/null
PROFILE_AFTER=$(api "$KC/admin/realms/$REALM/users/profile")
DECLARED=$(echo "$PROFILE_AFTER" | jq -r '[.attributes[].name] | join(", ")')
ok "declared: $DECLARED"

for a in user_id org_id entity_type registries; do
  echo "$DECLARED" | grep -q "$a" || die "attribute $a was not declared — tokens will have no $a claim"
done

# The name check cannot catch a WRONGLY-declared attribute, and single-valued is the one that hurts.
[ "$(echo "$PROFILE_AFTER" | jq -r '.attributes[] | select(.name=="registries") | .multivalued')" = "true" ] \
  || die "registries is declared single-valued — a second registry would be rejected with 400"
ok "registries is multi-valued"

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

# Out here, not in the scope-creation body, which only runs when the scope is absent.
# multivalued:"true" is the point: with "false" Keycloak emits only the FIRST value, WARN only.
REG_MAPPER='{
  "name": "registries",
  "protocol": "openid-connect",
  "protocolMapper": "oidc-usermodel-attribute-mapper",
  "consentRequired": false,
  "config": {
    "user.attribute": "registries", "claim.name": "registries", "jsonType.label": "String",
    "access.token.claim": "true", "id.token.claim": "true",
    "userinfo.token.claim": "true", "introspection.token.claim": "true",
    "multivalued": "true", "aggregate.attrs": "false"
  }
}'
MAPPERS_URL="$KC/admin/realms/$REALM/client-scopes/$SCOPE_ID/protocol-mappers/models"
REG_ID=$(api "$MAPPERS_URL" | jq -r '.[] | select(.name == "registries") | .id // empty')

if [ -z "$REG_ID" ]; then
  api -X POST "$MAPPERS_URL" "${J[@]}" -d "$REG_MAPPER" >/dev/null
  ok "added the registries mapper (multivalued)"
elif [ "$(api "$MAPPERS_URL/$REG_ID" | jq -r '.config.multivalued // empty')" = "true" ]; then
  skip "registries mapper already multivalued"
else
  # Repaired in place: a presence-only check would skip a wrong mapper forever. PUT wants the id.
  api -X PUT "$MAPPERS_URL/$REG_ID" "${J[@]}" \
    -d "$(echo "$REG_MAPPER" | jq --arg id "$REG_ID" '.id = $id')" >/dev/null
  ok "repaired the registries mapper -> multivalued"
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
step "3. Service account -> least-privilege user administration"
# ---------------------------------------------------------------------------------
# The auth-service creates, disables and deletes Keycloak users through its OWN client's
# service account, never through admin/admin: manage-users to write and end sessions,
# view-users to look one up by username. Nothing more — a leaked client secret must not be
# able to rewrite the realm.
SA_USER_ID=$(api "$KC/admin/realms/$REALM/clients/$CLIENT_UUID/service-account-user" | jq -r '.id // empty')
[ -n "$SA_USER_ID" ] || die "no service-account user — serviceAccountsEnabled did not take"

RM_ID=$(api "$KC/admin/realms/$REALM/clients?clientId=realm-management" | jq -r '.[0].id // empty')
[ -n "$RM_ID" ] || die "realm-management client not found in realm $REALM"

grant_role() {
  if api "$KC/admin/realms/$REALM/users/$SA_USER_ID/role-mappings/clients/$RM_ID" \
     | jq -e --arg n "$1" '.[] | select(.name == $n)' >/dev/null 2>&1; then
    skip "service account already has $1"
    return
  fi
  REP=$(api "$KC/admin/realms/$REALM/clients/$RM_ID/roles/$1" | jq -c '{id, name}')
  [ -n "$(echo "$REP" | jq -r '.id // empty')" ] || die "role $1 not found on realm-management"
  api -X POST "$KC/admin/realms/$REALM/users/$SA_USER_ID/role-mappings/clients/$RM_ID" \
    "${J[@]}" -d "[$REP]" >/dev/null
  ok "granted $1"
}
grant_role manage-users
grant_role view-users

# ---------------------------------------------------------------------------------
step "4. Direct Grant flow -> no credential check inside Keycloak"
# ---------------------------------------------------------------------------------
# The flow is reduced to direct-grant-validate-username: Keycloak resolves the user, enforces
# the `enabled` flag (which is what makes auth_user_revoke stick) and issues the token. It
# verifies no credential at all, on purpose — Keycloak holds none for these users.
#
# Stated plainly, because it is the security model: anyone who can reach this token endpoint
# WITH THE CLIENT SECRET can mint a token for any username in the realm. The secret is the
# only thing standing there, which is why step 5 exists and why neither this endpoint nor the
# auth-service may be routed through Kong or any ingress.
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

# Migration, not tidiness: a realm provisioned by an earlier version still has the custom
# authenticator wired, and the provider jar no longer exists in the image.
OLD_EXEC=$(executions | jq -r --arg p "$RETIRED_AUTHENTICATOR" '.[] | select(.providerId==$p) | .id')
if [ -n "$OLD_EXEC" ]; then
  api -X DELETE "$KC/admin/realms/$REALM/authentication/executions/$OLD_EXEC" >/dev/null
  ok "removed the retired $RETIRED_AUTHENTICATOR step"
else
  skip "no $RETIRED_AUTHENTICATOR step present"
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

# ---------------------------------------------------------------------------------
step "5. Lock down every other client"
# ---------------------------------------------------------------------------------
# directGrantFlow is a REALM-WIDE binding, and Keycloak auto-creates a PUBLIC `admin-cli`
# client with Direct Access Grants on in every realm. With no credential step in the flow,
# this would mint a live token for any user with no secret and no password:
#
#   POST /realms/OAS/protocol/openid-connect/token
#   grant_type=password&client_id=admin-cli&username=<any userId>
#
# Verified against Keycloak 26.7 — it really does issue a token. So Direct Access Grants must
# be off on every client except ours, and asserted rather than assumed: a rebuilt realm
# recreates admin-cli with the flag back on.
for cid in $(api "$KC/admin/realms/$REALM/clients" | jq -r '.[] | select(.directAccessGrantsEnabled == true) | .id'); do
  C_JSON=$(api "$KC/admin/realms/$REALM/clients/$cid")
  C_NAME=$(echo "$C_JSON" | jq -r .clientId)
  [ "$C_NAME" = "$CLIENT" ] && continue
  api -X PUT "$KC/admin/realms/$REALM/clients/$cid" "${J[@]}" \
    -d "$(echo "$C_JSON" | jq '.directAccessGrantsEnabled = false')" >/dev/null
  ok "disabled direct access grants on $C_NAME"
done

STILL_OPEN=$(api "$KC/admin/realms/$REALM/clients" \
  | jq -r --arg me "$CLIENT" '[.[] | select(.directAccessGrantsEnabled == true and .clientId != $me) | .clientId] | join(", ")')
[ -z "$STILL_OPEN" ] || die "these clients can still mint tokens without a password: $STILL_OPEN"
ok "only $CLIENT may use the direct grant"

# direct-grant-validate-username resolves via findUserByNameOrEmail, so with email login on, a
# userId that happens to equal another user's email address would resolve to the wrong user.
REALM_JSON=$(api "$KC/admin/realms/$REALM")
if [ "$(echo "$REALM_JSON" | jq -r '.loginWithEmailAllowed')" = "false" ]; then
  skip "email login already disabled"
else
  api -X PUT "$KC/admin/realms/$REALM" "${J[@]}" \
    -d "$(echo "$REALM_JSON" | jq '.loginWithEmailAllowed = false')" >/dev/null
  ok "disabled email login (userId is the only login identifier)"
fi

# ---------------------------------------------------------------------------------
step "6. Verify"
# ---------------------------------------------------------------------------------
# Catch a missing role or a half-applied flow here, not at the first publish.
SA_TOKEN=$(curl -sf -X POST "$KC/realms/$REALM/protocol/openid-connect/token" \
  -d 'grant_type=client_credentials' -d "client_id=$CLIENT" -d "client_secret=$SECRET" 2>/dev/null \
  | jq -r '.access_token // empty' 2>/dev/null || true)
[ -n "$SA_TOKEN" ] || die "client_credentials refused — is the service account enabled?"
curl -sf -H "Authorization: Bearer $SA_TOKEN" "$KC/admin/realms/$REALM/users?max=1" >/dev/null \
  || die "service account cannot read users — view-users not granted?"
ok "service account can administer users"

if executions | jq -e '.[] | select(.providerId != null and (.providerId | test("validate-password")))' >/dev/null 2>&1; then
  die "the bound flow still contains a password validation step"
fi
ok "no credential check in the bound flow"

# Asserted end to end: a single-valued mapper fails silently, so nothing downstream would notice.
api "$MAPPERS_URL" | jq -e '.[] | select(.name=="registries" and .config.multivalued=="true")' >/dev/null \
  || die "registries mapper missing or single-valued — tokens would carry only the first registry"
ok "registries claim is multi-valued end to end"

printf '\n%sRealm configured.%s\n' "$GRN" "$RST"
executions | jq -r '.[] | "  \(.index)  \(.displayName)  [\(.requirement)]"'
