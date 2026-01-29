#!/bin/sh
set -e

echo "================================"
echo "Configuring Keycloak OIDC Provider"
echo "================================"

# Wait for Keycloak to be fully ready
echo "Waiting for Keycloak to be ready..."
until curl -sf "${KEYCLOAK_URL}" > /dev/null 2>&1; do
  echo "Keycloak not ready yet, waiting..."
  sleep 2
done
echo "Keycloak is ready!"

# Get admin token
echo "Obtaining admin access token..."
ADMIN_TOKEN=$(curl -sf -X POST "${KEYCLOAK_URL}/realms/master/protocol/openid-connect/token" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "username=${KEYCLOAK_ADMIN}" \
  -d "password=${KEYCLOAK_ADMIN_PASSWORD}" \
  -d "grant_type=password" \
  -d "client_id=admin-cli" | jq -r '.access_token')

if [ -z "$ADMIN_TOKEN" ] || [ "$ADMIN_TOKEN" = "null" ]; then
  echo "Failed to obtain admin token"
  exit 1
fi
echo "Admin token obtained!"

# Create demo realm
echo "Creating demo realm..."
curl -sf -X POST "${KEYCLOAK_URL}/admin/realms" \
  -H "Authorization: Bearer ${ADMIN_TOKEN}" \
  -H "Content-Type: application/json" \
  -d '{
    "realm": "demo",
    "enabled": true,
    "displayName": "Token Exchange Demo Realm"
  }' || echo "Realm might already exist"

echo "Demo realm created or already exists!"

# Create or update demo-app client (for end users)
echo "Configuring demo-app client..."

DEMO_APP_CONFIG='{
  "clientId": "demo-app",
  "enabled": true,
  "publicClient": true,
  "directAccessGrantsEnabled": true,
  "serviceAccountsEnabled": false,
  "standardFlowEnabled": true,
  "implicitFlowEnabled": false,
  "protocol": "openid-connect",
  "attributes": {
    "access.token.lifespan": "3600"
  },
  "redirectUris": ["http://localhost:*", "http://keycloak.container.local.jmpd.in:8080/*", "http://*.container.local.jmpd.in:*"],
  "webOrigins": ["*"]
}'

# Check if client exists
DEMO_APP_UUID=$(curl -sf "${KEYCLOAK_URL}/admin/realms/demo/clients?clientId=demo-app" \
  -H "Authorization: Bearer ${ADMIN_TOKEN}" | jq -r '.[0].id // empty')

if [ -n "$DEMO_APP_UUID" ]; then
  echo "demo-app client exists, updating..."
  curl -sf -X PUT "${KEYCLOAK_URL}/admin/realms/demo/clients/${DEMO_APP_UUID}" \
    -H "Authorization: Bearer ${ADMIN_TOKEN}" \
    -H "Content-Type: application/json" \
    -d "$DEMO_APP_CONFIG"
  echo "demo-app client updated!"
else
  echo "Creating demo-app client..."
  curl -sf -X POST "${KEYCLOAK_URL}/admin/realms/demo/clients" \
    -H "Authorization: Bearer ${ADMIN_TOKEN}" \
    -H "Content-Type: application/json" \
    -d "$DEMO_APP_CONFIG"
  echo "demo-app client created!"
fi

# Get demo-app client UUID (may have just been created)
DEMO_APP_UUID=$(curl -sf "${KEYCLOAK_URL}/admin/realms/demo/clients?clientId=demo-app" \
  -H "Authorization: Bearer ${ADMIN_TOKEN}" | jq -r '.[0].id')

# In Keycloak 26, protocol mappers must be on a client scope (not directly on the client).
# Create a 'permissions' client scope with the mapper, then assign it to demo-app.
echo "Configuring permissions protocol mapper..."

MAPPER_CONFIG='{
  "name": "permissions",
  "protocol": "openid-connect",
  "protocolMapper": "oidc-usermodel-attribute-mapper",
  "config": {
    "claim.name": "permissions",
    "user.attribute": "permissions",
    "jsonType.label": "String",
    "multivalued": "true",
    "aggregate.attrs": "false",
    "id.token.claim": "true",
    "access.token.claim": "true",
    "userinfo.token.claim": "true"
  }
}'

# Create the permissions client scope (idempotent)
curl -sf -X POST "${KEYCLOAK_URL}/admin/realms/demo/client-scopes" \
  -H "Authorization: Bearer ${ADMIN_TOKEN}" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "permissions",
    "description": "Maps user permissions attribute into tokens",
    "protocol": "openid-connect",
    "attributes": {
      "include.in.token.scope": "false",
      "display.on.consent.screen": "false"
    }
  }' || true

# Get the scope ID and assign to demo-app as a default scope
PERMISSIONS_SCOPE_ID=$(curl -sf "${KEYCLOAK_URL}/admin/realms/demo/client-scopes" \
  -H "Authorization: Bearer ${ADMIN_TOKEN}" | jq -r '.[] | select(.name == "permissions") | .id')

if [ -n "$PERMISSIONS_SCOPE_ID" ]; then
  # Assign as default scope to demo-app
  curl -sf -X PUT \
    "${KEYCLOAK_URL}/admin/realms/demo/clients/${DEMO_APP_UUID}/default-client-scopes/${PERMISSIONS_SCOPE_ID}" \
    -H "Authorization: Bearer ${ADMIN_TOKEN}" || true

  # Add the mapper to the scope
  curl -sf -X POST \
    "${KEYCLOAK_URL}/admin/realms/demo/client-scopes/${PERMISSIONS_SCOPE_ID}/protocol-mappers/models" \
    -H "Authorization: Bearer ${ADMIN_TOKEN}" \
    -H "Content-Type: application/json" \
    -d "$MAPPER_CONFIG" || true

  echo "Permissions client scope configured and assigned to demo-app"
else
  echo "ERROR: Could not create or find permissions client scope"
fi

# Register 'permissions' in the User Profile configuration
# Keycloak 26 requires custom attributes to be declared in the User Profile
# before they can be stored on users (undeclared attributes are silently dropped)
echo "Configuring User Profile to include 'permissions' attribute..."
PROFILE=$(curl -s "${KEYCLOAK_URL}/admin/realms/demo/users/profile" \
  -H "Authorization: Bearer ${ADMIN_TOKEN}")

HAS_PERMISSIONS=$(echo "$PROFILE" | jq '[.attributes[].name] | index("permissions")')
if [ "$HAS_PERMISSIONS" = "null" ]; then
  UPDATED_PROFILE=$(echo "$PROFILE" | jq '.attributes += [{
    "name": "permissions",
    "displayName": "Permissions",
    "multivalued": true,
    "annotations": {},
    "validations": {},
    "permissions": {
      "view": ["admin", "user"],
      "edit": ["admin"]
    }
  }]')
  curl -s -o /dev/null -X PUT "${KEYCLOAK_URL}/admin/realms/demo/users/profile" \
    -H "Authorization: Bearer ${ADMIN_TOKEN}" \
    -H "Content-Type: application/json" \
    -d "$UPDATED_PROFILE"
  echo "User Profile updated: 'permissions' attribute registered"
else
  echo "User Profile already includes 'permissions' attribute"
fi

# Create demo users with permissions
echo "Creating demo users..."

# Create user: john@example.com (Customer Service Representative)
echo "Creating user: John Doe (Customer Service Representative)..."
JOHN_CREATE_HTTP=$(curl -s -o /dev/null -w "%{http_code}" -X POST "${KEYCLOAK_URL}/admin/realms/demo/users" \
  -H "Authorization: Bearer ${ADMIN_TOKEN}" \
  -H "Content-Type: application/json" \
  -d '{
    "username": "john",
    "email": "john@example.com",
    "firstName": "John",
    "lastName": "Doe",
    "enabled": true,
    "emailVerified": true,
    "attributes": {
      "permissions": ["read:customers", "write:customers"]
    },
    "credentials": [{
      "type": "password",
      "value": "password",
      "temporary": false
    }]
  }')

if [ "$JOHN_CREATE_HTTP" = "201" ]; then
  echo "User john created successfully"
elif [ "$JOHN_CREATE_HTTP" = "409" ]; then
  echo "User john already exists, updating permissions..."
  JOHN_UUID=$(curl -s "${KEYCLOAK_URL}/admin/realms/demo/users?username=john" \
    -H "Authorization: Bearer ${ADMIN_TOKEN}" | jq -r '.[0].id // empty')
  if [ -n "$JOHN_UUID" ]; then
    JOHN_EXISTING=$(curl -s "${KEYCLOAK_URL}/admin/realms/demo/users/${JOHN_UUID}" \
      -H "Authorization: Bearer ${ADMIN_TOKEN}")
    JOHN_UPDATED=$(echo "$JOHN_EXISTING" | jq '. + {
      "emailVerified": true,
      "requiredActions": [],
      "attributes": {"permissions": ["read:customers", "write:customers"]}
    }')
    curl -s -o /dev/null -X PUT "${KEYCLOAK_URL}/admin/realms/demo/users/${JOHN_UUID}" \
      -H "Authorization: Bearer ${ADMIN_TOKEN}" \
      -H "Content-Type: application/json" \
      -d "$JOHN_UPDATED"
    echo "John's account updated!"
  fi
else
  echo "WARNING: User john creation returned HTTP ${JOHN_CREATE_HTTP}"
fi

# Create user: jane@example.com (Marketing Analyst)
echo "Creating user: Jane Smith (Marketing Analyst)..."
JANE_CREATE_HTTP=$(curl -s -o /dev/null -w "%{http_code}" -X POST "${KEYCLOAK_URL}/admin/realms/demo/users" \
  -H "Authorization: Bearer ${ADMIN_TOKEN}" \
  -H "Content-Type: application/json" \
  -d '{
    "username": "jane",
    "email": "jane@example.com",
    "firstName": "Jane",
    "lastName": "Smith",
    "enabled": true,
    "emailVerified": true,
    "attributes": {
      "permissions": ["read:marketing", "write:marketing", "read:weather"]
    },
    "credentials": [{
      "type": "password",
      "value": "password",
      "temporary": false
    }]
  }')

if [ "$JANE_CREATE_HTTP" = "201" ]; then
  echo "User jane created successfully"
elif [ "$JANE_CREATE_HTTP" = "409" ]; then
  echo "User jane already exists, updating permissions..."
  JANE_UUID=$(curl -s "${KEYCLOAK_URL}/admin/realms/demo/users?username=jane" \
    -H "Authorization: Bearer ${ADMIN_TOKEN}" | jq -r '.[0].id // empty')

  if [ -n "$JANE_UUID" ]; then
    JANE_EXISTING=$(curl -s "${KEYCLOAK_URL}/admin/realms/demo/users/${JANE_UUID}" \
      -H "Authorization: Bearer ${ADMIN_TOKEN}")
    JANE_UPDATED=$(echo "$JANE_EXISTING" | jq '. + {
      "emailVerified": true,
      "requiredActions": [],
      "attributes": {"permissions": ["read:marketing", "write:marketing", "read:weather"]}
    }')
    curl -s -o /dev/null -X PUT "${KEYCLOAK_URL}/admin/realms/demo/users/${JANE_UUID}" \
      -H "Authorization: Bearer ${ADMIN_TOKEN}" \
      -H "Content-Type: application/json" \
      -d "$JANE_UPDATED"
    echo "Jane's account updated!"
  fi
else
  echo "WARNING: User jane creation returned HTTP ${JANE_CREATE_HTTP}"
fi

echo "Demo users created!"


echo ""
echo "================================"
echo "Keycloak Configuration Complete!"
echo "================================"
echo "Keycloak URL: ${KEYCLOAK_URL}"
echo "Admin Console: ${KEYCLOAK_URL}/admin"
echo "Admin Credentials: ${KEYCLOAK_ADMIN} / ${KEYCLOAK_ADMIN_PASSWORD}"
echo ""
echo "Demo Realm: demo"
echo "Client:"
echo "  - demo-app (public client for users)"
echo ""
echo "Demo Users:"
echo "  - john@example.com / password (Customer Service: read:customers, write:customers)"
echo "  - jane@example.com / password (Marketing: read:marketing, write:marketing, read:weather)"
echo ""
echo "JWKS Endpoint: ${KEYCLOAK_URL}/realms/demo/protocol/openid-connect/certs"
echo "Token Endpoint: ${KEYCLOAK_URL}/realms/demo/protocol/openid-connect/token"
echo ""
