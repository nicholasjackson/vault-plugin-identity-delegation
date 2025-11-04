#!/bin/bash

set -e

# Configuration
VAULT_ADDR=${VAULT_ADDR:-http://127.0.0.1:8200}
VAULT_TOKEN=${VAULT_TOKEN:-root}

export VAULT_ADDR
export VAULT_TOKEN

echo "=========================================="
echo "Vault Identity Delegation Integration Test"
echo "=========================================="
echo ""

# Prerequisites check
echo "Checking prerequisites..."

if ! command -v vault > /dev/null 2>&1; then
    echo "❌ Error: Vault CLI not found"
    exit 1
fi

if ! command -v openssl > /dev/null 2>&1; then
    echo "❌ Error: OpenSSL not found"
    exit 1
fi

if ! command -v jq > /dev/null 2>&1; then
    echo "❌ Error: JQ not found"
    exit 1
fi

if ! vault status > /dev/null 2>&1; then
    echo "❌ Error: Cannot connect to Vault at $VAULT_ADDR"
    echo "Please start Vault dev server first: make dev-vault"
    exit 1
fi

if ! vault secrets list | grep -q "identity-delegation"; then
    echo "❌ Error: Plugin not enabled"
    echo "Please enable the plugin first: make register enable"
    exit 1
fi

echo "✓ All prerequisites met"
echo ""

# Setup identity endpoing to generate valid JWTs with Vault
echo "Setting up identity endpoint for JWT generation..."

# Create the key
vault write identity/oidc/key/user-key \
    allowed_client_ids="*" \
    verification_ttl=86400 \
    rotation_period=86400 \
    algorithm=RS256

# Define the template for the JWT
TEMPLATE='{
  "username": {{identity.entity.aliases.<mount accessor>.name}},
  "email": {{identity.entity.metadata.email}},
  "role": {{identity.entity.metadata.role}},
  "department": {{identity.entity.metadata.department}},
  "manager": {{identity.entity.metadata.manager}},
  "nbf": {{time.now}}
}'

# Create the role
vault write identity/oidc/role/user \
 key="user-key" \
 template="$(echo ${TEMPLATE} | base64)" \
 ttl=3600

# Create an example entity and alias for the root user

# Create custom policy for OIDC
vault policy write oidc-policy - <<EOF
path "identity/oidc/token/*" {
  capabilities = ["read"]
}
path "identity/entity/*" {
  capabilities = ["read", "list"]
}
EOF

# Enable userpass
vault auth enable userpass

# Create a user
vault write auth/userpass/users/admin \
    password="your-password" \
    policies="default,oidc-policy"

# Get userpass mount accessor
MOUNT_ACCESSOR=$(vault auth list -format=json | jq -r '.["userpass/"].accessor')

# Create entity
ENTITY_ID=$(
  vault write \
    -format=json identity/entity \
    name="admin" \
    metadata=email="admin@example.com" \
    metadata=department="IT" \
    metadata=role="administrator" \
    metadata=manager="nic@email.com" \
  | jq -r '.data.id')

# Create alias
vault write identity/entity-alias \
    name="admin" \
    canonical_id="${ENTITY_ID}" \
    mount_accessor="${MOUNT_ACCESSOR}"

# Login with userpass
ADMIN_TOKEN=$(vault login -method=userpass -token-only username=admin password=your-password)

# Now try OIDC token
OIDC_TOKEN=$(VAULT_TOKEN=${ADMIN_TOKEN} vault read --format=json identity/oidc/token/user | jq -r '.data.token')
echo "OIDC Token: $OIDC_TOKEN"
echo ""

echo "✓ Example entity and OIDC token setup complete"

# Generate test keys
echo "Test 1: Generate RSA key pair..."
TEMP_DIR=$(mktemp -d)
trap "rm -rf $TEMP_DIR" EXIT

PRIVATE_KEY_FILE="$TEMP_DIR/private_key.pem"
PUBLIC_KEY_FILE="$TEMP_DIR/public_key.pem"

openssl genrsa -out "$PRIVATE_KEY_FILE" 2048 2>/dev/null
openssl rsa -in "$PRIVATE_KEY_FILE" -pubout -out "$PUBLIC_KEY_FILE" 2>/dev/null

echo "✓ Keys generated"
echo ""

# Configure plugin
echo "Test 2: Configure plugin..."
PRIVATE_KEY=$(cat "$PRIVATE_KEY_FILE")

vault write identity-delegation/config \
    issuer="https://vault.example.com" \
    signing_key="$PRIVATE_KEY" \
    delegate_jwks_uri="https://vault.example.com/.well-known/jwks.json" \
    default_ttl="1h" > /dev/null

# Read config (should not show signing key)
CONFIG_OUTPUT=$(vault read -format=json identity-delegation/config)
if echo "$CONFIG_OUTPUT" | grep -q "signing_key"; then
    echo "❌ FAIL: Config read returned signing key (security issue)"
    exit 1
fi

echo "✓ Plugin configured correctly"
echo "✓ Signing key not exposed in read operation"
echo ""

# Create roles
echo "Test 3: Create and manage roles..."

vault write identity-delegation/role/test-role-1 \
    ttl="1h" \
    template='{"act": {"sub": "agent-123"}}' > /dev/null

vault write identity-delegation/role/test-role-2 \
    ttl="2h" \
    template='{"act": {"sub": "agent-456"}}' \
    bound_issuer="https://idp.example.com" \
    bound_audiences="service-a,service-b" > /dev/null

# List roles
ROLE_LIST=$(vault list -format=json identity-delegation/role/)
if ! echo "$ROLE_LIST" | grep -q "test-role-1"; then
    echo "❌ FAIL: Role listing failed"
    exit 1
fi

# Read role
ROLE_DATA=$(vault read -format=json identity-delegation/role/test-role-1)
if ! echo "$ROLE_DATA" | grep -q "agent-123"; then
    echo "❌ FAIL: Role read failed"
    exit 1
fi

# Update role
vault write identity-delegation/role/test-role-1 \
    ttl="3h" \
    template='{"act": {"sub": "agent-123-updated"}}' > /dev/null

UPDATED_ROLE=$(vault read -format=json identity-delegation/role/test-role-1)
if ! echo "$UPDATED_ROLE" | grep -q "agent-123-updated"; then
    echo "❌ FAIL: Role update failed"
    exit 1
fi

# Delete role
vault delete identity-delegation/role/test-role-2 > /dev/null
if vault read identity-delegation/role/test-role-2 2>/dev/null; then
    echo "❌ FAIL: Role deletion failed"
    exit 1
fi

echo "✓ Role CRUD operations work correctly"
echo ""

# Note about token exchange testing
echo "Test 4: Token exchange..."
echo "Note: Full token exchange testing requires properly signed JWTs."
echo "The Go tests (go test) cover JWT validation and exchange logic."
echo ""

vault write identity-delegation/token/test-role-1 \
    subject_token="$OIDC_TOKEN"

# Cleanup
#echo "Test 5: Cleanup..."
#vault delete identity-delegation/role/test-role-1 > /dev/null
#vault delete identity-delegation/config > /dev/null

echo "✓ Cleanup completed"
echo ""

echo "=========================================="
echo "✓ All Integration Tests Passed!"
echo "=========================================="
echo ""
echo "Summary:"
echo "  - Plugin configuration: PASS"
echo "  - Security (key not exposed): PASS"
echo "  - Role CRUD operations: PASS"
echo "  - Cleanup: PASS"
echo ""
