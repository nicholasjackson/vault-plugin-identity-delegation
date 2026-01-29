#!/bin/sh
set -e

echo "================================"
echo "Configuring Vault AppRole Auth"
echo "================================"

# Wait for Vault to be ready
echo "Waiting for Vault to be ready..."
until vault status > /dev/null 2>&1; do
  sleep 1
done
echo "Vault is ready!"

# Check if auth method is already enabled
echo "Checking if AppRole auth is already configured..."
if vault auth list | grep -q "^approle/"; then
  echo "AppRole auth already enabled. Skipping enable step."
else
  echo "Enabling AppRole auth method..."
  vault auth enable approle
  echo "AppRole auth enabled!"
fi

# Create policy for customer-agent (can request delegated tokens and validate them)
echo "Creating policy for customer-agent..."
vault policy write customer-agent - <<EOF
# Allow access to token exchange endpoint
path "identity-delegation/token/*" {
  capabilities = ["create", "update"]
}

# Allow reading roles
path "identity-delegation/role/*" {
  capabilities = ["read", "list"]
}

# Allow reading JWKS for token validation
path "identity-delegation/jwks" {
  capabilities = ["read"]
}

# Allow reading own identity
path "auth/token/lookup-self" {
  capabilities = ["read"]
}
EOF

echo "Policy created: customer-agent"

# Create policy for customers-tool
echo "Creating policy for customers-tool..."
vault policy write customers-tool - <<EOF
# Allow access to token exchange endpoint
path "identity-delegation/token/*" {
  capabilities = ["create", "update"]
}

# Allow reading roles
path "identity-delegation/role/*" {
  capabilities = ["read", "list"]
}

# Allow reading JWKS for token validation
path "identity-delegation/jwks" {
  capabilities = ["read"]
}

# Allow reading own identity
path "auth/token/lookup-self" {
  capabilities = ["read"]
}
EOF

echo "Policy created: customers-tool"

# Create policy for weather-tool
echo "Creating policy for weather-tool..."
vault policy write weather-tool - <<EOF
# Allow access to token exchange endpoint
path "identity-delegation/token/*" {
  capabilities = ["create", "update"]
}

# Allow reading roles
path "identity-delegation/role/*" {
  capabilities = ["read", "list"]
}

# Allow reading JWKS for token validation
path "identity-delegation/jwks" {
  capabilities = ["read"]
}

# Allow reading own identity
path "auth/token/lookup-self" {
  capabilities = ["read"]
}
EOF

echo "Policy created: weather-tool"

# Create AppRole role for customer-agent
echo "Creating AppRole role: customer-agent..."
vault write auth/approle/role/customer-agent \
  token_policies="customer-agent" \
  token_ttl="1h" \
  token_max_ttl="4h" \
  secret_id_ttl="24h" \
  secret_id_num_uses=0

echo "AppRole role created: customer-agent"

# Create AppRole role for customers-tool
echo "Creating AppRole role: customers-tool..."
vault write auth/approle/role/customers-tool \
  token_policies="customers-tool" \
  token_ttl="1h" \
  token_max_ttl="4h" \
  secret_id_ttl="24h" \
  secret_id_num_uses=0

echo "AppRole role created: customers-tool"

# Create AppRole role for weather-tool
echo "Creating AppRole role: weather-tool..."
vault write auth/approle/role/weather-tool \
  token_policies="weather-tool" \
  token_ttl="1h" \
  token_max_ttl="4h" \
  secret_id_ttl="24h" \
  secret_id_num_uses=0

echo "AppRole role created: weather-tool"

# Get the role IDs
CUSTOMER_AGENT_ROLE_ID=$(vault read -format=json auth/approle/role/customer-agent/role-id | jq -r '.data.role_id')
CUSTOMERS_TOOL_ROLE_ID=$(vault read -format=json auth/approle/role/customers-tool/role-id | jq -r '.data.role_id')
WEATHER_TOOL_ROLE_ID=$(vault read -format=json auth/approle/role/weather-tool/role-id | jq -r '.data.role_id')

echo "Customer agent role ID: ${CUSTOMER_AGENT_ROLE_ID}"
echo "Customers tool role ID: ${CUSTOMERS_TOOL_ROLE_ID}"
echo "Weather tool role ID: ${WEATHER_TOOL_ROLE_ID}"

# Generate secret IDs
CUSTOMER_AGENT_SECRET_ID=$(vault write -format=json -f auth/approle/role/customer-agent/secret-id | jq -r '.data.secret_id')
CUSTOMERS_TOOL_SECRET_ID=$(vault write -format=json -f auth/approle/role/customers-tool/secret-id | jq -r '.data.secret_id')
WEATHER_TOOL_SECRET_ID=$(vault write -format=json -f auth/approle/role/weather-tool/secret-id | jq -r '.data.secret_id')

echo "Customer agent secret ID generated"
echo "Customers tool secret ID generated"
echo "Weather tool secret ID generated"

# Create Vault entities for the applications
echo "Creating Vault entity for customer-agent..."
CUSTOMER_AGENT_ENTITY_ID=$(vault write -format=json identity/entity \
  name="customer-agent" \
  metadata=type="ai-agent" \
  metadata=service="customer" 2>/dev/null | jq -r '.data.id' || \
  vault read -format=json identity/entity/name/customer-agent | jq -r '.data.id')

echo "Customer agent entity: ${CUSTOMER_AGENT_ENTITY_ID}"

echo "Creating Vault entity for customers-tool..."
CUSTOMERS_TOOL_ENTITY_ID=$(vault write -format=json identity/entity \
  name="customers-tool" \
  metadata=type="tool" \
  metadata=service="customers" 2>/dev/null | jq -r '.data.id' || \
  vault read -format=json identity/entity/name/customers-tool | jq -r '.data.id')

echo "Customers tool entity: ${CUSTOMERS_TOOL_ENTITY_ID}"

echo "Creating Vault entity for weather-tool..."
WEATHER_TOOL_ENTITY_ID=$(vault write -format=json identity/entity \
  name="weather-tool" \
  metadata=type="tool" \
  metadata=service="weather" 2>/dev/null | jq -r '.data.id' || \
  vault read -format=json identity/entity/name/weather-tool | jq -r '.data.id')

echo "Weather tool entity: ${WEATHER_TOOL_ENTITY_ID}"

# Get the approle auth accessor
APPROLE_ACCESSOR=$(vault auth list -format=json | jq -r '.["approle/"].accessor')

# Create entity aliases linking approle auth to entities
echo "Creating entity alias for customer-agent..."
vault write identity/entity-alias \
  name="${CUSTOMER_AGENT_ROLE_ID}" \
  canonical_id="${CUSTOMER_AGENT_ENTITY_ID}" \
  mount_accessor="${APPROLE_ACCESSOR}" 2>/dev/null || echo "Entity alias may already exist"

echo "Creating entity alias for customers-tool..."
vault write identity/entity-alias \
  name="${CUSTOMERS_TOOL_ROLE_ID}" \
  canonical_id="${CUSTOMERS_TOOL_ENTITY_ID}" \
  mount_accessor="${APPROLE_ACCESSOR}" 2>/dev/null || echo "Entity alias may already exist"

echo "Creating entity alias for weather-tool..."
vault write identity/entity-alias \
  name="${WEATHER_TOOL_ROLE_ID}" \
  canonical_id="${WEATHER_TOOL_ENTITY_ID}" \
  mount_accessor="${APPROLE_ACCESSOR}" 2>/dev/null || echo "Entity alias may already exist"

echo ""
echo "================================"
echo "AppRole Auth Configuration Complete!"
echo "================================"
echo ""
echo "Customer Agent AppRole:"
echo "  - Role: customer-agent"
echo "  - Role ID: ${CUSTOMER_AGENT_ROLE_ID}"
echo "  - Secret ID: ${CUSTOMER_AGENT_SECRET_ID}"
echo "  - Policy: customer-agent"
echo "  - Entity: customer-agent"
echo ""
echo "Customers Tool AppRole:"
echo "  - Role: customers-tool"
echo "  - Role ID: ${CUSTOMERS_TOOL_ROLE_ID}"
echo "  - Secret ID: ${CUSTOMERS_TOOL_SECRET_ID}"
echo "  - Policy: customers-tool"
echo "  - Entity: customers-tool"
echo ""
echo "Weather Tool AppRole:"
echo "  - Role: weather-tool"
echo "  - Role ID: ${WEATHER_TOOL_ROLE_ID}"
echo "  - Secret ID: ${WEATHER_TOOL_SECRET_ID}"
echo "  - Policy: weather-tool"
echo "  - Entity: weather-tool"
echo ""
echo "To test customer-agent AppRole login:"
echo "  curl -s -X POST 'http://vault.container.local.jmpd.in:8200/v1/auth/approle/login' \\"
echo "    -H 'Content-Type: application/json' \\"
echo "    -d '{\"role_id\": \"${CUSTOMER_AGENT_ROLE_ID}\", \"secret_id\": \"${CUSTOMER_AGENT_SECRET_ID}\"}' | jq ."
echo ""
echo "To test customers-tool AppRole login:"
echo "  curl -s -X POST 'http://vault.container.local.jmpd.in:8200/v1/auth/approle/login' \\"
echo "    -H 'Content-Type: application/json' \\"
echo "    -d '{\"role_id\": \"${CUSTOMERS_TOOL_ROLE_ID}\", \"secret_id\": \"${CUSTOMERS_TOOL_SECRET_ID}\"}' | jq ."
echo ""
