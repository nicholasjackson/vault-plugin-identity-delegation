#!/bin/sh
set -e

echo "================================"
echo "Configuring Vault Token Exchange Plugin"
echo "================================"

# Wait for Vault to be ready
echo "Waiting for Vault to be ready..."
until vault status > /dev/null 2>&1; do
  sleep 1
done
echo "Vault is ready!"

# PLUGIN_DIR can be set via environment variable (e.g. from Jumppad)
# or falls back to relative path from this script
if [ -z "$PLUGIN_DIR" ]; then
  CURRENT_DIR=$(dirname "$0")
  PLUGIN_DIR="${CURRENT_DIR}/../../bin"
fi

# Check if plugin is already enabled
echo "Checking if identity-delegation plugin is already configured..."
if vault secrets list | grep -q "^identity-delegation/"; then
  echo "Plugin already enabled at identity-delegation/. Skipping registration."
else
  echo "Plugin not found, proceeding with registration..."

  # Get the plugin SHA256
  echo "Calculating plugin SHA256..."
  PLUGIN_SHA256=$(sha256sum ${PLUGIN_DIR}/vault-plugin-identity-delegation | cut -d' ' -f1)
  echo "Plugin SHA256: ${PLUGIN_SHA256}"

  # Register the plugin
  echo "Registering token exchange plugin..."
  vault plugin register \
    -sha256="${PLUGIN_SHA256}" \
    -command="vault-plugin-identity-delegation" \
    secret \
    vault-plugin-identity-delegation

  echo "Plugin registered successfully!"

  # Enable the plugin
  echo "Enabling token exchange plugin at path: identity-delegation"
  vault secrets enable \
    -path=identity-delegation \
    -plugin-name=vault-plugin-identity-delegation \
    plugin

  echo "Plugin enabled successfully!"
fi

# Configure the plugin with Keycloak JWKS endpoint
echo "Configuring plugin with Keycloak JWKS endpoint..."

# Wait for Keycloak to be ready (it might still be starting up)
echo "Waiting for Keycloak to be ready..."
until curl -sf "${KEYCLOAK_URL}/realms/master/.well-known/openid-configuration" > /dev/null 2>&1; do
  echo "Keycloak not ready yet, waiting..."
  sleep 2
done
echo "Keycloak is ready!"

# Configure the token exchange with Keycloak JWKS endpoint
# Note: Use Jumppad FQDN which resolves from both host and containers
vault write identity-delegation/config \
  subject_jwks_uri="http://keycloak.container.local.jmpd.in:8080/realms/demo/protocol/openid-connect/certs" \
  issuer="https://vault.local" \
  default_ttl="1h"

echo "Plugin configured with Keycloak JWKS endpoint!"

# Create a signing key
echo "Creating signing key..."
vault write identity-delegation/key/demo-key \
  algorithm="RS256"

echo "Signing key created: demo-key"

# Create role for customer-agent
# Note: bound_issuer uses Jumppad FQDN - all clients should use this URL for Keycloak
# (*.local.jmpd.in resolves to 127.0.0.1)
echo "Creating customer-agent role..."
vault write identity-delegation/role/customer-agent \
  key="demo-key" \
  bound_issuer="http://keycloak.container.local.jmpd.in:8080/realms/demo" \
  bound_audiences="account" \
  context="read:customers,write:customers" \
  ttl="1h" \
  actor_template='{"act": {"sub": "{{identity.entity.name}}"}}' \
  subject_template='{"email": "{{identity.subject.email}}", "name": "{{identity.subject.name}}", "permissions": {{identity.subject.permissions}}}'

echo "Customer agent role created: customer-agent"

# Create role for customers-tool (read-only)
echo "Creating customers-tool role..."
vault write identity-delegation/role/customers-tool \
  key="demo-key" \
  bound_issuer="http://keycloak.container.local.jmpd.in:8080/realms/demo" \
  bound_audiences="account" \
  context="read:customers" \
  ttl="1h" \
  actor_template='{"act": {"sub": "{{identity.entity.name}}"}}' \
  subject_template='{"email": "{{identity.subject.email}}", "name": "{{identity.subject.name}}", "permissions": {{identity.subject.permissions}}}'

echo "Customers tool role created: customers-tool"

# Create role for weather-tool (read-only weather data)
echo "Creating weather-tool role..."
vault write identity-delegation/role/weather-tool \
  key="demo-key" \
  bound_issuer="http://keycloak.container.local.jmpd.in:8080/realms/demo" \
  bound_audiences="account" \
  context="read:weather" \
  ttl="1h" \
  actor_template='{"act": {"sub": "{{identity.entity.name}}"}}' \
  subject_template='{"email": "{{identity.subject.email}}", "name": "{{identity.subject.name}}", "permissions": {{identity.subject.permissions}}}'

echo "Weather tool role created: weather-tool"

# Create policy for identity delegation
echo "Creating identity-delegation policy..."
vault policy write identity-delegation - <<EOF
# Allow access to token exchange endpoint
path "identity-delegation/token/*" {
  capabilities = ["create", "update"]
}

# Allow reading roles (optional, for discovery)
path "identity-delegation/role/*" {
  capabilities = ["read", "list"]
}
EOF

echo ""
echo "================================"
echo "Vault Configuration Complete!"
echo "================================"
echo "Vault Address: ${VAULT_ADDR}"
echo "Vault Token: ${VAULT_TOKEN}"
echo ""
echo "Plugin enabled at: ${VAULT_ADDR}/v1/identity-delegation"
echo "Available roles:"
echo "  - customer-agent (scope: read:customers, write:customers)"
echo "  - customers-tool (scope: read:customers)"
echo "  - weather-tool (scope: read:weather)"
echo ""
echo "To test the plugin:"
echo "  vault read identity-delegation/config"
echo "  vault list identity-delegation/role"
echo ""
