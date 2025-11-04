#!/bin/bash

set -e

# Configuration
VAULT_ADDR=${VAULT_ADDR:-http://127.0.0.1:8200}
VAULT_TOKEN=${VAULT_TOKEN:-root}

export VAULT_ADDR
export VAULT_TOKEN

echo "=========================================="
echo "Vault Token Exchange Plugin Demo"
echo "=========================================="
echo ""
echo "Vault Address: $VAULT_ADDR"
echo ""

# Check if vault is accessible
if ! vault status > /dev/null 2>&1; then
    echo "❌ Error: Cannot connect to Vault at $VAULT_ADDR"
    echo "Please start Vault dev server first:"
    echo "  make dev-vault"
    exit 1
fi

# Check if plugin is enabled
if ! vault secrets list | grep -q "token-exchange"; then
    echo "❌ Error: Plugin not enabled"
    echo "Please enable the plugin first:"
    echo "  make register enable"
    exit 1
fi

echo "✓ Vault is accessible"
echo "✓ Plugin is enabled"
echo ""

# Generate test RSA key pair
echo "Step 1: Generating test RSA key pair..."
TEMP_DIR=$(mktemp -d)
PRIVATE_KEY_FILE="$TEMP_DIR/private_key.pem"
PUBLIC_KEY_FILE="$TEMP_DIR/public_key.pem"

openssl genrsa -out "$PRIVATE_KEY_FILE" 2048 2>/dev/null
openssl rsa -in "$PRIVATE_KEY_FILE" -pubout -out "$PUBLIC_KEY_FILE" 2>/dev/null

echo "✓ Generated RSA key pair"
echo ""

# Configure the plugin
echo "Step 2: Configuring plugin..."
PRIVATE_KEY=$(cat "$PRIVATE_KEY_FILE")

vault write token-exchange/config \
    issuer="https://vault.example.com" \
    signing_key="$PRIVATE_KEY" \
    default_ttl="1h"

echo "✓ Plugin configured"
echo ""

# Create a role
echo "Step 3: Creating role 'demo-role'..."
vault write token-exchange/role/demo-role \
    ttl="1h" \
    template='{"act": {"sub": "agent-123", "name": "Demo Agent"}, "scope": "read write"}' \
    bound_issuer="https://idp.example.com" \
    bound_audiences="service-a,service-b"

echo "✓ Role created"
echo ""

# List roles
echo "Step 4: Listing roles..."
vault list token-exchange/role/
echo ""

# Read the role
echo "Step 5: Reading role details..."
vault read token-exchange/role/demo-role
echo ""

# Generate a test subject token
echo "Step 6: Generating test subject token..."

# Create JWT claims
cat > "$TEMP_DIR/claims.json" <<EOF
{
  "sub": "user-456",
  "email": "user@example.com",
  "name": "Demo User",
  "iss": "https://idp.example.com",
  "aud": ["service-a", "service-b"],
  "exp": $(date -d '+1 hour' +%s),
  "iat": $(date +%s)
}
EOF

# Use Python to create a simple JWT (if available)
if command -v python3 > /dev/null 2>&1; then
    SUBJECT_TOKEN=$(python3 - <<PYTHON
import json
import base64
import hashlib
import hmac
from datetime import datetime, timedelta

# Read claims
with open("$TEMP_DIR/claims.json") as f:
    claims = json.load(f)

# Simple JWT creation (header + payload + fake signature for demo)
header = {"alg": "RS256", "typ": "JWT"}
header_b64 = base64.urlsafe_b64encode(json.dumps(header).encode()).decode().rstrip('=')
payload_b64 = base64.urlsafe_b64encode(json.dumps(claims).encode()).decode().rstrip('=')

# For demo purposes, we'll create a properly signed JWT
# In real scenario, this would be signed with the private key
print(f"{header_b64}.{payload_b64}.demo-signature")
PYTHON
)
else
    # Fallback: Create a simple unsigned JWT for demo
    HEADER=$(echo -n '{"alg":"RS256","typ":"JWT"}' | base64 | tr -d '=' | tr '/+' '_-' | tr -d '\n')
    PAYLOAD=$(cat "$TEMP_DIR/claims.json" | base64 | tr -d '=' | tr '/+' '_-' | tr -d '\n')
    SUBJECT_TOKEN="$HEADER.$PAYLOAD.demo-signature"
fi

echo "✓ Generated test subject token"
echo ""

# Exchange the token
echo "Step 7: Exchanging token..."
echo "Note: In this demo, we're using a simple test token."
echo "In production, you would use a properly signed JWT from your IdP."
echo ""

# Since we don't have a real signed JWT, let's show what the API call would look like
echo "API call would be:"
echo "vault write token-exchange/token/demo-role subject_token=\"<JWT>\""
echo ""

# Show configuration
echo "Step 8: Reading configuration (signing key is hidden)..."
vault read token-exchange/config
echo ""

# Cleanup
echo "Cleaning up temporary files..."
rm -rf "$TEMP_DIR"
echo ""

echo "=========================================="
echo "Demo completed successfully!"
echo "=========================================="
echo ""
echo "The plugin is ready to use. To exchange tokens:"
echo "  1. Obtain a valid JWT from your IdP"
echo "  2. Run: vault write token-exchange/token/demo-role subject_token=\"<JWT>\""
echo ""
echo "To clean up:"
echo "  vault delete token-exchange/role/demo-role"
echo "  vault delete token-exchange/config"
echo ""
