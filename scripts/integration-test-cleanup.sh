#!/bin/bash

set -e

# Configuration
VAULT_ADDR=${VAULT_ADDR:-http://127.0.0.1:8200}
VAULT_TOKEN=${VAULT_TOKEN:-root}

export VAULT_ADDR
export VAULT_TOKEN

echo "=========================================="
echo "Vault Identity Delegation Test Cleanup"
echo "=========================================="
echo ""

# Check if vault is available
if ! command -v vault > /dev/null 2>&1; then
    echo "❌ Error: Vault CLI not found"
    exit 1
fi

if ! vault status > /dev/null 2>&1; then
    echo "❌ Error: Cannot connect to Vault at $VAULT_ADDR"
    exit 1
fi

echo "Cleaning up test resources..."
echo ""

# Function to safely delete (ignore errors if resource doesn't exist)
safe_delete() {
    local path=$1
    local description=$2
    if vault delete "$path" > /dev/null 2>&1; then
        echo "✓ Deleted: $description"
    else
        echo "⚠ Skipped: $description (not found or already deleted)"
    fi
}

# Function to safely disable auth method
safe_disable_auth() {
    local path=$1
    local description=$2
    if vault auth disable "$path" > /dev/null 2>&1; then
        echo "✓ Disabled: $description"
    else
        echo "⚠ Skipped: $description (not found or already disabled)"
    fi
}

# Function to safely delete policy
safe_delete_policy() {
    local name=$1
    local description=$2
    if vault policy delete "$name" > /dev/null 2>&1; then
        echo "✓ Deleted: $description"
    else
        echo "⚠ Skipped: $description (not found or already deleted)"
    fi
}

echo "1. Cleaning up plugin roles..."
safe_delete "identity-delegation/role/test-role-1" "test-role-1"
safe_delete "identity-delegation/role/test-role-2" "test-role-2"
echo ""

echo "2. Cleaning up plugin configuration..."
safe_delete "identity-delegation/config" "plugin config"
echo ""

echo "3. Cleaning up identity entity and alias..."
# Get entity ID if it exists
ENTITY_ID=$(vault list -format=json identity/entity/name 2>/dev/null | jq -r '.[] | select(. == "admin")' || echo "")
if [ -n "$ENTITY_ID" ]; then
    # First, list and delete entity aliases
    ENTITY_FULL=$(vault read -format=json identity/entity/name/admin 2>/dev/null || echo "")
    if [ -n "$ENTITY_FULL" ]; then
        ENTITY_ID=$(echo "$ENTITY_FULL" | jq -r '.data.id')
        ALIASES=$(echo "$ENTITY_FULL" | jq -r '.data.aliases[]?.id // empty')
        for ALIAS_ID in $ALIASES; do
            safe_delete "identity/entity-alias/id/$ALIAS_ID" "entity alias $ALIAS_ID"
        done
        safe_delete "identity/entity/id/$ENTITY_ID" "entity admin"
    fi
else
    echo "⚠ Skipped: entity admin (not found)"
fi
echo ""

echo "4. Cleaning up userpass auth method..."
# Disable userpass auth method (this will also delete the user)
safe_disable_auth "userpass" "userpass auth method"
echo ""

echo "5. Cleaning up OIDC policy..."
safe_delete_policy "oidc-policy" "oidc-policy"
echo ""

echo "6. Cleaning up identity OIDC configuration..."
safe_delete "identity/oidc/role/user" "OIDC role user"
safe_delete "identity/oidc/key/user-key" "OIDC key user-key"
echo ""

echo "=========================================="
echo "✓ Cleanup Complete!"
echo "=========================================="
echo ""
echo "You can now run the integration tests again without restarting Vault."
echo ""
