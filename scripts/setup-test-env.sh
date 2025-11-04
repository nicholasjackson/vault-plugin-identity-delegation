#!/bin/bash

set -e

# Configuration
VAULT_ADDR=${VAULT_ADDR:-http://127.0.0.1:8200}
VAULT_TOKEN=${VAULT_TOKEN:-root}

export VAULT_ADDR
export VAULT_TOKEN

echo "=========================================="
echo "Setting up Vault Test Environment"
echo "=========================================="
echo ""

# Check if Vault is installed
if ! command -v vault > /dev/null 2>&1; then
    echo "❌ Error: Vault CLI not found"
    echo "Please install Vault from https://www.vaultproject.io/downloads"
    exit 1
fi

echo "✓ Vault CLI installed: $(vault version)"
echo ""

# Build the plugin
echo "Step 1: Building plugin..."
make build
echo ""

# Check if Vault is already running
if vault status > /dev/null 2>&1; then
    echo "✓ Vault is already running at $VAULT_ADDR"
    VAULT_RUNNING=true
else
    echo "⚠️  Vault is not running"
    echo ""
    echo "To start Vault dev server with plugin, run:"
    echo "  make dev-vault"
    echo ""
    echo "Then in another terminal, run:"
    echo "  make register enable"
    echo "  make demo"
    VAULT_RUNNING=false
fi

if [ "$VAULT_RUNNING" = true ]; then
    echo ""
    echo "Step 2: Registering plugin..."
    make register
    echo ""

    echo "Step 3: Enabling plugin..."
    make enable
    echo ""

    echo "=========================================="
    echo "Test Environment Ready!"
    echo "=========================================="
    echo ""
    echo "Vault Address: $VAULT_ADDR"
    echo "Root Token: $VAULT_TOKEN"
    echo ""
    echo "Plugin is enabled at: /token-exchange"
    echo ""
    echo "Next steps:"
    echo "  1. Run demo: make demo"
    echo "  2. Or configure manually:"
    echo "     vault write token-exchange/config issuer=... signing_key=..."
    echo "     vault write token-exchange/role/my-role ttl=1h template=..."
    echo ""
fi
