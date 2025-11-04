#!/bin/bash

set -e

# Configuration
VAULT_ADDR=${VAULT_ADDR:-http://127.0.0.1:8200}
VAULT_TOKEN=${VAULT_TOKEN:-root}
PLUGIN_NAME="vault-plugin-identity-delegation"
PLUGIN_DIR="./bin"
PLUGIN_PATH="$PLUGIN_DIR/$PLUGIN_NAME"

export VAULT_ADDR
export VAULT_TOKEN

echo "=========================================="
echo "Starting Vault Dev Server with Auto-Setup"
echo "=========================================="
echo ""

# Check if vault is installed
if ! command -v vault > /dev/null 2>&1; then
    echo "❌ Error: Vault CLI not found"
    echo "Please install Vault from https://www.vaultproject.io/downloads"
    exit 1
fi

# Build the plugin
echo "Step 1: Building plugin..."
if [ ! -d "$PLUGIN_DIR" ]; then
    mkdir -p "$PLUGIN_DIR"
fi

go build -o "$PLUGIN_PATH" cmd/vault-plugin-identity-delegation/main.go
echo "✓ Plugin built: $PLUGIN_PATH"
echo ""

# Get plugin SHA256
SHA256=$(shasum -a 256 "$PLUGIN_PATH" | cut -d' ' -f1)
echo "Plugin SHA256: $SHA256"
echo ""

# Start Vault in the background
echo "Step 2: Starting Vault dev server..."
vault server -dev \
    -dev-root-token-id="$VAULT_TOKEN" \
    -dev-plugin-dir="$PLUGIN_DIR" \
    -log-level=info > /tmp/vault-dev.log 2>&1 &

VAULT_PID=$!
echo "✓ Vault started (PID: $VAULT_PID)"
echo "  Address: $VAULT_ADDR"
echo "  Token: $VAULT_TOKEN"
echo "  Logs: /tmp/vault-dev.log"
echo ""

# Wait for Vault to be ready
echo "Step 3: Waiting for Vault to be ready..."
RETRIES=30
until vault status > /dev/null 2>&1; do
    RETRIES=$((RETRIES - 1))
    if [ $RETRIES -le 0 ]; then
        echo "❌ Error: Vault failed to start"
        kill $VAULT_PID 2>/dev/null || true
        exit 1
    fi
    sleep 1
done
echo "✓ Vault is ready"
echo ""

# Register the plugin
echo "Step 4: Registering plugin..."
vault plugin register \
    -sha256="$SHA256" \
    secret "$PLUGIN_NAME"
echo "✓ Plugin registered"
echo ""

# Enable the plugin
echo "Step 5: Enabling plugin at /identity-delegation..."
vault secrets enable \
    -path=identity-delegation \
    "$PLUGIN_NAME"
echo "✓ Plugin enabled"
echo ""

echo "=========================================="
echo "✅ Vault Dev Environment Ready!"
echo "=========================================="
echo ""
echo "Vault Address: $VAULT_ADDR"
echo "Root Token: $VAULT_TOKEN"
echo "Plugin Path: /identity-delegation"
echo ""
echo "Quick Start:"
echo "  vault write identity-delegation/config issuer=... signing_key=@key.pem"
echo "  vault write identity-delegation/role/my-role ttl=1h template=..."
echo ""
echo "Run demo:"
echo "  make demo"
echo ""
echo "View logs:"
echo "  tail -f /tmp/vault-dev.log"
echo ""
echo "Press Ctrl+C to stop Vault and exit..."
echo ""

# Handle cleanup on exit
cleanup() {
    echo ""
    echo "Shutting down Vault..."
    kill $VAULT_PID 2>/dev/null || true
    wait $VAULT_PID 2>/dev/null || true
    echo "✓ Vault stopped"
    rm -f /tmp/vault-dev.log
    exit 0
}

trap cleanup INT TERM

# Keep script running and tail logs
tail -f /tmp/vault-dev.log &
TAIL_PID=$!

# Wait for Vault process
wait $VAULT_PID 2>/dev/null || true

# Cleanup tail process
kill $TAIL_PID 2>/dev/null || true
