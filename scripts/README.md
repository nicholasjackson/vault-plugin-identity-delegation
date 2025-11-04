# Scripts

This directory contains helper scripts for development, testing, and demonstration.

## Available Scripts

### dev-vault.sh
**Automated dev server** - Starts Vault, builds plugin, registers, and enables it automatically.

**Usage:**
```bash
# One command - does everything!
make dev-vault

# Or run directly:
./scripts/dev-vault.sh
```

**What it does:**
- Builds the plugin
- Starts Vault dev server in background
- Waits for Vault to be ready
- Registers the plugin
- Enables it at /identity-delegation
- Displays logs and keeps running
- Press Ctrl+C to stop

### setup-test-env.sh
Sets up a complete test environment with Vault dev server and the plugin (manual registration).

**Usage:**
```bash
# Terminal 1: Start Vault dev server
make dev-vault-manual

# Terminal 2: Setup environment
./scripts/setup-test-env.sh
```

### demo.sh
Runs a complete demonstration of the plugin functionality.

**Usage:**
```bash
make demo
```

**What it does:**
- Generates test RSA keys
- Configures the plugin
- Creates a demo role
- Shows how to exchange tokens
- Cleans up

### integration-test.sh
Runs integration tests against a running Vault instance.

**Usage:**
```bash
./scripts/integration-test.sh
```

**Tests:**
- Plugin configuration
- Security (signing key not exposed)
- Role CRUD operations
- Cleanup

## Quick Start

### Option 1: Automated Dev Server (Easiest!)

```bash
# One command - starts Vault with plugin auto-registered!
make dev-vault

# In another terminal, run demo
make demo

# Or run integration tests
./scripts/integration-test.sh
```

### Option 2: Manual Registration

```bash
# Terminal 1: Start Vault
make dev-vault-manual

# Terminal 2: Register and enable plugin
make register enable

# Run demo
make demo
```

### Option 2: Docker Compose

```bash
# Build plugin
make build

# Start Vault in Docker
docker-compose up -d

# Register plugin (from host)
export VAULT_ADDR=http://127.0.0.1:8200
export VAULT_TOKEN=root
make register enable

# Run demo
make demo
```

## Environment Variables

- `VAULT_ADDR` - Vault server address (default: http://127.0.0.1:8200)
- `VAULT_TOKEN` - Vault authentication token (default: root)

## Prerequisites

- Vault CLI installed
- OpenSSL (for key generation in demos)
- Go 1.23+ (for building)
- Docker & Docker Compose (optional, for containerized testing)
