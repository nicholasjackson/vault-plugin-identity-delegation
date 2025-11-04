# Vault Plugin: Identity Delegation

A HashiCorp Vault secrets engine plugin that implements OAuth 2.0 Token Exchange (RFC 8693) for identity delegation and "on behalf of" scenarios with OIDC tokens.

## Purpose

This plugin enables AI agents and services to exchange existing OIDC tokens for new tokens that represent delegated authority. The resulting token contains:
- Original user's identity and permissions
- Agent/service identity for audit purposes
- "On behalf of" semantics per RFC 8693

## Quick Start

### Prerequisites

- Go 1.23+
- Vault CLI
- OpenSSL
- jq

### Easiest Way to Build and Test

The quickest way to get started is to use the automated dev server and integration tests:

```bash
# Terminal 1: Start Vault dev server with plugin (builds, registers, and enables automatically)
make dev-vault

# Terminal 2: Run integration tests
./scripts/integration-test.sh
```

This will:
1. Build the plugin
2. Start Vault in dev mode
3. Register and enable the plugin
4. Run comprehensive integration tests including token exchange

### Unit Tests

```bash
# Run all unit tests
make test

# Run with coverage report
make test-coverage

# Run linters
make lint

# Run everything
make all
```

### Alternative Setup Options

**Option 1: Manual Registration**

```bash
# Terminal 1: Start Vault dev server
make dev-vault-manual

# Terminal 2: Register and enable plugin
make register enable

# Run demo
make demo
```

**Option 2: Using Docker Compose**

```bash
# Build plugin
make build

# Start Vault
docker-compose up -d

# Register and enable (from host)
export VAULT_ADDR=http://127.0.0.1:8200
export VAULT_TOKEN=root
make register enable
```

**Option 3: Manual Setup**

```bash
# Build the plugin
go build -o bin/vault-plugin-identity-delegation cmd/vault-plugin-identity-delegation/main.go

# Start Vault in dev mode
vault server -dev -dev-plugin-dir=./bin

# In another terminal, register and enable
export VAULT_ADDR='http://127.0.0.1:8200'
export VAULT_TOKEN='root'
SHA256=$(shasum -a 256 bin/vault-plugin-identity-delegation | cut -d' ' -f1)
vault plugin register -sha256=$SHA256 secret vault-plugin-identity-delegation
vault secrets enable -path=identity-delegation vault-plugin-identity-delegation
```

## Usage

### Configure the Plugin

```bash
vault write identity-delegation/config \
    issuer="https://vault.example.com" \
    signing_key=@private_key.pem \
    default_ttl="24h"
```

### Create a Role

```bash
vault write identity-delegation/role/my-role \
    ttl="1h" \
    template='{"act": {"sub": "agent-123", "name": "My Agent"}}' \
    bound_issuer="https://idp.example.com" \
    bound_audiences="service-a,service-b"
```

### Exchange a Token

```bash
vault write identity-delegation/token/my-role \
    subject_token="<JWT from IdP>"
```

### List Roles

```bash
vault list identity-delegation/role/
```

### Read a Role

```bash
vault read identity-delegation/role/my-role
```

### Delete a Role

```bash
vault delete identity-delegation/role/my-role
```

## Development

See [CLAUDE.md](./CLAUDE.md) for development guidelines and architecture.

## Makefile Targets

Run `make help` to see all available targets:

- `make build` - Build the plugin binary
- `make test` - Run all tests
- `make test-coverage` - Generate coverage report
- `make lint` - Run linters
- `make clean` - Clean build artifacts
- `make dev-vault` - Start Vault dev server with plugin
- `make register` - Register plugin with Vault
- `make enable` - Enable plugin as secrets engine
- `make demo` - Run plugin demonstration
- `make all` - Run all checks and build

## Project Structure

```
.
├── cmd/vault-plugin-identity-delegation/  # Main entry point
├── scripts/                           # Helper scripts
│   ├── demo.sh                       # Plugin demonstration
│   ├── integration-test.sh           # Integration tests
│   └── setup-test-env.sh            # Test environment setup
├── .github/workflows/                # GitHub Actions CI/CD
├── backend.go                        # Backend implementation
├── path_config.go                    # Configuration path
├── path_role.go                      # Role management path
├── path_token.go                     # Token exchange path
├── Makefile                          # Build automation
└── docker-compose.yml                # Docker test environment
```

## Testing

The plugin includes comprehensive test coverage:

- **Unit Tests**: 25 tests covering all paths and operations
- **Integration Tests**: End-to-end testing with running Vault
- **Coverage**: 76.9% code coverage

## License

This project is licensed under the Apache License 2.0 - see the [LICENSE](LICENSE) file for details.
