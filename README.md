# Vault Plugin: Identity Delegation

A HashiCorp Vault secrets engine plugin that implements OAuth 2.0 Token Exchange (RFC 8693) for identity delegation and "on behalf of" scenarios with OIDC tokens.

## Purpose

This plugin enables AI agents and services to exchange existing OIDC tokens for new tokens that represent delegated authority. Following OAuth 2.0 Token Exchange (RFC 8693), the resulting token contains:
- **Subject** - Original user's identity and permissions (the person authorizing the action)
- **Actor** - Agent/service identity for audit purposes (the entity performing the action)
- **Context** - Delegated scopes that restrict the token's permissions
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

### Understanding Subject and Actor

This plugin follows the [OAuth 2.0 Token Exchange (RFC 8693)](https://datatracker.ietf.org/doc/html/rfc8693) standard for "on behalf of" delegation:

- **Subject** - The original user whose authority is being delegated (from `subject_token` parameter)
- **Actor** - The agent/service acting on behalf of the subject (from Vault entity making the request)

The exchanged token contains claims from both:
1. **Subject Claims** - Identity and permissions from the user's original token
2. **Actor Claims** - Identity information about the agent/service performing actions

This creates a clear audit trail showing both who authorized the action (subject) and who performed it (actor).

### Configure the Plugin

```bash
vault write identity-delegation/config \
    issuer="https://vault.example.com" \
    signing_key=@private_key.pem \
    subject_jwks_uri="http://127.0.0.1:8200/v1/identity/oidc/.well-known/keys" \
    default_ttl="24h"
```

Configuration fields:
- `issuer` - The issuer claim for generated tokens
- `signing_key` - RSA private key (PEM format) for signing tokens
- `subject_jwks_uri` - JWKS endpoint for validating subject tokens
- `default_ttl` - Default TTL for tokens if not specified in role

### Create a Role

```bash
vault write identity-delegation/role/my-role \
    ttl="1h" \
    subject_claims_template='{"department": "{{.department}}", "role": "{{.role}}"}' \
    actor_claims_template='{"act": {"sub": "agent-123", "name": "My Agent"}}' \
    context="urn:documents:read,urn:images:write" \
    bound_issuer="https://idp.example.com" \
    bound_audiences="service-a,service-b"
```

Role fields:
- `ttl` - Token lifetime (required)
- `subject_claims_template` - JSON template to extract/map claims from the user's subject token
- `actor_claims_template` - JSON template to define claims about the agent/service (adds RFC 8693 `act` claim)
- `context` - Comma-separated list of permitted scopes for the delegated token (RFC 8693 `ctx` claim)
- `bound_issuer` - Required issuer for incoming subject tokens (optional)
- `bound_audiences` - Comma-separated valid audiences for subject tokens (optional)

#### Template Variables

**Subject Claims Template** has access to claims from the user's token:
- `{{.sub}}` - Subject from the user's token
- `{{.email}}` - Email from the user's token
- Any custom claims from the subject token

**Actor Claims Template** can use static values or Vault entity metadata to describe the agent/service.

### Exchange a Token

```bash
vault write identity-delegation/token/my-role \
    subject_token="<JWT from IdP>"
```

The response contains a new JWT with merged claims:

```json
{
  "token": "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9..."
}
```

#### Example Token Structure

Given:
- Subject token with claims: `{"sub": "user123", "email": "user@example.com", "department": "engineering"}`
- Actor template: `{"act": {"sub": "agent-123", "name": "My Agent"}}`
- Subject template: `{"department": "{{.department}}"}`

The exchanged token payload would be:

```json
{
  "iss": "https://vault.example.com",
  "sub": "user123",
  "aud": "service-a",
  "iat": 1699564800,
  "exp": 1699568400,
  "department": "engineering",
  "act": {
    "sub": "agent-123",
    "name": "My Agent"
  }
}
```

**Debugging**: Use the JWT decoder script to inspect tokens:
```bash
./scripts/decode-jwt.py "$TOKEN"
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
│   ├── decode-jwt.py                 # JWT decoder for debugging
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
