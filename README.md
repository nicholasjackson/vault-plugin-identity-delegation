# Vault Plugin: Identity Delegation

A HashiCorp Vault secrets engine plugin that implements OAuth 2.0 Token Exchange (RFC 8693) for identity delegation and "on behalf of" scenarios with OIDC tokens.

## Purpose

This plugin enables AI agents and services to exchange existing OIDC tokens for new tokens that represent delegated authority. Following OAuth 2.0 Token Exchange (RFC 8693), the resulting token contains:
- **Subject** - Original user's identity and permissions (the person authorizing the action)
- **Actor** - Agent/service identity for audit purposes (the entity performing the action)
- **Context** - Delegated scopes that restrict the token's permissions
- "On behalf of" semantics per RFC 8693

## Interactive Demo

Want to see the plugin in action? The demo environment provides a complete Zero Trust Agentic Security setup with:

- **Chat UI** - Web interface for interacting with AI agents
- **AI Agents** - Customer and Weather agents running on Kubernetes
- **Keycloak** - OIDC identity provider with demo users
- **Vault** - Identity delegation plugin with Kubernetes auth

![Demo Screenshot](demo/images/home.png)

**Get started:**

```bash
cd demo
jumppad up
```

Then open http://chat.container.local.jmpd.in:3000 in your browser.

See [demo/Demo.md](demo/Demo.md) for the full walkthrough guide.

The demo uses the [Zero Trust Agentic AI Demo Application](https://github.com/nicholasjackson/demo-zero-trust-agentic-ai) which includes the Chat UI, agents, and tools.

---

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

### Authorization Model: Policy-Based vs. Consent-Based

**Important:** This plugin uses **policy-based authorization**, not runtime user consent. Understanding this distinction is critical for security and compliance:

#### How This Plugin Works (Policy-Based)

```
┌──────────────────────────────────────────────────┐
│ Configuration Time (Admin)                       │
├──────────────────────────────────────────────────┤
│ Admin → Creates role with allowed scopes         │
│ Admin → Configures bound issuer/audiences        │
│ Admin → Grants agent access to role              │
└──────────────────────────────────────────────────┘
                     ↓
┌──────────────────────────────────────────────────┐
│ Runtime (Automatic)                              │
├──────────────────────────────────────────────────┤
│ Agent → Presents user token + Vault auth         │
│ Vault → Validates + Exchanges (no user prompt)   │
│ Agent → Receives delegated token                 │
└──────────────────────────────────────────────────┘
```

**Characteristics:**
- **Administrators** pre-authorize agents via Vault policies and roles
- **No runtime user interaction** - token exchange happens server-to-server
- **Users never see** which agent is acting on their behalf
- **Scopes are fixed** in role configuration, not chosen by users

#### Alternative: Consent-Based Authorization (OAuth Standard)

For comparison, standard OAuth 2.0 consent-based flows work differently:

```
┌──────────────────────────────────────────────────┐
│ Runtime (User Consent)                           │
├──────────────────────────────────────────────────┤
│ Agent → Redirects user to authorization page     │
│ User → Sees "Agent X wants to access Y"          │
│ User → Clicks "Allow" or "Deny"                  │
│ IdP → Issues token only if user approved         │
└──────────────────────────────────────────────────┘
```

**Characteristics:**
- **Users** explicitly authorize each agent at runtime
- **Consent screen** shows agent identity and requested scopes
- **Users can deny** or grant subset of scopes
- **Full audit trail** of user consent decisions

See [draft-oauth-ai-agents-on-behalf-of-user](https://www.ietf.org/archive/id/draft-oauth-ai-agents-on-behalf-of-user-01.html) for the OAuth standard approach.

#### When to Use This Plugin

**✅ Appropriate Use Cases:**
- Enterprise internal agents where administrators control authorization policies
- Service-to-service delegation with user context in trusted environments
- Backend systems where user consent has been obtained through other means
- Centralized policy management via Vault is required

**❌ Not Appropriate For:**
- Consumer-facing AI assistants requiring explicit user consent (e.g., "ChatGPT wants to access your email")
- Compliance scenarios mandating runtime user authorization
- Public APIs where users must approve each agent individually
- Applications where users need to revoke agent access dynamically

#### Security Implications

**Policy-Based (This Plugin):**
- Security depends on administrator policy configuration
- Users trust administrators to configure appropriate agent permissions
- Agent authorization persists until admin modifies role
- No user visibility into which agents are authorized

**Consent-Based (OAuth Standard):**
- Security depends on user consent decisions
- Users directly control which agents can act on their behalf
- Agent authorization can be revoked by user at any time
- Full transparency of agent access to users

**Recommendation:** For consumer-facing applications or compliance-sensitive environments requiring explicit user consent, consider implementing the full OAuth 2.0 consent flow instead of or in addition to this plugin.

### Configure the Plugin

```bash
vault write identity-delegation/config \
    issuer="https://vault.example.com" \
    subject_jwks_uri="http://127.0.0.1:8200/v1/identity/oidc/.well-known/keys" \
    default_ttl="24h"
```

Configuration fields:
- `issuer` - The issuer claim for generated tokens
- `subject_jwks_uri` - JWKS endpoint for validating subject tokens
- `default_ttl` - Default TTL for tokens if not specified in role

**Note**: Signing keys are managed separately via the `/key` endpoint (see below). The config no longer contains a `signing_key` field.

### Manage Signing Keys

The plugin supports named key management for signing generated tokens. Each role references a specific key.

#### Create a Signing Key

```bash
# Generate a new RSA key pair (keys are automatically generated)
vault write identity-delegation/key/my-key \
    algorithm="RS256" \
    key_size="2048"
```

Key parameters:
- `algorithm` - Signing algorithm: `RS256`, `RS384`, or `RS512` (required)
- `key_size` - RSA key size: `2048`, `3072`, or `4096` (default: 2048)

**Note**: Keys are automatically generated and securely stored in Vault. For security reasons, you cannot import existing private keys - all keys must be generated by Vault.

#### List Keys

```bash
vault list identity-delegation/key/
```

#### Read Key Information

```bash
vault read identity-delegation/key/my-key
```

**Note**: Only the public key is returned. Private keys are never exposed via the API.

#### Delete a Key

```bash
vault delete identity-delegation/key/my-key
```

**Warning**: Deleting a key will break any roles that reference it.

#### Access Public Keys (JWKS Endpoint)

Public keys are exposed in standard JWKS (JSON Web Key Set) format for token verification:

```bash
# Get all public keys (no authentication required)
curl $VAULT_ADDR/v1/identity-delegation/jwks

# Get a specific key by ID
curl "$VAULT_ADDR/v1/identity-delegation/jwks?kid=my-key-v1"
```

**Important**: The JWKS endpoint is **publicly accessible** (unauthenticated) to allow external services to verify JWT signatures without requiring a Vault token. This endpoint is RFC 7517 compliant and returns only public keys - private keys are never exposed.

### Create a Role

```bash
vault write identity-delegation/role/my-role \
    key="my-key" \
    ttl="1h" \
    subject_template='{"department": "{{.department}}", "role": "{{.role}}"}' \
    actor_template='{"act": {"sub": "agent-123", "name": "My Agent"}}' \
    context="urn:documents:read,urn:images:write" \
    bound_issuer="https://idp.example.com" \
    bound_audiences="service-a,service-b"
```

Role fields:
- `key` - Name of the signing key to use for this role (required)
- `ttl` - Token lifetime (required)
- `subject_template` - JSON template to extract/map claims from the user's subject token (required)
- `actor_template` - JSON template to define claims about the agent/service (adds RFC 8693 `act` claim) (required)
- `context` - Comma-separated list of permitted scopes for the delegated token (maps to RFC 8693 `scope` claim) (required)
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
  "scope": "urn:documents:read urn:images:write",
  "subject_claims": {
    "department": "engineering"
  },
  "act": {
    "sub": "agent-123",
    "name": "My Agent"
  }
}
```

**Note**: The token header includes a `kid` (Key ID) field matching the key used to sign it (e.g., `"kid": "my-key-v1"`), allowing token verifiers to fetch the correct public key from the JWKS endpoint.

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
│   ├── integration-test.sh           # Integration tests
│   └── decode-jwt.py                 # JWT decoder for debugging
├── .github/workflows/                # GitHub Actions CI/CD
├── backend.go                        # Backend implementation
├── path_config.go                    # Configuration path
├── path_key.go                       # Key management paths
├── path_key_handlers.go              # Key CRUD operations
├── path_jwks.go                      # JWKS endpoint path
├── path_jwks_handlers.go             # JWKS endpoint handlers
├── path_role.go                      # Role management path
├── path_role_handlers.go             # Role CRUD operations
├── path_token.go                     # Token exchange path
├── path_token_handlers.go            # Token exchange logic
├── key.go                            # Key data structures
├── Makefile                          # Build automation
└── docker-compose.yml                # Docker test environment
```

## Testing

The plugin includes comprehensive test coverage:

- **Unit Tests**: 45+ tests covering all paths and operations
  - Key management (CRUD, versioning, algorithms)
  - Role management (key binding, validation)
  - Token exchange (kid header, JWKS integration)
  - RFC 8693 compliance (act claim, scope formatting)
- **Integration Tests**: End-to-end testing with running Vault
- **Coverage**: High code coverage across all paths

## License

This project is licensed under the Apache License 2.0 - see the [LICENSE](LICENSE) file for details.
