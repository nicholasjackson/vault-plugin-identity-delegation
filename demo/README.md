# Vault Identity Delegation Plugin Demo

This demo provides a complete environment to test the Vault Identity Delegation plugin using Jumppad. The demo includes:

- **HashiCorp Vault** with the identity delegation plugin pre-configured
- **Keycloak** as an OIDC identity provider
- Pre-configured demo realm, clients, and users
- Sample roles for identity delegation scenarios

## Prerequisites

- [Jumppad](https://jumppad.dev/) installed
- Docker or Podman for container runtime
- Internet connection (to download plugin from GitHub releases)

## Plugin Source

By default, the demo downloads the plugin binary from GitHub releases:
- Repository: https://github.com/nicholasjackson/vault-plugin-identity-delegation/releases
- Default version: `v0.0.5` (latest)
- Default platform: `linux-amd64`

Available platforms:
- `linux-amd64` (default for containers)
- `linux-arm64`
- `darwin-amd64`
- `darwin-arm64`
- `windows-amd64` (with .exe extension)

### Using a Different Version

To use a different release version or platform:

```bash
cd demo
jumppad up --var plugin_version=v0.0.5 --var plugin_platform=darwin-arm64
```

### Building Locally (Alternative)

If GitHub releases are not available or you want to build from source:

1. Edit `main.hcl` and comment out the `download_plugin` resource
2. Uncomment the `local_build_plugin` resource section
3. Update the Vault container's `depends_on` as noted in the comments
4. Run `jumppad up`

## Quick Start

### Automatic Setup (Recommended)

1. Start the demo environment with automatic configuration:
   ```bash
   cd demo
   jumppad up
   ```

2. Wait for all services to start and configure (this may take 1-2 minutes)
   - The plugin will be downloaded from GitHub releases automatically
   - Keycloak and Vault will start
   - Setup scripts will run automatically to configure both services

3. Access the services:
   - Vault UI: http://vault.container.local.jmpd.in:8200/ui (token: `root`)
   - Keycloak Admin: http://keycloak.container.local.jmpd.in:8080/admin (admin / admin)

### Manual Setup (Optional)

If you prefer to configure manually or skip auto-configuration:

1. Start containers only (without running setup scripts):
   ```bash
   cd demo
   jumppad up --var run_scripts=false
   ```

2. Manually run setup scripts when ready:
   ```bash
   # Configure Keycloak
   ./scripts/setup-keycloak.sh

   # Configure Vault identity delegation plugin
   ./scripts/setup-identity-plugin.sh

   # Configure Kubernetes auth (requires K8s cluster)
   ./scripts/setup-k8s-auth.sh

   # Configure AppRole auth
   ./scripts/setup-approle.sh
   ```

3. For live demos, skip only the identity plugin setup:
   ```bash
   cd demo
   jumppad up --var="run_identity_plugin=false"
   # Then run the plugin setup manually during the demo:
   ./scripts/setup-identity-plugin.sh
   ```

## Demo Personas

### End Users (Keycloak)

| User | Email | Role | Permissions | Description |
|------|-------|------|-------------|-------------|
| John Doe | john@example.com | Customer Service Rep | `read:customers`, `write:customers` | Handles customer inquiries, authorized to access customer data |
| Jane Smith | jane@example.com | Marketing Analyst | `read:marketing`, `write:marketing`, `read:weather` | Analyzes campaign data, can access weather data, no access to customer PII |

Both users have password: `password`

### Agents & Tools (Vault Entities)

| Entity | Type | Scope | Description |
|--------|------|-------|-------------|
| customer-agent | AI Agent | `read:customers write:customers` | AI agent that helps with customer service tasks |
| weather-agent | AI Agent | `read:weather write:weather` | AI agent that helps with weather-related tasks |
| customers-tool | Tool | N/A (validates via JWKS) | Database query tool for customer lookups |
| weather-tool | Tool | N/A (validates via JWKS) | Weather data retrieval tool |

> **Note**: Tools do not have identity-delegation roles. They validate delegated JWTs directly against Vault's JWKS endpoint and enforce `scope ∩ permissions` locally.

## Authorization Model

The demo implements **dual authorization** using permission intersection. Downstream services check two things:

1. **Agent scope** (`scope` claim): What operations is the agent/tool allowed to perform?
2. **User permissions** (`subject_claims.permissions`): What is the user authorized for?
3. **Effective permissions** = `scope ∩ user_permissions` — only operations in both sets are allowed.

### Example: John via customer-agent (ALLOWED)

```json
{
  "iss": "https://vault.local",
  "sub": "john-uuid",
  "act": { "sub": "customer-agent" },
  "scope": "read:customers write:customers",
  "subject_claims": {
    "email": "john@example.com",
    "name": "John Doe",
    "permissions": ["read:customers", "write:customers"]
  }
}
```

Effective: `{read:customers, write:customers} ∩ {read:customers, write:customers}` = **read:customers, write:customers** — request proceeds.

### Example: Jane via customer-agent (DENIED)

```json
{
  "iss": "https://vault.local",
  "sub": "jane-uuid",
  "act": { "sub": "customer-agent" },
  "scope": "read:customers write:customers",
  "subject_claims": {
    "email": "jane@example.com",
    "name": "Jane Smith",
    "permissions": ["read:marketing", "write:marketing", "read:weather"]
  }
}
```

Effective: `{read:customers, write:customers} ∩ {read:marketing, write:marketing, read:weather}` = **empty** — downstream service rejects the request.

> **Note**: The Vault plugin itself does not enforce user permissions — it issues the delegated token regardless. The enforcement happens at the downstream service that validates the token and checks the intersection.

## What Gets Configured

### Keycloak Setup

The demo creates a Keycloak realm called `demo` with:

**Client:**
- `demo-app` — Public client for end-user authentication

**Users:**
- `john@example.com` / `password` — permissions: `read:customers`, `write:customers`
- `jane@example.com` / `password` — permissions: `read:marketing`, `write:marketing`, `read:weather`

**Protocol Mapper:**
- `permissions` — Maps the user `permissions` attribute into the access token as a multi-valued claim

**Endpoints:**
- Token endpoint: `http://keycloak.container.local.jmpd.in:8080/realms/demo/protocol/openid-connect/token`
- JWKS endpoint: `http://keycloak.container.local.jmpd.in:8080/realms/demo/protocol/openid-connect/certs`

### Vault Setup

The demo configures Vault with:

**Plugin Configuration:**
- Registered and enabled at path: `identity-delegation`
- Connected to Keycloak JWKS endpoint for token validation

**Identity Delegation Roles (agents only):**
- `customer-agent` — For customer data (scope: `read:customers`, `write:customers`)
- `weather-agent` — For weather data (scope: `read:weather`, `write:weather`)

Both roles include `permissions` from the user's Keycloak token in `subject_claims`. Tools do not need identity-delegation roles — they validate delegated JWTs via the JWKS endpoint.

**Authentication Methods:**
- `kubernetes` — K8s service account auth at `kubernetes/` path
- `demo-auth-mount` — K8s service account auth at `demo-auth-mount/` path
- `approle` — Application authentication for non-K8s workloads

**Vault Entities:**
- `customer-agent` — Customer service AI agent
- `weather-agent` — Weather data AI agent
- `customers-tool` — Customer lookup tool (AppRole/K8s auth only, no delegation role)
- `weather-tool` — Weather data retrieval tool (AppRole/K8s auth only, no delegation role)

**Actor Identity:**
- The plugin uses Vault's built-in entity system for actor identity
- Actor identity is derived from the Vault token used to call the plugin
- The `act.sub` claim in the exchanged token contains the entity name

## Testing Identity Delegation

### Step 1: Get a User Token from Keycloak

```bash
# Get a token for John (has customer permissions)
JOHN_TOKEN=$(curl -s -X POST "http://keycloak.container.local.jmpd.in:8080/realms/demo/protocol/openid-connect/token" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "username=john" \
  -d "password=password" \
  -d "grant_type=password" \
  -d "client_id=demo-app" | jq -r '.access_token')

# Decode to verify permissions claim
echo $JOHN_TOKEN | cut -d'.' -f2 | base64 -d 2>/dev/null | jq .

# Get a token for Jane (has marketing permissions only)
JANE_TOKEN=$(curl -s -X POST "http://keycloak.container.local.jmpd.in:8080/realms/demo/protocol/openid-connect/token" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "username=jane" \
  -d "password=password" \
  -d "grant_type=password" \
  -d "client_id=demo-app" | jq -r '.access_token')

echo $JANE_TOKEN | cut -d'.' -f2 | base64 -d 2>/dev/null | jq .
```

### Step 2: Authenticate Agent to Vault

#### Using AppRole Auth

```bash
# Login as customer-agent
export VAULT_ROLE_ID=$(vault read -format=json auth/approle/role/customer-agent/role-id | jq -r '.data.role_id')
export VAULT_SECRET_ID=$(vault write -format=json -f auth/approle/role/customer-agent/secret-id | jq -r '.data.secret_id')

CUSTOMER_AGENT_TOKEN=$(curl -s -X POST "http://vault.container.local.jmpd.in:8200/v1/auth/approle/login" \
  -H "Content-Type: application/json" \
  -d "{\"role_id\": \"$VAULT_ROLE_ID\", \"secret_id\": \"$VAULT_SECRET_ID\"}" | jq -r '.auth.client_token')

# Login as weather-agent
export VAULT_ROLE_ID=$(vault read -format=json auth/approle/role/weather-agent/role-id | jq -r '.data.role_id')
export VAULT_SECRET_ID=$(vault write -format=json -f auth/approle/role/weather-agent/secret-id | jq -r '.data.secret_id')

WEATHER_AGENT_TOKEN=$(curl -s -X POST "http://vault.container.local.jmpd.in:8200/v1/auth/approle/login" \
  -H "Content-Type: application/json" \
  -d "{\"role_id\": \"$VAULT_ROLE_ID\", \"secret_id\": \"$VAULT_SECRET_ID\"}" | jq -r '.auth.client_token')
```

#### Using Kubernetes Auth

```bash
# Login as customer-agent
SA_TOKEN=$(kubectl get secret customer-agent-token -n demo -o jsonpath='{.data.token}' | base64 -d)

CUSTOMER_AGENT_TOKEN=$(curl -s -X POST "http://vault.container.local.jmpd.in:8200/v1/auth/demo-auth-mount/login" \
  -H "Content-Type: application/json" \
  -d "{\"role\": \"customer-agent\", \"jwt\": \"$SA_TOKEN\"}" | jq -r '.auth.client_token')

# Login as weather-agent
SA_TOKEN=$(kubectl get secret weather-agent-token -n demo -o jsonpath='{.data.token}' | base64 -d)

WEATHER_AGENT_TOKEN=$(curl -s -X POST "http://vault.container.local.jmpd.in:8200/v1/auth/demo-auth-mount/login" \
  -H "Content-Type: application/json" \
  -d "{\"role\": \"weather-agent\", \"jwt\": \"$SA_TOKEN\"}" | jq -r '.auth.client_token')
```

### Step 3: Exchange Tokens

```bash
# Exchange John's token via customer-agent (scope ∩ permissions = read:customers, write:customers)
JOHN_DELEGATED=$(curl -s -X POST "http://vault.container.local.jmpd.in:8200/v1/identity-delegation/token/customer-agent" \
  -H "X-Vault-Token: $CUSTOMER_AGENT_TOKEN" \
  -H "Content-Type: application/json" \
  -d "{\"subject_token\": \"$JOHN_TOKEN\"}" | jq -r '.data.token')

echo "=== John via customer-agent ==="
echo $JOHN_DELEGATED | cut -d'.' -f2 | base64 -d 2>/dev/null | jq .

# Exchange Jane's token via weather-agent (scope ∩ permissions = read:weather)
JANE_DELEGATED=$(curl -s -X POST "http://vault.container.local.jmpd.in:8200/v1/identity-delegation/token/weather-agent" \
  -H "X-Vault-Token: $WEATHER_AGENT_TOKEN" \
  -H "Content-Type: application/json" \
  -d "{\"subject_token\": \"$JANE_TOKEN\"}" | jq -r '.data.token')

echo "=== Jane via weather-agent ==="
echo $JANE_DELEGATED | cut -d'.' -f2 | base64 -d 2>/dev/null | jq .
```

### Step 4: Verify Downstream Authorization

Compare the `scope` and `subject_claims.permissions` in each token:

```bash
# John via customer-agent: scope={read:customers,write:customers} ∩ permissions={read:customers,write:customers} -> ALLOWED
echo "John via customer-agent:"
echo $JOHN_DELEGATED | cut -d'.' -f2 | base64 -d 2>/dev/null | jq '{scope, act, permissions: .subject_claims.permissions}'

# Jane via weather-agent: scope={read:weather,write:weather} ∩ permissions={read:marketing,write:marketing,read:weather} -> read:weather only
echo "Jane via weather-agent:"
echo $JANE_DELEGATED | cut -d'.' -f2 | base64 -d 2>/dev/null | jq '{scope, act, permissions: .subject_claims.permissions}'

# Jane via customer-agent: scope={read:customers,write:customers} ∩ permissions={read:marketing,write:marketing,read:weather} -> empty (DENIED)
echo "Jane via customer-agent:"
echo $JANE_CUSTOMER_DELEGATED | cut -d'.' -f2 | base64 -d 2>/dev/null | jq '{scope, act, permissions: .subject_claims.permissions}'
```

### Validate JWKS Endpoint

Downstream services can validate delegated tokens using the JWKS endpoint:

```bash
# Get JWKS from Vault (public endpoint, no auth required)
curl -s "http://vault.container.local.jmpd.in:8200/v1/identity-delegation/jwks" | jq .
```

## Delegated Token Structure (RFC 8693 Compliant)

The exchanged token is a JWT containing the following claims:

### Standard JWT Claims

| Claim | Type | Description | Source |
|-------|------|-------------|--------|
| `iss` | String | Token issuer | Plugin configuration (e.g., `https://vault.local`) |
| `sub` | String | Subject - the end user's identity | Original subject token's `sub` claim |
| `aud` | String/Array | Audience | From `actor_template` if specified |
| `iat` | Number | Issued at timestamp | Current time when token is generated |
| `exp` | Number | Expiration timestamp | `iat` + TTL from role configuration |

### RFC 8693 Delegation Claims

| Claim | Type | Description | Source |
|-------|------|-------------|--------|
| `act` | Object | Actor claim - identifies who is acting on behalf of the user | Role's `actor_template` |
| `act.sub` | String | Actor subject identifier | Template variable `{{identity.entity.name}}` |
| `scope` | String | Space-delimited list of delegated permissions | Role's `context` field |

### Custom Extension Claims

| Claim | Type | Description | Source |
|-------|------|-------------|--------|
| `subject_claims` | Object | Processed claims from the original user token | Role's `subject_template` |
| `subject_claims.permissions` | Array | User's fine-grained permissions from Keycloak | `{{identity.subject.permissions}}` |

### Example Token

```json
{
  "iss": "https://vault.local",
  "sub": "john-uuid",
  "aud": "account",
  "iat": 1699564800,
  "exp": 1699568400,
  "act": {
    "sub": "customer-agent"
  },
  "scope": "read:customers write:customers",
  "subject_claims": {
    "email": "john@example.com",
    "name": "John Doe",
    "permissions": ["read:customers", "write:customers"]
  }
}
```

### Claim Details

- **`sub`**: The end user's identity. Preserved from the original Keycloak token.

- **`act.sub`**: The actor (agent/tool) acting on behalf of the user. Populated from the Vault entity name via the `actor_template`. Downstream services use this to identify which agent made the request.

- **`scope`**: The delegated permissions as a space-delimited string. Built from the role's `context` configuration (e.g., `"read:customers,write:customers"` becomes `"read:customers write:customers"`).

- **`subject_claims.permissions`**: The user's fine-grained permissions from Keycloak. Downstream services intersect this with `scope` to determine effective permissions.

- **`subject_claims`**: A namespace containing processed claims from the original user token. The `subject_template` controls which claims are included.

### Template Variables

The `actor_template` and `subject_template` support these variables:

| Variable | Description |
|----------|-------------|
| `{{identity.entity.name}}` | Vault entity name of the authenticated agent |
| `{{identity.entity.id}}` | Vault entity ID |
| `{{identity.subject.<claim>}}` | Any claim from the original user token (e.g., `{{identity.subject.email}}`) |

## Verifying RFC 8693 Compliance

The exchanged token follows [RFC 8693 (OAuth 2.0 Token Exchange)](https://www.rfc-editor.org/rfc/rfc8693.html) specification:

1. **Standard `act` claim**: Uses the RFC-defined actor claim structure
2. **User-centric `sub`**: The `sub` claim always contains the user identity
3. **Actor identification**: `act.sub` contains the agent/actor identity for audit
4. **Space-delimited scopes**: The `scope` claim uses space-delimited format per OAuth 2.0
5. **Clear delegation chain**: The token structure provides a clear audit trail of who did what on whose behalf

## Cleanup

To stop and remove all containers:

```bash
jumppad down
```

## Troubleshooting

### Services not starting

If services fail to start, check the logs:

```bash
# Check Vault logs
jumppad logs vault

# Check Keycloak logs
jumppad logs keycloak
```

### Plugin not registered

If the plugin fails to register, check if the binary downloaded successfully:

```bash
ls -lh demo/build/vault-plugin-identity-delegation
```

The plugin binary should be present and executable.

If the download failed:
1. Check that the specified version exists in GitHub releases
2. Verify internet connectivity
3. Consider building locally instead (see "Building Locally" section above)

### Keycloak not accessible

Ensure Keycloak has fully started (can take 30-60 seconds):

```bash
curl http://keycloak.container.local.jmpd.in:8080/health/ready
```

## Architecture

```
┌─────────────────┐
│   Keycloak      │  OIDC Provider
│   :8080         │  - Realm: demo
└────────┬────────┘  - Users: John (customers), Jane (marketing)
         │           - Permissions via user attributes
         │ JWKS validation (subject tokens)
         │
         ▼
┌─────────────────┐     ┌─────────────────┐
│   Vault         │     │   Kubernetes    │
│   :8200         │◄────│   Cluster       │
│                 │     │   (K3s)         │
│  Auth Methods:  │     └─────────────────┘
│  - kubernetes   │            │
│  - approle      │            │ Service Account
│                 │            │ Tokens
│  Plugin:        │            │
│  - identity-    │     ┌──────┴──────────┐
│    delegation   │     │ Service Accounts│
│                 │     │ - customer-agent│
│  Roles:         │     │ - weather-agent │
│  - customer-    │     │ - customers-tool│
│    agent        │     └─────────────────┘
│  - weather-     │
│    agent        │
│  - customers-   │
│    tool         │
│  - weather-tool │
└────────┬────────┘
         │ JWKS (delegated tokens)
         ▼
┌─────────────────┐
│  Downstream     │  Validates:
│  Services       │  1. scope ∩ permissions
│  (validate JWT) │  2. act.sub identity
└─────────────────┘
```

## Quick Reference

### Identity Delegation Roles

| Role | Scope | Use Case |
|------|-------|----------|
| `customer-agent` | `read:customers`, `write:customers` | Full customer data access |
| `weather-agent` | `read:weather`, `write:weather` | Full weather data access |

> Tools (`customers-tool`, `weather-tool`) do not have identity-delegation roles. They validate delegated JWTs via the JWKS endpoint.

### Auth Methods & Entities

| Auth Method | Path | Roles | Entity |
|-------------|------|-------|--------|
| kubernetes | `auth/kubernetes` | customer-agent, weather-agent, customers-tool | Same as role |
| kubernetes | `auth/demo-auth-mount` | customer-agent, weather-agent, customers-tool | Same as role |
| approle | `auth/approle` | customer-agent, weather-agent, customers-tool, weather-tool | Same as role |

### Keycloak Test Users

| Email | Password | Permissions | Persona |
|-------|----------|-------------|---------|
| john@example.com | password | `read:customers`, `write:customers` | Customer Service Rep |
| jane@example.com | password | `read:marketing`, `write:marketing`, `read:weather` | Marketing Analyst |

## Next Steps

- Integrate with a resource server that validates the exchanged tokens and enforces `scope ∩ permissions`
- Explore delegation chains (multi-hop identity delegation)
- Add more personas and permission sets for different teams

## References

- [RFC 8693: OAuth 2.0 Token Exchange](https://www.rfc-editor.org/rfc/rfc8693.html)
- [Plugin Documentation](../CLAUDE.md)
- [Keycloak Documentation](https://www.keycloak.org/documentation)
- [Vault Plugin Documentation](https://developer.hashicorp.com/vault/docs/plugins)
