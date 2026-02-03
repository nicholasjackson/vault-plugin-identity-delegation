# Identity Delegation for Agentic AI - Live Demo Runbook

## Pre-Demo Setup

Start the infrastructure **without** the identity delegation plugin:

```bash
cd demo/
jumppad up --var="run_identity_plugin=false"
```

This starts Vault, Keycloak, Kubernetes, and configures:
- Keycloak realm, users, client, and permissions protocol mapper
- Vault AppRole auth with entities for customer-agent and weather-agent
- Vault Kubernetes auth (if K8s cluster is available)

Verify everything is running:
- Vault UI: http://vault.container.local.jmpd.in:8200/ui (token: `root`)
- Keycloak Admin: http://keycloak.container.local.jmpd.in:8080/admin (admin/admin)

Set environment variables for the demo terminal:

```bash
export VAULT_ADDR="http://vault.container.local.jmpd.in:8200"
export VAULT_TOKEN="root"
```

---

## Part 1: Slides (explain why + architecture)

Cover:
- The problem: AI agents acting on behalf of users need constrained, auditable authorization
- Current approach: shared API keys, over-privileged tokens, no delegation chain
- Solution: OAuth 2.0 Token Exchange (RFC 8693) via Vault plugin
- Architecture diagram: User -> Keycloak -> Agent -> Vault Plugin -> Delegated JWT -> Tool
- Dual authorization: `effective_permissions = agent_scope ∩ user_permissions`

---

## Part 2: Live Plugin Setup

### Step 1 - Register the Plugin

Show that Vault is running but the plugin is not yet configured:

```bash
vault secrets list
```

Register and enable the identity delegation plugin:

```bash
PLUGIN_SHA256=$(sha256sum bin/vault-plugin-identity-delegation | cut -d' ' -f1)

vault plugin register \
  -sha256="${PLUGIN_SHA256}" \
  -command="vault-plugin-identity-delegation" \
  secret \
  vault-plugin-identity-delegation

vault secrets enable \
  -path=identity-delegation \
  -plugin-name=vault-plugin-identity-delegation \
  plugin
```

Verify:

```bash
vault secrets list
```

### Step 2 - Configure the Plugin

Point the plugin at Keycloak's JWKS endpoint so it can validate incoming user tokens:

```bash
vault write identity-delegation/config \
  subject_jwks_uri="http://keycloak.container.local.jmpd.in:8080/realms/demo/protocol/openid-connect/certs" \
  issuer="https://vault.local" \
  default_ttl="1h"
```

Read back the config:

```bash
vault read identity-delegation/config
```

**Talking point:** The plugin will fetch the JWKS keys from Keycloak to validate user JWTs. The issuer is what the delegated tokens will be issued as.

### Step 3 - Create a Signing Key

```bash
vault write identity-delegation/key/demo-key \
  algorithm="RS256"
```

**Talking point:** The plugin generates its own RSA key pair for signing delegated tokens. Downstream services validate these tokens against the plugin's JWKS endpoint.

### Step 4 - Create Roles

Create the customer-agent role - defines what scope and claims the delegated token gets:

```bash
vault write identity-delegation/role/customer-agent \
  key="demo-key" \
  bound_issuer="http://keycloak.container.local.jmpd.in:8080/realms/demo" \
  bound_audiences="account" \
  context="read:customers,write:customers" \
  ttl="1h" \
  actor_template='{"act": {"sub": "{{identity.entity.name}}"}}' \
  subject_template='{"email": "{{identity.subject.email}}",
  "name": "{{identity.subject.name}}", 
  "permissions": {{identity.subject.permissions}}}'
```

Create the weather-agent role:

```bash
vault write identity-delegation/role/weather-agent \
  key="demo-key" \
  bound_issuer="http://keycloak.container.local.jmpd.in:8080/realms/demo" \
  bound_audiences="account" \
  context="read:weather,write:weather" \
  ttl="1h" \
  actor_template='{"act": {"sub": "{{identity.entity.name}}"}}' \
  subject_template='{"email": "{{identity.subject.email}}",
  "name": "{{identity.subject.name}}", 
  "permissions": {{identity.subject.permissions}}}'
```

**Talking points:**
- `context` defines the agent's scope - what operations it can perform
- `bound_issuer` + `bound_audiences` validate the incoming user token
- `actor_template` adds the agent identity (`act.sub`) from the Vault entity
- `subject_template` carries the user's email, name, and permissions into the delegated token
- `{{identity.subject.permissions}}` renders the user's Keycloak permissions array as JSON

Verify the roles:

```bash
vault list identity-delegation/role
vault read identity-delegation/role/customer-agent
```

### Step 5 - Create Policy

```bash
vault policy write identity-delegation - <<EOF
path "identity-delegation/token/*" {
  capabilities = ["create", "update"]
}
EOF
```

---

## Part 3: Test the Token Exchange

### Get a User Token from Keycloak

```bash
USER_TOKEN=$(curl -s -X POST \
  "http://keycloak.container.local.jmpd.in:8080/realms/demo/protocol/openid-connect/token" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "username=john@example.com" \
  -d "password=password" \
  -d "grant_type=password" \
  -d "client_id=demo-app" | jq -r '.access_token')
```

Decode and show the user token - note the `permissions` claim:

```bash
echo $USER_TOKEN | cut -d'.' -f2 | base64 -d 2>/dev/null | jq .
```

**Talking point:** John has `read:customers` and `write:customers` permissions. These come from the Keycloak user attribute and protocol mapper.

### Login as the Agent (AppRole)

```bash
# Get the customer-agent role ID and secret ID
ROLE_ID=$(vault read -format=json auth/approle/role/customer-agent/role-id | jq -r '.data.role_id')
SECRET_ID=$(vault write -format=json -f auth/approle/role/customer-agent/secret-id | jq -r '.data.secret_id')

# Login
AGENT_TOKEN=$(curl -s -X POST \
  "http://vault.container.local.jmpd.in:8200/v1/auth/approle/login" \
  -H "Content-Type: application/json" \
  -d "{\"role_id\": \"$ROLE_ID\", \"secret_id\": \"$SECRET_ID\"}" | jq -r '.auth.client_token')

echo "Agent token: $AGENT_TOKEN"
```

**Talking point:** In production, the agent gets its AppRole credentials from secure config or K8s secrets. The entity name "customer-agent" will appear in the delegated token's `act.sub`.

### Exchange the Token

```bash
DELEGATED=$(curl -s -X POST \
  "http://vault.container.local.jmpd.in:8200/v1/identity-delegation/token/customer-agent" \
  -H "X-Vault-Token: $AGENT_TOKEN" \
  -H "Content-Type: application/json" \
  -d "{\"subject_token\": \"$USER_TOKEN\"}" | jq -r '.data.token')
```

Decode the delegated token:

```bash
echo $DELEGATED | cut -d'.' -f2 | base64 -d 2>/dev/null | jq .
```

**Expected output:**
```json
{
  "iss": "https://vault.local",
  "sub": "<user-uuid>",
  "act": { "sub": "customer-agent" },
  "scope": "read:customers,write:customers",
  "subject_claims": {
    "email": "john@example.com",
    "name": "John Doe",
    "permissions": ["read:customers", "write:customers"]
  },
  "exp": ...,
  "iat": ...
}
```

**Talking points:**
- `act.sub` = "customer-agent" - identifies which agent is acting
- `scope` = the agent's allowed operations (from the role)
- `subject_claims.permissions` = the user's actual permissions
- Downstream tools check: `scope ∩ permissions` to determine effective access

### Show Jane Gets Different Permissions

```bash
JANE_TOKEN=$(curl -s -X POST \
  "http://keycloak.container.local.jmpd.in:8080/realms/demo/protocol/openid-connect/token" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "username=jane@example.com" \
  -d "password=password" \
  -d "grant_type=password" \
  -d "client_id=demo-app" | jq -r '.access_token')

JANE_DELEGATED=$(curl -s -X POST \
  "http://vault.container.local.jmpd.in:8200/v1/identity-delegation/token/customer-agent" \
  -H "X-Vault-Token: $AGENT_TOKEN" \
  -H "Content-Type: application/json" \
  -d "{\"subject_token\": \"$JANE_TOKEN\"}" | jq -r '.data.token')

echo $JANE_DELEGATED | cut -d'.' -f2 | base64 -d 2>/dev/null | jq .
```

**Talking point:** Jane has `read:marketing` and `write:marketing` permissions. The token exchange succeeds (she's a valid user), but the delegated token carries her marketing permissions. When the customer tool checks `scope ∩ permissions` = `{read:customers,write:customers} ∩ {read:marketing,write:marketing}` = empty set, so access is denied. The authorization decision happens at the tool, not at Vault.

### Show the JWKS Endpoint

```bash
curl -s "http://vault.container.local.jmpd.in:8200/v1/identity-delegation/jwks" | jq .
```

**Talking point:** Tools validate delegated tokens against this JWKS endpoint. No shared secrets needed - standard JWT verification.

---

## Part 4: Live Chat UI Demo

### Set the AppRole credentials for the agents

Fetch the role-ids and secret-ids so the UI agents can authenticate with Vault:

```bash
# Customer agent
export VAULT_ROLE_ID=$(vault read -format=json auth/approle/role/customer-agent/role-id | jq -r '.data.role_id')
export VAULT_SECRET_ID=$(vault write -format=json -f auth/approle/role/customer-agent/secret-id | jq -r '.data.secret_id')
export VAULT_IDENTITY_ROLE=customer-agent

echo "Customer Agent Role ID: $CUSTOMER_AGENT_ROLE_ID"
echo "Customer Agent Secret ID: $CUSTOMER_AGENT_SECRET_ID"

# Weather agent
export VAULT_ROLE_ID=$(vault read -format=json auth/approle/role/weather-agent/role-id | jq -r '.data.role_id')
export VAULT_SECRET_ID=$(vault write -format=json -f auth/approle/role/weather-agent/secret-id | jq -r '.data.secret_id')
export VAULT_IDENTITY_ROLE=weather-agent

echo "Weather Agent Role ID: $WEATHER_AGENT_ROLE_ID"
echo "Weather Agent Secret ID: $WEATHER_AGENT_SECRET_ID"
```

Open the chat UI and demonstrate the full flow with real agents:

1. **Login as John** (`john@example.com` / `password`)
2. **Ask the customer agent** a question about customers - should work (John has customer permissions)
3. **Ask the weather agent** a weather question - should work (John has... check this)
4. **Login as Jane** (`jane@example.com` / `password`)
5. **Ask the customer agent** - should be denied at the tool level (Jane lacks customer permissions)

**Talking point:** The same agent code runs for both users. The only difference is the user's permissions flowing through the delegated token. The tool makes the access decision based on the intersection of agent scope and user permissions.

---

## Quick Reference

### Service URLs

| Service | URL |
|---------|-----|
| Vault UI | http://vault.container.local.jmpd.in:8200/ui |
| Vault API | http://vault.container.local.jmpd.in:8200 |
| Keycloak Admin | http://keycloak.container.local.jmpd.in:8080/admin |
| Keycloak Token | http://keycloak.container.local.jmpd.in:8080/realms/demo/protocol/openid-connect/token |
| Vault JWKS | http://vault.container.local.jmpd.in:8200/v1/identity-delegation/jwks |

### Credentials

| Item | Value |
|------|-------|
| Vault Root Token | `root` |
| Keycloak Admin | `admin` / `admin` |
| John (customer rep) | `john@example.com` / `password` |
| Jane (marketing) | `jane@example.com` / `password` |

### Demo Users and Permissions

| User | Permissions | Customer Agent | Weather Agent |
|------|------------|----------------|---------------|
| John | `read:customers`, `write:customers` | Allowed | Denied (no weather perms) |
| Jane | `read:marketing`, `write:marketing` | Denied (no customer perms) | Denied (no weather perms) |

### Identity Delegation Roles

| Role | Scope | Purpose |
|------|-------|---------|
| `customer-agent` | `read:customers,write:customers` | Customer service AI agent |
| `weather-agent` | `read:weather,write:weather` | Weather data AI agent |

---

## Troubleshooting

### JWKS kid mismatch error
If you get `"key not found in JWKS"` when exchanging tokens, Keycloak may have restarted and regenerated its signing keys. Get a fresh user token from Keycloak.

### Plugin not registered
Run `vault secrets list` to check. If missing, re-run the registration steps from Part 2.

### Agent token has no entity
The root token has no entity. Always use AppRole (or K8s auth) to get an agent token with a proper entity.

### Token exchange returns empty permissions
Check the Keycloak user has the `permissions` attribute set and the protocol mapper is configured on the `demo-app` client scope.
