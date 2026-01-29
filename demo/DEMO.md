# Demo Quick Reference

## Service URLs and Credentials

### Keycloak (OIDC Provider)

| Item | Value |
|------|-------|
| Admin Console | http://keycloak.container.local.jmpd.in:8080/admin |
| Username | `admin` |
| Password | `admin` |
| Demo Realm | `demo` |
| Token Endpoint | http://keycloak.container.local.jmpd.in:8080/realms/demo/protocol/openid-connect/token |
| JWKS Endpoint | http://keycloak.container.local.jmpd.in:8080/realms/demo/protocol/openid-connect/certs |

**Demo Users:**
- `john@example.com` / `password`
- `jane@example.com` / `password`

**Demo Clients:**
- `demo-app` - Public client for end-user authentication
- `ai-agent` - Confidential client

### Vault (Identity Delegation)

| Item | Value |
|------|-------|
| UI | http://vault.container.local.jmpd.in:8200/ui |
| API | http://vault.container.local.jmpd.in:8200 |
| Root Token | `root` |
| Plugin Path | `identity-delegation` |

**Environment Variables:**
```bash
export VAULT_ADDR="http://vault.container.local.jmpd.in:8200"
export VAULT_TOKEN="root"
```

**Configured Roles:**
- `demo-agent` - Scopes: `read:documents`, `write:documents`
- `user-agent` - Scopes: `read:profile`, `write:profile`

**Demo Agent (userpass):**
- Username: `demo-agent`
- Password: `demo-agent`
- Entity Name: `demo-agent`

---

## Manual Plugin Configuration

If the plugin isn't automatically configured, run these commands:

```bash
export VAULT_ADDR="http://vault.container.local.jmpd.in:8200"
export VAULT_TOKEN="root"

# Register the plugin
PLUGIN_SHA256=$(sha256sum bin/vault-plugin-identity-delegation | cut -d' ' -f1)
vault plugin register \
  -sha256="${PLUGIN_SHA256}" \
  -command="vault-plugin-identity-delegation" \
  secret \
  vault-plugin-identity-delegation

# Enable the plugin
vault secrets enable \
  -path=identity-delegation \
  -plugin-name=vault-plugin-identity-delegation \
  plugin

# Configure with Keycloak JWKS endpoint
# Note: Use Jumppad FQDN which resolves from both host and containers
vault write identity-delegation/config \
  subject_jwks_uri="http://keycloak.container.local.jmpd.in:8080/realms/demo/protocol/openid-connect/certs" \
  issuer="https://vault.local" \
  default_ttl="1h"

# Create a signing key
vault write identity-delegation/key/demo-key \
  algorithm="RS256"

# Create demo-agent role
vault write identity-delegation/role/demo-agent \
  key="demo-key" \
  bound_issuer="http://keycloak.container.local.jmpd.in:8080/realms/demo" \
  bound_audiences="account" \
  context="read:documents,write:documents" \
  ttl="1h" \
  actor_template='{"act": {"sub": "{{identity.entity.name}}"}}' \
  subject_template='{"email": "{{identity.subject.email}}", "name": "{{identity.subject.name}}"}'

# Create policy for identity delegation
vault policy write identity-delegation - <<EOF
path "identity-delegation/token/*" {
  capabilities = ["create", "update"]
}
path "identity-delegation/role/*" {
  capabilities = ["read", "list"]
}
EOF

# Enable userpass auth and create demo agent
vault auth enable userpass
vault write auth/userpass/users/demo-agent password="demo-agent" policies="default,identity-delegation"

# Create entity for the demo agent
ENTITY_ID=$(vault write -format=json identity/entity name="demo-agent" metadata=type="ai-agent" | jq -r '.data.id')

# Link userpass user to entity
USERPASS_ACCESSOR=$(vault auth list -format=json | jq -r '.["userpass/"].accessor')
vault write identity/entity-alias name="demo-agent" canonical_id="${ENTITY_ID}" mount_accessor="${USERPASS_ACCESSOR}"
```

Verify configuration:

```bash
vault read identity-delegation/config
vault list identity-delegation/role
vault read identity-delegation/role/demo-agent
```

---

## Testing

### Test Keycloak Login

Get a token for a demo user using the password grant:

```bash
curl -s -X POST "http://keycloak.container.local.jmpd.in:8080/realms/demo/protocol/openid-connect/token" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "username=john@example.com" \
  -d "password=password" \
  -d "grant_type=password" \
  -d "client_id=demo-app" | jq .
```

Store the token in a variable:

```bash
USER_TOKEN=$(curl -s -X POST "http://keycloak.container.local.jmpd.in:8080/realms/demo/protocol/openid-connect/token" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "username=john@example.com" \
  -d "password=password" \
  -d "grant_type=password" \
  -d "client_id=demo-app" | jq -r '.access_token')
```

Decode and view the token claims:

```bash
echo $USER_TOKEN | cut -d'.' -f2 | base64 -d 2>/dev/null | jq .
```

### Test Identity Delegation via Vault

First, login as the demo-agent user (the root token has no entity):

```bash
AGENT_TOKEN=$(curl -s -X POST "http://vault.container.local.jmpd.in:8200/v1/auth/userpass/login/demo-agent" \
  -H "Content-Type: application/json" \
  -d '{"password": "demo-agent"}' | jq -r '.auth.client_token')

echo $AGENT_TOKEN
```

Exchange the user token for a delegated token:

```bash
EXCHANGED_TOKEN=$(curl -s -X POST "http://vault.container.local.jmpd.in:8200/v1/identity-delegation/token/demo-agent" \
  -H "X-Vault-Token: $AGENT_TOKEN" \
  -H "Content-Type: application/json" \
  -d "{\"subject_token\": \"$USER_TOKEN\"}" | jq -r '.data.token')

echo $EXCHANGED_TOKEN
```

Decode the exchanged token to see the delegation structure:

```bash
echo $EXCHANGED_TOKEN | cut -d'.' -f2 | base64 -d 2>/dev/null | jq .
```

---

## Kubernetes Agent Authentication

This section covers setting up Vault Kubernetes auth for AI agents running in the K8s cluster.

### Apply K8s Manifests

First, apply the required manifests:

```bash
# Create demo namespace
kubectl create namespace demo

# Apply token reviewer (for Vault to validate K8s service account tokens)
kubectl apply -f demo/k8s/vault-token-reviewer.yaml

# Apply agent service accounts
kubectl apply -f demo/k8s/agent-service-accounts.yaml

# Apply VSO auth (if using Vault Secrets Operator)
kubectl apply -f demo/k8s/vso-auth.yaml
```

### Configure Vault Kubernetes Auth

Run the setup script to configure Vault:

```bash
./demo/scripts/setup-vault-k8s.sh
```

Or configure manually:

```bash
export VAULT_ADDR="http://vault.container.local.jmpd.in:8200"
export VAULT_TOKEN="root"

# Get token reviewer JWT
TOKEN_REVIEWER_JWT=$(kubectl get secret vault-token-reviewer-token -n default -o jsonpath='{.data.token}' | base64 -d)

# Get K8s CA cert
K8S_CA_CERT=$(kubectl get secret vault-token-reviewer-token -n default -o jsonpath='{.data.ca\.crt}' | base64 -d)

# Get K8s host (from inside cluster or from kubeconfig)
K8S_HOST=$(kubectl config view --minify -o jsonpath='{.clusters[0].cluster.server}')

# Enable kubernetes auth
vault auth enable kubernetes

# Configure kubernetes auth
vault write auth/kubernetes/config \
  token_reviewer_jwt="${TOKEN_REVIEWER_JWT}" \
  kubernetes_host="${K8S_HOST}" \
  kubernetes_ca_cert="${K8S_CA_CERT}"

# Create role for weather-agent
vault write auth/kubernetes/role/weather-agent \
  bound_service_account_names=weather-agent \
  bound_service_account_namespaces=demo \
  policies=identity-delegation \
  ttl=1h

# Create role for customer-agent
vault write auth/kubernetes/role/customer-agent \
  bound_service_account_names=customer-agent \
  bound_service_account_namespaces=demo \
  policies=identity-delegation \
  ttl=1h

# Create entity for weather-agent
WEATHER_ENTITY_ID=$(vault write -format=json identity/entity \
  name="weather-agent" \
  metadata=type="ai-agent" \
  metadata=service="weather" | jq -r '.data.id')

# Create entity for customer-agent
CUSTOMER_ENTITY_ID=$(vault write -format=json identity/entity \
  name="customer-agent" \
  metadata=type="ai-agent" \
  metadata=service="customer" | jq -r '.data.id')

# Get kubernetes auth accessor
K8S_ACCESSOR=$(vault auth list -format=json | jq -r '.["kubernetes/"].accessor')

# Create entity aliases
vault write identity/entity-alias \
  name="weather-agent" \
  canonical_id="${WEATHER_ENTITY_ID}" \
  mount_accessor="${K8S_ACCESSOR}"

vault write identity/entity-alias \
  name="customer-agent" \
  canonical_id="${CUSTOMER_ENTITY_ID}" \
  mount_accessor="${K8S_ACCESSOR}"
```

### Test Kubernetes Auth Manually

Test from the host using a service account token:

```bash
# Create a test pod to get a service account token
kubectl run test-agent --image=curlimages/curl:latest \
  --serviceaccount=weather-agent \
  -n demo \
  --rm -it --restart=Never -- sh -c '
    SA_TOKEN=$(cat /var/run/secrets/kubernetes.io/serviceaccount/token)
    echo "Service Account Token:"
    echo $SA_TOKEN
  '
```

Or extract token directly and test from host:

```bash
# Create a temporary pod to get the projected token
kubectl run token-helper --image=bitnami/kubectl:latest \
  --serviceaccount=weather-agent \
  -n demo \
  --rm -it --restart=Never -- \
  cat /var/run/secrets/kubernetes.io/serviceaccount/token

# Save token and login to Vault
SA_TOKEN="<paste token here>"

# Login to Vault using kubernetes auth
AGENT_TOKEN=$(curl -s -X POST "http://vault.container.local.jmpd.in:8200/v1/auth/kubernetes/login" \
  -H "Content-Type: application/json" \
  -d "{\"role\": \"weather-agent\", \"jwt\": \"$SA_TOKEN\"}" | jq -r '.auth.client_token')

echo "Agent Vault Token: $AGENT_TOKEN"

# Verify the entity is set correctly
curl -s -H "X-Vault-Token: $AGENT_TOKEN" \
  "http://vault.container.local.jmpd.in:8200/v1/auth/token/lookup-self" | jq '.data.entity_id, .data.display_name'
```

### Full Flow: K8s Agent + User Token Exchange

Combine Kubernetes agent auth with user token exchange:

```bash
# 1. Get user token from Keycloak (simulating user login)
USER_TOKEN=$(curl -s -X POST "http://keycloak.container.local.jmpd.in:8080/realms/demo/protocol/openid-connect/token" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "username=john@example.com" \
  -d "password=password" \
  -d "grant_type=password" \
  -d "client_id=demo-app" | jq -r '.access_token')

# 2. Agent logs in to Vault using K8s service account
# (use token from previous step or run from within a pod)
AGENT_TOKEN="<vault token from k8s login>"

# 3. Exchange user token for delegated token
EXCHANGED_TOKEN=$(curl -s -X POST "http://vault.container.local.jmpd.in:8200/v1/identity-delegation/token/demo-agent" \
  -H "X-Vault-Token: $AGENT_TOKEN" \
  -H "Content-Type: application/json" \
  -d "{\"subject_token\": \"$USER_TOKEN\"}" | jq -r '.data.token')

# 4. View the delegated token - should show act.sub = "weather-agent"
echo $EXCHANGED_TOKEN | cut -d'.' -f2 | base64 -d 2>/dev/null | jq .
```

The resulting token should contain:
- User identity from the Keycloak token (email, name)
- `act.sub` claim with the agent's entity name (e.g., "weather-agent")
- Proper issuer and audience for downstream service validation

---

## AppRole Authentication

This section covers setting up Vault AppRole auth for applications authenticating outside of Kubernetes.

### Configure AppRole Auth

Run the setup script to configure AppRole authentication:

```bash
./demo/scripts/setup-approle.sh
```

This will:
- Enable the AppRole auth method
- Create roles for `customer-agent` and `customers-tool`
- Generate role IDs and secret IDs
- Create Vault entities and entity aliases
- Output the credentials for testing

### Manual AppRole Configuration

```bash
export VAULT_ADDR="http://vault.container.local.jmpd.in:8200"
export VAULT_TOKEN="root"

# Enable AppRole auth
vault auth enable approle

# Create AppRole role for customer-agent
vault write auth/approle/role/customer-agent \
  token_policies="customer-agent" \
  token_ttl="1h" \
  token_max_ttl="4h" \
  secret_id_ttl="24h"

# Get role ID
vault read auth/approle/role/customer-agent/role-id

# Generate secret ID
vault write -f auth/approle/role/customers-tool/secret-id
```

### Test AppRole Login

```bash
# Get credentials (from setup script output)
ROLE_ID="<role-id>"
SECRET_ID="<secret-id>"

# Login to Vault using AppRole
VAULT_TOKEN=$(curl -s -X POST "http://vault.container.local.jmpd.in:8200/v1/auth/approle/login" \
  -H "Content-Type: application/json" \
  -d "{\"role_id\": \"$ROLE_ID\", \"secret_id\": \"$SECRET_ID\"}" | jq -r '.auth.client_token')

echo "Vault Token: $VAULT_TOKEN"

# Verify entity is set correctly
curl -s -H "X-Vault-Token: $VAULT_TOKEN" \
  "http://vault.container.local.jmpd.in:8200/v1/auth/token/lookup-self" | jq '.data.entity_id, .data.display_name'
```

### AppRole + User Token Exchange

```bash
# 1. Get user token from Keycloak
USER_TOKEN=$(curl -s -X POST "http://keycloak.container.local.jmpd.in:8080/realms/demo/protocol/openid-connect/token" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "username=john@example.com&password=password&grant_type=password&client_id=demo-app" | jq -r '.access_token')

# 2. Login to Vault using AppRole
AGENT_TOKEN=$(curl -s -X POST "http://vault.container.local.jmpd.in:8200/v1/auth/approle/login" \
  -H "Content-Type: application/json" \
  -d "{\"role_id\": \"$ROLE_ID\", \"secret_id\": \"$SECRET_ID\"}" | jq -r '.auth.client_token')

# 3. Exchange user token for delegated token
EXCHANGED_TOKEN=$(curl -s -X POST "http://vault.container.local.jmpd.in:8200/v1/identity-delegation/token/customer-agent" \
  -H "X-Vault-Token: $AGENT_TOKEN" \
  -H "Content-Type: application/json" \
  -d "{\"subject_token\": \"$USER_TOKEN\"}" | jq -r '.data.token')

# 4. View the delegated token
echo $EXCHANGED_TOKEN | cut -d'.' -f2 | base64 -d 2>/dev/null | jq .
```
