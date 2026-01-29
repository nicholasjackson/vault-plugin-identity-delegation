#!/bin/sh
set -e

echo "================================"
echo "Configuring Vault Kubernetes Auth for VSO"
echo "================================"

# Wait for Vault to be ready
echo "Waiting for Vault to be ready..."
until vault status > /dev/null 2>&1; do
  sleep 1
done
echo "Vault is ready!"

# Check if auth method is already enabled
echo "Checking if Kubernetes auth is already configured at demo-auth-mount..."
if vault auth list | grep -q "^demo-auth-mount/"; then
  echo "Auth method already enabled at demo-auth-mount/. Skipping configuration."
  exit 0
fi
echo "Auth method not found, proceeding with configuration..."

# Enable Kubernetes auth method
echo "Enabling Kubernetes auth method at demo-auth-mount..."
vault auth enable -path=demo-auth-mount kubernetes

echo "Kubernetes auth enabled!"

# Create service account for Vault to use for TokenReview
echo "Creating Vault service account with TokenReview permissions..."

kubectl apply -f - <<EOF
---
apiVersion: v1
kind: ServiceAccount
metadata:
  name: vault-auth
  namespace: default
---
apiVersion: v1
kind: Secret
metadata:
  name: vault-auth-token
  namespace: default
  annotations:
    kubernetes.io/service-account.name: vault-auth
type: kubernetes.io/service-account-token
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: vault-auth-delegator
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: ClusterRole
  name: system:auth-delegator
subjects:
- kind: ServiceAccount
  name: vault-auth
  namespace: default
EOF

echo "Waiting for token to be created..."
sleep 2

# Get the Kubernetes configuration from the cluster
echo "Retrieving Kubernetes configuration..."

# Get the Kubernetes API host from the kubeconfig
K8S_HOST=$(kubectl config view --raw -o jsonpath='{.clusters[0].cluster.server}')
echo "Kubernetes API host: ${K8S_HOST}"

# Get the CA cert for API server verification
echo "Getting Kubernetes cluster CA certificate..."
K8S_CA_CERT=$(kubectl config view --raw -o jsonpath='{.clusters[0].cluster.certificate-authority-data}' | base64 -d)

# Get the service account JWT token for Vault to use
echo "Getting Vault service account token..."
TOKEN_REVIEWER_JWT=$(kubectl get secret vault-auth-token -n default -o jsonpath='{.data.token}' | base64 -d)

# Configure Kubernetes auth
# The Kubernetes auth method uses the TokenReview API to validate service account tokens
echo "Configuring Vault Kubernetes auth..."
vault write auth/demo-auth-mount/config \
  kubernetes_host="${K8S_HOST}" \
  kubernetes_ca_cert="${K8S_CA_CERT}" \
  token_reviewer_jwt="${TOKEN_REVIEWER_JWT}"

echo "Kubernetes auth configured!"

# Create a policy for reading the demo secrets
echo "Creating policy for demo secrets..."
vault policy write demo-secrets - <<EOF
# Allow reading KV secrets
path "secret/data/demo/*" {
  capabilities = ["read"]
}

path "secret/metadata/demo/*" {
  capabilities = ["read", "list"]
}
EOF

echo "Policy created: demo-secrets"

# Create a Kubernetes auth role for the demo-static-app service account
echo "Creating Kubernetes auth role: role1..."
vault write auth/demo-auth-mount/role/role1 \
  bound_service_account_names="demo-static-app" \
  bound_service_account_namespaces="app" \
  token_ttl="1h" \
  token_policies="demo-secrets"

echo "Role created: role1"
echo "  - Bound Service Account: demo-static-app"
echo "  - Bound Namespace: app"
echo "  - Policies: demo-secrets"
echo "  - Token TTL: 1h"

# Create policy for identity delegation
echo "Creating policy for identity delegation..."
vault policy write identity-delegation - <<EOF
path "identity-delegation/token/*" {
  capabilities = ["create", "update"]
}
path "identity-delegation/role/*" {
  capabilities = ["read", "list"]
}
EOF

echo "Policy created: identity-delegation"

# Create policy for customer-agent (can request delegated tokens and validate them)
echo "Creating policy for customer-agent..."
vault policy write customer-agent - <<EOF
# Allow access to token exchange endpoint
path "identity-delegation/token/*" {
  capabilities = ["create", "update"]
}

# Allow reading roles
path "identity-delegation/role/*" {
  capabilities = ["read", "list"]
}

# Allow reading JWKS for token validation
path "identity-delegation/jwks" {
  capabilities = ["read"]
}

# Allow reading own identity
path "auth/token/lookup-self" {
  capabilities = ["read"]
}
EOF

echo "Policy created: customer-agent"

# Create customer-agent service account and secret in Kubernetes
echo "Creating customer-agent service account..."
kubectl apply -f - <<EOF
---
apiVersion: v1
kind: ServiceAccount
metadata:
  name: customer-agent
  namespace: demo
---
apiVersion: v1
kind: Secret
metadata:
  name: customer-agent-token
  namespace: demo
  annotations:
    kubernetes.io/service-account.name: customer-agent
type: kubernetes.io/service-account-token
EOF

echo "Waiting for customer-agent token to be created..."
sleep 2

# Create Kubernetes auth role for customer-agent
echo "Creating Kubernetes auth role: customer-agent..."
vault write auth/demo-auth-mount/role/customer-agent \
  bound_service_account_names="customer-agent" \
  bound_service_account_namespaces="demo" \
  token_ttl="1h" \
  token_policies="customer-agent"

echo "Role created: customer-agent"
echo "  - Bound Service Account: customer-agent"
echo "  - Bound Namespace: demo"
echo "  - Policies: customer-agent"
echo "  - Token TTL: 1h"

# Create Vault entity for customer-agent
echo "Creating Vault entity for customer-agent..."
CUSTOMER_AGENT_ENTITY_ID=$(vault write -format=json identity/entity \
  name="customer-agent" \
  metadata=type="ai-agent" \
  metadata=service="customer" | jq -r '.data.id')

echo "Customer agent entity created: ${CUSTOMER_AGENT_ENTITY_ID}"

# Get the auth accessor for demo-auth-mount
K8S_ACCESSOR=$(vault auth list -format=json | jq -r '.["demo-auth-mount/"].accessor')

# Create entity alias linking k8s auth to entity
echo "Creating entity alias for customer-agent..."
vault write identity/entity-alias \
  name="customer-agent" \
  canonical_id="${CUSTOMER_AGENT_ENTITY_ID}" \
  mount_accessor="${K8S_ACCESSOR}"

echo "Entity alias created for customer-agent"

# Create policy for customers-tool (can request delegated tokens and validate them)
echo "Creating policy for customers-tool..."
vault policy write customers-tool - <<EOF
# Allow access to token exchange endpoint
path "identity-delegation/token/*" {
  capabilities = ["create", "update"]
}

# Allow reading roles
path "identity-delegation/role/*" {
  capabilities = ["read", "list"]
}

# Allow reading JWKS for token validation
path "identity-delegation/jwks" {
  capabilities = ["read"]
}

# Allow reading own identity
path "auth/token/lookup-self" {
  capabilities = ["read"]
}
EOF

echo "Policy created: customers-tool"

# Create customers-tool service account and secret in Kubernetes
echo "Creating customers-tool service account..."
kubectl apply -f - <<EOF
---
apiVersion: v1
kind: ServiceAccount
metadata:
  name: customers-tool
  namespace: demo
---
apiVersion: v1
kind: Secret
metadata:
  name: customers-tool-token
  namespace: demo
  annotations:
    kubernetes.io/service-account.name: customers-tool
type: kubernetes.io/service-account-token
EOF

echo "Waiting for customers-tool token to be created..."
sleep 2

# Create Kubernetes auth role for customers-tool
echo "Creating Kubernetes auth role: customers-tool..."
vault write auth/demo-auth-mount/role/customers-tool \
  bound_service_account_names="customers-tool" \
  bound_service_account_namespaces="demo" \
  token_ttl="1h" \
  token_policies="customers-tool"

echo "Role created: customers-tool"
echo "  - Bound Service Account: customers-tool"
echo "  - Bound Namespace: demo"
echo "  - Policies: customers-tool"
echo "  - Token TTL: 1h"

# Create Vault entity for customers-tool
echo "Creating Vault entity for customers-tool..."
CUSTOMERS_TOOL_ENTITY_ID=$(vault write -format=json identity/entity \
  name="customers-tool" \
  metadata=type="tool" \
  metadata=service="customers" | jq -r '.data.id')

echo "Customers tool entity created: ${CUSTOMERS_TOOL_ENTITY_ID}"

# Create entity alias linking k8s auth to entity
echo "Creating entity alias for customers-tool..."
vault write identity/entity-alias \
  name="customers-tool" \
  canonical_id="${CUSTOMERS_TOOL_ENTITY_ID}" \
  mount_accessor="${K8S_ACCESSOR}"

echo "Entity alias created for customers-tool"

# Create a sample KV secret
echo "Creating sample KV secret at secret/demo/config..."
vault kv put secret/demo/config \
  api_key="demo-api-key-12345" \
  database_url="postgresql://demo:password@localhost:5432/demo" \
  feature_flags='{"dark_mode":true,"beta_features":false}'

echo "Sample secret created at: secret/demo/config"

echo ""
echo "================================"
echo "Kubernetes Auth Configuration Complete!"
echo "================================"
echo ""
echo "The Vault Secrets Operator can now authenticate to Vault using:"
echo "  - Auth mount: demo-auth-mount"
echo "  - Auth method: Kubernetes"
echo "  - Role: role1"
echo "  - Service Account: demo-static-app (namespace: app)"
echo "  - Policy: demo-secrets"
echo ""
echo "Customer agent configured (token exchange and validation):"
echo "  - Role: customer-agent"
echo "  - Service Account: customer-agent (namespace: demo)"
echo "  - Policy: customer-agent (token exchange + JWKS validation)"
echo "  - Entity: customer-agent"
echo ""
echo "Customers tool configured (token exchange and validation):"
echo "  - Role: customers-tool"
echo "  - Service Account: customers-tool (namespace: demo)"
echo "  - Policy: customers-tool (token exchange + JWKS validation)"
echo "  - Entity: customers-tool"
echo ""
echo "Sample KV secret created:"
echo "  - Path: secret/demo/config"
echo "  - Keys: api_key, database_url, feature_flags"
echo ""
echo "To test customer-agent authentication:"
echo "  SA_TOKEN=\$(kubectl get secret customer-agent-token -n demo -o jsonpath='{.data.token}' | base64 -d)"
echo "  curl -s -X POST 'http://vault.container.local.jmpd.in:8200/v1/auth/demo-auth-mount/login' \\"
echo "    -H 'Content-Type: application/json' \\"
echo "    -d \"{\\\"role\\\": \\\"customer-agent\\\", \\\"jwt\\\": \\\"\$SA_TOKEN\\\"}\" | jq ."
echo ""
echo "To test customers-tool authentication:"
echo "  SA_TOKEN=\$(kubectl get secret customers-tool-token -n demo -o jsonpath='{.data.token}' | base64 -d)"
echo "  curl -s -X POST 'http://vault.container.local.jmpd.in:8200/v1/auth/demo-auth-mount/login' \\"
echo "    -H 'Content-Type: application/json' \\"
echo "    -d \"{\\\"role\\\": \\\"customers-tool\\\", \\\"jwt\\\": \\\"\$SA_TOKEN\\\"}\" | jq ."
echo ""
echo "To test the VSO configuration:"
echo "  kubectl apply -f demo/vso/auth.yaml"
echo ""
echo "To verify the secret sync:"
echo "  kubectl get vaultstaticsecret -n app"
echo "  kubectl get secret demo-secret -n app -o yaml"
echo ""
