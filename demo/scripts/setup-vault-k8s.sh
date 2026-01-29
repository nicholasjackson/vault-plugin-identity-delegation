#!/bin/sh
set -e

echo "================================"
echo "Configuring Vault Kubernetes Auth"
echo "================================"

# Wait for Vault to be ready
echo "Waiting for Vault to be ready..."
until vault status > /dev/null 2>&1; do
  sleep 1
done
echo "Vault is ready!"

# Get the Kubernetes host from the cluster
K8S_HOST="${K8S_HOST:-https://kubernetes.default.svc}"

# Get the token reviewer JWT from the service account secret
echo "Getting token reviewer JWT..."
TOKEN_REVIEWER_JWT=$(kubectl get secret vault-token-reviewer-token -n default -o jsonpath='{.data.token}' | base64 -d)

# Get the Kubernetes CA certificate
echo "Getting Kubernetes CA certificate..."
K8S_CA_CERT=$(kubectl get secret vault-token-reviewer-token -n default -o jsonpath='{.data.ca\.crt}' | base64 -d)

# Enable kubernetes auth method
echo "Enabling kubernetes auth method..."
vault auth enable kubernetes 2>/dev/null || echo "kubernetes auth already enabled"

# Configure kubernetes auth
echo "Configuring kubernetes auth..."
vault write auth/kubernetes/config \
  token_reviewer_jwt="${TOKEN_REVIEWER_JWT}" \
  kubernetes_host="${K8S_HOST}" \
  kubernetes_ca_cert="${K8S_CA_CERT}"

echo "Kubernetes auth configured!"

# Create a role for the demo agent (weather-agent service account)
echo "Creating kubernetes auth role for weather-agent..."
vault write auth/kubernetes/role/weather-agent \
  bound_service_account_names=weather-agent \
  bound_service_account_namespaces=demo \
  policies=identity-delegation \
  ttl=1h

# Create a role for the customer-agent
echo "Creating kubernetes auth role for customer-agent..."
vault write auth/kubernetes/role/customer-agent \
  bound_service_account_names=customer-agent \
  bound_service_account_namespaces=demo \
  policies=identity-delegation \
  ttl=1h

# Create a role for the customers-tool
echo "Creating kubernetes auth role for customers-tool..."
vault write auth/kubernetes/role/customers-tool \
  bound_service_account_names=customers-tool \
  bound_service_account_namespaces=demo \
  policies=identity-delegation \
  ttl=1h

# Create entities for the agents
echo "Creating Vault entities for agents..."

# Weather agent entity
WEATHER_ENTITY_ID=$(vault write -format=json identity/entity \
  name="weather-agent" \
  metadata=type="ai-agent" \
  metadata=service="weather" | jq -r '.data.id')
echo "Weather agent entity created: ${WEATHER_ENTITY_ID}"

# Customer agent entity
CUSTOMER_ENTITY_ID=$(vault write -format=json identity/entity \
  name="customer-agent" \
  metadata=type="ai-agent" \
  metadata=service="customer" | jq -r '.data.id')
echo "Customer agent entity created: ${CUSTOMER_ENTITY_ID}"

# Customers tool entity
CUSTOMERS_TOOL_ENTITY_ID=$(vault write -format=json identity/entity \
  name="customers-tool" \
  metadata=type="tool" \
  metadata=service="customers" | jq -r '.data.id')
echo "Customers tool entity created: ${CUSTOMERS_TOOL_ENTITY_ID}"

# Get the kubernetes auth accessor
K8S_ACCESSOR=$(vault auth list -format=json | jq -r '.["kubernetes/"].accessor')

# Create entity aliases linking k8s auth to entities
echo "Creating entity aliases..."
vault write identity/entity-alias \
  name="weather-agent" \
  canonical_id="${WEATHER_ENTITY_ID}" \
  mount_accessor="${K8S_ACCESSOR}"

vault write identity/entity-alias \
  name="customer-agent" \
  canonical_id="${CUSTOMER_ENTITY_ID}" \
  mount_accessor="${K8S_ACCESSOR}"

vault write identity/entity-alias \
  name="customers-tool" \
  canonical_id="${CUSTOMERS_TOOL_ENTITY_ID}" \
  mount_accessor="${K8S_ACCESSOR}"

echo ""
echo "================================"
echo "Vault Kubernetes Auth Complete!"
echo "================================"
echo ""
echo "Roles created:"
echo "  - weather-agent (bound to weather-agent SA in demo namespace)"
echo "  - customer-agent (bound to customer-agent SA in demo namespace)"
echo "  - customers-tool (bound to customers-tool SA in demo namespace)"
echo ""
echo "To test manually from a pod:"
echo "  # Get service account token"
echo "  SA_TOKEN=\$(cat /var/run/secrets/kubernetes.io/serviceaccount/token)"
echo ""
echo "  # Login to Vault"
echo "  vault write auth/kubernetes/login role=weather-agent jwt=\$SA_TOKEN"
echo ""
