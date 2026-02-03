# Vault Token Exchange Plugin Demo
# This Jumppad configuration sets up a complete demo environment with:
# - Keycloak as OIDC provider
# - HashiCorp Vault with the token exchange plugin
# - Network isolation for secure communication

# Variables for configuration
variable "plugin_version" {
  default     = "v0.0.5"
  description = "Version of the vault-plugin-identity-delegation to download from GitHub releases"
}

variable "plugin_platform" {
  default     = "linux-amd64"
  description = "Platform binary to download (linux-amd64, darwin-amd64, darwin-arm64, etc.)"
}

variable "run_scripts" {
  default = true
}

variable "run_identity_plugin" {
  default = true
}

variable "deploy_agents" {
  default     = true
  description = "Deploy agent, tool, and UI workloads to the Kubernetes cluster"
}

variable "ollama_host" {
  default     = env("OLLAMA_HOST")
  description = "Ollama API host address (defaults to OLLAMA_HOST environment variable)"
}

variable "app_version" {
  default     = "0.1.2"
  description = "Version tag for agent, tool, and UI container images"
}

variable "vault_ip" {
  default     = "10.10.0.30"
  description = "IP address of the Vault container, reachable from K8s pods"
}

variable "openweather_api_key" {
  default     = env("OPENWEATHER_API_KEY")
  description = "OpenWeather API key for the weather tool (defaults to OPENWEATHER_API_KEY environment variable)"
}

# Create an isolated network for the demo
resource "network" "demo" {
  subnet = "10.10.0.0/16"
}

output "PLUGIN_VERSION" {
  value = variable.plugin_version
}

output "PLUGIN_PLATFORM" {
  value = variable.plugin_platform
}

output "KEYCLOAK_URL" {
  value = "http://localhost:8080"
}

output "KEYCLOAK_ADMIN" {
  value = "admin"
}

output "KEYCLOAK_ADMIN_PASSWORD" {
  value = "admin"
}

output "VAULT_ADDR" {
  value = "http://localhost:8200"
}

output "VAULT_TOKEN" {
  value = "root"
}