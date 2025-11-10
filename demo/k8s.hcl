# Kubernetes cluster for testing Vault operator integration
# This cluster uses the Vault operator helm chart to connect to the standalone
# Vault container running at 10.10.0.30:8200

resource "k8s_cluster" "demo" {
  network {
    id = resource.network.demo.meta.id
  }

  depends_on = ["resource.container.vault"]
}

# Helm chart for Vault operator
# Configures the Vault agent injector to connect to the external Vault server
resource "helm" "vault_operator" {
  cluster = resource.k8s_cluster.demo

  repository {
    name = "hashicorp"
    url  = "https://helm.releases.hashicorp.com"
  }

  chart   = "hashicorp/vault-secrets-operator"
  version = "1.0.1"

  health_check {
    timeout = "120s"
    pods    = ["app.kubernetes.io/name=vault-secretss-operator"]
  }
}

# Output Kubernetes configuration
output "KUBECONFIG" {
  value = resource.k8s_cluster.demo.kube_config.path
}

output "K8S_VAULT_ADDR" {
  value = "Vault accessible from K8s at: http://10.10.0.30:8200"
}
