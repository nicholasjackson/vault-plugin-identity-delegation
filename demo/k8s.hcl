# Kubernetes cluster and Vault Secrets Operator setup

resource "k8s_cluster" "k3s" {
  network {
    id = resource.network.demo.meta.id
  }
}

resource "helm" "vault_secrets_operator" {
  cluster = resource.k8s_cluster.k3s

  repository {
    name = "hashicorp"
    url  = "https://helm.releases.hashicorp.com"
  }

  chart            = "hashicorp/vault-secrets-operator"
  version          = "0.10.0"
  namespace        = "vault-secrets-operator"
  create_namespace = true

  values_string = {
    "defaultVaultConnection.enabled" = "true"
    "defaultVaultConnection.address" = "http://vault.container.local.jmpd.in:8200"
  }

  health_check {
    timeout = "120s"
    pods    = ["app.kubernetes.io/name=vault-secrets-operator"]
  }
}

# Configure Vault Kubernetes auth at demo-auth-mount path
resource "exec" "configure_k8s_auth" {
  disabled   = !variable.run_scripts
  depends_on = ["resource.helm.vault_secrets_operator", "resource.exec.configure_vault"]

  script = file("./scripts/setup-k8s-auth.sh")

  environment = {
    VAULT_ADDR  = "http://localhost:8200"
    VAULT_TOKEN = "root"
    KUBECONFIG  = resource.k8s_cluster.k3s.kube_config.path
  }
}

# Configure Vault Kubernetes auth at kubernetes/ path
resource "exec" "configure_vault_k8s" {
  disabled   = !variable.run_scripts
  depends_on = ["resource.helm.vault_secrets_operator", "resource.exec.configure_vault"]

  script = file("./scripts/setup-vault-k8s.sh")

  environment = {
    VAULT_ADDR  = "http://localhost:8200"
    VAULT_TOKEN = "root"
    KUBECONFIG  = resource.k8s_cluster.k3s.kube_config.path
    K8S_HOST    = "https://server.${resource.k8s_cluster.k3s.meta.id}.k8s-cluster.shipyard.run:6443"
  }
}

resource "ingress" "chat_ui" {
  port = 3001

  target {
    resource = resource.k8s_cluster.k3s
    port     = 80

    config = {
      service   = "chat-ui"
      namespace = "demo"
    }
  }
}

output "KUBECONFIG" {
  value = resource.k8s_cluster.k3s.kube_config.path
}

output "CHAT_UI_URL" {
  value = "http://localhost:3001"
}
