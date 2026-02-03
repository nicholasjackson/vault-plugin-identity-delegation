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

# Template and deploy agent/tool/UI workloads when deploy_agents is enabled
resource "template" "chat_ui" {
  disabled = !variable.deploy_agents

  source      = file("./k8s/chat-ui.yaml")
  destination = "${data("deploy")}/chat-ui.yaml"

  variables = {
    app_version = variable.app_version
    vault_ip    = variable.vault_ip
  }
}

resource "template" "customer_agent" {
  disabled = !variable.deploy_agents

  source      = file("./k8s/customer-agent-deploy.yaml")
  destination = "${data("deploy")}/customer-agent-deploy.yaml"

  variables = {
    app_version = variable.app_version
    ollama_host = variable.ollama_host
    vault_ip    = variable.vault_ip
  }
}

resource "template" "weather_agent" {
  disabled = !variable.deploy_agents

  source      = file("./k8s/weather-agent-deploy.yaml")
  destination = "${data("deploy")}/weather-agent-deploy.yaml"

  variables = {
    app_version = variable.app_version
    ollama_host = variable.ollama_host
    vault_ip    = variable.vault_ip
  }
}

resource "template" "customers_tool" {
  disabled = !variable.deploy_agents

  source      = file("./k8s/customers-tool-deploy.yaml")
  destination = "${data("deploy")}/customers-tool-deploy.yaml"

  variables = {
    app_version = "0.1.3"
    vault_ip    = variable.vault_ip
  }
}

resource "template" "weather_tool" {
  disabled = !variable.deploy_agents

  source      = file("./k8s/weather-tool-deploy.yaml")
  destination = "${data("deploy")}/weather-tool-deploy.yaml"

  variables = {
    app_version         = variable.app_version
    vault_ip            = variable.vault_ip
    openweather_api_key = variable.openweather_api_key
  }
}

resource "k8s_config" "service_accounts" {
  disabled   = !variable.deploy_agents
  cluster    = resource.k8s_cluster.k3s
  depends_on = ["resource.helm.vault_secrets_operator"]

  paths = [
    "./k8s/namespace.yaml",
    "./k8s/agent-service-accounts.yaml",
    "./k8s/vault-token-reviewer.yaml",
  ]

  wait_until_ready = true
}

resource "k8s_config" "agent_deployments" {
  disabled = !variable.deploy_agents
  cluster  = resource.k8s_cluster.k3s
  depends_on = [
    "resource.k8s_config.service_accounts",
  ]

  paths = [
    resource.template.chat_ui.destination,
    resource.template.customer_agent.destination,
    resource.template.weather_agent.destination,
    resource.template.customers_tool.destination,
    resource.template.weather_tool.destination,
  ]

  wait_until_ready = true
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
