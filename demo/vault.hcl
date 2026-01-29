# Download the Vault plugin from GitHub releases
# NOTE: If releases are not available, you can build locally instead:
#   1. Comment out this resource
#   2. Uncomment the local_build_plugin resource below
#   3. Run: jumppad up
resource "exec" "download_plugin" {

  script = file("./scripts/download-plugin.sh")

  environment = {
    PLUGIN_VERSION  = variable.plugin_version
    PLUGIN_PLATFORM = variable.plugin_platform
    VAULT_ADDR      = "http://localhost:8200"
    VAULT_TOKEN     = "root"
    KEYCLOAK_URL    = "http://localhost:8080"
  }
}

# HashiCorp Vault with Token Exchange Plugin
resource "container" "vault" {

  depends_on = ["resource.exec.download_plugin"]

  network {
    id         = resource.network.demo.meta.id
    ip_address = "10.10.0.30"
    aliases    = ["vault"]
  }

  image {
    name = "hashicorp/vault:1.21.0"
  }

  command = ["vault", "server", "-dev", "-dev-root-token-id=root", "-dev-plugin-dir=/vault/plugins"]

  environment = {
    VAULT_DEV_ROOT_TOKEN_ID  = "root"
    VAULT_DEV_LISTEN_ADDRESS = "0.0.0.0:8200"
    VAULT_ADDR               = "http://127.0.0.1:8200"
  }

  volume {
    source      = "../bin"
    destination = "/vault/plugins"
  }

  port {
    local = 8200
    host  = 8200
  }

  health_check {
    timeout = "30s"
    http {
      address       = "http://127.0.0.1:8200/v1/sys/health"
      success_codes = [200]
    }
  }
}

# Configure Vault with the plugin
resource "exec" "configure_vault" {
  disabled   = !variable.run_scripts
  depends_on = ["resource.container.vault", "resource.container.keycloak"]

  script = file("./scripts/setup-vault.sh")

  environment = {
    VAULT_ADDR   = "http://localhost:8200"
    VAULT_TOKEN  = "root"
    KEYCLOAK_URL = "http://localhost:8080"
    PLUGIN_DIR   = "${dir()}/../bin"
  }
}

# Configure AppRole auth for customer-agent and customers-tool
resource "exec" "configure_approle" {
  disabled   = !variable.run_scripts
  depends_on = ["resource.exec.configure_vault"]

  script = file("./scripts/setup-approle.sh")

  environment = {
    VAULT_ADDR  = "http://localhost:8200"
    VAULT_TOKEN = "root"
  }
}
