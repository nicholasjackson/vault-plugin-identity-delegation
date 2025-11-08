# Keycloak OIDC Provider
resource "container" "keycloak" {
  network {
    id         = resource.network.demo.meta.id
    ip_address = "10.10.0.10"
    aliases    = ["keycloak"]
  }

  image {
    name = "quay.io/keycloak/keycloak:26.0"
  }

  command = [
    "start-dev"
  ]

  environment = {
    KC_BOOTSTRAP_ADMIN_USERNAME = "admin"
    KC_BOOTSTRAP_ADMIN_PASSWORD = "admin"
    KC_HEALTH_ENABLED           = true
  }

  port {
    local = 8080
    host  = 8080
  }

  health_check {
    timeout = "30s"
    http {
      address       = "http://localhost:8080/admin/master/console/"
      success_codes = [200]
    }
  }
}