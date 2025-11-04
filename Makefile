.PHONY: build test lint clean dev-vault register enable demo help

# Binary name
BINARY=vault-plugin-identity-delegation

# Build directory
BUILD_DIR=./bin

# Vault dev server settings
VAULT_ADDR?=http://127.0.0.1:8200
VAULT_TOKEN?=root

help: ## Display this help message
	@echo "Available targets:"
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-20s\033[0m %s\n", $$1, $$2}'

build: ## Build the plugin binary
	@echo "Building plugin..."
	@mkdir -p $(BUILD_DIR)
	@go build -o $(BUILD_DIR)/$(BINARY) cmd/vault-plugin-identity-delegation/main.go
	@echo "✓ Binary built: $(BUILD_DIR)/$(BINARY)"

test: ## Run all tests
	@echo "Running tests..."
	@go test -v -cover ./...

test-coverage: ## Run tests with coverage report
	@echo "Running tests with coverage..."
	@go test -coverprofile=coverage.txt -covermode=atomic ./...
	@go tool cover -html=coverage.txt -o coverage.html
	@echo "✓ Coverage report: coverage.html"

test-race: ## Run tests with race detector (requires CGO)
	@echo "Running tests with race detector..."
	@CGO_ENABLED=1 go test -race ./...

lint: ## Run linters
	@echo "Running go vet..."
	@go vet ./...
	@echo "Running gofmt..."
	@test -z "$$(gofmt -s -l . | grep -v vendor)" || (echo "Code not formatted, run 'make fmt'" && exit 1)
	@echo "✓ All linters passed"

fmt: ## Format code
	@echo "Formatting code..."
	@gofmt -s -w .
	@echo "✓ Code formatted"

clean: ## Clean build artifacts and test data
	@echo "Cleaning..."
	@rm -rf $(BUILD_DIR)
	@rm -f coverage.txt coverage.html
	@rm -f vault-plugin-identity-delegation
	@rm -rf ./data
	@echo "✓ Cleaned"

dev-vault: ## Start Vault dev server with plugin (auto-register and enable)
	@./scripts/dev-vault.sh

dev-vault-manual: build ## Start Vault dev server (manual registration required)
	@echo "Starting Vault dev server..."
	@echo "Plugin directory: $(BUILD_DIR)"
	@echo "Vault address: $(VAULT_ADDR)"
	@echo ""
	@echo "After Vault starts, run in another terminal:"
	@echo "  make register enable"
	@echo ""
	@vault server -dev \
		-dev-root-token-id=$(VAULT_TOKEN) \
		-dev-plugin-dir=$(BUILD_DIR) \
		-log-level=info

register: build ## Register plugin with Vault (requires running Vault)
	@echo "Registering plugin with Vault..."
	@export VAULT_ADDR=$(VAULT_ADDR); \
	export VAULT_TOKEN=$(VAULT_TOKEN); \
	SHA256=$$(shasum -a 256 $(BUILD_DIR)/$(BINARY) | cut -d' ' -f1); \
	echo "Plugin SHA256: $$SHA256"; \
	vault plugin register \
		-sha256=$$SHA256 \
		secret $(BINARY)
	@echo "✓ Plugin registered"

enable: ## Enable plugin as secrets engine (requires registered plugin)
	@echo "Enabling plugin..."
	@export VAULT_ADDR=$(VAULT_ADDR); \
	export VAULT_TOKEN=$(VAULT_TOKEN); \
	vault secrets enable \
		-path=identity-delegation \
		$(BINARY)
	@echo "✓ Plugin enabled at /identity-delegation"

disable: ## Disable plugin secrets engine
	@echo "Disabling plugin..."
	@export VAULT_ADDR=$(VAULT_ADDR); \
	export VAULT_TOKEN=$(VAULT_TOKEN); \
	vault secrets disable identity-delegation
	@echo "✓ Plugin disabled"

reload: disable register enable ## Reload plugin (disable, register, enable)
	@echo "✓ Plugin reloaded"

demo: ## Run a demo of the plugin (requires enabled plugin)
	@echo "Running plugin demo..."
	@./scripts/demo.sh

all: clean lint test build ## Run all checks and build
	@echo "✓ All tasks completed successfully"
