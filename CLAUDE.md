# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

This is a HashiCorp Vault plugin for identity delegation designed to enable agentic authorization workflows. The plugin implements the OAuth 2.0 Token Exchange specification (RFC 8693) with OIDC tokens to support "on behalf of" scenarios.

### Purpose

The plugin facilitates authorization for AI agents acting on behalf of users by:
- Accepting two OIDC tokens: one from the end user and one from the agent
- Merging these tokens using the OAuth 2.0 Token Exchange "on behalf of" flow
- Returning a combined token that represents the agent acting with the user's authority

This enables secure delegation scenarios where an AI agent needs to perform actions on behalf of an authenticated user while maintaining a clear audit trail of both the user and agent identities.

### Use Case

When an AI agent needs to call external services or APIs on behalf of a user, this plugin creates a token that:
- Contains the user's identity and permissions
- Includes the agent's identity for audit purposes
- Follows the OAuth 2.0 Token Exchange specification for proper "on behalf of" semantics
- Can be validated by downstream services that understand identity delegation

## Development Commands

### Building the Plugin
```bash
go build -o vault-plugin-identity-delegation cmd/vault-plugin-identity-delegation/main.go
```

### Running Tests
```bash
# Run all tests
go test ./...

# Run tests with coverage
go test -v -cover ./...

# Run a specific test
go test -v -run TestSpecificFunction ./path/to/package
```

### Linting
```bash
# Run golangci-lint
golangci-lint run

# Run go vet
go vet ./...

# Format code
go fmt ./...
```

### Local Development with Vault
```bash
# Build the plugin
go build -o vault-plugin-identity-delegation cmd/vault-plugin-identity-delegation/main.go

# Start Vault in dev mode
vault server -dev -dev-plugin-dir=./

# In another terminal, register the plugin
export VAULT_ADDR='http://127.0.0.1:8200'
vault plugin register -sha256=$(shasum -a 256 vault-plugin-identity-delegation | cut -d' ' -f1) secret vault-plugin-identity-delegation

# Enable the plugin
vault secrets enable -path=identity-delegation vault-plugin-identity-delegation
```

## Architecture

### Vault Plugin Structure

Vault plugins follow a specific architecture pattern:

1. **Plugin Backend**: The main backend struct that implements the `logical.Backend` interface, containing the plugin's configuration and path definitions.

2. **Path Definitions**: Each API endpoint in the plugin is defined as a path with specific operations (GET, POST, DELETE, etc.). Paths are registered in the backend's `Paths()` method.

3. **Path Handlers**: Functions that handle requests to specific paths. They receive a context and request object, and return a response or error.

4. **Storage Layer**: Vault provides a storage backend interface for persisting data. The plugin should use `req.Storage` to read/write data.

5. **Plugin Communication**: Vault plugins run as separate processes and communicate with Vault over gRPC using the go-plugin library.

### Key Components

- **backend.go**: Defines the main backend structure and implements the `logical.Backend` interface
- **path_*.go**: Path handlers for different API endpoints
- **client.go**: External service client implementations (if needed)
- **cmd/vault-plugin-identity-delegation/main.go**: Plugin entry point

### Testing Approach

- Use `logical.TestBackend()` for integration tests that test the plugin as a whole
- Mock external dependencies for unit tests
- Test both success and error paths
- Validate proper secrets management and cleanup

## Plugin Development Notes

### Secret Management
- Always use Vault's storage interface for persisting sensitive data
- Never log secrets or sensitive information
- Implement proper lease management for secrets with TTLs
- Use renewable tokens where appropriate

### Error Handling
- Return `logical.ErrorResponse()` for user-facing errors
- Include helpful error messages that don't expose internal details
- Use structured logging with `b.Logger()` for debugging

### Configuration
- Plugin configuration should be stored in Vault's storage backend
- Support rotation of credentials and configuration updates
- Validate all configuration inputs

### Performance
- Use connection pooling for external service clients
- Implement caching where appropriate (with proper invalidation)
- Consider rate limiting for external API calls

### Security
- Validate all inputs to prevent injection attacks
- Use TLS for all external communications
- Follow principle of least privilege for any external service access
- Audit all sensitive operations using Vault's audit backend
