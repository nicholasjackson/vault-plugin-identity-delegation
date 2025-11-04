# Vault Plugin Scaffold - Context & Dependencies

**Last Updated**: 2025-11-04

## Quick Summary

Scaffold a basic Vault secrets engine plugin for OAuth 2.0 Token Exchange (RFC 8693) following the identity engine pattern. The plugin accepts existing OIDC tokens, validates them, and generates new JWTs with "on behalf of" claims using role-based templates. Includes GitHub Actions CI/CD with build, test, lint, and coverage.

## Key Files & Locations

### Files to Create:

**Root Directory:**
- `go.mod` - Go module definition with Vault SDK dependencies
- `go.sum` - Dependency checksums (auto-generated)
- `.gitignore` - Go-specific ignore patterns
- `README.md` - Project documentation
- `Makefile` - Build and test automation (optional but recommended)

**Plugin Core:**
- `backend.go` - Backend struct, Factory function, path registration
- `backend_test.go` - Backend initialization tests
- `path_config.go` - Plugin configuration endpoint handlers
- `path_config_test.go` - Config path CRUD tests
- `path_role.go` - Role management endpoint handlers
- `path_role_test.go` - Role path CRUD tests
- `path_token.go` - Token exchange endpoint handler
- `path_token_test.go` - Token exchange logic tests

**Main Entry Point:**
- `cmd/vault-plugin-token-exchange/main.go` - Plugin entry point with ServeMultiplex

**CI/CD:**
- `.github/workflows/test.yml` - GitHub Actions workflow

### Files to Reference:

**External Reference (Vault source):**
- `github.com/hashicorp/vault/vault/identity_store_oidc.go:1081-1165` - Token generation pattern
- `github.com/hashicorp/vault/vault/identity_store_oidc.go:1269-1282` - Role storage pattern
- `github.com/hashicorp/vault/vault/identity_store_oidc.go:1035-1051` - JWT signing pattern

**Project Documentation:**
- `CLAUDE.md` - Project architecture and development guidelines
- `.docs/adhoc/vault-plugin-scaffold/vault-plugin-scaffold-research.md` - Research findings
- `.docs/adhoc/vault-plugin-scaffold/vault-plugin-scaffold-plan.md` - Implementation plan

## Dependencies

### Go Module Dependencies:
```go
require (
    github.com/hashicorp/vault/api v1.16.0      // Plugin API and metadata
    github.com/hashicorp/vault/sdk v0.17.0      // Plugin SDK framework
    github.com/hashicorp/go-hclog v1.6.3        // Structured logging
    gopkg.in/square/go-jose.v2 v2.6.0           // JWT signing and verification
    github.com/stretchr/testify v1.9.0          // Testing with require assertions
)
```

### External Dependencies:
- None (plugin runs as subprocess, no external services initially)

### Development Dependencies:
- Go 1.23+ (latest stable)
- golangci-lint (for CI/CD linting)
- make (optional, for build automation)

## Key Technical Decisions

1. **Architecture Pattern**: Follow Vault identity engine's OIDC implementation closely
   - Rationale: Proven production pattern, similar use case (token generation), reduces development risk

2. **Path Structure**: Use identity engine-style paths
   - `/token-exchange/config` - Plugin configuration
   - `/token-exchange/role/:name` - Role CRUD operations
   - `/token-exchange/token/:name` - Token exchange endpoint
   - Rationale: Familiar to Vault users, consistent with ecosystem

3. **Storage Pattern**: Prefix-based keys like identity engine
   - `token_exchange/config/` - Configuration
   - `token_exchange/roles/:name` - Role definitions
   - Rationale: Namespace isolation, follows Vault conventions

4. **Signing Approach**: Simplified key management initially (not dedicated key management paths)
   - Store signing key in config for scaffold phase
   - Future: Add `/token-exchange/key/:name` paths like identity engine
   - Rationale: Keep scaffold simple, add complexity later

5. **JWT Validation**: Simple validation initially (signature + expiration)
   - Validate JWT signature using public key from config
   - Check expiration and standard claims
   - Future: Add full OIDC discovery, JWKS, etc.
   - Rationale: Focus on structure, defer complexity

6. **Testing Strategy**: TDD with testify/require, logical.TestBackend()
   - Unit tests for each path handler
   - Integration tests using logical.TestBackend()
   - No real Vault instance required
   - Rationale: Fast CI/CD, sufficient coverage for scaffold phase

7. **CI/CD**: GitHub Actions with build, test, lint, coverage
   - Jobs: build, test, golangci-lint, coverage reporting
   - No integration tests with real Vault server
   - Rationale: User requirement, keeps CI fast and simple

## Integration Points

- **Vault Core**: Plugin communicates with Vault via gRPC using plugin.ServeMultiplex()
- **Vault Storage**: Uses logical.Storage interface for persistence (Vault manages actual storage backend)
- **Vault Logging**: Uses hclog.Logger provided by Vault for structured logging
- **Vault TLS**: Uses TLS configuration provided by Vault for secure plugin communication

## Environment Requirements

- **Go version**: 1.23 (latest stable as of 2025-11-04)
- **Vault version**: 1.17+ (uses modern SDK features)
- **Environment variables**: None required for plugin itself (Vault sets up plugin environment)
- **Database migrations**: N/A (uses Vault's storage, no schema management needed)
- **Build requirements**: Go toolchain, no CGO dependencies

## Storage Schema

### Config Storage (`token_exchange/config`):
```json
{
  "issuer": "https://vault.example.com",
  "signing_key": "<PEM-encoded private key>",
  "default_ttl": "24h"
}
```

### Role Storage (`token_exchange/roles/:name`):
```json
{
  "name": "user-agent-exchange",
  "ttl": "1h",
  "template": "{\"act\": {\"sub\": \"{{.user.sub}}\", \"email\": \"{{.user.email}}\"}}",
  "bound_audiences": ["service-a", "service-b"],
  "bound_issuer": "https://idp.example.com"
}
```

## Related Documentation

- **Original Plan**: `.docs/adhoc/vault-plugin-scaffold/vault-plugin-scaffold-plan.md`
- **Research Notes**: `.docs/adhoc/vault-plugin-scaffold/vault-plugin-scaffold-research.md`
- **Task Checklist**: `.docs/adhoc/vault-plugin-scaffold/vault-plugin-scaffold-tasks.md`
- **Project Guidelines**: `CLAUDE.md`
- **Vault Plugin Docs**: https://developer.hashicorp.com/vault/docs/plugins
- **RFC 8693**: OAuth 2.0 Token Exchange specification
