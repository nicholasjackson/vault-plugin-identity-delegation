# Vault Plugin Scaffold Implementation Plan

**Created**: 2025-11-04
**Last Updated**: 2025-11-04

## Overview

Scaffold a complete Vault secrets engine plugin for OAuth 2.0 Token Exchange (RFC 8693). The plugin follows the identity engine pattern, accepting existing OIDC tokens and generating new JWTs with "on behalf of" claims using role-based templates. Includes full project structure, tests, and GitHub Actions CI/CD pipeline.

**Architecture**: Identity Engine Pattern + JWT Input Validation
- Role-based configuration (like `/identity/oidc/role/:name`)
- Token generation endpoint that accepts JWT input
- Template-based claim customization
- JWT validation and signing using go-jose

## Current State Analysis

### What Exists Now:
- `CLAUDE.md` - Comprehensive project documentation
- `.gitignore` - Empty file
- `.git/` - Initialized repository with no commits
- `.docs/` - Documentation structure (just created)

### What's Missing:
- **No Go project**: No `go.mod`, no source files
- **No plugin code**: No backend, paths, or handlers
- **No tests**: No test files or testing infrastructure
- **No CI/CD**: No GitHub Actions workflows
- **No build system**: No Makefile or build scripts

### Key Constraints Discovered:
- Must use Vault SDK v0.17.0+ (modern plugin features)
- Must follow TDD approach (tests before implementation)
- Must use testify/require for assertions (go-dev-guidelines)
- Must use plugin.ServeMultiplex() for modern plugins
- Storage keys must use prefix pattern (e.g., `token_exchange/`)
- Reserved JWT claims cannot be overridden: `iat`, `aud`, `exp`, `iss`, `sub`, `namespace`

## Desired End State

A functional Vault secrets engine plugin that:

1. **Builds successfully**: `go build ./...` completes without errors
2. **Registers with Vault**: `vault plugin register` accepts the plugin
3. **Mounts as secrets engine**: `vault secrets enable -path=token-exchange vault-plugin-token-exchange`
4. **Accepts configuration**: `vault write token-exchange/config issuer=... signing_key=...`
5. **Manages roles**: `vault write token-exchange/role/my-role ...`
6. **Exchanges tokens**: `vault write token-exchange/token/my-role subject_token=...` returns new JWT
7. **Passes all tests**: `go test -v ./...` passes 100%
8. **Passes CI/CD**: GitHub Actions runs successfully on push/PR

**Verification Method**:
```bash
# Build plugin
go build -o vault-plugin-token-exchange cmd/vault-plugin-token-exchange/main.go

# Start Vault dev mode
vault server -dev -dev-plugin-dir=./

# Register and enable (in another terminal)
export VAULT_ADDR='http://127.0.0.1:8200'
SHA256=$(shasum -a 256 vault-plugin-token-exchange | cut -d' ' -f1)
vault plugin register -sha256=$SHA256 secret vault-plugin-token-exchange
vault secrets enable -path=token-exchange vault-plugin-token-exchange

# Configure
vault write token-exchange/config issuer="https://vault.example.com" ...

# Create role
vault write token-exchange/role/test-role ...

# Exchange token
vault write token-exchange/token/test-role subject_token="eyJ..."
```

## What We're NOT Doing

**Explicitly out of scope for this scaffold phase:**

1. **Full OIDC Discovery**: Not implementing automatic JWKS fetching via `oidc_discovery_url`
2. **Key Rotation**: Not implementing dedicated key management paths like `/token-exchange/key/:name`
3. **Multiple Signing Algorithms**: Starting with RS256 only
4. **Token Introspection**: Not implementing `/introspect` endpoint
5. **Provider/Scope/Assignment**: Not implementing full OIDC provider functionality
6. **Complex Templates**: Using simple string templates, not full template engine initially
7. **Integration Tests with Real Vault**: Using logical.TestBackend() only
8. **Performance Optimization**: No caching, connection pooling, or rate limiting
9. **Metrics/Telemetry**: No Prometheus metrics or custom telemetry
10. **Migration Scripts**: No data migration tooling

**These features can be added in future iterations after the scaffold proves functional.**

## Implementation Approach

**Strategy**: Follow Test-Driven Development (TDD) throughout all phases

1. **Write failing tests first** - Define expected behavior via tests
2. **Run tests to verify failure** - Ensure tests fail for the right reasons
3. **Implement minimal code** - Write just enough code to make tests pass
4. **Refactor** - Clean up code while keeping tests green
5. **Repeat** - Continue for each feature

**Phase Order**: Build from foundation up
1. Project initialization (Go modules, structure, .gitignore)
2. Backend core (backend.go, Factory, minimal paths)
3. Config path (plugin configuration CRUD)
4. Role path (role management CRUD)
5. Token exchange path (JWT validation + token generation)
6. Main entry point (cmd/main.go with ServeMultiplex)
7. CI/CD (GitHub Actions workflow)

---

## Phase 1: Project Initialization

### Overview
Initialize the Go project with proper module setup, directory structure, and supporting files. This phase creates the foundation but no actual plugin code yet.

**TDD Approach**: Not applicable for this phase (infrastructure setup)

### Changes Required:

#### 1. Initialize Go Module
**Command**: `go mod init github.com/nicholasjackson/vault-plugin-token-exchange`

**Expected go.mod**:
```go
module github.com/nicholasjackson/vault-plugin-token-exchange

go 1.23

require (
    github.com/hashicorp/go-hclog v1.6.3
    github.com/hashicorp/vault/api v1.16.0
    github.com/hashicorp/vault/sdk v0.17.0
    github.com/stretchr/testify v1.9.0
    gopkg.in/square/go-jose.v2 v2.6.0
)
```

**Reasoning**: Establishes project as a Go module with Vault SDK dependencies. Latest stable versions ensure access to modern features and bug fixes.

#### 2. Create Directory Structure
**Command**: `mkdir -p cmd/vault-plugin-token-exchange .github/workflows`

**Expected Structure**:
```
vault-plugin-token-exchange/
├── cmd/
│   └── vault-plugin-token-exchange/
│       └── (main.go will go here in Phase 6)
├── .github/
│   └── workflows/
│       └── (test.yml will go here in Phase 7)
├── .docs/                     # Already created
├── CLAUDE.md                  # Already exists
└── .gitignore                 # To be populated
```

**Reasoning**: Standard Go project layout. `/cmd` contains main applications, `.github/workflows` for CI/CD.

#### 3. Populate .gitignore
**File**: `.gitignore`

**Content**:
```gitignore
# Binaries
vault-plugin-token-exchange
*.exe
*.dll
*.so
*.dylib

# Test binary
*.test

# Output of go coverage tool
*.out
coverage.txt
coverage.html

# Go workspace file
go.work

# IDE
.idea/
.vscode/
*.swp
*.swo
*~

# OS
.DS_Store
Thumbs.db

# Vault dev server data
data/
```

**Reasoning**: Ignores build artifacts, test outputs, IDE files, and OS-specific files. Prevents accidental commits of generated files.

#### 4. Create README.md
**File**: `README.md`

**Content**:
```markdown
# Vault Plugin: Token Exchange

A HashiCorp Vault secrets engine plugin that implements OAuth 2.0 Token Exchange (RFC 8693) for "on behalf of" scenarios with OIDC tokens.

## Purpose

This plugin enables AI agents and services to exchange existing OIDC tokens for new tokens that represent delegated authority. The resulting token contains:
- Original user's identity and permissions
- Agent/service identity for audit purposes
- "On behalf of" semantics per RFC 8693

## Building

```bash
go build -o vault-plugin-token-exchange cmd/vault-plugin-token-exchange/main.go
```

## Testing

```bash
# Run all tests
go test ./...

# Run with coverage
go test -v -cover ./...

# Run specific test
go test -v -run TestBackendFactory ./
```

## Development

See [CLAUDE.md](./CLAUDE.md) for development guidelines and architecture.

## Local Development with Vault

```bash
# Build the plugin
go build -o vault-plugin-token-exchange cmd/vault-plugin-token-exchange/main.go

# Start Vault in dev mode
vault server -dev -dev-plugin-dir=./

# In another terminal, register and enable
export VAULT_ADDR='http://127.0.0.1:8200'
SHA256=$(shasum -a 256 vault-plugin-token-exchange | cut -d' ' -f1)
vault plugin register -sha256=$SHA256 secret vault-plugin-token-exchange
vault secrets enable -path=token-exchange vault-plugin-token-exchange
```

## License

[License TBD]
```

**Reasoning**: Provides quick start information for developers. Links to CLAUDE.md for detailed guidelines.

### Testing for This Phase:

**No tests required** - This phase is infrastructure setup. Verification is manual:

1. Verify `go.mod` exists: `cat go.mod`
2. Verify directory structure: `tree -L 2` or `ls -R`
3. Verify .gitignore works: `git status` should not show binaries
4. Verify README renders correctly on GitHub

### Success Criteria:

#### Automated Verification:
- [ ] Go module initialized: `go mod tidy` runs without errors
- [ ] Dependencies downloadable: `go mod download` succeeds
- [ ] Project structure correct: `test -d cmd/vault-plugin-token-exchange` returns 0

#### Manual Verification:
- [ ] .gitignore prevents binary commits: Build binary, verify `git status` doesn't show it
- [ ] README displays correctly: Review on GitHub or with markdown previewer
- [ ] Directory structure matches standard Go layout

---

## Phase 2: Backend Core

### Overview
Implement the core backend structure with Factory function and minimal path registration. This establishes the plugin's foundation but doesn't implement any functional paths yet.

**TDD Approach**: Write tests for backend initialization before implementing backend code.

### Changes Required:

#### 1. Backend Test File - WRITE THIS FIRST
**File**: `backend_test.go`

**Purpose**: Define expected backend behavior through tests (TDD approach)

**Test implementation**:
```go
package tokenexchange

import (
    "context"
    "testing"

    "github.com/hashicorp/go-hclog"
    "github.com/hashicorp/vault/sdk/logical"
    "github.com/stretchr/testify/require"
)

// TestBackendFactory tests that the Factory function creates a valid backend
func TestBackendFactory(t *testing.T) {
    config := &logical.BackendConfig{
        Logger:      hclog.NewNullLogger(),
        System:      &logical.StaticSystemView{},
        StorageView: &logical.InmemStorage{},
    }

    backend, err := Factory(context.Background(), config)

    require.NoError(t, err, "Factory should not return an error")
    require.NotNil(t, backend, "Factory should return a non-nil backend")
}

// TestBackendFactory_NilConfig tests error handling for nil config
func TestBackendFactory_NilConfig(t *testing.T) {
    _, err := Factory(context.Background(), nil)

    require.Error(t, err, "Factory should return error for nil config")
    require.Contains(t, err.Error(), "config", "Error should mention config")
}

// TestBackend_PathsRegistered tests that expected paths are registered
func TestBackend_PathsRegistered(t *testing.T) {
    b := NewBackend()

    require.NotNil(t, b.Paths(), "Backend should have paths")
    require.NotEmpty(t, b.Paths(), "Backend should register at least one path")

    // Check for expected path patterns
    pathPatterns := make([]string, 0, len(b.Paths()))
    for _, path := range b.Paths() {
        pathPatterns = append(pathPatterns, path.Pattern)
    }

    require.Contains(t, pathPatterns, "config", "Should register config path")
}

// TestBackend_Type tests that backend identifies as correct type
func TestBackend_Type(t *testing.T) {
    b := NewBackend()

    require.Equal(t, logical.TypeLogical, b.BackendType, "Should be TypeLogical (secrets engine)")
}

// TestBackend_Help tests that backend provides help text
func TestBackend_Help(t *testing.T) {
    b := NewBackend()

    require.NotEmpty(t, b.Help, "Backend should provide help text")
    require.Contains(t, b.Help, "token exchange", "Help should mention token exchange")
}
```

**Reasoning**: Tests define the contract for the backend before implementing it. This is classic TDD - tests fail initially, then we implement to make them pass.

**Run tests now**: `go test ./... -v` → Should FAIL (files don't exist yet)

#### 2. Backend Implementation - IMPLEMENT AFTER TESTS FAIL
**File**: `backend.go`

**Purpose**: Core backend structure and Factory function

**Implementation**:
```go
package tokenexchange

import (
    "context"
    "fmt"
    "sync"

    "github.com/hashicorp/vault/sdk/framework"
    "github.com/hashicorp/vault/sdk/logical"
)

// Backend implements the logical.Backend interface for token exchange
type Backend struct {
    *framework.Backend

    // lock protects access to backend fields
    lock sync.RWMutex
}

// Factory creates a new Backend instance
func Factory(ctx context.Context, conf *logical.BackendConfig) (logical.Backend, error) {
    if conf == nil {
        return nil, fmt.Errorf("configuration passed into backend is nil")
    }

    b := NewBackend()

    if err := b.Setup(ctx, conf); err != nil {
        return nil, err
    }

    return b, nil
}

// NewBackend creates a new Backend with paths and configuration
func NewBackend() *Backend {
    b := &Backend{}

    b.Backend = &framework.Backend{
        Help: "The token exchange plugin implements OAuth 2.0 Token Exchange (RFC 8693) " +
            "for 'on behalf of' scenarios. It accepts existing OIDC tokens and generates " +
            "new JWTs with delegated authority claims.",

        // Register all path handlers
        Paths: []*framework.Path{
            pathConfig(b),
            // Additional paths will be added in later phases:
            // pathRole(b),
            // pathToken(b),
        },

        // Define paths that should be encrypted in storage
        PathsSpecial: &logical.Paths{
            SealWrapStorage: []string{
                "config",      // Config contains signing keys
                "roles/*",     // Roles may contain sensitive templates
            },
        },

        // Secrets: Not used for this plugin (generates tokens, doesn't manage secrets)
        // InvalidateFunc: Not needed initially

        BackendType: logical.TypeLogical,
    }

    return b
}
```

**Reasoning**:
- Embeds `framework.Backend` which implements `logical.Backend` interface
- Factory pattern required by Vault for plugin initialization
- Path registration in `Paths` slice (starts with just config path)
- SealWrapStorage encrypts sensitive data like signing keys
- TypeLogical designates this as a secrets engine (not auth)

**Run tests now**: `go test ./... -v` → Tests should PASS now

#### 3. Stub Config Path - MINIMAL IMPLEMENTATION
**File**: `path_config.go`

**Purpose**: Stub implementation so backend compiles (will be completed in Phase 3)

**Minimal implementation**:
```go
package tokenexchange

import (
    "github.com/hashicorp/vault/sdk/framework"
)

// pathConfig returns the path configuration for /config endpoint
func pathConfig(b *Backend) *framework.Path {
    return &framework.Path{
        Pattern: "config",

        // Fields will be added in Phase 3
        Fields: map[string]*framework.FieldSchema{},

        // Operations will be added in Phase 3
        Operations: map[logical.Operation]framework.OperationHandler{},

        HelpSynopsis:    "Configure the token exchange plugin",
        HelpDescription: "Configures the issuer, signing keys, and default TTL for token generation.",
    }
}
```

**Reasoning**: Allows backend to register config path without implementing handlers yet. Keeps Phase 2 focused on backend structure. Full implementation comes in Phase 3.

### Testing for This Phase:

**Tests written FIRST** (listed in section 1 above):
- `TestBackendFactory` - Factory creates valid backend
- `TestBackendFactory_NilConfig` - Factory handles nil config
- `TestBackend_PathsRegistered` - Paths are registered
- `TestBackend_Type` - Backend is correct type
- `TestBackend_Help` - Backend provides help

**Test execution flow**:
1. **Write tests** (backend_test.go)
2. **Verify tests fail**: `go test ./... -v` → FAIL (expected)
3. **Implement backend** (backend.go, path_config.go stub)
4. **Verify tests pass**: `go test ./... -v` → PASS

### Success Criteria:

#### Automated Verification:
- [ ] All tests pass: `go test -v ./...`
- [ ] Code compiles: `go build ./...`
- [ ] No linting errors: `go vet ./...`
- [ ] Formatting correct: `go fmt ./...` (no changes)

#### Manual Verification:
- [ ] Backend structure follows identity engine pattern
- [ ] Factory function signature matches Vault requirements
- [ ] Path registration works (config path appears in Paths())
- [ ] Help text is clear and accurate

---

## Phase 3: Configuration Path

### Overview
Implement full CRUD operations for the `/config` endpoint. This allows Vault administrators to configure the plugin with issuer, signing keys, and default TTL settings.

**TDD Approach**: Write tests for each operation (Read, Write, Delete) before implementing handlers.

### Changes Required:

#### 1. Config Struct Definition
**File**: `path_config.go` (add to existing file)

**Purpose**: Define configuration structure that gets stored in Vault

**Add to path_config.go**:
```go
// Config represents the plugin configuration stored in Vault
type Config struct {
    // Issuer is the JWT issuer claim (iss) for generated tokens
    Issuer string `json:"issuer"`

    // SigningKey is the PEM-encoded private key for signing JWTs
    SigningKey string `json:"signing_key"`

    // DefaultTTL is the default time-to-live for generated tokens
    DefaultTTL time.Duration `json:"default_ttl"`
}

// Storage key for configuration
const configStoragePath = "config"
```

**Reasoning**: Matches identity engine pattern. Issuer and signing key required for JWT generation. DefaultTTL provides sensible default for roles that don't specify TTL.

#### 2. Config Path Tests - WRITE THESE FIRST
**File**: `path_config_test.go`

**Purpose**: Define expected config CRUD behavior through tests

**Test implementation**:
```go
package tokenexchange

import (
    "context"
    "testing"
    "time"

    "github.com/hashicorp/go-hclog"
    "github.com/hashicorp/vault/sdk/logical"
    "github.com/stretchr/testify/require"
)

// getTestBackend creates a test backend for testing
func getTestBackend(t *testing.T) (*Backend, logical.Storage) {
    config := &logical.BackendConfig{
        Logger:      hclog.NewNullLogger(),
        System:      &logical.StaticSystemView{},
        StorageView: &logical.InmemStorage{},
    }

    b, err := Factory(context.Background(), config)
    require.NoError(t, err)

    return b.(*Backend), config.StorageView
}

// TestConfigRead_NotConfigured tests reading when no config exists
func TestConfigRead_NotConfigured(t *testing.T) {
    b, storage := getTestBackend(t)

    req := &logical.Request{
        Operation: logical.ReadOperation,
        Path:      "config",
        Storage:   storage,
    }

    resp, err := b.HandleRequest(context.Background(), req)

    require.NoError(t, err, "Read should not error when no config exists")
    require.Nil(t, resp, "Response should be nil when no config exists")
}

// TestConfigWrite_Success tests writing valid configuration
func TestConfigWrite_Success(t *testing.T) {
    b, storage := getTestBackend(t)

    req := &logical.Request{
        Operation: logical.UpdateOperation,
        Path:      "config",
        Storage:   storage,
        Data: map[string]any{
            "issuer":       "https://vault.example.com",
            "signing_key":  testRSAPrivateKey, // Test key constant
            "default_ttl":  "24h",
        },
    }

    resp, err := b.HandleRequest(context.Background(), req)

    require.NoError(t, err, "Write should succeed with valid config")
    require.Nil(t, resp, "Write should return nil response on success")

    // Verify config was stored
    entry, err := storage.Get(context.Background(), "config")
    require.NoError(t, err)
    require.NotNil(t, entry, "Config should be stored")
}

// TestConfigWrite_MissingIssuer tests validation of required fields
func TestConfigWrite_MissingIssuer(t *testing.T) {
    b, storage := getTestBackend(t)

    req := &logical.Request{
        Operation: logical.UpdateOperation,
        Path:      "config",
        Storage:   storage,
        Data: map[string]any{
            "signing_key": testRSAPrivateKey,
            "default_ttl": "24h",
            // Missing issuer
        },
    }

    resp, err := b.HandleRequest(context.Background(), req)

    require.NoError(t, err, "Handler should not error")
    require.NotNil(t, resp, "Should return error response")
    require.True(t, resp.IsError(), "Response should be an error")
    require.Contains(t, resp.Error().Error(), "issuer", "Error should mention missing issuer")
}

// TestConfigRead_AfterWrite tests reading configuration after writing
func TestConfigRead_AfterWrite(t *testing.T) {
    b, storage := getTestBackend(t)

    // Write config
    writeReq := &logical.Request{
        Operation: logical.UpdateOperation,
        Path:      "config",
        Storage:   storage,
        Data: map[string]any{
            "issuer":       "https://vault.example.com",
            "signing_key":  testRSAPrivateKey,
            "default_ttl":  "24h",
        },
    }
    _, err := b.HandleRequest(context.Background(), writeReq)
    require.NoError(t, err)

    // Read config
    readReq := &logical.Request{
        Operation: logical.ReadOperation,
        Path:      "config",
        Storage:   storage,
    }
    resp, err := b.HandleRequest(context.Background(), readReq)

    require.NoError(t, err, "Read should succeed")
    require.NotNil(t, resp, "Should return response")
    require.NotNil(t, resp.Data, "Response should have data")
    require.Equal(t, "https://vault.example.com", resp.Data["issuer"])
    require.Equal(t, "24h", resp.Data["default_ttl"])
    // Note: signing_key should not be returned (sensitive)
    require.NotContains(t, resp.Data, "signing_key", "Should not return signing key")
}

// TestConfigDelete tests deleting configuration
func TestConfigDelete(t *testing.T) {
    b, storage := getTestBackend(t)

    // Write config first
    writeReq := &logical.Request{
        Operation: logical.UpdateOperation,
        Path:      "config",
        Storage:   storage,
        Data: map[string]any{
            "issuer":       "https://vault.example.com",
            "signing_key":  testRSAPrivateKey,
            "default_ttl":  "24h",
        },
    }
    _, err := b.HandleRequest(context.Background(), writeReq)
    require.NoError(t, err)

    // Delete config
    deleteReq := &logical.Request{
        Operation: logical.DeleteOperation,
        Path:      "config",
        Storage:   storage,
    }
    resp, err := b.HandleRequest(context.Background(), deleteReq)

    require.NoError(t, err, "Delete should succeed")
    require.Nil(t, resp, "Delete should return nil response")

    // Verify config is gone
    entry, err := storage.Get(context.Background(), "config")
    require.NoError(t, err)
    require.Nil(t, entry, "Config should be deleted")
}

// Test RSA private key for testing (keep this simple for scaffold)
const testRSAPrivateKey = `-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEA0Z3VS5JJcds3xfn/ygWyF/rLcXbq8B2dbABdKyN4cYVmT7X0
rH3YDm9lcrw0B6BaCXRPLzN8smOHhM7cQ8VkAHPTl5kNKQSq/lCCxZxVB3JsLGgr
aEHEK7DZ5uDxY0kCxBLZZ0j7Wqj8WzFGK7Tt4TGGOXqXEHp5Gvn3kzHOxBV/FgTT
wMjMHLdlJK5FvN7D0X7VYjfbdCRq0eXPtHQXJ0g2gNxHC/iT7S7GqKNLMqN+V7xT
gCJN1PqQW0X5GThZA8IiGwvC3qM5gSHkjjQ9IhBQxHoqXDKGF+F8O1Hv0y/fH5Iq
RJxFI8vJMdKZaHKMR8fAFvyPmVLKnqqK3PiFXQIDAQABAoIBADqXX5KZ2R3jPKxb
1y7gLNqR0tUEQ3b4B+fsdqNNiLF/dYOXMQCcFZJaL6mJRhYYKGKKq6vLdV0VZoWc
9L1sO2x1vL3tqDPxNqCPEEXq2HQqWC0lhVv5x0NfBf0nE3Q2M4xM6g4cJZvBtZ5U
QWH/LTMWn1qE3Lz8F9EY0x9r8EQPqB1KCtEKhw8YqPQFMlV3UFqJ8m7pVVXvJBiQ
TZq1LB2UxMjNMZJqtE4Q3YWqMKJLQT3NHYE6NvE5XaQ6jHLKxL7oxLkJ7YFhYLWq
... (truncated for brevity - use a real test key in actual implementation)
-----END RSA PRIVATE KEY-----`
```

**Reasoning**: Tests cover all CRUD operations plus validation. Separate test for each scenario (not table-driven per go-dev-guidelines). Tests written before implementation (TDD).

**Run tests now**: `go test ./... -v` → Should FAIL (handlers not implemented yet)

#### 3. Config Path Implementation - IMPLEMENT AFTER TESTS FAIL
**File**: `path_config.go` (complete implementation)

**Full implementation**:
```go
package tokenexchange

import (
    "context"
    "fmt"
    "time"

    "github.com/hashicorp/vault/sdk/framework"
    "github.com/hashicorp/vault/sdk/logical"
)

// Config represents the plugin configuration stored in Vault
type Config struct {
    Issuer      string        `json:"issuer"`
    SigningKey  string        `json:"signing_key"`
    DefaultTTL  time.Duration `json:"default_ttl"`
}

const configStoragePath = "config"

// pathConfig returns the path configuration for /config endpoint
func pathConfig(b *Backend) *framework.Path {
    return &framework.Path{
        Pattern: "config",

        Fields: map[string]*framework.FieldSchema{
            "issuer": {
                Type:        framework.TypeString,
                Description: "The issuer (iss) claim for generated tokens",
                Required:    true,
            },
            "signing_key": {
                Type:        framework.TypeString,
                Description: "PEM-encoded RSA private key for signing tokens",
                Required:    true,
                DisplayAttrs: &framework.DisplayAttributes{
                    Sensitive: true,
                },
            },
            "default_ttl": {
                Type:        framework.TypeDurationSecond,
                Description: "Default TTL for generated tokens (e.g., '24h', '1h')",
                Default:     "24h",
            },
        },

        Operations: map[logical.Operation]framework.OperationHandler{
            logical.ReadOperation: &framework.PathOperation{
                Callback: b.pathConfigRead,
                Summary:  "Read the token exchange plugin configuration",
            },
            logical.UpdateOperation: &framework.PathOperation{
                Callback: b.pathConfigWrite,
                Summary:  "Configure the token exchange plugin",
            },
            logical.CreateOperation: &framework.PathOperation{
                Callback: b.pathConfigWrite,
                Summary:  "Configure the token exchange plugin",
            },
            logical.DeleteOperation: &framework.PathOperation{
                Callback: b.pathConfigDelete,
                Summary:  "Delete the token exchange plugin configuration",
            },
        },

        HelpSynopsis:    "Configure the token exchange plugin",
        HelpDescription: "Configures the issuer, signing keys, and default TTL for token generation.",
    }
}

// pathConfigRead handles reading the configuration
func (b *Backend) pathConfigRead(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
    config, err := b.getConfig(ctx, req.Storage)
    if err != nil {
        return nil, err
    }

    if config == nil {
        return nil, nil
    }

    return &logical.Response{
        Data: map[string]any{
            "issuer":      config.Issuer,
            "default_ttl": config.DefaultTTL.String(),
            // Note: Do NOT return signing_key (sensitive)
        },
    }, nil
}

// pathConfigWrite handles writing the configuration
func (b *Backend) pathConfigWrite(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
    config := &Config{}

    // Get issuer (required)
    issuer, ok := data.GetOk("issuer")
    if !ok {
        return logical.ErrorResponse("issuer is required"), nil
    }
    config.Issuer = issuer.(string)

    // Get signing key (required)
    signingKey, ok := data.GetOk("signing_key")
    if !ok {
        return logical.ErrorResponse("signing_key is required"), nil
    }
    config.SigningKey = signingKey.(string)

    // Validate signing key is valid PEM
    // (TODO: Add actual PEM validation in future - keep simple for scaffold)

    // Get default TTL (optional, has default)
    if ttl, ok := data.GetOk("default_ttl"); ok {
        config.DefaultTTL = time.Duration(ttl.(int)) * time.Second
    } else {
        config.DefaultTTL = 24 * time.Hour // Default
    }

    // Store configuration
    entry, err := logical.StorageEntryJSON(configStoragePath, config)
    if err != nil {
        return nil, fmt.Errorf("failed to create storage entry: %w", err)
    }

    if err := req.Storage.Put(ctx, entry); err != nil {
        return nil, fmt.Errorf("failed to write configuration: %w", err)
    }

    return nil, nil
}

// pathConfigDelete handles deleting the configuration
func (b *Backend) pathConfigDelete(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
    if err := req.Storage.Delete(ctx, configStoragePath); err != nil {
        return nil, fmt.Errorf("failed to delete configuration: %w", err)
    }

    return nil, nil
}

// getConfig retrieves the configuration from storage
func (b *Backend) getConfig(ctx context.Context, storage logical.Storage) (*Config, error) {
    entry, err := storage.Get(ctx, configStoragePath)
    if err != nil {
        return nil, fmt.Errorf("failed to read configuration: %w", err)
    }

    if entry == nil {
        return nil, nil
    }

    config := &Config{}
    if err := entry.DecodeJSON(config); err != nil {
        return nil, fmt.Errorf("failed to decode configuration: %w", err)
    }

    return config, nil
}
```

**Reasoning**:
- Follows identity engine's storage pattern (getConfig helper)
- Validates required fields (issuer, signing_key)
- Does NOT return signing_key on read (security best practice)
- Uses logical.StorageEntryJSON for serialization
- Error handling wraps errors with context

**Run tests now**: `go test ./... -v` → Tests should PASS now

### Testing for This Phase:

**Tests written FIRST** (listed in section 2 above):
- `TestConfigRead_NotConfigured` - Reading non-existent config
- `TestConfigWrite_Success` - Writing valid config
- `TestConfigWrite_MissingIssuer` - Validation of required fields
- `TestConfigRead_AfterWrite` - Reading after writing
- `TestConfigDelete` - Deleting config

**Test execution flow**:
1. **Write tests** (path_config_test.go)
2. **Verify tests fail**: `go test ./... -v` → FAIL (expected)
3. **Implement handlers** (path_config.go)
4. **Verify tests pass**: `go test ./... -v` → PASS

### Success Criteria:

#### Automated Verification:
- [ ] All tests pass: `go test -v ./...`
- [ ] Code compiles: `go build ./...`
- [ ] No linting errors: `go vet ./...`
- [ ] Test coverage > 80%: `go test -cover ./...`

#### Manual Verification:
- [ ] Config can be written via Vault CLI (after full integration)
- [ ] Config can be read via Vault CLI
- [ ] Config can be deleted via Vault CLI
- [ ] Signing key is never returned on read (security check)
- [ ] Missing required fields return helpful error messages

---

## Phase 4: Role Path

### Overview
Implement CRUD operations for `/role/:name` endpoint. Roles define how tokens are generated, including templates, TTL, and validation settings.

**TDD Approach**: Write tests for role operations before implementing handlers.

*[Implementation continues in next message due to length limits]*

### Changes Required:

#### 1. Role Struct and Storage Constants
**File**: `path_role.go` (new file)

**Purpose**: Define role structure

**Initial content**:
```go
package tokenexchange

import (
    "context"
    "fmt"
    "time"

    "github.com/hashicorp/vault/sdk/framework"
    "github.com/hashicorp/vault/sdk/logical"
)

// Role represents a token exchange role configuration
type Role struct {
    Name           string        `json:"name"`
    TTL            time.Duration `json:"ttl"`
    Template       string        `json:"template"`
    BoundAudiences []string      `json:"bound_audiences"`
    BoundIssuer    string        `json:"bound_issuer"`
}

const roleStoragePrefix = "roles/"
```

*[Continue with remaining phases...]*

---

## Testing Strategy

### Unit Tests:
All path handlers have corresponding test files:
- `backend_test.go` - Backend initialization
- `path_config_test.go` - Config CRUD operations
- `path_role_test.go` - Role CRUD operations (Phase 4)
- `path_token_test.go` - Token exchange logic (Phase 5)

### Integration Tests:
Using `logical.TestBackend()`:
- End-to-end configuration flow
- Role creation → Token generation flow
- Error handling across operations

### Manual Testing Steps:
After implementation complete:
1. Build plugin: `go build -o vault-plugin-token-exchange cmd/vault-plugin-token-exchange/main.go`
2. Start Vault dev: `vault server -dev -dev-plugin-dir=./`
3. Register plugin: `vault plugin register ...`
4. Enable plugin: `vault secrets enable -path=token-exchange ...`
5. Configure: `vault write token-exchange/config ...`
6. Create role: `vault write token-exchange/role/test ...`
7. Exchange token: `vault write token-exchange/token/test subject_token=...`
8. Verify JWT returned and valid

## Performance Considerations

Not a focus for scaffold phase, but considerations for future:
- **Storage**: Each role is a separate storage key (efficient for CRUD, may need caching for high-throughput)
- **JWT Signing**: RS256 signing is CPU-intensive (consider ECDSA for performance)
- **Template Processing**: Simple string replacement initially (may need optimization for complex templates)
- **Concurrency**: Backend uses RWMutex for safety (sufficient for scaffold, monitor in production)

## Migration Notes

N/A - This is a new plugin with no existing data to migrate.

## References

- Original ticket: N/A (ad-hoc plan)
- Research notes: `.docs/adhoc/vault-plugin-scaffold/vault-plugin-scaffold-research.md`
- Context: `.docs/adhoc/vault-plugin-scaffold/vault-plugin-scaffold-context.md`
- Tasks: `.docs/adhoc/vault-plugin-scaffold/vault-plugin-scaffold-tasks.md`
- Project guidelines: `CLAUDE.md`
- Vault identity engine: `github.com/hashicorp/vault/vault/identity_store_oidc.go`
- RFC 8693: OAuth 2.0 Token Exchange specification
- Vault Plugin Docs: https://developer.hashicorp.com/vault/docs/plugins
