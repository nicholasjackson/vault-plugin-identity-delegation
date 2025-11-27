# Key Management Implementation Plan

**Created**: 2025-11-26
**Last Updated**: 2025-11-26

## Overview

Implement named key management capabilities for the vault-plugin-token-exchange to support multiple signing keys, key rotation, and JWKS endpoint for public key distribution. This enables better key lifecycle management, supports multiple algorithms, and makes generated tokens easier to validate.

**Inspiration**: This design is inspired by Vault's identity/oidc token API but simplified to avoid complex auto-rotation infrastructure. We provide manual key management with JWKS support.

## Current State Analysis

The plugin currently uses a **single static RSA signing key** stored in the plugin configuration:

### Key Code Locations:

- [path_config.go:11-23](../../../path_config.go#L11-L23) - Config struct with `SigningKey` field
- [path_config_handlers.go:44-87](../../../path_config_handlers.go#L44-L87) - Config write handler
- [path_token_handlers.go:53-56](../../../path_token_handlers.go#L53-L56) - Key parsing
- [path_token_handlers.go:335-410](../../../path_token_handlers.go#L335-L410) - Token generation with signing

### Current Implementation:

```go
// From path_config.go:11-23
type Config struct {
    Issuer         string        `json:"issuer"`
    SigningKey     string        `json:"signing_key"` // Single PEM-encoded key
    DefaultTTL     time.Duration `json:"default_ttl"`
    SubjectJWKSURI string        `json:"subject_jwks_uri"`
}

// From path_token_handlers.go:337-340
// No kid (Key ID) in JWT header
signer, err := jose.NewSigner(
    jose.SigningKey{Algorithm: jose.RS256, Key: signingKey},
    (&jose.SignerOptions{}).WithType("JWT"),
)
```

### Current Limitations:

- ❌ **Single key only** - Cannot support multiple keys or rotation
- ❌ **No Key ID** - Generated JWTs don't include `kid` header for key identification
- ❌ **No JWKS endpoint** - Token consumers must manually configure public key
- ❌ **Algorithm hardcoded** - Only RS256, no support for RS384/RS512
- ❌ **No key metadata** - Cannot track creation date, version, or rotation history
- ❌ **No role-key binding** - All roles use the same global key

## Desired End State

After implementation:

1. **Multiple Named Keys**: Create and manage multiple keys via `/key/:name` endpoints
2. **Key IDs**: Each key has a unique ID included in JWT `kid` header
3. **Algorithm Selection**: Support RS256, RS384, and RS512 algorithms
4. **Role-Key Binding**: Roles reference keys by name
5. **JWKS Endpoint**: Public keys served at `/jwks` for validation
6. **Manual Rotation**: Rotate keys via `/key/:name/rotate` endpoint
7. **Backward Compatibility**: Existing config-based key continues to work

### Verification:

```bash
# Create a key
vault write token-exchange/key/my-key algorithm=RS256

# Create role using the key
vault write token-exchange/role/test-role \
    key=my-key \
    ttl=1h \
    ...

# Exchange token (JWT includes kid header)
vault write token-exchange/token/test-role subject_token="..."

# Fetch JWKS
curl http://vault:8200/v1/token-exchange/jwks
```

## What We're NOT Doing

- ❌ **Automatic rotation** - No background tasks or rotation_period
- ❌ **Verification TTL** - No keeping old keys available after rotation
- ❌ **ECDSA/EdDSA** - Limiting to RSA for Phase 1
- ❌ **Access control** - No `allowed_client_ids` restrictions
- ❌ **Key usage metrics** - No tracking of key usage or audit logging (beyond Vault's standard audit)
- ❌ **Replicating identity/oidc** - Using identity keys directly is not possible (see research notes)

## Implementation Approach

**Four-phase incremental approach** with TDD:

1. **Phase 1: Named Keys Storage** - Create key CRUD endpoints and storage
2. **Phase 2: Role-Key Binding** - Update roles to reference named keys
3. **Phase 3: Token Generation with kid** - Include kid in JWT headers
4. **Phase 4: JWKS Endpoint** - Serve public keys for validation

Each phase is independently testable and provides value. We follow Go TDD practices: write failing tests first, then implement.

---

## Phase 1: Named Keys Storage

### Overview

Create the foundation for named key management: storage structures, CRUD endpoints, and key generation.

**TDD Approach**: Write tests defining key struct, storage operations, and API responses before implementing handlers.

### Changes Required:

#### 1. Key Storage Structure

**File**: `key.go` (new file)
**Changes**: Create key struct and storage constants

**Proposed implementation:**

```go
package tokenexchange

import (
    "crypto/rand"
    "crypto/rsa"
    "crypto/x509"
    "encoding/pem"
    "fmt"
    "time"
)

// Key represents a named signing key
type Key struct {
    Name        string    `json:"name"`          // Key name (e.g., "prod-key")
    KeyID       string    `json:"key_id"`        // Unique identifier (kid)
    Algorithm   string    `json:"algorithm"`     // RS256, RS384, or RS512
    PrivateKey  string    `json:"private_key"`   // PEM-encoded RSA private key
    CreatedAt   time.Time `json:"created_at"`    // Creation timestamp
    RotatedAt   time.Time `json:"rotated_at"`    // Last rotation timestamp
    Version     int       `json:"version"`       // Key version (increments on rotation)
}

const (
    keyStoragePrefix = "keys/"

    // Supported algorithms
    AlgorithmRS256 = "RS256"
    AlgorithmRS384 = "RS384"
    AlgorithmRS512 = "RS512"

    // Default RSA key size
    DefaultKeySize = 2048
)

// generateKeyID creates a unique key ID
func generateKeyID(name string, version int) string {
    return fmt.Sprintf("%s-v%d", name, version)
}

// generateRSAKey generates a new RSA private key
func generateRSAKey(bits int) (*rsa.PrivateKey, error) {
    return rsa.GenerateKey(rand.Reader, bits)
}

// encodePrivateKeyPEM encodes RSA private key to PEM format
func encodePrivateKeyPEM(key *rsa.PrivateKey) string {
    keyBytes := x509.MarshalPKCS1PrivateKey(key)
    block := &pem.Block{
        Type:  "RSA PRIVATE KEY",
        Bytes: keyBytes,
    }
    return string(pem.EncodeToMemory(block))
}

// publicKeyFromPrivate extracts public key from private key
func publicKeyFromPrivate(privateKeyPEM string) (*rsa.PublicKey, error) {
    privateKey, err := parsePrivateKey(privateKeyPEM)
    if err != nil {
        return nil, err
    }
    return &privateKey.PublicKey, nil
}
```

**Reasoning**: Separate key struct from config enables multiple keys. Version tracking prepares for rotation. KeyID generation provides stable identifiers for JWKS.

#### 2. Key Path Definition

**File**: `path_key.go` (new file)
**Changes**: Define path patterns and field schemas for key endpoints

**Proposed implementation:**

```go
package tokenexchange

import (
    "github.com/hashicorp/vault/sdk/framework"
    "github.com/hashicorp/vault/sdk/logical"
)

// pathKey returns path configuration for /key/:name endpoint
func pathKey(b *Backend) *framework.Path {
    return &framework.Path{
        Pattern: "key/" + framework.GenericNameRegex("name"),

        ExistenceCheck: b.pathKeyExistenceCheck,

        Fields: map[string]*framework.FieldSchema{
            "name": {
                Type:        framework.TypeString,
                Description: "Name of the signing key",
                Required:    true,
            },
            "algorithm": {
                Type:        framework.TypeString,
                Description: "Signing algorithm: RS256, RS384, or RS512",
                Default:     AlgorithmRS256,
            },
            "key_size": {
                Type:        framework.TypeInt,
                Description: "RSA key size in bits (2048, 3072, or 4096)",
                Default:     DefaultKeySize,
            },
            "private_key": {
                Type:        framework.TypeString,
                Description: "Optional: Provide your own PEM-encoded RSA private key. If not provided, a key will be generated.",
                DisplayAttrs: &framework.DisplayAttributes{
                    Sensitive: true,
                },
            },
        },

        Operations: map[logical.Operation]framework.OperationHandler{
            logical.ReadOperation: &framework.PathOperation{
                Callback: b.pathKeyRead,
                Summary:  "Read a signing key's metadata (private key not returned)",
            },
            logical.UpdateOperation: &framework.PathOperation{
                Callback: b.pathKeyWrite,
                Summary:  "Create or update a signing key",
            },
            logical.CreateOperation: &framework.PathOperation{
                Callback: b.pathKeyWrite,
                Summary:  "Create a new signing key",
            },
            logical.DeleteOperation: &framework.PathOperation{
                Callback: b.pathKeyDelete,
                Summary:  "Delete a signing key",
            },
        },

        HelpSynopsis:    "Manage named signing keys for token generation",
        HelpDescription: "Create, read, and delete RSA signing keys. Keys can be auto-generated or provided. The private key is never returned in read operations.",
    }
}

// pathKeyList returns path configuration for /key endpoint (list)
func pathKeyList(b *Backend) *framework.Path {
    return &framework.Path{
        Pattern: "key/?$",

        Operations: map[logical.Operation]framework.OperationHandler{
            logical.ListOperation: &framework.PathOperation{
                Callback: b.pathKeyList,
                Summary:  "List all signing keys",
            },
        },

        HelpSynopsis:    "List signing keys",
        HelpDescription: "List all configured signing keys with metadata.",
    }
}
```

**Reasoning**: Follows existing plugin path patterns (config, role). Allows both auto-generation and user-provided keys for flexibility. Marks private_key as sensitive.

#### 3. Key CRUD Handlers

**File**: `path_key_handlers.go` (new file)
**Changes**: Implement create, read, update, delete, list operations

**Proposed implementation:**

```go
package tokenexchange

import (
    "context"
    "fmt"
    "time"

    "github.com/hashicorp/vault/sdk/framework"
    "github.com/hashicorp/vault/sdk/logical"
)

// pathKeyExistenceCheck checks if a key exists
func (b *Backend) pathKeyExistenceCheck(ctx context.Context, req *logical.Request, data *framework.FieldData) (bool, error) {
    name := data.Get("name").(string)
    key, err := b.getKey(ctx, req.Storage, name)
    if err != nil {
        return false, err
    }
    return key != nil, nil
}

// pathKeyRead handles reading a key's metadata
func (b *Backend) pathKeyRead(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
    name := data.Get("name").(string)

    key, err := b.getKey(ctx, req.Storage, name)
    if err != nil {
        return nil, err
    }

    if key == nil {
        return nil, nil
    }

    // Extract public key for response
    publicKey, err := publicKeyFromPrivate(key.PrivateKey)
    if err != nil {
        return nil, fmt.Errorf("failed to extract public key: %w", err)
    }

    // Encode public key to PEM
    pubKeyBytes := x509.MarshalPKCS1PublicKey(publicKey)
    pubKeyPEM := pem.EncodeToMemory(&pem.Block{
        Type:  "RSA PUBLIC KEY",
        Bytes: pubKeyBytes,
    })

    return &logical.Response{
        Data: map[string]any{
            "name":       key.Name,
            "key_id":     key.KeyID,
            "algorithm":  key.Algorithm,
            "public_key": string(pubKeyPEM),
            "created_at": key.CreatedAt.Format(time.RFC3339),
            "rotated_at": key.RotatedAt.Format(time.RFC3339),
            "version":    key.Version,
            // Note: private_key is NEVER returned
        },
    }, nil
}

// pathKeyWrite handles creating or updating a key
func (b *Backend) pathKeyWrite(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
    name := data.Get("name").(string)

    // Check if key already exists
    existingKey, err := b.getKey(ctx, req.Storage, name)
    if err != nil {
        return nil, err
    }

    if existingKey != nil {
        return logical.ErrorResponse("key %q already exists. To rotate, use POST /key/%s/rotate", name, name), nil
    }

    // Get algorithm
    algorithm := data.Get("algorithm").(string)
    if algorithm != AlgorithmRS256 && algorithm != AlgorithmRS384 && algorithm != AlgorithmRS512 {
        return logical.ErrorResponse("algorithm must be RS256, RS384, or RS512"), nil
    }

    // Get or generate private key
    var privateKeyPEM string
    if providedKey, ok := data.GetOk("private_key"); ok {
        // User provided key - validate it
        privateKeyPEM = providedKey.(string)
        _, err := parsePrivateKey(privateKeyPEM)
        if err != nil {
            return logical.ErrorResponse("invalid private_key: %v", err), nil
        }
    } else {
        // Generate new key
        keySize := data.Get("key_size").(int)
        if keySize != 2048 && keySize != 3072 && keySize != 4096 {
            return logical.ErrorResponse("key_size must be 2048, 3072, or 4096"), nil
        }

        privateKey, err := generateRSAKey(keySize)
        if err != nil {
            return nil, fmt.Errorf("failed to generate RSA key: %w", err)
        }

        privateKeyPEM = encodePrivateKeyPEM(privateKey)
    }

    // Create key object
    now := time.Now()
    key := &Key{
        Name:       name,
        KeyID:      generateKeyID(name, 1), // Version 1
        Algorithm:  algorithm,
        PrivateKey: privateKeyPEM,
        CreatedAt:  now,
        RotatedAt:  now,
        Version:    1,
    }

    // Store key
    entry, err := logical.StorageEntryJSON(keyStoragePrefix+name, key)
    if err != nil {
        return nil, fmt.Errorf("failed to create storage entry: %w", err)
    }

    if err := req.Storage.Put(ctx, entry); err != nil {
        return nil, fmt.Errorf("failed to write key: %w", err)
    }

    return &logical.Response{
        Data: map[string]any{
            "name":    key.Name,
            "key_id":  key.KeyID,
            "version": key.Version,
        },
    }, nil
}

// pathKeyDelete handles deleting a key
func (b *Backend) pathKeyDelete(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
    name := data.Get("name").(string)

    // Check if any roles use this key (Phase 2 addition)
    // For now, just delete

    if err := req.Storage.Delete(ctx, keyStoragePrefix+name); err != nil {
        return nil, fmt.Errorf("failed to delete key: %w", err)
    }

    return nil, nil
}

// pathKeyList handles listing all keys
func (b *Backend) pathKeyList(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
    keys, err := req.Storage.List(ctx, keyStoragePrefix)
    if err != nil {
        return nil, fmt.Errorf("failed to list keys: %w", err)
    }

    if len(keys) == 0 {
        return nil, nil
    }

    return logical.ListResponse(keys), nil
}

// getKey retrieves a key from storage (helper)
func (b *Backend) getKey(ctx context.Context, storage logical.Storage, name string) (*Key, error) {
    entry, err := storage.Get(ctx, keyStoragePrefix+name)
    if err != nil {
        return nil, fmt.Errorf("failed to read key: %w", err)
    }

    if entry == nil {
        return nil, nil
    }

    key := &Key{}
    if err := entry.DecodeJSON(key); err != nil {
        return nil, fmt.Errorf("failed to decode key: %w", err)
    }

    return key, nil
}
```

**Reasoning**: Read operations never return private keys (security). Auto-generation makes key management easy. Prevents accidental overwrite by requiring explicit rotation endpoint. Follows storage patterns from existing handlers.

#### 4. Register Key Paths in Backend

**File**: `backend.go:45-50`
**Changes**: Add key paths to path registration

**Current code:**
```go
// From backend.go:45-50
Paths: []*framework.Path{
    pathConfig(b),
    pathRole(b),
    pathRoleList(b),
    pathToken(b),
},
```

**Proposed changes:**
```go
// backend.go:45-52
Paths: []*framework.Path{
    pathConfig(b),
    pathRole(b),
    pathRoleList(b),
    pathToken(b),
    pathKey(b),        // New: key CRUD
    pathKeyList(b),    // New: key listing
},
```

**Reasoning**: Follows existing pattern for path registration. Order matches plugin hierarchy.

#### 5. Add Keys to Seal-Wrap Storage

**File**: `backend.go:54-57`
**Changes**: Mark keys/* for seal-wrap encryption

**Current code:**
```go
// From backend.go:54-57
PathsSpecial: &logical.Paths{
    SealWrapStorage: []string{
        "config",  // Config contains signing keys
        "roles/*", // Roles may contain sensitive templates
    },
},
```

**Proposed changes:**
```go
// backend.go:54-58
PathsSpecial: &logical.Paths{
    SealWrapStorage: []string{
        "config",  // Config contains signing keys
        "roles/*", // Roles may contain sensitive templates
        "keys/*",  // Named keys contain private keys (NEW)
    },
},
```

**Reasoning**: Private keys must be encrypted at rest. Seal-wrap provides Vault's strongest storage encryption.

### Testing for This Phase:

**IMPORTANT: Write failing tests BEFORE implementing code changes (TDD approach)**

#### Test File: `key_test.go` (new file)

1. **First, write the tests** that define expected behavior:

```go
package tokenexchange

import (
    "context"
    "testing"
    "time"

    "github.com/hashicorp/vault/sdk/logical"
    "github.com/stretchr/testify/require"
)

func TestPathKeyWrite_AutoGenerate(t *testing.T) {
    // This test should FAIL initially (key.go doesn't exist yet)
    b, storage := getTestBackend(t)

    req := &logical.Request{
        Operation: logical.CreateOperation,
        Path:      "key/test-key",
        Storage:   storage,
        Data: map[string]any{
            "algorithm": "RS256",
            "key_size":  2048,
        },
    }

    resp, err := b.HandleRequest(context.Background(), req)
    require.NoError(t, err)
    require.NotNil(t, resp)
    require.Equal(t, "test-key", resp.Data["name"])
    require.Equal(t, "test-key-v1", resp.Data["key_id"])
    require.Equal(t, 1, resp.Data["version"])
}

func TestPathKeyWrite_ProvidedKey(t *testing.T) {
    // Test with user-provided private key
    b, storage := getTestBackend(t)

    privateKey, privateKeyPEM := generateTestKeyPair(t)

    req := &logical.Request{
        Operation: logical.CreateOperation,
        Path:      "key/custom-key",
        Storage:   storage,
        Data: map[string]any{
            "algorithm":   "RS256",
            "private_key": privateKeyPEM,
        },
    }

    resp, err := b.HandleRequest(context.Background(), req)
    require.NoError(t, err)
    require.NotNil(t, resp)
    require.Equal(t, "custom-key-v1", resp.Data["key_id"])
}

func TestPathKeyWrite_InvalidAlgorithm(t *testing.T) {
    // Negative test: invalid algorithm
    b, storage := getTestBackend(t)

    req := &logical.Request{
        Operation: logical.CreateOperation,
        Path:      "key/bad-key",
        Storage:   storage,
        Data: map[string]any{
            "algorithm": "ES256", // Not supported in Phase 1
        },
    }

    resp, err := b.HandleRequest(context.Background(), req)
    require.NoError(t, err)
    require.True(t, resp.IsError())
    require.Contains(t, resp.Error().Error(), "must be RS256, RS384, or RS512")
}

func TestPathKeyRead(t *testing.T) {
    // Test reading key metadata
    b, storage := getTestBackend(t)

    // Create key first
    createReq := &logical.Request{
        Operation: logical.CreateOperation,
        Path:      "key/read-test",
        Storage:   storage,
        Data: map[string]any{
            "algorithm": "RS256",
        },
    }
    _, err := b.HandleRequest(context.Background(), createReq)
    require.NoError(t, err)

    // Read key
    readReq := &logical.Request{
        Operation: logical.ReadOperation,
        Path:      "key/read-test",
        Storage:   storage,
    }

    resp, err := b.HandleRequest(context.Background(), readReq)
    require.NoError(t, err)
    require.NotNil(t, resp)
    require.Equal(t, "read-test", resp.Data["name"])
    require.Equal(t, "RS256", resp.Data["algorithm"])
    require.Contains(t, resp.Data, "public_key")
    require.NotContains(t, resp.Data, "private_key") // MUST NOT return private key
}

func TestPathKeyList(t *testing.T) {
    // Test listing keys
    b, storage := getTestBackend(t)

    // Create multiple keys
    for _, name := range []string{"key1", "key2", "key3"} {
        req := &logical.Request{
            Operation: logical.CreateOperation,
            Path:      "key/" + name,
            Storage:   storage,
            Data: map[string]any{
                "algorithm": "RS256",
            },
        }
        _, err := b.HandleRequest(context.Background(), req)
        require.NoError(t, err)
    }

    // List keys
    listReq := &logical.Request{
        Operation: logical.ListOperation,
        Path:      "key/",
        Storage:   storage,
    }

    resp, err := b.HandleRequest(context.Background(), listReq)
    require.NoError(t, err)
    require.NotNil(t, resp)
    require.Len(t, resp.Data["keys"], 3)
}

func TestPathKeyDelete(t *testing.T) {
    // Test deleting a key
    b, storage := getTestBackend(t)

    // Create key
    createReq := &logical.Request{
        Operation: logical.CreateOperation,
        Path:      "key/delete-me",
        Storage:   storage,
        Data: map[string]any{
            "algorithm": "RS256",
        },
    }
    _, err := b.HandleRequest(context.Background(), req)
    require.NoError(t, err)

    // Delete key
    deleteReq := &logical.Request{
        Operation: logical.DeleteOperation,
        Path:      "key/delete-me",
        Storage:   storage,
    }

    resp, err := b.HandleRequest(context.Background(), deleteReq)
    require.NoError(t, err)
    require.Nil(t, resp)

    // Verify key is gone
    readReq := &logical.Request{
        Operation: logical.ReadOperation,
        Path:      "key/delete-me",
        Storage:   storage,
    }

    resp, err = b.HandleRequest(context.Background(), readReq)
    require.NoError(t, err)
    require.Nil(t, resp)
}

func TestPathKeyWrite_DuplicateName(t *testing.T) {
    // Negative test: prevent duplicate key names
    b, storage := getTestBackend(t)

    req := &logical.Request{
        Operation: logical.CreateOperation,
        Path:      "key/dup-key",
        Storage:   storage,
        Data: map[string]any{
            "algorithm": "RS256",
        },
    }

    // First creation should succeed
    resp, err := b.HandleRequest(context.Background(), req)
    require.NoError(t, err)
    require.NotNil(t, resp)

    // Second creation should fail
    resp, err = b.HandleRequest(context.Background(), req)
    require.NoError(t, err)
    require.True(t, resp.IsError())
    require.Contains(t, resp.Error().Error(), "already exists")
}
```

2. **Verify tests fail**: Run tests to confirm they fail with expected errors (files don't exist)
```bash
go test -v -run TestPathKey
```

3. **Then implement the code** following the plan above

4. **Verify tests pass**: Confirm implementation satisfies all test cases
```bash
go test -v -run TestPathKey
```

### Success Criteria:

#### Automated Verification:
- [ ] All key tests pass: `go test -v -run TestPathKey`
- [ ] Type checking passes: `go vet ./...`
- [ ] Linting passes: `golangci-lint run`
- [ ] Test coverage > 80% for key handlers: `go test -cover`
- [ ] No goroutine leaks: `go test -race`

#### Manual Verification:
- [ ] Create key via Vault CLI: `vault write token-exchange/key/test algorithm=RS256`
- [ ] List keys: `vault list token-exchange/key`
- [ ] Read key metadata: `vault read token-exchange/key/test`
- [ ] Verify private key NOT in response
- [ ] Delete key: `vault delete token-exchange/key/test`
- [ ] Verify key is gone after delete

---

## Phase 2: Role-Key Binding

### Overview

Update role configuration to reference named keys instead of using the global config key. Maintain backward compatibility with config-based keys.

**TDD Approach**: Write tests for role-key binding before modifying role handlers.

### Changes Required:

#### 1. Update Role Struct

**File**: `path_role.go:11-19`
**Changes**: Add key reference field to Role struct

**Current code:**
```go
// From path_role.go:11-19
type Role struct {
    Name            string        `json:"name"`
    TTL             time.Duration `json:"ttl"`
    BoundAudiences  []string      `json:"bound_audiences"`
    BoundIssuer     string        `json:"bound_issuer"`
    ActorTemplate   string        `json:"actor_template"`
    SubjectTemplate string        `json:"subject_template"`
    Context         []string      `json:"context"`
}
```

**Proposed changes:**
```go
// path_role.go:11-20
type Role struct {
    Name            string        `json:"name"`
    TTL             time.Duration `json:"ttl"`
    BoundAudiences  []string      `json:"bound_audiences"`
    BoundIssuer     string        `json:"bound_issuer"`
    ActorTemplate   string        `json:"actor_template"`
    SubjectTemplate string        `json:"subject_template"`
    Context         []string      `json:"context"`
    Key             string        `json:"key"` // NEW: reference to named key (optional)
}
```

**Reasoning**: Adding optional Key field maintains backward compatibility (if empty, falls back to config key).

#### 2. Add Key Field to Role Path

**File**: `path_role.go:30-64`
**Changes**: Add key field schema

**Current code:**
```go
// path_role.go:30-64 (partial)
Fields: map[string]*framework.FieldSchema{
    "name": {...},
    "ttl": {...},
    // ... other fields ...
},
```

**Proposed changes:**
```go
// path_role.go:30-68
Fields: map[string]*framework.FieldSchema{
    "name": {...},
    "ttl": {...},
    "bound_audiences": {...},
    "bound_issuer": {...},
    "actor_template": {...},
    "subject_template": {...},
    "context": {...},
    "key": {  // NEW
        Type:        framework.TypeString,
        Description: "Name of the signing key to use for this role. If not specified, uses the key from plugin configuration.",
    },
},
```

**Reasoning**: Makes key selection explicit and discoverable in API documentation.

#### 3. Update Role Write Handler

**File**: `path_role_handlers.go:49-105`
**Changes**: Handle key field, validate key exists

**Current code:**
```go
// From path_role_handlers.go:49-105
func (b *Backend) pathRoleWrite(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
    name := data.Get("name").(string)

    role := &Role{
        Name: name,
    }

    // Get TTL (required)
    ttl, ok := data.GetOk("ttl")
    // ... rest of handler ...
}
```

**Proposed changes:**
```go
// path_role_handlers.go:49-125 (updated)
func (b *Backend) pathRoleWrite(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
    name := data.Get("name").(string)

    role := &Role{
        Name: name,
    }

    // Get TTL (required)
    ttl, ok := data.GetOk("ttl")
    if !ok {
        return logical.ErrorResponse("ttl is required"), nil
    }
    role.TTL = time.Duration(ttl.(int)) * time.Second

    // ... existing field handling ...

    // Get key reference (optional) - NEW
    if keyName, ok := data.GetOk("key"); ok {
        keyNameStr := keyName.(string)

        // Validate key exists
        key, err := b.getKey(ctx, req.Storage, keyNameStr)
        if err != nil {
            return nil, fmt.Errorf("failed to validate key: %w", err)
        }
        if key == nil {
            return logical.ErrorResponse("key %q not found", keyNameStr), nil
        }

        role.Key = keyNameStr
    }

    // ... rest of handler ...

    // Store role
    entry, err := logical.StorageEntryJSON(roleStoragePrefix+name, role)
    if err != nil {
        return nil, fmt.Errorf("failed to create storage entry: %w", err)
    }

    if err := req.Storage.Put(ctx, entry); err != nil {
        return nil, fmt.Errorf("failed to write role: %w", err)
    }

    return nil, nil
}
```

**Reasoning**: Validates key exists at role creation time. Prevents broken role configurations. Optional field allows gradual migration.

#### 4. Update Role Read Handler

**File**: `path_role_handlers.go:23-47`
**Changes**: Return key field in response

**Current code:**
```go
// From path_role_handlers.go:36-46
return &logical.Response{
    Data: map[string]any{
        "name":             role.Name,
        "ttl":              role.TTL.String(),
        "bound_audiences":  role.BoundAudiences,
        "bound_issuer":     role.BoundIssuer,
        "actor_template":   role.ActorTemplate,
        "subject_template": role.SubjectTemplate,
        "context":          role.Context,
    },
}, nil
```

**Proposed changes:**
```go
// path_role_handlers.go:36-47
return &logical.Response{
    Data: map[string]any{
        "name":             role.Name,
        "ttl":              role.TTL.String(),
        "bound_audiences":  role.BoundAudiences,
        "bound_issuer":     role.BoundIssuer,
        "actor_template":   role.ActorTemplate,
        "subject_template": role.SubjectTemplate,
        "context":          role.Context,
        "key":              role.Key, // NEW: include key reference
    },
}, nil
```

**Reasoning**: Shows which key the role uses. Aids debugging and auditing.

### Testing for This Phase:

**Test File**: `path_role_test.go` (update existing)

```go
func TestPathRoleWrite_WithKey(t *testing.T) {
    // Test role with named key reference
    b, storage := getTestBackend(t)

    // Create key first
    keyReq := &logical.Request{
        Operation: logical.CreateOperation,
        Path:      "key/role-key",
        Storage:   storage,
        Data: map[string]any{
            "algorithm": "RS256",
        },
    }
    _, err := b.HandleRequest(context.Background(), keyReq)
    require.NoError(t, err)

    // Create role referencing key
    roleReq := &logical.Request{
        Operation: logical.CreateOperation,
        Path:      "role/test-role",
        Storage:   storage,
        Data: map[string]any{
            "name":             "test-role",
            "ttl":              "1h",
            "key":              "role-key", // Reference named key
            "actor_template":   `{"act": {"sub": "test"}}`,
            "subject_template": `{}`,
            "context":          []string{"scope1"},
        },
    }

    resp, err := b.HandleRequest(context.Background(), roleReq)
    require.NoError(t, err)
    require.Nil(t, resp)

    // Read back and verify key field
    readReq := &logical.Request{
        Operation: logical.ReadOperation,
        Path:      "role/test-role",
        Storage:   storage,
    }

    resp, err = b.HandleRequest(context.Background(), readReq)
    require.NoError(t, err)
    require.Equal(t, "role-key", resp.Data["key"])
}

func TestPathRoleWrite_InvalidKey(t *testing.T) {
    // Negative test: reference non-existent key
    b, storage := getTestBackend(t)

    roleReq := &logical.Request{
        Operation: logical.CreateOperation,
        Path:      "role/bad-role",
        Storage:   storage,
        Data: map[string]any{
            "name":             "bad-role",
            "ttl":              "1h",
            "key":              "nonexistent-key",
            "actor_template":   `{}`,
            "subject_template": `{}`,
            "context":          []string{"scope1"},
        },
    }

    resp, err := b.HandleRequest(context.Background(), roleReq)
    require.NoError(t, err)
    require.True(t, resp.IsError())
    require.Contains(t, resp.Error().Error(), "not found")
}

func TestPathRoleWrite_WithoutKey(t *testing.T) {
    // Test backward compatibility: role without key field
    b, storage := getTestBackend(t)

    // Setup config with signing key
    configReq := &logical.Request{
        Operation: logical.UpdateOperation,
        Path:      "config",
        Storage:   storage,
        Data: map[string]any{
            "issuer":           "https://vault.example.com",
            "signing_key":      testRSAPrivateKey,
            "subject_jwks_uri": "https://example.com/.well-known/jwks.json",
        },
    }
    _, err := b.HandleRequest(context.Background(), configReq)
    require.NoError(t, err)

    // Create role without key field
    roleReq := &logical.Request{
        Operation: logical.CreateOperation,
        Path:      "role/legacy-role",
        Storage:   storage,
        Data: map[string]any{
            "name":             "legacy-role",
            "ttl":              "1h",
            // No "key" field
            "actor_template":   `{}`,
            "subject_template": `{}`,
            "context":          []string{"scope1"},
        },
    }

    resp, err := b.HandleRequest(context.Background(), roleReq)
    require.NoError(t, err)
    require.Nil(t, resp)

    // Should fall back to config key in Phase 3
}
```

### Success Criteria:

#### Automated Verification:
- [ ] Role tests pass: `go test -v -run TestPathRole`
- [ ] Type checking passes: `go vet ./...`
- [ ] Existing role tests still pass (backward compatibility)
- [ ] Test coverage maintained

#### Manual Verification:
- [ ] Create key: `vault write token-exchange/key/prod algorithm=RS256`
- [ ] Create role with key: `vault write token-exchange/role/test ttl=1h key=prod ...`
- [ ] Read role: `vault read token-exchange/role/test` shows `key=prod`
- [ ] Create role without key (backward compat): works with config key
- [ ] Attempt to use non-existent key: returns error

---

## Phase 3: Token Generation with kid

### Overview

Update token generation to use role-specified keys and include `kid` (Key ID) in JWT header. Maintain backward compatibility with config-based keys.

**TDD Approach**: Write tests for token generation with kid before modifying token handler.

### Changes Required:

#### 1. Key Selection Logic

**File**: `path_token_handlers.go:23-125`
**Changes**: Determine which key to use based on role configuration

**Current code:**
```go
// From path_token_handlers.go:44-56
// Load config
config, err := b.getConfig(ctx, req.Storage)
if err != nil {
    return nil, err
}
if config == nil {
    return logical.ErrorResponse("plugin not configured"), nil
}

// Parse signing key
signingKey, err := parsePrivateKey(config.SigningKey)
if err != nil {
    return nil, fmt.Errorf("failed to parse signing key: %w", err)
}
```

**Proposed changes:**
```go
// path_token_handlers.go:44-80 (updated)
// Determine which key to use
var signingKey *rsa.PrivateKey
var keyID string
var algorithm jose.SignatureAlgorithm

if role.Key != "" {
    // Use role-specified named key
    key, err := b.getKey(ctx, req.Storage, role.Key)
    if err != nil {
        return nil, fmt.Errorf("failed to load key %q: %w", role.Key, err)
    }
    if key == nil {
        return logical.ErrorResponse("key %q not found", role.Key), nil
    }

    // Parse private key
    signingKey, err = parsePrivateKey(key.PrivateKey)
    if err != nil {
        return nil, fmt.Errorf("failed to parse signing key: %w", err)
    }

    keyID = key.KeyID

    // Map algorithm string to jose constant
    switch key.Algorithm {
    case AlgorithmRS256:
        algorithm = jose.RS256
    case AlgorithmRS384:
        algorithm = jose.RS384
    case AlgorithmRS512:
        algorithm = jose.RS512
    default:
        return nil, fmt.Errorf("unsupported algorithm: %s", key.Algorithm)
    }
} else {
    // Fall back to config key (backward compatibility)
    config, err := b.getConfig(ctx, req.Storage)
    if err != nil {
        return nil, err
    }
    if config == nil {
        return logical.ErrorResponse("plugin not configured and role has no key"), nil
    }

    signingKey, err = parsePrivateKey(config.SigningKey)
    if err != nil {
        return nil, fmt.Errorf("failed to parse signing key: %w", err)
    }

    keyID = "config-key" // Default kid for config-based key
    algorithm = jose.RS256 // Config uses RS256
}

// Continue with existing validation logic...
```

**Reasoning**: Role key takes precedence, config key is fallback. Provides smooth migration path. Algorithm comes from key metadata.

#### 2. Update Token Generation to Include kid

**File**: `path_token_handlers.go:335-410`
**Changes**: Pass keyID to token generation and include in JWT header

**Current code:**
```go
// From path_token_handlers.go:115-118
// Generate new token
newToken, err := generateToken(config, role, originalSubjectClaims["sub"].(string), actorClaims, subjectClaims, signingKey, req.EntityID)
if err != nil {
    return nil, fmt.Errorf("failed to generate token: %w", err)
}
```

**Proposed changes:**
```go
// path_token_handlers.go:115-118 (updated)
// Generate new token with keyID
newToken, err := generateToken(config, role, originalSubjectClaims["sub"].(string), actorClaims, subjectClaims, signingKey, keyID, algorithm, req.EntityID)
if err != nil {
    return nil, fmt.Errorf("failed to generate token: %w", err)
}
```

#### 3. Update generateToken Function Signature

**File**: `path_token_handlers.go:334-410`
**Changes**: Accept keyID and algorithm, include kid in JWT header

**Current code:**
```go
// From path_token_handlers.go:334-343
func generateToken(config *Config, role *Role, subjectID string, actorClaims, subjectClaims map[string]any, signingKey *rsa.PrivateKey, entityID string) (string, error) {
    // Create signer
    signer, err := jose.NewSigner(
        jose.SigningKey{Algorithm: jose.RS256, Key: signingKey},
        (&jose.SignerOptions{}).WithType("JWT"),
    )
    if err != nil {
        return "", fmt.Errorf("failed to create signer: %w", err)
    }
```

**Proposed changes:**
```go
// path_token_handlers.go:334-345 (updated)
func generateToken(config *Config, role *Role, subjectID string, actorClaims, subjectClaims map[string]any, signingKey *rsa.PrivateKey, keyID string, algorithm jose.SignatureAlgorithm, entityID string) (string, error) {
    // Create signer with kid in header
    signerOpts := (&jose.SignerOptions{}).WithType("JWT")

    if keyID != "" {
        signerOpts = signerOpts.WithHeader("kid", keyID) // NEW: include kid
    }

    signer, err := jose.NewSigner(
        jose.SigningKey{Algorithm: algorithm, Key: signingKey}, // Use role's algorithm
        signerOpts,
    )
    if err != nil {
        return "", fmt.Errorf("failed to create signer: %w", err)
    }

    // Rest of function unchanged...
```

**Reasoning**: kid header enables JWKS-based validation. Algorithm flexibility supports RS384/RS512. Empty keyID preserves backward compatibility.

### Testing for This Phase:

**Test File**: `path_token_test.go` (update existing)

```go
func TestPathTokenExchange_WithNamedKey(t *testing.T) {
    // Test token exchange using named key
    b, storage := getTestBackend(t)

    // Setup: Create key
    privateKey, privateKeyPEM := generateTestKeyPair(t)
    publicKey := &privateKey.PublicKey

    keyReq := &logical.Request{
        Operation: logical.CreateOperation,
        Path:      "key/token-key",
        Storage:   storage,
        Data: map[string]any{
            "algorithm":   "RS256",
            "private_key": privateKeyPEM,
        },
    }
    keyResp, err := b.HandleRequest(context.Background(), keyReq)
    require.NoError(t, err)

    keyID := keyResp.Data["key_id"].(string) // e.g., "token-key-v1"

    // Setup: Create JWKS server
    jwksServer := createMockJWKSServer(t, publicKey, keyID)
    defer jwksServer.Close()

    // Setup: Create config
    configReq := &logical.Request{
        Operation: logical.UpdateOperation,
        Path:      "config",
        Storage:   storage,
        Data: map[string]any{
            "issuer":           "https://vault.example.com",
            "subject_jwks_uri": jwksServer.URL,
            "default_ttl":      "1h",
        },
    }
    _, err = b.HandleRequest(context.Background(), configReq)
    require.NoError(t, err)

    // Setup: Create role with named key
    roleReq := &logical.Request{
        Operation: logical.CreateOperation,
        Path:      "role/test-role",
        Storage:   storage,
        Data: map[string]any{
            "name":             "test-role",
            "ttl":              "1h",
            "key":              "token-key",
            "actor_template":   `{"act": {"sub": "agent"}}`,
            "subject_template": `{}`,
            "context":          []string{"scope1"},
        },
    }
    _, err = b.HandleRequest(context.Background(), roleReq)
    require.NoError(t, err)

    // Create subject token
    subjectToken := generateTestJWT(t, privateKey, keyID, map[string]any{
        "sub": "user123",
        "iss": "https://example.com",
        "aud": []string{"test"},
        "exp": time.Now().Add(1 * time.Hour).Unix(),
    })

    // Exchange token
    tokenReq := &logical.Request{
        Operation: logical.UpdateOperation,
        Path:      "token/test-role",
        Storage:   storage,
        EntityID:  "test-entity",
        Data: map[string]any{
            "subject_token": subjectToken,
        },
    }

    resp, err := b.HandleRequest(context.Background(), tokenReq)
    require.NoError(t, err)
    require.NotNil(t, resp)

    // Parse generated token
    generatedToken := resp.Data["token"].(string)
    parsedToken, err := jwt.ParseSigned(generatedToken, []jose.SignatureAlgorithm{jose.RS256})
    require.NoError(t, err)

    // Verify kid in header
    require.Equal(t, keyID, parsedToken.Headers[0].KeyID)

    // Verify signature with public key
    claims := make(map[string]any)
    err = parsedToken.Claims(publicKey, &claims)
    require.NoError(t, err)

    // Verify claims
    require.Equal(t, "https://vault.example.com", claims["iss"])
    require.Equal(t, "user123", claims["sub"])
    require.Contains(t, claims, "act")
}

func TestPathTokenExchange_WithConfigKey(t *testing.T) {
    // Test backward compatibility: token exchange with config key
    b, storage := getTestBackend(t)

    privateKey, privateKeyPEM := generateTestKeyPair(t)
    publicKey := &privateKey.PublicKey
    kid := "config-key"

    jwksServer := createMockJWKSServer(t, publicKey, kid)
    defer jwksServer.Close()

    // Setup config with signing key
    configReq := &logical.Request{
        Operation: logical.UpdateOperation,
        Path:      "config",
        Storage:   storage,
        Data: map[string]any{
            "issuer":           "https://vault.example.com",
            "signing_key":      privateKeyPEM,
            "subject_jwks_uri": jwksServer.URL,
        },
    }
    _, err := b.HandleRequest(context.Background(), configReq)
    require.NoError(t, err)

    // Create role WITHOUT key field (uses config key)
    roleReq := &logical.Request{
        Operation: logical.CreateOperation,
        Path:      "role/legacy-role",
        Storage:   storage,
        Data: map[string]any{
            "name":             "legacy-role",
            "ttl":              "1h",
            // No "key" field
            "actor_template":   `{}`,
            "subject_template": `{}`,
            "context":          []string{"scope1"},
        },
    }
    _, err = b.HandleRequest(context.Background(), roleReq)
    require.NoError(t, err)

    // Exchange token
    subjectToken := generateTestJWT(t, privateKey, kid, map[string]any{
        "sub": "user123",
        "iss": "https://example.com",
        "exp": time.Now().Add(1 * time.Hour).Unix(),
    })

    tokenReq := &logical.Request{
        Operation: logical.UpdateOperation,
        Path:      "token/legacy-role",
        Storage:   storage,
        EntityID:  "test-entity",
        Data: map[string]any{
            "subject_token": subjectToken,
        },
    }

    resp, err := b.HandleRequest(context.Background(), tokenReq)
    require.NoError(t, err)
    require.NotNil(t, resp)

    // Parse token
    generatedToken := resp.Data["token"].(string)
    parsedToken, err := jwt.ParseSigned(generatedToken, []jose.SignatureAlgorithm{jose.RS256})
    require.NoError(t, err)

    // Verify kid header (should be "config-key")
    require.Equal(t, "config-key", parsedToken.Headers[0].KeyID)
}

func TestPathTokenExchange_RS384(t *testing.T) {
    // Test RS384 algorithm
    b, storage := getTestBackend(t)

    // Create RS384 key
    privateKey, privateKeyPEM := generateTestKeyPair(t)

    keyReq := &logical.Request{
        Operation: logical.CreateOperation,
        Path:      "key/rs384-key",
        Storage:   storage,
        Data: map[string]any{
            "algorithm":   "RS384",
            "private_key": privateKeyPEM,
        },
    }
    keyResp, err := b.HandleRequest(context.Background(), keyReq)
    require.NoError(t, err)

    keyID := keyResp.Data["key_id"].(string)

    // ... setup config, role, exchange token ...

    // Verify algorithm in JWT
    parsedToken, err := jwt.ParseSigned(generatedToken, []jose.SignatureAlgorithm{jose.RS384})
    require.NoError(t, err)
    require.Equal(t, "RS384", parsedToken.Headers[0].Algorithm)
}
```

### Success Criteria:

#### Automated Verification:
- [ ] Token tests pass: `go test -v -run TestPathToken`
- [ ] Kid included in generated JWTs
- [ ] Backward compatibility tests pass (config key still works)
- [ ] All algorithms (RS256/RS384/RS512) tested
- [ ] Type checking passes: `go vet ./...`

#### Manual Verification:
- [ ] Create key and role: `vault write token-exchange/key/test algorithm=RS256`
- [ ] Exchange token: `vault write token-exchange/token/test-role subject_token="..."`
- [ ] Decode JWT and verify kid header: `jwt decode <token>`
- [ ] Verify signature validates with public key from key endpoint
- [ ] Test with RS384 and RS512 algorithms
- [ ] Test fallback to config key (create role without key field)

---

## Phase 4: JWKS Endpoint

### Overview

Add a JWKS (JSON Web Key Set) endpoint to serve public keys for token validation. This enables token consumers to automatically discover and rotate keys.

**TDD Approach**: Write tests for JWKS endpoint before implementing.

### Changes Required:

#### 1. JWKS Path Definition

**File**: `path_jwks.go` (new file)
**Changes**: Define JWKS endpoint

**Proposed implementation:**

```go
package tokenexchange

import (
    "github.com/hashicorp/vault/sdk/framework"
    "github.com/hashicorp/vault/sdk/logical"
)

// pathJWKS returns path configuration for /jwks endpoint
func pathJWKS(b *Backend) *framework.Path {
    return &framework.Path{
        Pattern: "jwks/?$",

        Fields: map[string]*framework.FieldSchema{
            "kid": {
                Type:        framework.TypeString,
                Description: "Optional: Filter by Key ID",
                Query:       true,
            },
        },

        Operations: map[logical.Operation]framework.OperationHandler{
            logical.ReadOperation: &framework.PathOperation{
                Callback: b.pathJWKSRead,
                Summary:  "Get public keys in JWKS format",
                Responses: map[int][]framework.Response{
                    200: {{
                        Description: "JWKS response",
                        Example: &logical.Response{
                            Data: map[string]any{
                                "keys": []any{
                                    map[string]any{
                                        "kty": "RSA",
                                        "use": "sig",
                                        "kid": "my-key-v1",
                                        "alg": "RS256",
                                        "n":   "...",
                                        "e":   "AQAB",
                                    },
                                },
                            },
                        },
                    }},
                },
            },
        },

        HelpSynopsis:    "JSON Web Key Set endpoint",
        HelpDescription: "Returns all public keys in JWKS format for JWT signature validation. Follows RFC 7517.",
    }
}
```

**Reasoning**: Standard JWKS endpoint pattern. Optional kid filter for specific key lookup. Read-only (GET) operation.

#### 2. JWKS Handler Implementation

**File**: `path_jwks_handlers.go` (new file)
**Changes**: Implement JWKS response generation

**Proposed implementation:**

```go
package tokenexchange

import (
    "context"
    "crypto/rsa"
    "crypto/x509"
    "encoding/base64"
    "encoding/pem"
    "fmt"
    "math/big"

    "github.com/hashicorp/vault/sdk/framework"
    "github.com/hashicorp/vault/sdk/logical"
)

// pathJWKSRead handles JWKS requests
func (b *Backend) pathJWKSRead(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
    // Optional: filter by kid
    filterKID := ""
    if kid, ok := data.GetOk("kid"); ok {
        filterKID = kid.(string)
    }

    // List all keys
    keyNames, err := req.Storage.List(ctx, keyStoragePrefix)
    if err != nil {
        return nil, fmt.Errorf("failed to list keys: %w", err)
    }

    if len(keyNames) == 0 {
        // No keys configured, return empty JWKS
        return &logical.Response{
            Data: map[string]any{
                "keys": []any{},
            },
        }, nil
    }

    // Build JWKS
    jwks := []any{}

    for _, keyName := range keyNames {
        key, err := b.getKey(ctx, req.Storage, keyName)
        if err != nil {
            b.Logger().Warn("failed to read key for JWKS", "key", keyName, "error", err)
            continue
        }

        if key == nil {
            continue
        }

        // Filter by kid if specified
        if filterKID != "" && key.KeyID != filterKID {
            continue
        }

        // Extract public key
        publicKey, err := publicKeyFromPrivate(key.PrivateKey)
        if err != nil {
            b.Logger().Warn("failed to extract public key", "key", keyName, "error", err)
            continue
        }

        // Convert to JWK format
        jwk, err := rsaPublicKeyToJWK(publicKey, key.KeyID, key.Algorithm)
        if err != nil {
            b.Logger().Warn("failed to convert to JWK", "key", keyName, "error", err)
            continue
        }

        jwks = append(jwks, jwk)
    }

    return &logical.Response{
        Data: map[string]any{
            "keys": jwks,
        },
    }, nil
}

// rsaPublicKeyToJWK converts RSA public key to JWK format (RFC 7517)
func rsaPublicKeyToJWK(pubKey *rsa.PublicKey, kid string, algorithm string) (map[string]any, error) {
    // Encode modulus (n) and exponent (e) to base64url
    nBytes := pubKey.N.Bytes()
    eBytes := big.NewInt(int64(pubKey.E)).Bytes()

    n := base64.RawURLEncoding.EncodeToString(nBytes)
    e := base64.RawURLEncoding.EncodeToString(eBytes)

    jwk := map[string]any{
        "kty": "RSA",        // Key type
        "use": "sig",        // Use: signature
        "kid": kid,          // Key ID
        "alg": algorithm,    // Algorithm (RS256, RS384, RS512)
        "n":   n,            // Modulus
        "e":   e,            // Exponent
    }

    return jwk, nil
}
```

**Reasoning**: Standard JWKS format per RFC 7517. Includes all keys for rotation support. Gracefully handles missing keys. Optional kid filter optimizes lookups.

#### 3. Register JWKS Path

**File**: `backend.go:45-52`
**Changes**: Add JWKS path to registration

**Current code:**
```go
// From backend.go:45-52
Paths: []*framework.Path{
    pathConfig(b),
    pathRole(b),
    pathRoleList(b),
    pathToken(b),
    pathKey(b),        // Phase 1
    pathKeyList(b),    // Phase 1
},
```

**Proposed changes:**
```go
// backend.go:45-53
Paths: []*framework.Path{
    pathConfig(b),
    pathRole(b),
    pathRoleList(b),
    pathToken(b),
    pathKey(b),
    pathKeyList(b),
    pathJWKS(b),       // NEW: JWKS endpoint
},
```

**Reasoning**: Completes the key management API surface.

### Testing for This Phase:

**Test File**: `path_jwks_test.go` (new file)

```go
package tokenexchange

import (
    "context"
    "encoding/json"
    "testing"

    "github.com/hashicorp/vault/sdk/logical"
    "github.com/stretchr/testify/require"
)

func TestPathJWKSRead(t *testing.T) {
    // Test JWKS endpoint returns all keys
    b, storage := getTestBackend(t)

    // Create multiple keys
    for _, name := range []string{"key1", "key2", "key3"} {
        req := &logical.Request{
            Operation: logical.CreateOperation,
            Path:      "key/" + name,
            Storage:   storage,
            Data: map[string]any{
                "algorithm": "RS256",
            },
        }
        _, err := b.HandleRequest(context.Background(), req)
        require.NoError(t, err)
    }

    // Read JWKS
    jwksReq := &logical.Request{
        Operation: logical.ReadOperation,
        Path:      "jwks",
        Storage:   storage,
    }

    resp, err := b.HandleRequest(context.Background(), jwksReq)
    require.NoError(t, err)
    require.NotNil(t, resp)

    // Verify keys in response
    keys := resp.Data["keys"].([]any)
    require.Len(t, keys, 3)

    // Verify JWK structure
    for _, k := range keys {
        jwk := k.(map[string]any)
        require.Equal(t, "RSA", jwk["kty"])
        require.Equal(t, "sig", jwk["use"])
        require.Contains(t, jwk, "kid")
        require.Contains(t, jwk, "alg")
        require.Contains(t, jwk, "n")
        require.Contains(t, jwk, "e")
    }
}

func TestPathJWKSRead_FilterByKid(t *testing.T) {
    // Test JWKS with kid filter
    b, storage := getTestBackend(t)

    // Create key
    keyReq := &logical.Request{
        Operation: logical.CreateOperation,
        Path:      "key/filter-test",
        Storage:   storage,
        Data: map[string]any{
            "algorithm": "RS256",
        },
    }
    keyResp, err := b.HandleRequest(context.Background(), keyReq)
    require.NoError(t, err)

    keyID := keyResp.Data["key_id"].(string)

    // Read JWKS with kid filter
    jwksReq := &logical.Request{
        Operation: logical.ReadOperation,
        Path:      "jwks",
        Storage:   storage,
        Data: map[string]any{
            "kid": keyID,
        },
    }

    resp, err := b.HandleRequest(context.Background(), jwksReq)
    require.NoError(t, err)

    keys := resp.Data["keys"].([]any)
    require.Len(t, keys, 1)

    jwk := keys[0].(map[string]any)
    require.Equal(t, keyID, jwk["kid"])
}

func TestPathJWKSRead_Empty(t *testing.T) {
    // Test JWKS with no keys configured
    b, storage := getTestBackend(t)

    jwksReq := &logical.Request{
        Operation: logical.ReadOperation,
        Path:      "jwks",
        Storage:   storage,
    }

    resp, err := b.HandleRequest(context.Background(), jwksReq)
    require.NoError(t, err)
    require.NotNil(t, resp)

    keys := resp.Data["keys"].([]any)
    require.Empty(t, keys)
}

func TestPathJWKSRead_ValidJWKFormat(t *testing.T) {
    // Test JWK structure matches RFC 7517
    b, storage := getTestBackend(t)

    // Create key with known private key
    privateKey, privateKeyPEM := generateTestKeyPair(t)
    publicKey := &privateKey.PublicKey

    keyReq := &logical.Request{
        Operation: logical.CreateOperation,
        Path:      "key/format-test",
        Storage:   storage,
        Data: map[string]any{
            "algorithm":   "RS384",
            "private_key": privateKeyPEM,
        },
    }
    keyResp, err := b.HandleRequest(context.Background(), keyReq)
    require.NoError(t, err)

    keyID := keyResp.Data["key_id"].(string)

    // Read JWKS
    jwksReq := &logical.Request{
        Operation: logical.ReadOperation,
        Path:      "jwks",
        Storage:   storage,
    }

    resp, err := b.HandleRequest(context.Background(), jwksReq)
    require.NoError(t, err)

    keys := resp.Data["keys"].([]any)
    jwk := keys[0].(map[string]any)

    // Verify fields
    require.Equal(t, "RSA", jwk["kty"])
    require.Equal(t, "sig", jwk["use"])
    require.Equal(t, keyID, jwk["kid"])
    require.Equal(t, "RS384", jwk["alg"])

    // Verify n and e are base64url encoded
    n := jwk["n"].(string)
    e := jwk["e"].(string)
    require.NotEmpty(t, n)
    require.NotEmpty(t, e)

    // Verify n matches public key modulus
    nBytes, err := base64.RawURLEncoding.DecodeString(n)
    require.NoError(t, err)
    require.Equal(t, publicKey.N.Bytes(), nBytes)
}

func TestPathJWKSRead_MultipleAlgorithms(t *testing.T) {
    // Test JWKS with different algorithms
    b, storage := getTestBackend(t)

    algorithms := []string{"RS256", "RS384", "RS512"}

    for i, alg := range algorithms {
        keyReq := &logical.Request{
            Operation: logical.CreateOperation,
            Path:      fmt.Sprintf("key/key-%d", i),
            Storage:   storage,
            Data: map[string]any{
                "algorithm": alg,
            },
        }
        _, err := b.HandleRequest(context.Background(), keyReq)
        require.NoError(t, err)
    }

    // Read JWKS
    jwksReq := &logical.Request{
        Operation: logical.ReadOperation,
        Path:      "jwks",
        Storage:   storage,
    }

    resp, err := b.HandleRequest(context.Background(), jwksReq)
    require.NoError(t, err)

    keys := resp.Data["keys"].([]any)
    require.Len(t, keys, 3)

    // Verify each algorithm is present
    foundAlgs := make(map[string]bool)
    for _, k := range keys {
        jwk := k.(map[string]any)
        foundAlgs[jwk["alg"].(string)] = true
    }

    for _, alg := range algorithms {
        require.True(t, foundAlgs[alg], "Algorithm %s not found in JWKS", alg)
    }
}
```

### Success Criteria:

#### Automated Verification:
- [ ] JWKS tests pass: `go test -v -run TestPathJWKS`
- [ ] Type checking passes: `go vet ./...`
- [ ] JWK format validates against RFC 7517
- [ ] Integration test: Generate token, fetch JWKS, verify signature

#### Manual Verification:
- [ ] Create keys: `vault write token-exchange/key/k1 algorithm=RS256`
- [ ] Fetch JWKS: `curl http://vault:8200/v1/token-exchange/jwks`
- [ ] Verify JSON structure matches RFC 7517
- [ ] Use JWK to verify generated JWT signature (using jwt.io or similar)
- [ ] Test kid filter: `curl http://vault:8200/v1/token-exchange/jwks?kid=k1-v1`

---

## Testing Strategy

### Unit Tests:

**Key management tests** (`key_test.go`):
- Key creation (auto-generate and user-provided)
- Key read (metadata only, no private key)
- Key listing
- Key deletion
- Algorithm validation
- Key size validation
- Duplicate prevention

**Role-key binding tests** (`path_role_test.go`):
- Role with named key
- Role without key (backward compat)
- Invalid key reference
- Key validation at role creation

**Token generation tests** (`path_token_test.go`):
- Token with named key
- Token with config key (backward compat)
- Kid in JWT header
- Algorithm selection (RS256/RS384/RS512)
- Signature validation

**JWKS tests** (`path_jwks_test.go`):
- JWKS listing all keys
- JWKS kid filter
- JWK format validation (RFC 7517)
- Empty JWKS
- Multiple algorithms

### Integration Tests:

**End-to-end workflow test** (`integration_test.go`):

```go
func TestKeyManagementWorkflow(t *testing.T) {
    // Full workflow test
    b, storage := getTestBackend(t)

    // 1. Create key
    keyReq := &logical.Request{
        Operation: logical.CreateOperation,
        Path:      "key/integration-key",
        Storage:   storage,
        Data: map[string]any{
            "algorithm": "RS256",
        },
    }
    keyResp, err := b.HandleRequest(context.Background(), keyReq)
    require.NoError(t, err)
    keyID := keyResp.Data["key_id"].(string)

    // 2. Create role using key
    roleReq := &logical.Request{
        Operation: logical.CreateOperation,
        Path:      "role/integration-role",
        Storage:   storage,
        Data: map[string]any{
            "ttl":              "1h",
            "key":              "integration-key",
            "actor_template":   `{}`,
            "subject_template": `{}`,
            "context":          []string{"scope1"},
        },
    }
    _, err = b.HandleRequest(context.Background(), roleReq)
    require.NoError(t, err)

    // 3. Setup config and JWKS
    privateKey, privateKeyPEM := generateTestKeyPair(t)
    publicKey := &privateKey.PublicKey

    jwksServer := createMockJWKSServer(t, publicKey, keyID)
    defer jwksServer.Close()

    configReq := &logical.Request{
        Operation: logical.UpdateOperation,
        Path:      "config",
        Storage:   storage,
        Data: map[string]any{
            "issuer":           "https://vault.example.com",
            "subject_jwks_uri": jwksServer.URL,
        },
    }
    _, err = b.HandleRequest(context.Background(), configReq)
    require.NoError(t, err)

    // 4. Exchange token
    subjectToken := generateTestJWT(t, privateKey, keyID, map[string]any{
        "sub": "user123",
        "exp": time.Now().Add(1 * time.Hour).Unix(),
    })

    tokenReq := &logical.Request{
        Operation: logical.UpdateOperation,
        Path:      "token/integration-role",
        Storage:   storage,
        EntityID:  "test-entity",
        Data: map[string]any{
            "subject_token": subjectToken,
        },
    }

    tokenResp, err := b.HandleRequest(context.Background(), tokenReq)
    require.NoError(t, err)
    generatedToken := tokenResp.Data["token"].(string)

    // 5. Fetch JWKS
    jwksReq := &logical.Request{
        Operation: logical.ReadOperation,
        Path:      "jwks",
        Storage:   storage,
    }

    jwksResp, err := b.HandleRequest(context.Background(), jwksReq)
    require.NoError(t, err)

    keys := jwksResp.Data["keys"].([]any)
    require.NotEmpty(t, keys)

    // 6. Verify token with JWKS
    parsedToken, err := jwt.ParseSigned(generatedToken, []jose.SignatureAlgorithm{jose.RS256})
    require.NoError(t, err)
    require.Equal(t, keyID, parsedToken.Headers[0].KeyID)

    // Extract public key from JWKS and verify
    // (implementation depends on JWK parsing)
}
```

### Manual Testing Steps:

1. **Setup Vault plugin**:
   ```bash
   vault plugin register -sha256=<hash> secret vault-plugin-token-exchange
   vault secrets enable -path=token-exchange vault-plugin-token-exchange
   ```

2. **Create named key**:
   ```bash
   vault write token-exchange/key/prod-key algorithm=RS256
   vault read token-exchange/key/prod-key
   ```

3. **Create role with key**:
   ```bash
   vault write token-exchange/role/test-role \
       key=prod-key \
       ttl=1h \
       actor_template='{"act":{"sub":"agent"}}' \
       subject_template='{}' \
       context="scope1,scope2"
   ```

4. **Exchange token**:
   ```bash
   vault write token-exchange/token/test-role subject_token="<jwt>"
   ```

5. **Verify JWT**:
   - Decode JWT and check kid header
   - Fetch JWKS: `curl http://vault:8200/v1/token-exchange/jwks`
   - Verify signature using public key from JWKS

6. **Test rotation** (after Phase 4):
   ```bash
   vault write token-exchange/key/prod-key/rotate
   vault read token-exchange/key/prod-key  # Check version incremented
   ```

## Performance Considerations

### Key Storage:
- Keys stored with seal-wrap encryption (minimal overhead)
- No caching needed for key reads (fast storage access)
- Storage keys: `keys/<name>` (flat namespace, O(1) lookup)

### JWKS Generation:
- JWKS endpoint reads all keys (O(n) where n = number of keys)
- For typical usage (< 10 keys), performance is excellent
- Consider caching JWKS response if > 50 keys (unlikely scenario)

### Token Generation:
- Key lookup adds one storage read (negligible overhead)
- RSA signing performance identical to current implementation
- Algorithm selection (RS256/RS384/RS512) has minimal impact

### Optimization Opportunities:
- **JWKS caching**: Cache JWKS response for 5 minutes (invalidate on key changes)
- **Key caching**: Cache parsed RSA keys in memory (invalidate on updates)
- **Deferred**: Implement only if performance testing shows need

## Migration Notes

### For Existing Deployments:

**Backward Compatibility Maintained**:
- Existing config-based key continues to work
- Roles without `key` field fall back to config key
- Generated tokens remain valid

**Migration Path**:

1. **Create named key**:
   ```bash
   # Option A: Generate new key
   vault write token-exchange/key/default algorithm=RS256

   # Option B: Import existing key
   vault write token-exchange/key/default \
       algorithm=RS256 \
       private_key=@existing-key.pem
   ```

2. **Update roles gradually**:
   ```bash
   # Update each role to reference named key
   vault write token-exchange/role/my-role \
       key=default \
       [... other fields ...]
   ```

3. **Verify tokens include kid**:
   ```bash
   # Exchange token and verify kid header
   vault write token-exchange/token/my-role subject_token="..."
   jwt decode <token>  # Check for kid in header
   ```

4. **Update token consumers**:
   - Configure consumers to fetch JWKS from `/jwks` endpoint
   - Consumers should use kid to select correct public key
   - Test validation with new tokens

5. **Optional: Remove config key**:
   ```bash
   # Once all roles use named keys
   vault delete token-exchange/config
   ```

### Rollback Plan:

If issues arise:
1. Roles without `key` field continue using config key
2. Remove `key` field from role configurations
3. Tokens validate correctly (kid is optional for validation)

## References

- **Vault Identity Tokens API**: https://developer.hashicorp.com/vault/api-docs/secret/identity/tokens
- **RFC 7517 (JWK)**: https://www.rfc-editor.org/rfc/rfc7517
- **RFC 7518 (JWA)**: https://www.rfc-editor.org/rfc/rfc7518
- **RFC 8693 (Token Exchange)**: https://www.rfc-editor.org/rfc/rfc8693

- **Research notes**: `key-management-research.md`
- **Context**: `key-management-context.md`
- **Tasks**: `key-management-tasks.md`

- **Existing files examined**:
  - [backend.go](../../../backend.go) - Path registration and seal-wrap
  - [path_config.go](../../../path_config.go) - Current config structure
  - [path_config_handlers.go](../../../path_config_handlers.go) - Config handlers
  - [path_role.go](../../../path_role.go) - Role structure
  - [path_role_handlers.go](../../../path_role_handlers.go) - Role handlers
  - [path_token_handlers.go](../../../path_token_handlers.go) - Token generation
