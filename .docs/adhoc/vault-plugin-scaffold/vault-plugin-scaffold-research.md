# Vault Plugin Scaffold - Research & Working Notes

**Research Date**: 2025-11-04
**Researchers**: Claude + nicj

## Initial Understanding

Initially understood the task as: "Scaffold a basic Vault secrets engine for token exchange with GitHub Actions CI/CD." The project appeared to be completely empty (no existing code) with only CLAUDE.md documentation outlining the intended OAuth 2.0 Token Exchange (RFC 8693) functionality.

## Research Process

### Files Examined:
- `CLAUDE.md` (lines 1-131)
  - Finding: Comprehensive documentation of the plugin's intended purpose
  - Project goal: OAuth 2.0 Token Exchange for "on behalf of" scenarios with OIDC tokens
  - Architecture: Standard Vault plugin structure with backend, paths, storage integration
  - Testing: Use logical.TestBackend() for integration tests, TDD with testify/require

### Current Repository State:
- Empty project - no `go.mod`, no `.go` files, no tests, no CI/CD
- Only files: `CLAUDE.md`, `.gitignore` (empty), `.git/` directory
- No GitHub Actions workflows
- Fresh slate for implementation

### Sub-tasks Spawned:

1. **iw-learnings**: Search for past learnings
   - Result: No existing learnings found (new project)
   - Action: Will document discoveries as we go

2. **Explore agent - codebase structure** (medium thoroughness):
   - Result: Confirmed empty project structure
   - Key discovery: Need to create entire project from scratch

3. **Explore agent - Vault plugin patterns** (medium thoroughness):
   - Result: No existing Vault code in repository
   - Confirmed need to implement all core components

4. **Explore agent - test patterns and CI** (medium thoroughness):
   - Result: No existing test files or CI configuration
   - Need to create GitHub Actions workflow

5. **general-purpose agent - Vault secrets engine requirements**:
   - Result: Comprehensive analysis of minimal Vault plugin requirements
   - Key findings:
     - Must implement Factory function pattern
     - Backend embeds `framework.Backend`
     - Requires path definitions for config and credentials
     - Uses logical.Storage for persistence
     - JWT signing with go-jose library
     - Path pattern: `oidc/role/:name`, `oidc/token/:name`, etc.

6. **general-purpose agent - JWT auth engine config research**:
   - Result: Detailed JWT/OIDC validation requirements
   - Key configuration fields:
     - Three mutually exclusive key validation methods: oidc_discovery_url, jwks_url, or jwt_validation_pubkeys
     - Token validation: bound_issuer, jwt_supported_algs, bound_audiences
     - Clock skew settings for production reliability
   - Insight: Token validation is complex, need simpler approach

7. **general-purpose agent - Identity engine research** (user suggested):
   - Result: Found Vault's identity secrets engine as perfect pattern to follow
   - Repository: github.com/hashicorp/vault (builtin/logical/identity/)
   - Key files:
     - `/vault/identity_store_oidc.go` - Main OIDC implementation
     - Role storage: `oidc_tokens/roles/{roleName}`
     - Token generation: `pathOIDCGenerateToken()` function (lines 1081-1165)
     - Template processing: `identitytpl.PopulateString()`
     - JWT signing: `signPayload()` using go-jose
   - Path structure: `/oidc/config`, `/oidc/role/:name`, `/oidc/token/:name`, `/oidc/key/:name`

### Questions Asked & Answers:

1. Q: What configuration fields should the plugin store for validation?
   A: User clarified that both user token and agent token need validation, suggested looking at JWT auth engine config
   Follow-up research: Found JWT auth engine uses oidc_discovery_url, jwks_url, jwt_validation_pubkeys, bound_issuer, jwt_supported_algs, etc.

2. Q: Should we include a credentials/token exchange path initially, or just config?
   A: YES - include the token exchange endpoint from the start

3. Q: Which Go version?
   A: Latest Go version (Go 1.23 as of 2025-11-04)

4. Q: Should GitHub Actions include coverage and golangci-lint?
   A: YES - include both coverage reporting and golangci-lint (but no integration tests with real Vault server initially)

5. Q: How should this engine work architecturally?
   A: **CRITICAL CLARIFICATION**: User explained the plugin should work similar to identity engine:
      - "Core difference is that when you call a role to create an identity, you pass an existing OIDC token"
      - "Token must be validated before details are added to the on-behalf-of section of the new JWT"
      - Follow identity engine pattern but accept JWT as input

## Key Discoveries

### Technical Discoveries:
- **Empty Project State**: This is a greenfield project requiring complete scaffolding from scratch
- **Identity Engine Pattern**: The Vault identity secrets engine provides the perfect architectural template
  - Uses role-based configuration
  - Generates tokens via `/oidc/token/:role` endpoint
  - Template-based claim customization
  - Signing key management with `/oidc/key/:name`
  - Storage pattern: `oidc_tokens/config/`, `oidc_tokens/roles/`, `oidc_tokens/named_keys/`

- **Go Dev Guidelines**: Project uses TDD approach with testify/require for assertions
  - Write tests BEFORE implementation
  - Separate positive and negative test cases
  - Use mockery for mocks in `mocks/` subfolder
  - Never use table-driven tests
  - Follow standard Go directory structure: `/cmd`, `/internal`, `/pkg`

- **Vault Plugin Architecture**:
  - Backend embeds `framework.Backend`
  - Paths registered in `Paths: []*framework.Path{}`
  - Each path has Pattern, Fields, Operations (map of CRUD handlers)
  - Request handlers: `func(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error)`
  - Storage via `req.Storage.Put()`, `req.Storage.Get()`, etc.
  - Use `logical.StorageEntryJSON()` for serialization

### Patterns to Follow:

1. **Identity Engine Role Pattern**:
```go
// From vault/identity_store_oidc.go
type role struct {
    TokenTTL time.Duration `json:"token_ttl"`
    Key      string        `json:"key"`
    Template string        `json:"template"`
    ClientID string        `json:"client_id"`
}

// Storage path
const roleConfigPath = "oidc_tokens/roles/"

// Role retrieval
func (i *IdentityStore) getOIDCRole(ctx context.Context, s logical.Storage, roleName string) (*role, error) {
    entry, err := s.Get(ctx, roleConfigPath+roleName)
    if err != nil {
        return nil, err
    }
    if entry == nil {
        return nil, nil
    }
    var role role
    if err := entry.DecodeJSON(&role); err != nil {
        return nil, err
    }
    return &role, nil
}
```

2. **Token Generation Pattern**:
```go
// From vault/identity_store_oidc.go:1081-1165
func (i *IdentityStore) pathOIDCGenerateToken(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
    // 1. Load role from storage
    // 2. Load signing key
    // 3. Validate permissions
    // 4. Create base ID token
    // 5. Load entity data
    // 6. Populate template
    // 7. Generate JWT payload
    // 8. Sign the payload
    // 9. Return token response
}
```

3. **JWT Signing Pattern**:
```go
// Uses go-jose library
func (k *namedKey) signPayload(payload []byte) (string, error) {
    signingKey := jose.SigningKey{
        Key:       k.SigningKey,
        Algorithm: jose.SignatureAlgorithm(k.Algorithm),
    }

    signer, err := jose.NewSigner(signingKey, &jose.SignerOptions{})
    // ... sign and return compact JWS
}
```

4. **Path Definition Pattern**:
```go
{
    Pattern: "oidc/role/" + framework.GenericNameRegex("name"),
    Fields: map[string]*framework.FieldSchema{
        "name": {
            Type:        framework.TypeString,
            Description: "Name of the role",
        },
        "key": {
            Type:        framework.TypeString,
            Description: "The OIDC key to use for generating tokens",
            Required:    true,
        },
        // ... more fields
    },
    Operations: map[logical.Operation]framework.OperationHandler{
        logical.UpdateOperation: &framework.PathOperation{
            Callback: i.pathOIDCCreateUpdateRole,
            Summary:  "Create or update a role",
        },
        logical.ReadOperation: &framework.PathOperation{
            Callback: i.pathOIDCReadRole,
            Summary:  "Read a role configuration",
        },
        // ... more operations
    },
}
```

### Constraints Identified:
- Must use Vault SDK v0.17.0+ for modern plugin features
- Must use plugin.ServeMultiplex() for modern plugins (not old plugin.Serve())
- Go version: 1.23 (latest)
- Testing: Use logical.TestBackend(), not real Vault instance
- Storage keys should use prefix pattern (e.g., "oidc_tokens/")
- Reserved JWT claims cannot be overridden by templates: `iat`, `aud`, `exp`, `iss`, `sub`, `namespace`
- TDD required: tests before implementation (go-dev-guidelines)

## Design Decisions

### Decision 1: Plugin Architecture Pattern
**Options considered:**
- Option A: Create custom architecture from scratch
- Option B: Follow Vault's identity engine pattern closely

**Chosen**: Option B - Follow identity engine pattern

**Rationale**:
- Identity engine already solves similar problem (token generation with templates)
- Proven architecture used in production Vault
- Well-structured with role-based configuration
- User explicitly suggested this approach
- Reduces risk and development time

### Decision 2: Token Validation Approach
**Options considered:**
- Option A: Full JWT auth engine validation config (oidc_discovery_url, jwks_url, etc.)
- Option B: Simple validation + defer complex validation to later phase
- Option C: No validation in initial scaffold, just structure

**Chosen**: Option B - Simple validation

**Rationale**:
- Scaffold phase focuses on structure, not full functionality
- Can validate JWT signature and expiration initially
- Complex OIDC discovery can be added in later phase
- User emphasized "for now this just needs to build and work with vault"

### Decision 3: Initial Paths to Implement
**Options considered:**
- Option A: Just config path (minimal)
- Option B: Config + role + token paths (functional)
- Option C: Full identity engine paths including keys

**Chosen**: Option B - Config, role, and token exchange paths

**Rationale**:
- User confirmed token exchange path should be included
- Role-based approach matches identity engine pattern
- Config path needed for plugin configuration
- Signing keys can use simplified approach initially (future: dedicated key management like identity engine)

### Decision 4: Testing Strategy
**Options considered:**
- Option A: Full integration tests with real Vault dev server
- Option B: Unit tests with logical.TestBackend() + GitHub Actions
- Option C: Minimal testing

**Chosen**: Option B

**Rationale**:
- User requested GitHub Actions but NO integration tests initially
- logical.TestBackend() provides sufficient integration testing
- Faster CI/CD without Vault server setup
- Can add full integration tests later

### Decision 5: Go Module Dependencies
**Options considered:**
- Option A: Use latest Vault SDK versions
- Option B: Match identity engine's exact versions
- Option C: Minimal dependencies

**Chosen**: Option A - Latest stable versions

**Rationale**:
- New project, no legacy compatibility concerns
- Latest SDK has bug fixes and improvements
- Vault 1.17+ is current LTS
- Go 1.23 is latest stable

## Open Questions (During Research)

- [x] Q: Should this use JWT auth engine config pattern or identity engine pattern?
      Resolved: Identity engine pattern, but accept JWT as input

- [x] Q: What paths should the initial scaffold include?
      Resolved: Config, role, and token exchange paths

- [x] Q: Should we validate incoming JWT tokens?
      Resolved: Yes, but keep it simple initially (signature + expiration)

- [x] Q: What Go version to use?
      Resolved: Latest (Go 1.23)

- [x] Q: GitHub Actions scope?
      Resolved: Build, test, lint, coverage - but NO integration tests with real Vault

**Note**: All questions resolved. Ready to finalize plan.

## Code Snippets Reference

### Identity Engine Role Storage (vault/identity_store_oidc.go:1269-1282):
```go
func (i *IdentityStore) getOIDCRole(ctx context.Context, s logical.Storage, roleName string) (*role, error) {
    entry, err := s.Get(ctx, roleConfigPath+roleName)
    if err != nil {
        return nil, err
    }
    if entry == nil {
        return nil, nil
    }
    var role role
    if err := entry.DecodeJSON(&role); err != nil {
        return nil, err
    }
    return &role, nil
}
```

### Identity Engine Token Generation (vault/identity_store_oidc.go:1081-1165):
```go
func (i *IdentityStore) pathOIDCGenerateToken(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
    // Load role from storage
    role, err := i.getOIDCRole(ctx, req.Storage, roleName)

    // Load signing key
    key, err := i.getNamedKey(ctx, req.Storage, role.Key)

    // Create base ID token
    idToken := idToken{
        Issuer:    issuer,
        Subject:   req.EntityID,
        Audience:  role.ClientID,
        Expiry:    now.Add(expiry).Unix(),
        IssuedAt:  now.Unix(),
    }

    // Populate template with entity data
    _, populatedTemplate, err := identitytpl.PopulateString(identitytpl.PopulateStringInput{
        Mode:    identitytpl.JSONTemplating,
        String:  role.Template,
        Entity:  identity.ToSDKEntity(e),
        Groups:  identity.ToSDKGroups(groups),
    })

    // Generate and sign JWT
    payload, err := idToken.generatePayload(i.Logger(), populatedTemplate)
    signedIdToken, err := key.signPayload(payload)

    return &logical.Response{
        Data: map[string]interface{}{
            "token":     signedIdToken,
            "client_id": role.ClientID,
            "ttl":       int64(role.TokenTTL.Seconds()),
        },
    }, nil
}
```

### Go-Jose JWT Signing (vault/identity_store_oidc.go:1035-1051):
```go
func (k *namedKey) signPayload(payload []byte) (string, error) {
    if k.SigningKey == nil {
        return "", fmt.Errorf("signing key is nil")
    }

    signingKey := jose.SigningKey{
        Key:       k.SigningKey,
        Algorithm: jose.SignatureAlgorithm(k.Algorithm),
    }

    signer, err := jose.NewSigner(signingKey, &jose.SignerOptions{})
    if err != nil {
        return "", err
    }

    signature, err := signer.Sign(payload)
    if err != nil {
        return "", err
    }

    return signature.CompactSerialize()
}
```

### Vault Plugin Backend Setup Pattern:
```go
func NewBackend() *Backend {
    b := &Backend{}

    b.Backend = framework.Backend{
        Help: "Description of your secrets engine",

        Paths: []*framework.Path{
            pathConfig(b),
            pathRole(b),
            pathToken(b),
        },

        BackendType: logical.TypeLogical,

        PathsSpecial: &logical.Paths{
            SealWrapStorage: []string{
                "config",
                "role/*",
            },
        },
    }

    return b
}

func Factory(ctx context.Context, conf *logical.BackendConfig) (logical.Backend, error) {
    b := NewBackend()

    if err := b.Setup(ctx, conf); err != nil {
        return nil, err
    }

    return b, nil
}
```

## Architectural Insights

**Key Pattern Discovered**: Token Exchange = Identity Engine Pattern + JWT Input Validation

The plugin will:
1. Accept incoming JWT(s) via POST to `/token-exchange/token/:role` endpoint
2. Validate the incoming JWT (signature, expiration, issuer)
3. Extract claims from validated JWT
4. Use role configuration (like identity engine) to define template
5. Generate new JWT with "on behalf of" claims populated from incoming token
6. Sign and return the new token

This is simpler than initially thought - we're not building a full auth engine, just a token transformer that:
- Takes JWT in → Validates → Extracts → Templates → Signs → Returns new JWT

The identity engine already has 90% of the structure we need. We just add JWT validation at the input.
