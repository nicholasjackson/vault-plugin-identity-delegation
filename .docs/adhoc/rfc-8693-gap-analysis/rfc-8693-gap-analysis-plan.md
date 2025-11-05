# RFC 8693 Compliance Gap Analysis

**Created**: 2025-11-05
**Type**: Analysis Report
**Status**: Complete

---

## Overview

This document provides a comprehensive analysis of the current Vault Token Exchange plugin implementation against the OAuth 2.0 Token Exchange specification (RFC 8693). It identifies gaps between the current implementation and the RFC requirements, and provides detailed comparisons of delegation patterns.

## Executive Summary

The current plugin implements a custom token exchange mechanism for "on behalf of" scenarios but **deviates significantly from RFC 8693** in the following critical areas:

1. **Non-compliant request/response format** - Missing required parameters and response fields
2. **Custom claim structure** - Uses `obo` claim instead of standard `act` claim
3. **Missing token type handling** - No URN-based token type identifiers
4. **Incomplete validation** - Bound audience/issuer checks not implemented
5. **Non-standard error responses** - Missing RFC-specified error codes

**Compliance Level**: ~30% RFC-compliant (basic token exchange concept only)

## Critical Gaps (MUST Requirements from RFC 8693)

### 1. Missing Grant Type Parameter (RFC 8693 Section 2.1)

**Current State**: The plugin uses a simple `/token/:name` endpoint with only `subject_token` parameter
**Location**: `path_token.go:13-24`

**RFC Requirement**: MUST accept `grant_type` parameter with value `urn:ietf:params:oauth:grant-type:token-exchange`

**Current Request Schema**:
```go
Fields: map[string]*framework.FieldSchema{
    "name": {
        Type:        framework.TypeString,
        Description: "Name of the role to use for token exchange",
        Required:    true,
    },
    "subject_token": {
        Type:        framework.TypeString,
        Description: "The subject token (JWT) to exchange",
        Required:    true,
    },
}
```

**RFC-Compliant Request Should Include**:
```http
POST /token/:name
Content-Type: application/x-www-form-urlencoded

grant_type=urn:ietf:params:oauth:grant-type:token-exchange
&subject_token=eyJhbGc...
&subject_token_type=urn:ietf:params:oauth:token-type:jwt
```

**Impact**: Non-compliant clients expecting standard OAuth 2.0 token exchange will fail

---

### 2. Missing subject_token_type Parameter (RFC 8693 Section 2.1)

**Current State**: Plugin assumes JWT but doesn't require token type specification
**Location**: `path_token.go:19-23`

**RFC Requirement**: MUST include `subject_token_type` parameter to identify token format
**Expected value**: `urn:ietf:params:oauth:token-type:jwt`

**Why This Matters**:
- Enables support for multiple token formats (JWT, SAML, etc.)
- Provides explicit contract about token format
- Required for RFC compliance

**Impact**: Cannot support multiple token types; implicit assumptions about format

---

### 3. Missing actor_token and actor_token_type Parameters (RFC 8693 Section 2.1)

**Current State**: Plugin uses Vault entity information to generate actor claims
**Location**: `path_token_handlers.go:69-102`

**Current Implementation**:
```go
// Fetch entity
entity, err := fetchEntity(req, b.System())
if err != nil {
    return nil, err
}

// Process template to create additional claims
im := map[string]any{
    "identity": map[string]map[string]any{
        "entity": {
            "id":           entity.ID,
            "name":         entity.Name,
            "namespace_id": entity.NamespaceID,
            "metadata":     entity.Metadata,
        },
    },
}

actorClaims, err := processTemplate(role.ActorTemplate, im)
```

**RFC Requirement**: SHOULD support optional `actor_token` parameter for explicit actor identity
**RFC Requirement**: MUST include `actor_token_type` when `actor_token` is present

**RFC-Compliant Request**:
```http
POST /token
grant_type=urn:ietf:params:oauth:grant-type:token-exchange
&subject_token=eyJhbGc...user-jwt
&subject_token_type=urn:ietf:params:oauth:token-type:jwt
&actor_token=eyJhbGc...agent-jwt
&actor_token_type=urn:ietf:params:oauth:token-type:jwt
```

**Impact**: Current implementation conflates authentication (Vault entity) with actor token semantics; cannot accept explicit actor tokens from external sources

---

### 4. Non-Compliant Response Format (RFC 8693 Section 2.2)

**Current State**: Returns `{"token": "..."}` at `path_token_handlers.go:110-114`

**Current Response**:
```go
return &logical.Response{
    Data: map[string]any{
        "token": newToken,
    },
}, nil
```

**RFC Requirement**: MUST return:
- `access_token` (REQUIRED) - not "token"
- `issued_token_type` (REQUIRED) - missing entirely
- `token_type` (REQUIRED) - missing entirely (should be "Bearer" or "N_A")
- `expires_in` (RECOMMENDED) - missing entirely
- `scope` (OPTIONAL) - missing

**RFC-Compliant Response**:
```json
{
  "access_token": "eyJhbGc...",
  "issued_token_type": "urn:ietf:params:oauth:token-type:jwt",
  "token_type": "N_A",
  "expires_in": 3600,
  "scope": "read write"
}
```

**Impact**: Non-compliant clients cannot parse response; missing critical metadata about issued token

---

### 5. Missing Token Type Identifiers (RFC 8693 Section 3)

**Current State**: No token type validation or specification
**Location**: Throughout `path_token_handlers.go`

**RFC Requirement**: MUST use URN identifiers for token types:
- Input: `urn:ietf:params:oauth:token-type:jwt`
- Output: `urn:ietf:params:oauth:token-type:access_token` or `urn:ietf:params:oauth:token-type:jwt`

**Standard Token Type URNs**:
- `urn:ietf:params:oauth:token-type:access_token` - OAuth 2.0 access token
- `urn:ietf:params:oauth:token-type:refresh_token` - OAuth 2.0 refresh token
- `urn:ietf:params:oauth:token-type:id_token` - OpenID Connect ID Token
- `urn:ietf:params:oauth:token-type:saml1` - SAML 1.1 assertion
- `urn:ietf:params:oauth:token-type:saml2` - SAML 2.0 assertion
- `urn:ietf:params:oauth:token-type:jwt` - JSON Web Token

**Impact**: Cannot validate token types; no extensibility for other token formats

---

### 6. Non-Standard Actor Claim Structure (RFC 8693 Section 4.1)

**Current State**: Uses custom `obo` claim structure at `path_token_handlers.go:298-302`

**Current Implementation**:
```go
// Add the on-behalf-of context
claims["obo"] = map[string]any{
    "prn": subjectID,
    "ctx": strings.Join(role.Context, ","),
}
```

**Current Token Structure**:
```json
{
  "iss": "vault-issuer",
  "sub": "user@example.com",
  "iat": 1234567890,
  "exp": 1234654290,
  "subject_claims": {...},
  "actor_claim1": "value1",
  "actor_claim2": "value2",
  "obo": {
    "prn": "user@example.com",
    "ctx": "urn:documents:read,urn:images:write"
  }
}
```

**RFC Requirement**: MUST use `act` (Actor) claim with standard structure:
```json
{
  "sub": "user@example.com",
  "act": {
    "sub": "actor-identifier"
  }
}
```

**RFC-Compliant Token Structure**:
```json
{
  "iss": "https://issuer.example.com",
  "sub": "user@example.com",
  "aud": "https://resource.example.com",
  "iat": 1234567890,
  "exp": 1234654290,
  "act": {
    "sub": "agent@example.com"
  },
  "scope": "read write"
}
```

**Impact**: Non-standard claim structure; resource servers expecting RFC 8693 format cannot process tokens correctly

---

## Important Gaps (SHOULD/RECOMMENDED Requirements)

### 7. Missing resource and audience Parameters (RFC 8693 Section 2.1)

**Current State**: Audience is extracted from actor claims template
**Location**: `path_token_handlers.go:283-285`

```go
// Add audience if present
if aud, ok := actorClaims["aud"]; ok {
    claims["aud"] = aud
}
```

**RFC Requirement**: SHOULD support `resource` and `audience` parameters to specify target services

**RFC-Compliant Request**:
```http
POST /token
grant_type=urn:ietf:params:oauth:grant-type:token-exchange
&subject_token=eyJhbGc...
&subject_token_type=urn:ietf:params:oauth:token-type:jwt
&resource=https://backend.example.com/api
&audience=backend-service
```

**Impact**: Cannot explicitly declare which service the token is intended for; relies on template configuration

---

### 8. Missing scope Parameter (RFC 8693 Section 2.1)

**Current State**: Uses `context` array in role config, hardcoded in response
**Location**: `path_role.go:59-63`, `path_token_handlers.go:301`

**Current Role Configuration**:
```go
"context": {
    Type:        framework.TypeCommaStringSlice,
    Description: "List of permitted delegate scopes to map to the on-behalf-of 'ctx' claim...",
    Required:    true,
}
```

**RFC Requirement**: SHOULD accept `scope` parameter to request specific permissions

**RFC-Compliant Request**:
```http
POST /token
grant_type=urn:ietf:params:oauth:grant-type:token-exchange
&subject_token=eyJhbGc...
&subject_token_type=urn:ietf:params:oauth:token-type:jwt
&scope=read write
```

**Impact**: Client cannot dynamically request scopes; all scopes are pre-configured in role

---

### 9. Missing requested_token_type Parameter (RFC 8693 Section 2.1)

**Current State**: Always returns JWT
**Location**: `path_token_handlers.go:262-312`

**RFC Requirement**: SHOULD support `requested_token_type` to allow clients to request specific token formats

**Impact**: Cannot support scenarios where different token formats are needed

---

### 10. Missing Error Codes (RFC 8693 Section 2.2.2)

**Current State**: Generic error responses
**Location**: `path_token_handlers.go:30,40,49,61,66`

**Current Error Handling**:
```go
if !ok {
    return logical.ErrorResponse("subject_token is required"), nil
}

if role == nil {
    return logical.ErrorResponse("role %q not found", roleName), nil
}

if config == nil {
    return logical.ErrorResponse("plugin not configured"), nil
}
```

**RFC Requirement**:
- MUST use `invalid_request` for invalid tokens or missing required parameters
- SHOULD use `invalid_target` for resource/audience issues

**RFC-Compliant Error Response**:
```json
{
  "error": "invalid_request",
  "error_description": "subject_token parameter is required"
}
```

**Impact**: Non-standard error handling; clients cannot parse errors according to OAuth 2.0 specification

---

### 11. Missing Bound Audience/Issuer Validation

**Current State**: Role has `BoundAudiences` and `BoundIssuer` fields defined but **not validated**
**Location**:
- Defined: `path_role.go:14-15`
- Missing validation: `path_token_handlers.go:58-67`

**Current Code**:
```go
// Validate and parse subject token
originalSubjectClaims, err := validateAndParseClaims(subjectTokenStr, config.SubjectJWKSURI)
if err != nil {
    return logical.ErrorResponse("failed to validate subject token: %v", err), nil
}

// Check expiration
if err := checkExpiration(originalSubjectClaims); err != nil {
    return logical.ErrorResponse("subject token expired: %v", err), nil
}
// NO VALIDATION OF AUDIENCE OR ISSUER HERE
```

**Required Validation**:
```go
// Validate issuer
if role.BoundIssuer != "" {
    if iss, ok := originalSubjectClaims["iss"].(string); !ok || iss != role.BoundIssuer {
        return logical.ErrorResponse("token issuer does not match bound_issuer"), nil
    }
}

// Validate audience
if len(role.BoundAudiences) > 0 {
    aud, ok := originalSubjectClaims["aud"]
    if !ok {
        return logical.ErrorResponse("token missing aud claim"), nil
    }
    // Check if aud matches any bound audience
    // Handle both string and []string aud claims
}
```

**Impact**: Security risk - tokens with wrong issuer or audience can be exchanged

---

### 12. Missing scope Claim in Output Token (RFC 8693 Section 4.3)

**Current State**: Scopes stored in custom `obo.ctx` field as comma-delimited string
**Location**: `path_token_handlers.go:299-302`

```go
claims["obo"] = map[string]any{
    "prn": subjectID,
    "ctx": strings.Join(role.Context, ","),  // Comma-delimited
}
```

**RFC Requirement**: SHOULD include `scope` claim as space-delimited string

**RFC-Compliant Implementation**:
```go
claims["scope"] = strings.Join(role.Context, " ")  // Space-delimited
```

**Impact**: Scope information not in standard location; non-compliant with JWT best practices

---

## Additional Observations

### 13. Non-Standard Endpoint Pattern

**Current**: `/token/:name` (role-based routing)
**RFC 8693**: Typically uses a single token endpoint (e.g., `/token`) with role specified via parameters or client authentication

**Note**: This may be acceptable given Vault's path-based routing model, but differs from typical OAuth 2.0 implementations

---

### 14. Missing Client Authentication

**Current**: Relies on Vault token authentication
**RFC 8693**: Recommends OAuth 2.0 client authentication methods

**Note**: This may be acceptable given Vault's authentication model, but should be documented

---

### 15. Custom Subject Claims Structure

**Current**: Wraps subject-derived claims under `subject_claims` key
**Location**: `path_token_handlers.go:288`

```go
// add the subject claims under "subject_claims" key
claims["subject_claims"] = subjectClaims
```

**RFC 8693**: No specific requirement, but this is non-standard

**Impact**: Minor deviation; resource servers need custom logic to access subject claims

---

## Delegation Pattern Comparison

### Current Implementation Pattern

**Token Structure**:
```json
{
  "iss": "vault-issuer",
  "sub": "user@example.com",
  "iat": 1234567890,
  "exp": 1234654290,
  "subject_claims": {
    "email": "user@example.com",
    "name": "John Doe"
  },
  "actor_custom_claim": "value",
  "obo": {
    "prn": "user@example.com",
    "ctx": "urn:documents:read,urn:images:write"
  }
}
```

**Characteristics**:
- Custom `obo` claim for delegation context
- Actor claims merged at top level
- Subject claims nested under `subject_claims`
- Comma-delimited scopes in `ctx`
- Duplicates subject in `sub` and `obo.prn`

---

### RFC 8693 Pattern 1: Impersonation

**Use Case**: Service acts AS the user, indistinguishable from them

**Request**:
```http
POST /token
grant_type=urn:ietf:params:oauth:grant-type:token-exchange
&subject_token=eyJhbGc...user-jwt
&subject_token_type=urn:ietf:params:oauth:token-type:jwt
&audience=https://backend.example.com
```

**Token Structure**:
```json
{
  "iss": "https://issuer.example.com",
  "sub": "user@example.com",
  "aud": "https://backend.example.com",
  "iat": 1234567890,
  "exp": 1234654290,
  "scope": "read write"
}
```

**Characteristics**:
- No `act` claim
- Service completely impersonates user
- Resource server sees only user identity
- Simpler authorization model
- No audit trail of delegation

---

### RFC 8693 Pattern 2: Delegation (Current Actor)

**Use Case**: Agent acts ON BEHALF OF user with clear audit trail

**Request**:
```http
POST /token
grant_type=urn:ietf:params:oauth:grant-type:token-exchange
&subject_token=eyJhbGc...user-jwt
&subject_token_type=urn:ietf:params:oauth:token-type:jwt
&actor_token=eyJhbGc...agent-jwt
&actor_token_type=urn:ietf:params:oauth:token-type:jwt
&audience=https://backend.example.com
```

**Token Structure**:
```json
{
  "iss": "https://issuer.example.com",
  "sub": "user@example.com",
  "aud": "https://backend.example.com",
  "iat": 1234567890,
  "exp": 1234654290,
  "act": {
    "sub": "ai-agent@example.com"
  },
  "scope": "read write"
}
```

**Characteristics**:
- Has `act` claim identifying actor
- Clear distinction between user (`sub`) and agent (`act`)
- Resource server knows agent is acting on behalf of user
- Better for audit, compliance, and fine-grained authorization
- Supports delegation-aware access control

---

### RFC 8693 Pattern 3: Delegation Chain (Multi-hop)

**Use Case**: Multiple services in chain, each delegating to next

**Request at Service 2**:
```http
POST /token
grant_type=urn:ietf:params:oauth:grant-type:token-exchange
&subject_token=eyJhbGc...token-from-service1
&actor_token=eyJhbGc...service2-jwt
```

**Token Structure**:
```json
{
  "iss": "https://issuer.example.com",
  "sub": "user@example.com",
  "aud": "https://backend.example.com",
  "iat": 1234567890,
  "exp": 1234654290,
  "act": {
    "sub": "service2.example.com",
    "act": {
      "sub": "service1.example.com"
    }
  },
  "scope": "read write"
}
```

**Characteristics**:
- Nested `act` claims show full delegation history
- Outermost `act` = current actor
- Inner nested `act` = previous actors (informational)
- Only top-level `sub` and immediate `act.sub` used for authorization
- Full audit trail maintained

---

### RFC 8693 Pattern 4: Pre-Authorization (may_act)

**Use Case**: Issue token granting permission for specific agent to act later

**Token with Pre-Authorization**:
```json
{
  "iss": "https://issuer.example.com",
  "sub": "user@example.com",
  "aud": "https://authorization-server.example.com",
  "iat": 1234567890,
  "exp": 1234654290,
  "may_act": {
    "sub": "ai-agent@example.com"
  }
}
```

**Characteristics**:
- `may_act` declares who CAN act on behalf of subject
- Authorization server validates this when processing exchange
- Enables conditional delegation policies
- Supports fine-grained delegation control

---

## Pattern Comparison Table

| Aspect | Current Implementation | RFC Impersonation | RFC Delegation | RFC Delegation Chain |
|--------|------------------------|------------------|----------------|---------------------|
| **Claim Name** | `obo` (custom) | None | `act` | Nested `act` |
| **Actor Identity** | Merged at top level | N/A | `act.sub` | `act.sub` + nested |
| **Subject Identity** | `sub` + `obo.prn` | `sub` | `sub` | `sub` |
| **Scopes** | `obo.ctx` (comma) | `scope` (space) | `scope` (space) | `scope` (space) |
| **Audit Trail** | Single level | None | Current actor | Full chain |
| **Standards** | Non-standard | RFC 8693 | RFC 8693 | RFC 8693 |
| **Use Case** | AI agent delegation | Service impersonation | Explicit delegation | Multi-hop |

---

## Semantic Analysis

### Current Plugin Intent

**What the plugin INTENDS to do**: Delegation (RFC Pattern 2)
- Accept user token (`subject_token`)
- Use Vault entity as implicit actor
- Merge claims and add context
- Support AI agents acting on behalf of users

### How It Actually Differs

1. **No explicit actor_token parameter** - Uses Vault authentication context instead of explicit actor token
2. **Custom claim structure** - Uses `obo` instead of standard `act` claim
3. **Claim mixing** - Actor claims merged at top level instead of separated in `act`
4. **Non-standard scopes** - Uses `ctx` in `obo` instead of top-level `scope` claim
5. **No delegation chain support** - Cannot represent multi-hop delegation scenarios
6. **Missing pre-authorization** - No `may_act` claim validation
7. **Subject duplication** - Subject appears in both `sub` and `obo.prn`

---

## Recommendations

Based on the plugin's use case (AI agents acting on behalf of users), recommend:

### Primary Pattern: Delegation with Actor Claim (RFC Pattern 2)

**Why:**
- Clear audit trail showing both user and agent identity
- Enables resource servers to make delegation-aware authorization decisions
- Supports compliance requirements for AI agent operations
- Maintains accountability for agent actions
- Industry standard approach

### Migration Path

**Phase 1**: Add RFC-compliant `act` claim structure while maintaining backward-compatible `obo` claim
**Phase 2**: Support explicit `actor_token` parameter (optional, can default to Vault entity)
**Phase 3**: Add `may_act` validation for enhanced security
**Phase 4**: Deprecate custom `obo` claim in favor of standard `act`

---

## Summary of Required Changes

To bring the plugin inline with RFC 8693:

### Request Schema Changes
- [ ] Add `grant_type` parameter (MUST)
- [ ] Add `subject_token_type` parameter (MUST)
- [ ] Add `actor_token` parameter (SHOULD)
- [ ] Add `actor_token_type` parameter (MUST when actor_token present)
- [ ] Add `resource` parameter (SHOULD)
- [ ] Add `audience` parameter (SHOULD)
- [ ] Add `scope` parameter (SHOULD)
- [ ] Add `requested_token_type` parameter (SHOULD)

### Response Format Changes
- [ ] Rename `token` to `access_token` (MUST)
- [ ] Add `issued_token_type` field (MUST)
- [ ] Add `token_type` field (MUST)
- [ ] Add `expires_in` field (RECOMMENDED)
- [ ] Add `scope` field (OPTIONAL)

### Token Claims Changes
- [ ] Replace `obo` claim with `act` claim (MUST)
- [ ] Move actor identity to `act.sub` (MUST)
- [ ] Add top-level `scope` claim (SHOULD)
- [ ] Support nested `act` for delegation chains (SHOULD)
- [ ] Remove `subject_claims` wrapper (OPTIONAL)

### Validation Changes
- [ ] Validate `grant_type` matches expected value (MUST)
- [ ] Validate token type identifiers (MUST)
- [ ] Implement bound audience validation (SHOULD)
- [ ] Implement bound issuer validation (SHOULD)
- [ ] Add `may_act` claim validation (OPTIONAL)

### Error Handling Changes
- [ ] Use `invalid_request` error code (MUST)
- [ ] Use `invalid_target` error code (SHOULD)
- [ ] Return RFC-compliant error responses (MUST)

### Optional Enhancements
- [ ] Support explicit `actor_token` parameter
- [ ] Support multiple token types (SAML, etc.)
- [ ] Implement JWKS caching for performance
- [ ] Add delegation chain support

---

## Impact Assessment

### Breaking Changes
- Request format changes (new required parameters)
- Response format changes (renamed fields)
- Token claim structure changes (obo → act)

### Backward Compatibility Options
1. Support both old and new formats during transition period
2. Use configuration flag to enable RFC compliance mode
3. Create new endpoint (`/token-exchange`) alongside existing endpoint

### Migration Considerations
- Existing clients will need updates
- Resource servers expecting `obo` claim will need updates
- Consider deprecation timeline for old format

---

## References

- [RFC 8693: OAuth 2.0 Token Exchange](https://www.rfc-editor.org/rfc/rfc8693.html)
- Current implementation: `path_token.go`, `path_token_handlers.go`
- Plugin documentation: `CLAUDE.md`

---

## File References

### Request Handling
- `path_token.go:9-36` - Token exchange endpoint definition
- `path_token.go:13-24` - Current request field schema
- `path_token_handlers.go:22-115` - Main exchange handler

### Response Generation
- `path_token_handlers.go:110-114` - Response construction
- `path_token_handlers.go:262-312` - Token generation

### Claim Processing
- `path_token_handlers.go:298-302` - Custom `obo` claim structure
- `path_token_handlers.go:288` - Subject claims wrapping
- `path_token_handlers.go:290-296` - Actor claims merging

### Validation
- `path_token_handlers.go:58-67` - Token validation (incomplete)
- `path_token_handlers.go:142-171` - JWT signature validation
- `path_token_handlers.go:197-225` - Expiration checking

### Configuration
- `path_config.go:10-23` - Config structure
- `path_role.go:10-19` - Role structure
- `path_role.go:14-15` - Bound audience/issuer (not validated)
