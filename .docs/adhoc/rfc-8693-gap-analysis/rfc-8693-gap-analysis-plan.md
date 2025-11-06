# RFC 8693 Compliance Gap Analysis

**Created**: 2025-11-05
**Updated**: 2025-11-05
**Type**: Analysis Report
**Status**: Complete

---

## Scope Clarification

**IMPORTANT**: This analysis focuses on **TOKEN FORMAT compliance with RFC 8693**, not full API compliance.

### In Scope: Token Format
- ✅ Token claims structure (`act` claim)
- ✅ Token semantics (delegation model)
- ✅ Token type identifiers
- ✅ Claim validation

### Out of Scope: HTTP API
- ❌ Request parameter format (grant_type, subject_token_type, etc.)
- ❌ Response format (access_token vs token)
- ❌ HTTP error codes
- ❌ Token exchange protocol endpoints

**Goal**: Issue RFC 8693 compliant tokens that can be validated by standard resource servers, while maintaining Vault's existing HTTP API patterns.

---

## Overview

This document provides a comprehensive analysis of the current Vault Token Exchange plugin's token format against RFC 8693 (OAuth 2.0 Token Exchange) specification. It identifies gaps in token structure and provides detailed comparisons of delegation patterns.

## Executive Summary

The current plugin implements a custom token exchange mechanism for "on behalf of" scenarios but **uses non-standard token format** in the following areas:

1. **Custom claim structure** - Uses `obo` claim (expired 2010 draft) instead of standard `act` claim (RFC 8693)
2. **Semantic inversion** - Token structure emphasizes actor over user (opposite of RFC 8693 delegation model)
3. **Incomplete validation** - Bound audience/issuer checks not implemented

**Token Format Compliance Level**: ~40% RFC-compliant (correct subject, but wrong delegation structure)

**Note**: HTTP API compliance (request/response format) is OUT OF SCOPE for this analysis.

## Token Format Gaps (In Scope)

### Gap 1: Non-Standard Actor Claim Structure (RFC 8693 Section 4.1) 🔴 CRITICAL

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

**Impact**: 🔴 **CRITICAL** - Resource servers expecting RFC 8693 format cannot process tokens correctly

**Priority**: HIGH - Core token format issue

---

### Gap 2: Token Structure Organization - User vs Actor Claim Prominence

**Current State**: Token structure emphasizes actor metadata at top-level, with user metadata nested
**Location**: `path_token_handlers.go:288-302`

**Current Token Structure**:
```json
{
  "sub": "user@example.com",              // Subject correct

  // Actor metadata PROMINENT (top level)
  "entity_id": "vault-entity-123",
  "department": "AI Services",
  "agent_type": "gpt-4",

  // User metadata SUBORDINATE (nested)
  "subject_claims": {
    "email": "user@example.com",
    "name": "John Doe"
  }
}
```

**RFC 8693 Compliant Structure Options**:

**Option A: User-Centric (More Standard)**
```json
{
  "sub": "user@example.com",              // User is primary subject
  "act": {"sub": "agent@example.com"},    // Actor delegation

  // User metadata PROMINENT (top level)
  "email": "user@example.com",
  "name": "John Doe",
  "roles": ["user", "premium"],

  // Actor metadata NAMESPACED
  "actor_metadata": {
    "entity_id": "vault-entity-123",
    "department": "AI Services",
    "agent_type": "gpt-4"
  }
}
```

**Option B: Dual Namespaced (Clearest)**
```json
{
  "sub": "user@example.com",              // User is primary subject
  "act": {"sub": "agent@example.com"},    // Actor delegation
  "scope": "read write",                  // Delegated scopes

  // User metadata NAMESPACED
  "subject_claims": {
    "email": "user@example.com",
    "name": "John Doe",
    "roles": ["user", "premium"]
  },

  // Actor metadata NAMESPACED
  "actor_metadata": {
    "entity_id": "vault-entity-123",
    "department": "AI Services",
    "agent_type": "gpt-4"
  }
}
```

**Design Decision Required**: Choose between:
- **Option A**: User claims prominent (more standard, follows typical JWT patterns)
- **Option B**: Both namespaced (clearest provenance, symmetric structure)

**Why This Matters**: RFC 8693 delegation semantics are user-centric ("user authority wielded by agent"), not agent-centric ("agent acting with user reference")

**Note**: Actor metadata storage is a **design extension beyond RFC 8693** (see Design Decisions section). RFC only mandates actor identity in `act.sub`.

**Impact**: Affects token interpretation and resource server expectations

**Priority**: MEDIUM - Structural organization, both options are RFC-compliant

---

### Gap 3: Historical OBO Claim Origin

**Discovery**: The `obo` claim comes from an **expired 2010 Internet Draft** that was never standardized.

**History**:
- **2010**: `draft-jones-on-behalf-of-jwt-00` proposed `obo` claim (Microsoft authors)
- **2011**: Draft expired April 29, 2011 - never adopted
- **2020**: RFC 8693 published with `act` claim instead (different structure)

**Current `obo` Structure** (from expired draft):
```json
{
  "obo": {
    "prn": "user@example.com",    // Principal
    "ctx": ["read", "write"]      // Context (array)
  }
}
```

**RFC 8693 `act` Structure** (official standard):
```json
{
  "act": {
    "sub": "agent@example.com"    // Actor identity only
  },
  "scope": "read write"           // Scopes at top level (space-delimited)
}
```

**Why This Matters**: Using an expired, non-standard draft instead of published RFC

**Impact**: No standard tooling/libraries recognize `obo`; not interoperable

**Priority**: HIGH - Using non-standard specification

---

### Gap 4: Missing Bound Audience/Issuer Validation 🔴 SECURITY RISK

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

**Impact**: 🔴 **SECURITY RISK** - Tokens with wrong issuer or audience can be exchanged; violates principle of least privilege

**Priority**: CRITICAL - Security vulnerability

---

### Gap 5: Missing scope Claim in Output Token (RFC 8693 Section 4.3)

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

**Priority**: MEDIUM - Affects scope representation

---

## HTTP API Gaps (Out of Scope)

The following gaps relate to the HTTP API protocol, not token format. These are **OUT OF SCOPE** for this analysis as the goal is token format compliance only.

### ❌ OUT OF SCOPE: Missing Grant Type Parameter (RFC 8693 Section 2.1)

**Reason**: HTTP API compliance not required - only token format compliance

**Note**: Vault plugins use their own path-based routing. Client integration handles the Vault-specific API.

---

### ❌ OUT OF SCOPE: Missing subject_token_type Parameter

**Reason**: HTTP API parameter - not part of token format

---

### ❌ OUT OF SCOPE: Missing actor_token Parameter

**Reason**: HTTP API parameter - plugin uses Vault entity for actor identity (valid design choice)

---

### ❌ OUT OF SCOPE: Non-Compliant Response Format

**Current**: Returns `{"token": "..."}`
**RFC**: Should return `{"access_token": "...", "issued_token_type": "...", "token_type": "..."}`

**Reason**: HTTP API response format - not part of token format. Client integration can map response fields.

---

### ❌ OUT OF SCOPE: Missing Token Type URN Identifiers in API

**Reason**: HTTP API parameter validation - not required for token format compliance

---

### ❌ OUT OF SCOPE: Missing resource/audience Request Parameters

**Reason**: HTTP API parameters - audience can be set via role configuration

---

### ❌ OUT OF SCOPE: Missing scope Request Parameter

**Reason**: HTTP API parameter - scopes configured via role context

---

### ❌ OUT OF SCOPE: Missing requested_token_type Parameter

**Reason**: HTTP API parameter - plugin always issues JWT (valid design choice)

---

### ❌ OUT OF SCOPE: Missing RFC Error Codes

**Reason**: HTTP API error response format - Vault has its own error handling patterns

---

## Design Decisions (Not Gaps)

These are intentional design choices that differ from typical RFC 8693 implementations but are not compliance issues:

### ✅ Endpoint Pattern: `/token/:name`

**Current**: Role-based path routing
**RFC 8693**: Typically single `/token` endpoint

**Decision**: Acceptable - Vault uses path-based routing for all plugins

---

### ✅ Vault Token Authentication

**Current**: Vault token authentication
**RFC 8693**: OAuth 2.0 client authentication

**Decision**: Acceptable - Vault has its own authentication model

---

### ✅ Subject Claims Structure

**Current**: Wraps subject-derived claims under `subject_claims` key
**Location**: `path_token_handlers.go:288`

```go
// add the subject claims under "subject_claims" key
claims["subject_claims"] = subjectClaims
```

**RFC 8693**: No specification (explicitly out of scope)

**Decision**: Valid design choice - RFC 8693 Section 1 states claim handling from subject_token is "out of scope"

**Alternative Options**:
1. **Top-level merge** - Merge subject claims at top level (more standard)
2. **Namespaced** (current) - Keep under `subject_claims` (clearer provenance)

Both are RFC-compliant as the RFC doesn't specify this.

---

### ✅ Actor Metadata Storage (Beyond RFC Scope)

**Decision**: The plugin MAY optionally store actor metadata (non-identity information) in the issued token, even though RFC 8693 does not specify this.

**Status**: OPTIONAL custom extension

**Rationale** (when used):
- AI agent use cases may require rich context about the actor (agent type, department, capabilities, etc.)
- Resource servers may need this metadata for authorization decisions (e.g., "only GPT-4 agents can access sensitive data")
- Audit and compliance requirements may need detailed actor information

**RFC 8693 Position**:
- RFC 8693 Section 4.1 restricts the `act` claim to **identity only** (`sub`, `iss`)
- Non-identity metadata is explicitly prohibited in `act` claim
- RFC does not specify WHERE actor metadata should go (out of scope)

**Implementation Options**:

**Option 1: Top-Level Claims (Standard JWT Practice)**
```json
{
  "sub": "user@example.com",
  "act": {
    "sub": "agent@example.com"         // Identity only (RFC 8693)
  },

  // Actor metadata at top level
  "entity_id": "vault-entity-123",
  "department": "AI Services",
  "agent_type": "gpt-4",
  "agent_version": "2.1.0"
}
```
**Pros**: Standard JWT pattern; easy access
**Cons**: Can clash with other top-level claims

**Option 2: Namespaced Actor Metadata (Clearer)**
```json
{
  "sub": "user@example.com",
  "act": {
    "sub": "agent@example.com"         // Identity only (RFC 8693)
  },

  // Actor metadata in namespace
  "actor_metadata": {
    "entity_id": "vault-entity-123",
    "department": "AI Services",
    "agent_type": "gpt-4",
    "agent_version": "2.1.0"
  }
}
```
**Pros**: Clear provenance; no collision risk; consistent with `subject_claims` pattern
**Cons**: Resource servers need to know custom structure

**Recommended**: Option 2 (namespaced) for consistency with `subject_claims` approach and clear separation of concerns.

**Note**: This is a **design extension**, not an RFC 8693 requirement. Resource servers must be aware of this custom structure.

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

### Token Format Changes (In Scope)

**Priority: HIGH**
- [ ] Replace `obo` claim with `act` claim structure
- [ ] Move actor identity to `act.sub` (identity only, no metadata)
- [ ] Add top-level `scope` claim (space-delimited string)
- [ ] Implement bound audience validation
- [ ] Implement bound issuer validation

**Priority: MEDIUM**
- [ ] Decide on token structure organization:
  - Option A: User claims top-level, actor metadata namespaced
  - Option B: Both user and actor claims namespaced (symmetric)
- [ ] Decide if actor metadata should be included (optional extension beyond RFC 8693)
- [ ] Document subject claims handling approach

**Priority: LOW**
- [ ] Support nested `act` for delegation chains (future enhancement)
- [ ] Support `may_act` claim validation (future enhancement)

### HTTP API Changes (Out of Scope)

These changes are NOT required for token format compliance:
- ❌ Request parameter format changes (grant_type, subject_token_type, etc.)
- ❌ Response format changes (access_token vs token)
- ❌ Token type URN identifiers in API
- ❌ RFC error codes
- ❌ Explicit actor_token parameter support

**Rationale**: The plugin integrates with Vault's existing API patterns. Only the issued TOKEN needs to be RFC 8693 compliant, not the HTTP API.

---

## Impact Assessment

### Breaking Changes (Token Format Only)
- Token claim structure changes (`obo` → `act`)
- Scope format changes (comma-delimited → space-delimited)
- Token structure changes (actor-centric → user-centric)

### Backward Compatibility Options
1. **Dual-claim period**: Issue both `obo` and `act` claims temporarily
2. **Configuration flag**: Enable RFC-compliant token format per role
3. **Version in token**: Add claim indicating token format version

### Migration Considerations
- **Resource servers** expecting `obo` claim will need updates to recognize `act`
- **Clients** using the HTTP API don't need changes (API stays the same)
- **Token validators** will need to handle new claim structure
- Consider deprecation timeline for `obo` claim (6-12 months)

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
