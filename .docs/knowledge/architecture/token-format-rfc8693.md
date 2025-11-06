# Token Format Architecture: RFC 8693 Compliance

**Created**: 2025-11-05
**Status**: Architectural Decision
**Applies To**: All token exchange operations

---

## Decision

**The Vault Token Exchange plugin MUST follow RFC 8693 (OAuth 2.0 Token Exchange) for all token formats and structures.**

---

## Context

The plugin implements OAuth 2.0 Token Exchange for "on behalf of" scenarios where AI agents act on behalf of users. To ensure interoperability, standards compliance, and future maintainability, all tokens issued by this plugin must conform to RFC 8693.

**RFC Reference**: [RFC 8693 - OAuth 2.0 Token Exchange](https://www.rfc-editor.org/rfc/rfc8693.html)

---

## Token Structure Requirements

### Issued Token Format (RFC 8693 Compliant + Custom Extensions)

```json
{
  "iss": "https://vault.example.com",
  "sub": "user@example.com",                    // User is the subject (REQUIRED)
  "aud": "https://resource-server.example.com",
  "iat": 1234567890,
  "exp": 1234654290,

  "act": {                                      // RFC 8693 actor claim (REQUIRED)
    "sub": "agent@example.com",                 // Agent identity only
    "iss": "https://vault.example.com"          // Optional: actor issuer
  },

  "scope": "read write",                        // Space-delimited scopes (REQUIRED)

  "actor_metadata": {                           // OPTIONAL - Custom extension (beyond RFC 8693)
    "entity_id": "vault-entity-123",            // Plugin MAY store rich actor context
    "department": "AI Services",                // For AI agent use cases
    "agent_type": "gpt-4",
    "agent_version": "2.1.0"
  },

  "subject_claims": {                           // OPTIONAL - Design choice (RFC doesn't specify)
    "email": "user@example.com",                // Claims from subject token
    "name": "John Doe",
    "roles": ["user", "premium"]
  }
}
```

**Note**: `actor_metadata` and `subject_claims` are **OPTIONAL custom extensions** for this plugin's use case. RFC 8693 only mandates the standard claims and `act` structure.

---

## Required Claims (RFC 8693)

### Standard JWT Claims

| Claim | Required | Description | Source |
|-------|----------|-------------|--------|
| `iss` | Yes | Token issuer | Plugin configuration |
| `sub` | Yes | Subject (user identity) | Subject token |
| `aud` | Yes | Target audience | Exchange request or role config |
| `iat` | Yes | Issued at timestamp | Generation time |
| `exp` | Yes | Expiration timestamp | Generation time + TTL |

### Delegation Claims

| Claim | Required | Description | Source |
|-------|----------|-------------|--------|
| `act` | Yes | Actor identity (agent) | Vault entity or actor_token |
| `act.sub` | Yes | Actor subject identifier | Vault entity or actor_token |
| `act.iss` | Optional | Actor issuer (for uniqueness) | Vault issuer |
| `scope` | Recommended | Space-delimited scopes | Role context configuration |

---

## Prohibited Patterns

### ❌ DO NOT Use: `obo` Claim (Non-Standard)

```json
{
  "sub": "user@example.com",
  "obo": {                              // ❌ NOT RFC 8693
    "prn": "user@example.com",
    "ctx": "read,write"
  }
}
```

**Why**: The `obo` claim is from an expired 2010 Internet Draft (`draft-jones-on-behalf-of-jwt-00`) that was never standardized. RFC 8693 uses the `act` claim instead.

**History**:
- 2010: `draft-jones-on-behalf-of-jwt-00` proposed `obo` claim
- 2011: Draft expired (never adopted)
- 2020: RFC 8693 published with `act` claim instead

---

### ❌ DO NOT Use: Actor as Subject

```json
{
  "sub": "agent@example.com",           // ❌ Wrong: actor as subject
  "act": {
    "sub": "user@example.com"           // ❌ Wrong: user as actor
  }
}
```

**Why**: RFC 8693 delegation semantics require the user to be the subject and the agent to be the actor. This represents "agent acting on behalf of user", not "user acting as agent".

---

### ❌ DO NOT Use: Non-Identity Claims in `act`

```json
{
  "sub": "user@example.com",
  "act": {
    "sub": "agent@example.com",
    "exp": 1234567890,                  // ❌ NOT ALLOWED
    "nbf": 1234567890,                  // ❌ NOT ALLOWED
    "aud": "resource.com",              // ❌ NOT ALLOWED
    "department": "AI Services",        // ❌ NOT ALLOWED (metadata)
    "roles": ["admin"]                  // ❌ NOT ALLOWED (metadata)
  }
}
```

**Why**: RFC 8693 Section 4.1 explicitly states:
> "claims within the `act` claim pertain **only to the identity of the actor** and are not relevant to the validity of the containing JWT"

> "non-identity claims (e.g., `exp`, `nbf`, and `aud`) are **not meaningful** when used within an `act` claim"

**Only identity claims allowed**: `sub`, `iss`

---

## Custom Extensions (Beyond RFC 8693)

### Actor Metadata Storage (Plugin Design Decision)

**Decision**: This plugin MAY optionally store actor metadata (non-identity information) in issued tokens to support AI agent use cases.

**Status**: OPTIONAL - Not required by RFC 8693

**Rationale**:
- AI agent scenarios require rich context about the actor (agent type, capabilities, department)
- Resource servers need this metadata for authorization decisions
- Audit and compliance requirements demand detailed actor information
- Example: "Only GPT-4 agents from AI Services department can access sensitive customer data"

**RFC 8693 Position**:
- RFC 8693 Section 4.1 restricts the `act` claim to **identity only** (`sub`, `iss`)
- Non-identity metadata is explicitly prohibited in `act` claim
- RFC does not specify WHERE actor metadata should go (out of scope)

**Implementation**: Namespaced Metadata (Recommended)

```json
{
  "sub": "user@example.com",
  "act": {
    "sub": "agent@example.com"          // Identity only (RFC 8693)
  },
  "scope": "read write",

  // Actor metadata in namespace (CUSTOM EXTENSION)
  "actor_metadata": {
    "entity_id": "vault-entity-123",
    "department": "AI Services",
    "team": "Customer Support",
    "agent_type": "gpt-4",
    "agent_version": "2.1.0",
    "capabilities": ["document-access", "data-analysis"]
  }
}
```

**Why Namespaced**:
- ✅ Clear provenance (know this came from Vault entity, not RFC standard)
- ✅ No collision risk with standard claims
- ✅ Consistent with `subject_claims` pattern
- ✅ Resource servers can opt-in to using this metadata

**Alternative**: Top-level claims (more standard JWT practice, but less clear provenance)

**Important**: This is a **design extension**, not an RFC 8693 requirement. Resource servers must be aware of this custom structure.

---

### Subject Token Claims (If Preserved)

RFC 8693 does not specify how to handle subject token claims. Two valid approaches:

**Option 1: Top-Level Merge (Standard JWT Practice)**
```json
{
  "sub": "user@example.com",
  "act": {"sub": "agent@example.com"},

  // Subject claims merged at top level
  "email": "user@example.com",
  "name": "John Doe",
  "roles": ["user", "premium"]
}
```

**Option 2: Namespaced (Clearer Provenance)**
```json
{
  "sub": "user@example.com",
  "act": {"sub": "agent@example.com"},

  // Subject claims in namespace
  "subject_claims": {
    "email": "user@example.com",
    "name": "John Doe",
    "roles": ["user", "premium"]
  }
}
```

**Note**: Both are valid as RFC 8693 explicitly states claim handling from subject_token is "out of scope" (Section 1).

---

## Delegation Semantics

### User-Centric Model (RFC 8693)

```
Token represents: USER's authority
Actor: AGENT is using that authority
Authorization: Check if USER can do action, then check if AGENT can delegate
```

**Example Authorization Logic**:
```python
# Resource server checks user permissions first
if can_user_access(token.sub, resource):
    # Then verify agent is authorized to delegate
    if can_actor_delegate(token.act.sub):
        audit_log(f"{token.act.sub} accessed {resource} on behalf of {token.sub}")
        return ALLOW
```

### ❌ NOT: Agent-Centric Model

```
Token represents: AGENT's authority
Principal: USER is the beneficiary
Authorization: Check if AGENT can act on behalf of users
```

This inverts RFC 8693 semantics and is non-compliant.

---

## Request/Response Format

### Token Exchange Request (RFC 8693 Section 2.1)

**Required Parameters**:
```http
POST /token/:role-name
Content-Type: application/x-www-form-urlencoded

grant_type=urn:ietf:params:oauth:grant-type:token-exchange
&subject_token=eyJhbGc...
&subject_token_type=urn:ietf:params:oauth:token-type:jwt
```

**Optional Parameters**:
```http
&actor_token=eyJhbGc...
&actor_token_type=urn:ietf:params:oauth:token-type:jwt
&resource=https://api.example.com
&audience=api-service
&scope=read write
&requested_token_type=urn:ietf:params:oauth:token-type:jwt
```

### Token Exchange Response (RFC 8693 Section 2.2)

**Required Fields**:
```json
{
  "access_token": "eyJhbGc...",
  "issued_token_type": "urn:ietf:params:oauth:token-type:jwt",
  "token_type": "N_A"
}
```

**Recommended Fields**:
```json
{
  "access_token": "eyJhbGc...",
  "issued_token_type": "urn:ietf:params:oauth:token-type:jwt",
  "token_type": "N_A",
  "expires_in": 3600,
  "scope": "read write"
}
```

---

## Token Type Identifiers (RFC 8693 Section 3)

All token types MUST use URN identifiers:

| Token Type | URN Identifier |
|------------|----------------|
| JWT | `urn:ietf:params:oauth:token-type:jwt` |
| OAuth 2.0 Access Token | `urn:ietf:params:oauth:token-type:access_token` |
| OAuth 2.0 Refresh Token | `urn:ietf:params:oauth:token-type:refresh_token` |
| OIDC ID Token | `urn:ietf:params:oauth:token-type:id_token` |
| SAML 1.1 Assertion | `urn:ietf:params:oauth:token-type:saml1` |
| SAML 2.0 Assertion | `urn:ietf:params:oauth:token-type:saml2` |

---

## Error Responses (RFC 8693 Section 2.2.2)

### Standard Error Codes

| Error Code | When to Use |
|------------|-------------|
| `invalid_request` | Missing required parameter, invalid token, malformed request |
| `invalid_target` | Cannot issue token for specified resource/audience |
| `invalid_grant` | Subject token invalid, expired, or revoked |
| `unauthorized_client` | Client not authorized for token exchange |

### Error Response Format

```json
{
  "error": "invalid_request",
  "error_description": "subject_token parameter is required",
  "error_uri": "https://tools.ietf.org/html/rfc8693#section-2.2.2"
}
```

---

## Delegation Patterns (RFC 8693 Section 4)

### Pattern 1: Impersonation (No Actor)

**Use Case**: Service acts AS the user
```json
{
  "sub": "user@example.com",
  "scope": "read write"
  // No act claim
}
```

### Pattern 2: Delegation (Current Actor)

**Use Case**: Agent acts ON BEHALF OF user
```json
{
  "sub": "user@example.com",
  "act": {
    "sub": "agent@example.com"
  },
  "scope": "read write"
}
```

### Pattern 3: Delegation Chain (Multi-Hop)

**Use Case**: Multiple services delegating
```json
{
  "sub": "user@example.com",
  "act": {
    "sub": "service2.example.com",
    "act": {
      "sub": "service1.example.com"
    }
  }
}
```

**Note**: Only top-level `sub` and immediate `act.sub` are used for authorization. Nested actors are informational.

### Pattern 4: Pre-Authorization (may_act)

**Use Case**: Grant permission for future delegation
```json
{
  "sub": "user@example.com",
  "may_act": {
    "sub": "agent@example.com"
  }
}
```

**This Plugin Uses**: Pattern 2 (Delegation with Current Actor)

---

## Validation Requirements

### Subject Token Validation

1. ✅ Verify JWT signature against JWKS
2. ✅ Check expiration (`exp` claim)
3. ✅ Validate issuer (`iss` claim) against bound_issuer if configured
4. ✅ Validate audience (`aud` claim) against bound_audiences if configured
5. ✅ Check not-before (`nbf` claim) if present

### Actor Token Validation (If Explicit actor_token Provided)

1. ✅ Verify JWT signature
2. ✅ Check expiration
3. ✅ Extract actor identity (`sub` claim)

### Issued Token Requirements

1. ✅ Must have valid `iss`, `sub`, `aud`, `iat`, `exp`
2. ✅ Must have `act` claim with `act.sub` for delegation
3. ✅ Must sign with configured signing key (RS256)
4. ✅ Must use TTL from role configuration

---

## Implementation Checklist

### Current State
- [x] Token generation and signing
- [x] Subject token validation (signature, expiration)
- [x] Vault entity integration for actor identity
- [ ] RFC 8693 compliant `act` claim (currently uses `obo`)
- [ ] RFC 8693 compliant request parameters
- [ ] RFC 8693 compliant response format
- [ ] Bound audience/issuer validation
- [ ] Token type URN identifiers
- [ ] Standard error codes

### Target State (RFC 8693 Compliant)
- [ ] Replace `obo` with `act` claim
- [ ] Add `grant_type` parameter validation
- [ ] Add `subject_token_type` parameter
- [ ] Support optional `actor_token` parameter
- [ ] Return `access_token`, `issued_token_type`, `token_type`
- [ ] Add `expires_in` to response
- [ ] Use space-delimited `scope` claim
- [ ] Implement bound audience/issuer validation
- [ ] Use URN token type identifiers
- [ ] Return RFC error codes

---

## References

- **RFC 8693**: OAuth 2.0 Token Exchange - https://www.rfc-editor.org/rfc/rfc8693.html
- **Gap Analysis**: `.docs/adhoc/rfc-8693-gap-analysis/rfc-8693-gap-analysis-plan.md`
- **Section 4.1**: Actor Claim - https://www.rfc-editor.org/rfc/rfc8693.html#section-4.1
- **Section 2.1**: Request Parameters - https://www.rfc-editor.org/rfc/rfc8693.html#section-2.1
- **Section 2.2**: Response Format - https://www.rfc-editor.org/rfc/rfc8693.html#section-2.2

---

## Related Documentation

- **Plugin Overview**: `/CLAUDE.md`
- **Gap Analysis**: `.docs/adhoc/rfc-8693-gap-analysis/`
- **Current Implementation**:
  - `path_token.go` - Endpoint definition
  - `path_token_handlers.go` - Token generation
  - `path_role.go` - Role configuration

---

## Change History

| Date | Change | Reason |
|------|--------|--------|
| 2025-11-05 | Initial architecture document | Establish RFC 8693 as token format standard |

---

## Notes

- This is an architectural **decision**, not just documentation
- All future token-related code MUST follow RFC 8693
- Deviations require explicit justification and documentation
- Backward compatibility considerations should be addressed during migration

---

## Architectural Principle

**"The plugin SHALL be RFC 8693 compliant to ensure interoperability, standards adherence, and future maintainability of token exchange operations."**
