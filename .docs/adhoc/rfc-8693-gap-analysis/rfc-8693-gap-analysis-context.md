# RFC 8693 Gap Analysis - Quick Reference

**Created**: 2025-11-05
**Status**: Complete

## Quick Summary

Comprehensive gap analysis of the Vault Token Exchange plugin against RFC 8693 (OAuth 2.0 Token Exchange specification). **Compliance Level: ~30%** - Plugin implements basic token exchange concept but deviates significantly in request/response format, claim structure, and validation.

## Key Files & Locations

### Plugin Implementation
- `path_token.go:9-36` - Token exchange endpoint definition
- `path_token.go:13-24` - Request schema (missing RFC parameters)
- `path_token_handlers.go:22-115` - Main exchange handler
- `path_token_handlers.go:298-302` - Custom `obo` claim (should be `act`)
- `path_token_handlers.go:110-114` - Non-compliant response format

### Configuration
- `path_config.go:10-23` - Plugin configuration structure
- `path_role.go:10-19` - Role configuration structure
- `path_role.go:14-15` - Bound audience/issuer (defined but not validated)

### Validation (Incomplete)
- `path_token_handlers.go:58-67` - Token validation (missing audience/issuer checks)
- `path_token_handlers.go:142-171` - JWT signature validation
- `path_token_handlers.go:197-225` - Expiration checking

## Critical Gaps (MUST Requirements)

1. **Missing grant_type parameter** - `path_token.go:13-24`
2. **Missing subject_token_type parameter** - `path_token.go:19-23`
3. **Missing actor_token/actor_token_type parameters** - `path_token_handlers.go:69-102`
4. **Non-compliant response format** - `path_token_handlers.go:110-114` (returns "token" instead of "access_token", missing required fields)
5. **Missing token type identifiers** - No URN-based token types throughout
6. **Non-standard actor claim** - `path_token_handlers.go:298-302` (uses `obo` instead of `act`)

## Important Gaps (SHOULD/RECOMMENDED)

7. **Missing resource/audience parameters** - Cannot explicitly declare target service
8. **Missing scope parameter** - Cannot dynamically request scopes
9. **Missing requested_token_type parameter** - Always returns JWT
10. **Missing RFC error codes** - `path_token_handlers.go:30,40,49,61,66` (generic errors)
11. **Missing bound audience/issuer validation** - Security risk, fields defined but not checked
12. **Missing scope claim in output** - Uses `obo.ctx` instead of standard `scope`

## Key Technical Decisions

### Current vs. RFC Pattern

**Current Implementation**: Custom delegation with `obo` claim
```json
{
  "sub": "user@example.com",
  "obo": {"prn": "user@example.com", "ctx": "scope1,scope2"}
}
```

**RFC 8693 Delegation**: Standard `act` claim
```json
{
  "sub": "user@example.com",
  "act": {"sub": "agent@example.com"},
  "scope": "scope1 scope2"
}
```

### Delegation Patterns Supported by RFC

1. **Impersonation** - No `act` claim, service acts AS user
2. **Delegation** - Has `act` claim, agent acts ON BEHALF OF user
3. **Delegation Chain** - Nested `act` claims for multi-hop scenarios
4. **Pre-Authorization** - `may_act` claim for conditional delegation

**Plugin Intent**: Delegation (Pattern 2) but with non-standard structure

## Integration Points

### Request Flow
1. Client → `/token/:name` with `subject_token`
2. Plugin validates JWT signature against JWKS
3. Plugin fetches Vault entity info
4. Plugin processes templates to generate actor/subject claims
5. Plugin generates new JWT with merged claims
6. Plugin returns custom response format

### External Dependencies
- JWKS endpoint (config.SubjectJWKSURI) - for validating subject tokens
- Vault entity system - for implicit actor information
- RSA signing key - for signing issued tokens

## Environment Requirements

### Current
- Vault 1.x+ with plugin support
- JWKS endpoint accessible for subject token validation
- RSA private key (PEM format, PKCS1 or PKCS8)

### No Additional Requirements for RFC Compliance
- Same dependencies
- Breaking changes to request/response format
- Client and resource server updates required

## Related Documentation

- Full analysis: `rfc-8693-gap-analysis-plan.md`
- Research notes: `rfc-8693-gap-analysis-research.md`
- RFC 8693 specification: https://www.rfc-editor.org/rfc/rfc8693.html
- Plugin documentation: `/CLAUDE.md`

## Migration Impact

### Breaking Changes
- Request format (new required parameters)
- Response format (renamed fields, new fields)
- Token claims structure (`obo` → `act`)

### Backward Compatibility Strategies
1. Support both formats during transition
2. Configuration flag for RFC compliance mode
3. New endpoint alongside existing endpoint
