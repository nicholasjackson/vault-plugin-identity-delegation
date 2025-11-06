# RFC 8693 Token Format Implementation - Quick Reference

**Created**: 2025-11-05
**Status**: Ready for Implementation

---

## What We're Building

Implement RFC 8693 compliant token format for the Vault Token Exchange plugin.

**Scope**: Token format ONLY (claims structure, semantics, validation)
**Out of Scope**: HTTP API compliance (request/response format remains Vault-specific)

---

## Why We're Building It

1. **Security Fix**: BoundAudiences/BoundIssuer fields exist but are never validated (CRITICAL)
2. **Standards Compliance**: Current `obo` claim is from expired 2010 draft, not RFC 8693
3. **Interoperability**: Resource servers expect RFC 8693 format
4. **Future Maintenance**: Standard format is easier to maintain and extend

---

## Implementation Phases

### Phase 1: Add Bound Validation (SECURITY - 4-6 hours)
- ✅ Fix critical security vulnerability
- ✅ Validate bound_issuer and bound_audiences
- ✅ Test-driven implementation

### Phase 2: RFC 8693 Token Format (COMPLIANCE - 6-8 hours)
- ✅ Replace `obo` claim with RFC 8693 `act` claim
- ✅ Add space-delimited `scope` claim
- ✅ Separate actor metadata from identity
- ✅ Update existing tests

### Phase 3: Comprehensive Testing (VALIDATION - 3-4 hours)
- ✅ RFC 8693 compliance test suite
- ✅ Full test coverage
- ✅ Integration testing

**Total**: 13-18 hours

---

## Key Changes

### Security (Phase 1)

**Before**: No validation of bound fields
```go
// Loads role, but never checks role.BoundAudiences or role.BoundIssuer
```

**After**: Validate issuer and audience
```go
// Validate bound issuer
if err := validateBoundIssuer(originalSubjectClaims, role.BoundIssuer); err != nil {
    return logical.ErrorResponse("failed to validate issuer: %v", err), nil
}

// Validate bound audiences
if err := validateBoundAudiences(originalSubjectClaims, role.BoundAudiences); err != nil {
    return logical.ErrorResponse("failed to validate audience: %v", err), nil
}
```

### Token Format (Phase 2)

**Before**: Non-standard `obo` claim
```json
{
  "sub": "user-123",
  "obo": {
    "prn": "user-123",
    "ctx": "urn:docs:read,urn:images:write"
  }
}
```

**After**: RFC 8693 compliant `act` and `scope`
```json
{
  "sub": "user-123",
  "act": {
    "sub": "agent:entity-456",
    "iss": "https://vault.example.com"
  },
  "scope": "urn:docs:read urn:images:write",
  "actor_metadata": {
    "entity_id": "entity-456",
    "department": "AI Services"
  }
}
```

---

## Critical File Locations

### Implementation Files
- **path_token_handlers.go:298-302** - Replace `obo` with `act` and `scope`
- **path_token_handlers.go:58-67** - Add bound validation after expiration check
- **path_token_handlers.go:262** - Update `generateToken` signature (add entityID)
- **path_token_handlers.go:105** - Update `generateToken` call (pass entityID)
- **path_role.go:51, 61** - Update field descriptions

### Test Files
- **path_token_test.go** - Add bound validation tests, update existing tests
- **path_token_rfc8693_test.go** - NEW: RFC 8693 compliance suite

---

## RFC 8693 Requirements

### Token Claims Structure

**Required Standard Claims**:
- `iss`: Token issuer (from plugin config)
- `sub`: Subject identity (user, from original token)
- `iat`: Issued at timestamp
- `exp`: Expiration timestamp

**Required Delegation Claims**:
- `act`: Actor identity (agent acting on behalf of user)
  - `act.sub`: Actor subject identifier (REQUIRED)
  - `act.iss`: Actor issuer (OPTIONAL)
- `scope`: Space-delimited scopes (RECOMMENDED)

**Optional Extensions** (custom, not RFC):
- `actor_metadata`: Actor metadata (department, capabilities, etc.)
- `subject_claims`: Subject token claims for reference

**Prohibited**:
- `obo` claim (expired 2010 draft)
- Non-identity claims in `act` (exp, iat, aud, nbf, metadata)
- Comma-delimited scopes

### Validation Requirements

**Subject Token Validation**:
1. ✅ Verify JWT signature (already done)
2. ✅ Check expiration (already done)
3. ❌ **NEW**: Validate issuer against `bound_issuer`
4. ❌ **NEW**: Validate audience against `bound_audiences`

---

## Test Strategy

### TDD Cycle
1. **Write test first** (red) - Define expected behavior
2. **Implement code** (green) - Make test pass
3. **Refactor** - Improve code quality
4. **Verify** - Run all tests

### Test Categories

**Phase 1 Tests** (Bound Validation):
- `TestTokenExchange_BoundIssuerMismatch` - Reject wrong issuer
- `TestTokenExchange_BoundIssuerMatch` - Accept correct issuer
- `TestTokenExchange_BoundAudienceMismatch` - Reject wrong audience
- `TestTokenExchange_BoundAudienceMatch` - Accept correct audience (string)
- `TestTokenExchange_BoundAudienceMatchArray` - Accept correct audience (array)

**Phase 2 Tests** (Token Format):
- `TestTokenExchange_ActClaimStructure` - Validate RFC 8693 act claim
- `TestTokenExchange_ActorMetadataOptional` - Verify metadata separation

**Phase 3 Tests** (RFC Compliance):
- `TestRFC8693_TokenStructure` - Complete structure validation
- `TestRFC8693_UserCentricSemantics` - Delegation semantics
- `TestRFC8693_ScopeFormat` - Space-delimited scope

---

## Success Criteria

### Automated
- ✅ All new tests pass
- ✅ All existing tests pass (after updates)
- ✅ Test coverage above 80%
- ✅ `go vet` passes
- ✅ `gofmt` passes

### Manual
- ✅ Generated token has `act` claim with actor identity only
- ✅ Generated token has space-delimited `scope` claim
- ✅ Generated token does NOT have `obo` claim
- ✅ Bound issuer validation rejects wrong issuers
- ✅ Bound audience validation rejects wrong audiences
- ✅ Actor metadata is separate from `act` claim (if present)
- ✅ Subject is user, actor is agent (user-centric delegation)

---

## Breaking Changes

**Token Format Changes**:
1. `obo` claim removed → `act` and `scope` claims added
2. `obo.ctx` (comma) → `scope` (space)
3. `obo.prn` → `sub` (no change, but `obo` wrapper removed)
4. Actor identity → `act.sub` (was in template-defined location)

**Impact**: Resource servers need to update token validation logic

**Migration Guide**: See plan document, Appendix

---

## Quick Command Reference

### Run Phase 1 Tests
```bash
go test -v -run TestTokenExchange_Bound ./...
```

### Run Phase 2 Tests
```bash
go test -v -run TestTokenExchange_Act ./...
```

### Run Phase 3 Tests
```bash
go test -v -run TestRFC8693 ./...
```

### Run All Tests
```bash
go test -v ./...
```

### Run with Coverage
```bash
go test -v -cover ./...
```

### Format Code
```bash
gofmt -w .
go vet ./...
```

---

## References

- **Detailed Plan**: `rfc-8693-token-format-implementation-plan.md`
- **Research Notes**: `rfc-8693-token-format-implementation-research.md`
- **Task Checklist**: `rfc-8693-token-format-implementation-tasks.md`
- **Gap Analysis**: `.docs/adhoc/rfc-8693-gap-analysis/`
- **Architecture**: `.docs/knowledge/architecture/token-format-rfc8693.md`
- **RFC 8693**: https://www.rfc-editor.org/rfc/rfc8693.html

---

## Key Takeaways

1. **Security First**: Phase 1 fixes critical vulnerability
2. **RFC Compliant**: Phase 2 implements standard format
3. **Well Tested**: Phase 3 ensures long-term compliance
4. **Breaking Change**: Resource servers must update validation
5. **TDD Approach**: Tests written before implementation
6. **Incremental**: Three independent, testable phases
