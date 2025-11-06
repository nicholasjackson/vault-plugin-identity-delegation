# RFC 8693 Token Format Implementation - Task Checklist

**Created**: 2025-11-05
**Status**: Ready for Execution

---

## Phase 1: Add Bound Audience/Issuer Validation (CRITICAL SECURITY)

**Estimated Time**: 4-6 hours

### 1.1 Write Validation Tests
- [ ] Add `TestTokenExchange_BoundIssuerMismatch` to `path_token_test.go`
- [ ] Add `TestTokenExchange_BoundIssuerMatch` to `path_token_test.go`
- [ ] Add `TestTokenExchange_BoundAudienceMismatch` to `path_token_test.go`
- [ ] Add `TestTokenExchange_BoundAudienceMatch` to `path_token_test.go`
- [ ] Add `TestTokenExchange_BoundAudienceMatchArray` to `path_token_test.go`
- [ ] Run tests and verify they fail (red)

### 1.2 Implement Validation Functions
- [ ] Add `validateBoundIssuer()` function to `path_token_handlers.go` (after line 225)
- [ ] Add `validateBoundAudiences()` function to `path_token_handlers.go` (after validateBoundIssuer)
- [ ] Update `pathTokenExchange()` to call `validateBoundIssuer()` (after line 67)
- [ ] Update `pathTokenExchange()` to call `validateBoundAudiences()` (after validateBoundIssuer)

### 1.3 Run Tests and Verify
- [ ] Run new validation tests: `go test -v -run TestTokenExchange_Bound ./...`
- [ ] Verify all new tests pass (green)
- [ ] Run all tests: `go test -v ./...`
- [ ] Verify no regressions

### 1.4 Manual Verification
- [ ] Test token exchange with wrong issuer (should reject)
- [ ] Test token exchange with correct issuer (should accept)
- [ ] Test token exchange with wrong audience (should reject)
- [ ] Test token exchange with correct audience (should accept)

**Phase 1 Complete**: ✅ Security vulnerability fixed

---

## Phase 2: Replace `obo` Claim with RFC 8693 `act` Claim

**Estimated Time**: 6-8 hours

### 2.1 Write Token Format Tests
- [ ] Add `TestTokenExchange_ActClaimStructure` to `path_token_test.go`
- [ ] Add `TestTokenExchange_ActorMetadataOptional` to `path_token_test.go`
- [ ] Run tests and verify they fail (red)

### 2.2 Update generateToken Signature
- [ ] Update `generateToken()` signature to accept `entityID string` parameter (line 262)
- [ ] Update caller in `pathTokenExchange()` to pass `req.EntityID` (line 105)

### 2.3 Implement Token Generation Changes
- [ ] Replace lines 298-302 in `path_token_handlers.go` (remove `obo` claim)
- [ ] Add `act` claim generation with actor identity (after line 285)
- [ ] Add `scope` claim generation (space-delimited) (after act claim)
- [ ] Update subject_claims logic to be conditional (only if non-empty)
- [ ] Update actor claims merge to protect `act` claim from override

### 2.4 Run Token Format Tests
- [ ] Run new format tests: `go test -v -run TestTokenExchange_Act ./...`
- [ ] Verify all new tests pass (green)
- [ ] Note: Existing tests may fail (expected)

### 2.5 Update Existing Tests
- [ ] Update `TestTokenExchange_VerifyGeneratedToken` (lines 467-469)
  - [ ] Verify `act` claim exists
  - [ ] Verify `scope` claim is space-delimited
  - [ ] Verify `obo` claim does NOT exist
- [ ] Update `TestTokenExchange_Success` actor_template if needed (line 109)
- [ ] Update other test templates to use RFC format if needed

### 2.6 Run All Tests
- [ ] Run all tests: `go test -v ./...`
- [ ] Verify all tests pass
- [ ] Fix any remaining test failures

### 2.7 Update Documentation
- [ ] Update `context` field description in `path_role.go` (line 61)
- [ ] Update `actor_template` field description in `path_role.go` (line 51)

**Phase 2 Complete**: ✅ RFC 8693 compliant token format

---

## Phase 3: Add Comprehensive RFC 8693 Test Suite

**Estimated Time**: 3-4 hours

### 3.1 Create New Test File
- [ ] Create `path_token_rfc8693_test.go`
- [ ] Add package declaration and imports

### 3.2 Write RFC 8693 Compliance Tests
- [ ] Add `TestRFC8693_TokenStructure` with subtests:
  - [ ] StandardClaims subtest (iss, sub, iat, exp)
  - [ ] DelegationClaims subtest (act, scope)
  - [ ] OptionalExtensions subtest (actor_metadata, subject_claims)
  - [ ] ProhibitedClaims subtest (no obo)
- [ ] Add `TestRFC8693_UserCentricSemantics`
- [ ] Add `TestRFC8693_ScopeFormat` with test cases:
  - [ ] Single scope
  - [ ] Multiple scopes
  - [ ] Empty scopes

### 3.3 Run Compliance Tests
- [ ] Run RFC 8693 tests: `go test -v -run TestRFC8693 ./...`
- [ ] Verify all compliance tests pass
- [ ] Fix any issues found

### 3.4 Run Full Test Suite
- [ ] Run all tests: `go test -v ./...`
- [ ] Verify no regressions
- [ ] Check test coverage: `go test -v -cover ./...`
- [ ] Verify coverage above 80%

**Phase 3 Complete**: ✅ Comprehensive RFC 8693 compliance validation

---

## Final Verification

### Code Quality
- [ ] Run `gofmt -w .` to format code
- [ ] Run `go vet ./...` to check for issues
- [ ] Verify no warnings or errors

### Test Execution
- [ ] Run full test suite: `go test -v ./...`
- [ ] Verify all tests pass
- [ ] Run with race detection: `go test -race ./...`
- [ ] Verify no race conditions

### Manual Integration Testing
- [ ] Configure plugin with bound_issuer and bound_audiences
- [ ] Exchange token with correct issuer and audience (should succeed)
- [ ] Exchange token with wrong issuer (should fail)
- [ ] Exchange token with wrong audience (should fail)
- [ ] Decode generated token and verify structure:
  - [ ] Has `sub` with user identity
  - [ ] Has `act` with actor identity only
  - [ ] Has `scope` with space-delimited string
  - [ ] Has optional `actor_metadata` (if template provides it)
  - [ ] Does NOT have `obo` claim
  - [ ] `act` claim does NOT contain metadata

### Documentation
- [ ] Verify field descriptions are updated in `path_role.go`
- [ ] Verify plan document is complete
- [ ] Verify research document is complete
- [ ] Verify context document is complete
- [ ] Verify task checklist is complete

---

## Success Metrics

### Required
- ✅ All tests pass (100% pass rate)
- ✅ Test coverage above 80%
- ✅ `go vet` passes with no warnings
- ✅ `gofmt` shows no formatting issues
- ✅ Security vulnerability fixed (bound validation)
- ✅ RFC 8693 compliant token format

### Optional (Nice to Have)
- ✅ Test coverage above 85%
- ✅ No race conditions detected
- ✅ Integration tests pass
- ✅ Manual verification complete

---

## Task Summary

**Total Tasks**: 52

**Phase 1**: 14 tasks (Security)
**Phase 2**: 20 tasks (RFC Compliance)
**Phase 3**: 12 tasks (Comprehensive Testing)
**Final Verification**: 16 tasks

---

## Time Tracking

**Phase 1 Actual**: _____ hours
**Phase 2 Actual**: _____ hours
**Phase 3 Actual**: _____ hours
**Final Verification Actual**: _____ hours

**Total Actual**: _____ hours (Estimated: 13-18 hours)

---

## Notes

Use this checklist during implementation to track progress. Check off tasks as you complete them.

**TDD Reminder**: Write tests BEFORE implementation for each phase. Follow red-green-refactor cycle.

**Test First**: Every implementation task should have a corresponding test task that comes before it in the checklist.

---

## Rollback Plan

If issues are discovered after implementation:

### Phase 1 Rollback
- [ ] Remove validation function calls from `pathTokenExchange()`
- [ ] Remove `validateBoundIssuer()` and `validateBoundAudiences()` functions
- [ ] Remove validation tests

### Phase 2 Rollback
- [ ] Restore lines 298-302 (`obo` claim generation)
- [ ] Remove `act` and `scope` claim generation
- [ ] Restore original `generateToken()` signature
- [ ] Restore original test expectations

**Note**: Phase 1 rollback NOT RECOMMENDED (security vulnerability). Only rollback Phase 2 if absolutely necessary.

---

## References

- **Detailed Plan**: `rfc-8693-token-format-implementation-plan.md` (full implementation details)
- **Research Notes**: `rfc-8693-token-format-implementation-research.md` (design decisions)
- **Quick Reference**: `rfc-8693-token-format-implementation-context.md` (key changes summary)
