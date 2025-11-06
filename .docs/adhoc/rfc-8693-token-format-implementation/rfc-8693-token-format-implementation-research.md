# RFC 8693 Token Format Implementation - Research Notes

**Created**: 2025-11-05
**

Status**: Planning Complete

---

## Research Process

### Step 1: Reviewed Gap Analysis Documents

**Action**: Read comprehensive gap analysis from `.docs/adhoc/rfc-8693-gap-analysis/`
**Files Read**:
- `rfc-8693-gap-analysis-plan.md` (786 lines)
- `rfc-8693-gap-analysis-context.md` (122 lines)
- `rfc-8693-gap-analysis-research.md` (467 lines)
- `rfc-8693-gap-analysis-tasks.md` (115 lines)

**Key Findings**:
- **5 token format gaps** identified (security + compliance)
- **8 HTTP API gaps** marked out of scope
- **Scope clarification**: Only token format, not HTTP API
- **Security risk**: Bound audience/issuer validation missing

### Step 2: Activated Go Development Guidelines

**Action**: Invoked `go-dev-guidelines` skill
**Outcome**: Established TDD approach with testify/require
**Patterns**:
- Write tests first (red-green-refactor)
- Separate positive and negative test cases
- Use mockery for mocks (not needed for this implementation)
- No table-driven tests
- Explicit error handling

### Step 3: Launched Parallel Research Agents

**Action**: 3 concurrent Task agents for codebase analysis
**Agents**:
1. **Token Generation Agent**: Analyzed `path_token_handlers.go`
2. **Role Configuration Agent**: Analyzed `path_role.go`
3. **Test Coverage Agent**: Analyzed test files

**Results**: Comprehensive understanding of current implementation

### Step 4: Read Implementation Files

**Files Read**:
- `path_token_handlers.go` (313 lines) - Token generation logic
- `path_role.go` (106 lines) - Role configuration
- `path_token_test.go` (471 lines) - Existing tests

**Code Analysis Complete**: Full understanding of current structure

---

## Key Discoveries

### Discovery 1: Critical Security Vulnerability

**Finding**: `BoundAudiences` and `BoundIssuer` fields defined but NEVER validated

**Location**: `path_role.go:14-15` defines fields, but `path_token_handlers.go:58-67` doesn't validate them

**Evidence**:
```go
// Role definition (path_role.go:14-15)
BoundAudiences  []string      `json:"bound_audiences"`
BoundIssuer     string        `json:"bound_issuer"`

// Validation code (path_token_handlers.go:58-67)
// Validate and parse subject token
originalSubjectClaims, err := validateAndParseClaims(subjectTokenStr, config.SubjectJWKSURI)
if err != nil {
    return logical.ErrorResponse("failed to validate subject token: %v", err), nil
}

// Check expiration
if err := checkExpiration(originalSubjectClaims); err != nil {
    return logical.ErrorResponse("subject token expired: %v", err), nil
}
// NO VALIDATION OF AUDIENCE OR ISSUER HERE ❌
```

**Impact**: Security vulnerability allowing token exchange beyond intended scope

**Priority**: CRITICAL - Must fix in Phase 1

### Discovery 2: Non-Standard Token Format

**Finding**: Uses custom `obo` claim from expired 2010 draft

**Location**: `path_token_handlers.go:298-302`

**Evidence**:
```go
// Add the on-behalf-of context
claims["obo"] = map[string]any{
    "prn": subjectID,
    "ctx": strings.Join(role.Context, ","),  // ❌ Non-standard
}
```

**History**:
- `obo` claim from `draft-jones-on-behalf-of-jwt-00` (2010, expired 2011)
- RFC 8693 (2020) uses `act` claim instead
- Microsoft adopted draft, still used in some implementations

**RFC 8693 Requirement**:
```go
claims["act"] = map[string]any{
    "sub": actorIdentity,  // ✅ Standard
    "iss": issuer,         // Optional
}
claims["scope"] = "space delimited string"  // ✅ Standard
```

### Discovery 3: Scope Format Mismatch

**Finding**: Context stored as comma-delimited in nested claim, RFC requires space-delimited top-level

**Current**: `obo.ctx: "urn:docs:read,urn:images:write"`
**Required**: `scope: "urn:docs:read urn:images:write"`

**Location**: `path_token_handlers.go:301`

**Impact**: Token incompatible with RFC 8693 parsers

### Discovery 4: Actor Identity Extraction Pattern

**Finding**: Actor identity comes from Vault entity, not explicit token parameter

**Flow**:
1. Request includes `EntityID` from Vault authentication
2. `fetchEntity()` retrieves entity info from Vault (lines 69-74)
3. Entity data passed to `actor_template` for processing
4. Template output merged into token claims

**Current Implementation**:
```go
// Fetch entity (line 69-74)
b.Logger().Info("Get EntityID", "entity_id", req.EntityID)
entity, err := fetchEntity(req, b.System())

// Process template (line 88-91)
actorClaims, err := processTemplate(role.ActorTemplate, im)
```

**RFC 8693 Pattern**: Accepts explicit `actor_token` parameter (out of scope for this implementation)

**Decision**: Keep implicit entity-based actor identity, ensure RFC-compliant output format

### Discovery 5: Template-Based Claim Generation

**Finding**: Both actor and subject claims are template-processed

**Actor Template** (line 88-91):
- Input: Vault entity data (ID, name, namespace, metadata)
- Output: Claims merged into token (currently flexible, need to enforce `act` structure)

**Subject Template** (line 99-102):
- Input: Original subject token claims
- Output: Claims added under `subject_claims` key

**Risk**: Templates could override standard claims if not protected

**Mitigation**: Lines 291-296 already protect reserved claims:
```go
// Don't allow overriding reserved claims
if key != "iss" && key != "sub" && key != "iat" && key != "exp" && key != "aud" {
    claims[key] = value
}
```

**Enhancement Needed**: Also protect `act` claim from override

### Discovery 6: Test Coverage Observations

**Existing Tests**: 6 test functions in `path_token_test.go`
- `TestTokenExchange_Success` - Happy path
- `TestTokenExchange_MissingSubjectToken` - Required parameter
- `TestTokenExchange_InvalidJWT` - Invalid format
- `TestTokenExchange_ExpiredToken` - Expiration
- `TestTokenExchange_RoleNotFound` - Missing role
- `TestTokenExchange_VerifyGeneratedToken` - Token structure

**Gaps Identified**:
1. **No bound issuer validation tests** (security risk not caught)
2. **No bound audience validation tests** (security risk not caught)
3. **No RFC 8693 compliance tests** (format issues not caught)
4. **No `obo` claim validation tests** (current structure not validated)

**Test Infrastructure**: Good foundation with utilities:
- `generateTestKeyPair()` - Creates RSA keys
- `generateTestJWT()` - Signs JWTs
- `createMockJWKSServer()` - JWKS endpoint
- `getTestBackend()` - Test backend setup

**Pattern**: Uses `testify/require` for assertions (consistent with Go guidelines)

---

## Design Decisions

### Decision 1: Three-Phase Implementation Approach

**Decision**: Split implementation into 3 phases

**Phases**:
1. **Phase 1**: Add bound audience/issuer validation (SECURITY FIX)
2. **Phase 2**: Replace `obo` with `act` and `scope` claims (RFC COMPLIANCE)
3. **Phase 3**: Add comprehensive RFC 8693 test suite (VALIDATION)

**Reasoning**:
- Phase 1 addresses critical security vulnerability first
- Phase 2 achieves RFC compliance without breaking existing functionality until ready
- Phase 3 ensures long-term compliance with comprehensive tests
- Each phase is independently testable and verifiable

**Alternative Considered**: Single-phase "big bang" implementation
- Rejected: Too risky, harder to debug, all-or-nothing deployment

**Outcome**: Incremental, testable, lower-risk implementation

### Decision 2: Test-Driven Development Approach

**Decision**: Write tests before implementation for each phase

**TDD Cycle**:
1. Write failing test (red)
2. Implement minimum code to pass (green)
3. Refactor for clarity
4. Verify all tests still pass

**Reasoning**:
- Ensures code meets requirements
- Prevents regressions
- Documents expected behavior
- Follows Go development guidelines

**Alternative Considered**: Implementation first, tests later
- Rejected: Tests might accommodate bugs, harder to verify correctness

**Outcome**: High confidence in correctness, clear requirements

### Decision 3: Token Format - Actor Metadata Separation

**Decision**: Store actor metadata in separate `actor_metadata` namespace, not in `act` claim

**Implementation**:
```json
{
  "act": {
    "sub": "agent:entity-123",  // Identity only (RFC 8693)
    "iss": "https://vault.example.com"
  },
  "actor_metadata": {  // Custom extension (OPTIONAL)
    "entity_id": "entity-123",
    "department": "AI Services",
    "capabilities": ["document-access"]
  }
}
```

**Reasoning**:
- RFC 8693 Section 4.1 explicitly restricts `act` to identity claims only
- Non-identity claims (metadata) are prohibited in `act`
- Namespace makes provenance clear
- Resource servers can opt-in to using metadata
- Consistent with `subject_claims` pattern

**Alternative Considered**: Top-level claims without namespace
- Rejected: Less clear provenance, collision risk

**Outcome**: RFC-compliant with optional extension capability

### Decision 4: Actor Identity Fallback Strategy

**Decision**: If `actor_template` doesn't provide `act.sub`, fallback to `entity:<entity_id>`

**Implementation**:
```go
actorSubject := ""

// Check if actor_template provided act.sub
if actClaimRaw, ok := actorClaims["act"]; ok {
    if actClaimMap, ok := actClaimRaw.(map[string]any); ok {
        if sub, ok := actClaimMap["sub"].(string); ok {
            actorSubject = sub
        }
    }
}

// Fallback to entity ID
if actorSubject == "" {
    actorSubject = fmt.Sprintf("entity:%s", entityID)
}
```

**Reasoning**:
- Templates are flexible and might not include `act` claim
- Entity ID is always available from Vault authentication
- Prefixed format `entity:<id>` makes it clear this is Vault-specific
- Prevents missing actor identity (RFC 8693 requirement)

**Alternative Considered**: Require `act.sub` in template, fail if missing
- Rejected: Too strict, breaks backward compatibility with existing templates

**Outcome**: Robust fallback with clear semantics

### Decision 5: Scope Claim Generation

**Decision**: Generate `scope` claim from `role.Context` field (space-delimited)

**Implementation**:
```go
if len(role.Context) > 0 {
    claims["scope"] = strings.Join(role.Context, " ")
}
```

**Reasoning**:
- `role.Context` already exists and is required (no schema change)
- Field description calls it "delegate scopes" (matches RFC 8693 semantics)
- Simple transformation: comma-input → space-delimited output
- Empty context = no scope claim (valid per RFC)

**Alternative Considered**: New `scopes` field in role configuration
- Rejected: Unnecessary field duplication, migration complexity

**Outcome**: Minimal changes, backward-compatible configuration

### Decision 6: Validation Function Placement

**Decision**: Create separate validation functions, not inline validation

**Functions**:
- `validateBoundIssuer(claims, boundIssuer) error`
- `validateBoundAudiences(claims, boundAudiences) error`

**Reasoning**:
- Testable in isolation
- Reusable if needed elsewhere
- Clear separation of concerns
- Easier to understand and maintain

**Alternative Considered**: Inline validation in `pathTokenExchange`
- Rejected: Harder to test, harder to read

**Outcome**: Clean, testable validation logic

### Decision 7: Hard Cutover (No Dual Format)

**Decision**: Implement RFC 8693 format completely, remove `obo` claim entirely

**No Backward Compatibility Period**:
- Don't emit both `obo` and `act` claims
- No gradual migration with deprecation warnings
- Clean break to RFC 8693 format

**Reasoning**:
- Plugin not widely deployed (based on context)
- Dual format adds complexity and confusion
- RFC 8693 is the standard going forward
- Clean implementation better than technical debt

**Alternative Considered**: Emit both formats temporarily
- Rejected: Adds complexity, delays full compliance, confusing to users

**Outcome**: Clean RFC 8693 implementation

### Decision 8: Update Existing Tests vs. New Test File

**Decision**: Split test additions

**Approach**:
- **Update `path_token_test.go`**: Add bound validation tests, update existing tests
- **New `path_token_rfc8693_test.go`**: Comprehensive RFC 8693 compliance suite

**Reasoning**:
- Keep existing test file for related token exchange tests
- Separate RFC compliance tests for clarity and organization
- Easier to maintain and understand test categories

**Alternative Considered**: All tests in one file
- Rejected: File would be too large (800+ lines), harder to navigate

**Outcome**: Well-organized test suites

---

## Open Questions

### Question 1: Actor Template Migration

**Question**: Should existing actor templates be automatically migrated?

**Context**: Current templates might use custom formats, not RFC-compliant `act` structure

**Options**:
1. **Require manual template updates**: Users must update templates to include `act` claim
2. **Auto-wrap in act claim**: Plugin automatically wraps template output in `act.sub`
3. **Fallback strategy**: Use template if RFC-compliant, fallback to entity ID

**Current Decision**: Option 3 (Fallback strategy) implemented in Decision 4

**Resolution**: RESOLVED - Fallback to entity ID if template doesn't provide `act.sub`

### Question 2: Subject Claims Namespace

**Question**: Keep `subject_claims` namespace or merge to top-level?

**Context**: RFC 8693 doesn't specify how to handle subject token claims

**Options**:
1. **Keep namespace**: `subject_claims: {...}` (current implementation)
2. **Merge top-level**: Claims added directly to token
3. **Make configurable**: Role setting to choose behavior

**Current Decision**: Option 1 (Keep namespace) - provides clear provenance

**Resolution**: RESOLVED - Maintain `subject_claims` namespace for consistency with `actor_metadata`

### Question 3: Audience Claim in Generated Token

**Question**: Should generated token have `aud` claim?

**Context**: Current implementation adds `aud` from actor template (line 283-285)

**Current Behavior**:
```go
// Add audience if present
if aud, ok := actorClaims["aud"]; ok {
    claims["aud"] = aud
}
```

**RFC 8693**: `aud` claim should identify target resource server

**Current Decision**: Keep current behavior (template-based `aud`)

**Resolution**: RESOLVED - Template can specify `aud`, but it's optional

---

## Code Snippets Reference

### Current Token Generation (Before)

```go
// path_token_handlers.go:272-302 (BEFORE)
// Build claims
now := time.Now()
claims := make(map[string]any)

// Standard claims
claims["iss"] = config.Issuer
claims["sub"] = subjectID
claims["iat"] = now.Unix()
claims["exp"] = now.Add(role.TTL).Unix()

// Add audience if present
if aud, ok := actorClaims["aud"]; ok {
    claims["aud"] = aud
}

// add the subject claims under "subject_claims" key
claims["subject_claims"] = subjectClaims

// Merge actor claims
for key, value := range actorClaims {
    if key != "iss" && key != "sub" && key != "iat" && key != "exp" && key != "aud" {
        claims[key] = value
    }
}

// Add the on-behalf-of context
claims["obo"] = map[string]any{
    "prn": subjectID,
    "ctx": strings.Join(role.Context, ","),
}
```

### RFC 8693 Token Generation (After)

```go
// path_token_handlers.go:272-320 (AFTER)
// Build claims
now := time.Now()
claims := make(map[string]any)

// Standard claims (RFC 8693)
claims["iss"] = config.Issuer
claims["sub"] = subjectID
claims["iat"] = now.Unix()
claims["exp"] = now.Add(role.TTL).Unix()

// Add audience if present
if aud, ok := actorClaims["aud"]; ok {
    claims["aud"] = aud
}

// Add RFC 8693 actor claim (delegation)
actorSubject := ""
if actClaimRaw, ok := actorClaims["act"]; ok {
    if actClaimMap, ok := actClaimRaw.(map[string]any); ok {
        if sub, ok := actClaimMap["sub"].(string); ok {
            actorSubject = sub
        }
    }
}
if actorSubject == "" {
    actorSubject = fmt.Sprintf("entity:%s", entityID)
}

claims["act"] = map[string]any{
    "sub": actorSubject,
    "iss": config.Issuer,
}

// Add RFC 8693 scope claim (space-delimited)
if len(role.Context) > 0 {
    claims["scope"] = strings.Join(role.Context, " ")
}

// Add subject claims (optional extension)
if len(subjectClaims) > 0 {
    claims["subject_claims"] = subjectClaims
}

// Merge actor claims (for optional extensions)
for key, value := range actorClaims {
    if key != "iss" && key != "sub" && key != "iat" && key != "exp" && key != "aud" && key != "act" {
        claims[key] = value
    }
}
```

### Bound Validation Functions (New)

```go
// validateBoundIssuer checks if the token issuer matches the role's bound issuer
func validateBoundIssuer(claims map[string]any, boundIssuer string) error {
    if boundIssuer == "" {
        return nil // No bound issuer configured
    }

    iss, ok := claims["iss"]
    if !ok {
        return fmt.Errorf("token missing iss claim")
    }

    issStr, ok := iss.(string)
    if !ok {
        return fmt.Errorf("invalid iss claim type")
    }

    if issStr != boundIssuer {
        return fmt.Errorf("token issuer %q does not match bound_issuer %q", issStr, boundIssuer)
    }

    return nil
}

// validateBoundAudiences checks if the token audience matches any of the role's bound audiences
func validateBoundAudiences(claims map[string]any, boundAudiences []string) error {
    if len(boundAudiences) == 0 {
        return nil // No bound audiences configured
    }

    aud, ok := claims["aud"]
    if !ok {
        return fmt.Errorf("token missing aud claim")
    }

    // JWT aud claim can be string or []string
    var tokenAudiences []string
    switch v := aud.(type) {
    case string:
        tokenAudiences = []string{v}
    case []interface{}:
        for _, audVal := range v {
            if audStr, ok := audVal.(string); ok {
                tokenAudiences = append(tokenAudiences, audStr)
            }
        }
    case []string:
        tokenAudiences = v
    default:
        return fmt.Errorf("invalid aud claim type")
    }

    // Check if any token audience matches any bound audience
    for _, tokenAud := range tokenAudiences {
        for _, boundAud := range boundAudiences {
            if tokenAud == boundAud {
                return nil
            }
        }
    }

    return fmt.Errorf("token audience does not match any bound_audiences")
}
```

---

## Research Tools Used

1. **Read Tool** - Analyzed gap analysis documents and architecture docs
2. **go-dev-guidelines Skill** - Established TDD patterns and Go best practices
3. **Task Tool (Explore agents)** - Parallel codebase analysis (3 agents)
4. **Read Tool** - Full file reads of implementation and tests

---

## References

- **Gap Analysis**: `.docs/adhoc/rfc-8693-gap-analysis/rfc-8693-gap-analysis-plan.md`
- **Architecture**: `.docs/knowledge/architecture/token-format-rfc8693.md`
- **RFC 8693**: https://www.rfc-editor.org/rfc/rfc8693.html
- **RFC 8693 Section 4.1 (Actor Claim)**: https://www.rfc-editor.org/rfc/rfc8693.html#section-4.1
- **Go Dev Guidelines**: `go-dev-guidelines` skill

---

## Corrections During Planning

**NONE** - No user corrections required during planning process. All decisions based on:
- Gap analysis findings
- RFC 8693 specification requirements
- Go development best practices
- Current implementation analysis

---

## Time Breakdown

1. **Document Review**: 5 minutes (4 gap analysis files + architecture)
2. **Go Guidelines Activation**: 1 minute
3. **Parallel Research**: 5 minutes (3 concurrent agents)
4. **Implementation File Analysis**: 5 minutes (3 key files)
5. **Design Decisions**: 15 minutes (8 major decisions)
6. **Plan Documentation**: 45 minutes (comprehensive plan with tests)

**Total Planning Time**: ~76 minutes

---

## Confidence Level

**Very High Confidence (95%+)** in plan:
- Gap analysis is comprehensive and validated
- RFC 8693 requirements are clear and unambiguous
- Current implementation is fully understood
- Test strategy is well-defined
- Design decisions are documented with reasoning
- Code changes are specific and detailed

**Areas of Certainty**:
- Security vulnerability exists and solution is correct
- RFC 8693 format is well-specified
- TDD approach will catch issues early
- Implementation is achievable in estimated timeline

**Validated Assumptions**:
- Plugin scope is token format only (confirmed by user)
- Actor metadata is optional (confirmed by user)
- Hard cutover is acceptable (based on deployment status)
