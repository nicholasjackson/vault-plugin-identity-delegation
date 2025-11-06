# RFC 8693 Token Format Implementation Plan

**Created**: 2025-11-05
**Status**: Ready for Implementation
**Plan Type**: Detailed

---

## Executive Summary

This plan implements RFC 8693 compliant token format for the Vault Token Exchange plugin. The implementation focuses on token structure compliance while maintaining existing HTTP API patterns.

**Scope**: Token format only (claims structure, semantics, validation)
**Out of Scope**: HTTP API compliance (request/response format, error codes remain Vault-specific)

**Architecture Reference**: `.docs/knowledge/architecture/token-format-rfc8693.md`
**Gap Analysis**: `.docs/adhoc/rfc-8693-gap-analysis/rfc-8693-gap-analysis-plan.md`

---

## Implementation Phases

### Phase 1: Add Bound Audience/Issuer Validation (SECURITY FIX)

**Priority**: CRITICAL
**Rationale**: Security vulnerability - fields exist but are never validated
**Location**: `path_token_handlers.go`
**Test-Driven**: Yes (write tests first)

#### 1.1 Write Validation Tests

**File**: `path_token_test.go`

**Test 1: Reject token with wrong issuer**
```go
// TestTokenExchange_BoundIssuerMismatch tests that tokens with wrong issuer are rejected
func TestTokenExchange_BoundIssuerMismatch(t *testing.T) {
    b, storage := getTestBackend(t)

    // Generate test key pair and JWKS server
    privateKey, privateKeyPEM := generateTestKeyPair(t)
    testKID := "test-key-1"
    jwksServer := createMockJWKSServer(t, &privateKey.PublicKey, testKID)
    defer jwksServer.Close()

    // Configure plugin
    configReq := &logical.Request{
        Operation: logical.UpdateOperation,
        Path:      "config",
        Storage:   storage,
        Data: map[string]any{
            "issuer":           "https://vault.example.com",
            "subject_jwks_uri": jwksServer.URL,
            "signing_key":      privateKeyPEM,
            "default_ttl":      "1h",
        },
    }
    _, err := b.HandleRequest(context.Background(), configReq)
    require.NoError(t, err)

    // Create role with bound_issuer
    roleReq := &logical.Request{
        Operation: logical.CreateOperation,
        Path:      "role/test-role",
        Storage:   storage,
        Data: map[string]any{
            "name":             "test-role",
            "ttl":              "1h",
            "bound_issuer":     "https://trusted-idp.example.com",  // Required issuer
            "actor_template":   `{"act": {"sub": "agent-123"}}`,
            "subject_template": `{"department": "IT"}`,
            "context":          []string{"urn:documents:read"},
        },
    }
    _, err = b.HandleRequest(context.Background(), roleReq)
    require.NoError(t, err)

    // Generate subject token with DIFFERENT issuer
    subjectClaims := map[string]any{
        "sub": "user-123",
        "iss": "https://untrusted-idp.example.com",  // WRONG ISSUER
        "aud": []string{"service-a"},
        "exp": time.Now().Add(1 * time.Hour).Unix(),
        "iat": time.Now().Unix(),
    }
    subjectToken := generateTestJWT(t, privateKey, testKID, subjectClaims)

    // Attempt token exchange
    tokenReq := &logical.Request{
        Operation: logical.UpdateOperation,
        Path:      "token/test-role",
        Storage:   storage,
        EntityID:  "test_entity",
        Data: map[string]any{
            "subject_token": subjectToken,
        },
    }
    resp, err := b.HandleRequest(context.Background(), tokenReq)

    require.NoError(t, err, "Handler should not panic")
    require.NotNil(t, resp, "Should return error response")
    require.True(t, resp.IsError(), "Response should be an error")
    require.Contains(t, resp.Error().Error(), "issuer", "Error should mention issuer mismatch")
}

// TestTokenExchange_BoundIssuerMatch tests that tokens with correct issuer are accepted
func TestTokenExchange_BoundIssuerMatch(t *testing.T) {
    b, storage := getTestBackend(t)

    // Generate test key pair and JWKS server
    privateKey, privateKeyPEM := generateTestKeyPair(t)
    testKID := "test-key-1"
    jwksServer := createMockJWKSServer(t, &privateKey.PublicKey, testKID)
    defer jwksServer.Close()

    // Configure plugin
    configReq := &logical.Request{
        Operation: logical.UpdateOperation,
        Path:      "config",
        Storage:   storage,
        Data: map[string]any{
            "issuer":           "https://vault.example.com",
            "subject_jwks_uri": jwksServer.URL,
            "signing_key":      privateKeyPEM,
            "default_ttl":      "1h",
        },
    }
    _, err := b.HandleRequest(context.Background(), configReq)
    require.NoError(t, err)

    // Create role with bound_issuer
    roleReq := &logical.Request{
        Operation: logical.CreateOperation,
        Path:      "role/test-role",
        Storage:   storage,
        Data: map[string]any{
            "name":             "test-role",
            "ttl":              "1h",
            "bound_issuer":     "https://trusted-idp.example.com",  // Required issuer
            "actor_template":   `{"act": {"sub": "agent-123"}}`,
            "subject_template": `{"department": "IT"}`,
            "context":          []string{"urn:documents:read"},
        },
    }
    _, err = b.HandleRequest(context.Background(), roleReq)
    require.NoError(t, err)

    // Generate subject token with MATCHING issuer
    subjectClaims := map[string]any{
        "sub": "user-123",
        "iss": "https://trusted-idp.example.com",  // CORRECT ISSUER
        "aud": []string{"service-a"},
        "exp": time.Now().Add(1 * time.Hour).Unix(),
        "iat": time.Now().Unix(),
    }
    subjectToken := generateTestJWT(t, privateKey, testKID, subjectClaims)

    // Attempt token exchange
    tokenReq := &logical.Request{
        Operation: logical.UpdateOperation,
        Path:      "token/test-role",
        Storage:   storage,
        EntityID:  "test_entity",
        Data: map[string]any{
            "subject_token": subjectToken,
        },
    }
    resp, err := b.HandleRequest(context.Background(), tokenReq)

    require.NoError(t, err, "Handler should not error")
    require.NotNil(t, resp, "Should return response")
    require.False(t, resp.IsError(), "Response should not be an error")
    require.Contains(t, resp.Data, "token", "Should return token")
}
```

**Test 2: Reject token with wrong audience**
```go
// TestTokenExchange_BoundAudienceMismatch tests that tokens with wrong audience are rejected
func TestTokenExchange_BoundAudienceMismatch(t *testing.T) {
    b, storage := getTestBackend(t)

    // Generate test key pair and JWKS server
    privateKey, privateKeyPEM := generateTestKeyPair(t)
    testKID := "test-key-1"
    jwksServer := createMockJWKSServer(t, &privateKey.PublicKey, testKID)
    defer jwksServer.Close()

    // Configure plugin
    configReq := &logical.Request{
        Operation: logical.UpdateOperation,
        Path:      "config",
        Storage:   storage,
        Data: map[string]any{
            "issuer":           "https://vault.example.com",
            "subject_jwks_uri": jwksServer.URL,
            "signing_key":      privateKeyPEM,
            "default_ttl":      "1h",
        },
    }
    _, err := b.HandleRequest(context.Background(), configReq)
    require.NoError(t, err)

    // Create role with bound_audiences
    roleReq := &logical.Request{
        Operation: logical.CreateOperation,
        Path:      "role/test-role",
        Storage:   storage,
        Data: map[string]any{
            "name":             "test-role",
            "ttl":              "1h",
            "bound_audiences":  []string{"service-a", "service-b"},  // Allowed audiences
            "actor_template":   `{"act": {"sub": "agent-123"}}`,
            "subject_template": `{"department": "IT"}`,
            "context":          []string{"urn:documents:read"},
        },
    }
    _, err = b.HandleRequest(context.Background(), roleReq)
    require.NoError(t, err)

    // Generate subject token with DIFFERENT audience
    subjectClaims := map[string]any{
        "sub": "user-123",
        "iss": "https://idp.example.com",
        "aud": []string{"service-c"},  // WRONG AUDIENCE
        "exp": time.Now().Add(1 * time.Hour).Unix(),
        "iat": time.Now().Unix(),
    }
    subjectToken := generateTestJWT(t, privateKey, testKID, subjectClaims)

    // Attempt token exchange
    tokenReq := &logical.Request{
        Operation: logical.UpdateOperation,
        Path:      "token/test-role",
        Storage:   storage,
        EntityID:  "test_entity",
        Data: map[string]any{
            "subject_token": subjectToken,
        },
    }
    resp, err := b.HandleRequest(context.Background(), tokenReq)

    require.NoError(t, err, "Handler should not panic")
    require.NotNil(t, resp, "Should return error response")
    require.True(t, resp.IsError(), "Response should be an error")
    require.Contains(t, resp.Error().Error(), "audience", "Error should mention audience mismatch")
}

// TestTokenExchange_BoundAudienceMatch tests that tokens with correct audience are accepted
func TestTokenExchange_BoundAudienceMatch(t *testing.T) {
    b, storage := getTestBackend(t)

    // Generate test key pair and JWKS server
    privateKey, privateKeyPEM := generateTestKeyPair(t)
    testKID := "test-key-1"
    jwksServer := createMockJWKSServer(t, &privateKey.PublicKey, testKID)
    defer jwksServer.Close()

    // Configure plugin
    configReq := &logical.Request{
        Operation: logical.UpdateOperation,
        Path:      "config",
        Storage:   storage,
        Data: map[string]any{
            "issuer":           "https://vault.example.com",
            "subject_jwks_uri": jwksServer.URL,
            "signing_key":      privateKeyPEM,
            "default_ttl":      "1h",
        },
    }
    _, err := b.HandleRequest(context.Background(), configReq)
    require.NoError(t, err)

    // Create role with bound_audiences
    roleReq := &logical.Request{
        Operation: logical.CreateOperation,
        Path:      "role/test-role",
        Storage:   storage,
        Data: map[string]any{
            "name":             "test-role",
            "ttl":              "1h",
            "bound_audiences":  []string{"service-a", "service-b"},  // Allowed audiences
            "actor_template":   `{"act": {"sub": "agent-123"}}`,
            "subject_template": `{"department": "IT"}`,
            "context":          []string{"urn:documents:read"},
        },
    }
    _, err = b.HandleRequest(context.Background(), roleReq)
    require.NoError(t, err)

    // Generate subject token with MATCHING audience (string format)
    subjectClaims := map[string]any{
        "sub": "user-123",
        "iss": "https://idp.example.com",
        "aud": "service-a",  // CORRECT AUDIENCE (string)
        "exp": time.Now().Add(1 * time.Hour).Unix(),
        "iat": time.Now().Unix(),
    }
    subjectToken := generateTestJWT(t, privateKey, testKID, subjectClaims)

    // Attempt token exchange
    tokenReq := &logical.Request{
        Operation: logical.UpdateOperation,
        Path:      "token/test-role",
        Storage:   storage,
        EntityID:  "test_entity",
        Data: map[string]any{
            "subject_token": subjectToken,
        },
    }
    resp, err := b.HandleRequest(context.Background(), tokenReq)

    require.NoError(t, err, "Handler should not error")
    require.NotNil(t, resp, "Should return response")
    require.False(t, resp.IsError(), "Response should not be an error")
    require.Contains(t, resp.Data, "token", "Should return token")
}

// TestTokenExchange_BoundAudienceMatchArray tests array audience format
func TestTokenExchange_BoundAudienceMatchArray(t *testing.T) {
    b, storage := getTestBackend(t)

    // Generate test key pair and JWKS server
    privateKey, privateKeyPEM := generateTestKeyPair(t)
    testKID := "test-key-1"
    jwksServer := createMockJWKSServer(t, &privateKey.PublicKey, testKID)
    defer jwksServer.Close()

    // Configure plugin
    configReq := &logical.Request{
        Operation: logical.UpdateOperation,
        Path:      "config",
        Storage:   storage,
        Data: map[string]any{
            "issuer":           "https://vault.example.com",
            "subject_jwks_uri": jwksServer.URL,
            "signing_key":      privateKeyPEM,
            "default_ttl":      "1h",
        },
    }
    _, err := b.HandleRequest(context.Background(), configReq)
    require.NoError(t, err)

    // Create role with bound_audiences
    roleReq := &logical.Request{
        Operation: logical.CreateOperation,
        Path:      "role/test-role",
        Storage:   storage,
        Data: map[string]any{
            "name":             "test-role",
            "ttl":              "1h",
            "bound_audiences":  []string{"service-a", "service-b"},
            "actor_template":   `{"act": {"sub": "agent-123"}}`,
            "subject_template": `{"department": "IT"}`,
            "context":          []string{"urn:documents:read"},
        },
    }
    _, err = b.HandleRequest(context.Background(), roleReq)
    require.NoError(t, err)

    // Generate subject token with MATCHING audience (array format)
    subjectClaims := map[string]any{
        "sub": "user-123",
        "iss": "https://idp.example.com",
        "aud": []string{"service-b", "other-service"},  // CORRECT AUDIENCE (array)
        "exp": time.Now().Add(1 * time.Hour).Unix(),
        "iat": time.Now().Unix(),
    }
    subjectToken := generateTestJWT(t, privateKey, testKID, subjectClaims)

    // Attempt token exchange
    tokenReq := &logical.Request{
        Operation: logical.UpdateOperation,
        Path:      "token/test-role",
        Storage:   storage,
        EntityID:  "test_entity",
        Data: map[string]any{
            "subject_token": subjectToken,
        },
    }
    resp, err := b.HandleRequest(context.Background(), tokenReq)

    require.NoError(t, err, "Handler should not error")
    require.NotNil(t, resp, "Should return response")
    require.False(t, resp.IsError(), "Response should not be an error")
    require.Contains(t, resp.Data, "token", "Should return token")
}
```

#### 1.2 Implement Validation Functions

**File**: `path_token_handlers.go`

**Add validation helper functions** (after `checkExpiration`, around line 226):
```go
// validateBoundIssuer checks if the token issuer matches the role's bound issuer
func validateBoundIssuer(claims map[string]any, boundIssuer string) error {
    if boundIssuer == "" {
        return nil // No bound issuer configured, skip validation
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
        return nil // No bound audiences configured, skip validation
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
                return nil // Match found
            }
        }
    }

    return fmt.Errorf("token audience does not match any bound_audiences")
}
```

**Update pathTokenExchange handler** (insert after line 67):
```go
// Check expiration
if err := checkExpiration(originalSubjectClaims); err != nil {
    return logical.ErrorResponse("subject token expired: %v", err), nil
}

// Validate bound issuer
if err := validateBoundIssuer(originalSubjectClaims, role.BoundIssuer); err != nil {
    return logical.ErrorResponse("failed to validate issuer: %v", err), nil
}

// Validate bound audiences
if err := validateBoundAudiences(originalSubjectClaims, role.BoundAudiences); err != nil {
    return logical.ErrorResponse("failed to validate audience: %v", err), nil
}

// Fetch entity
b.Logger().Info("Get EntityID", "entity_id", req.EntityID)
```

#### 1.3 Run Tests and Verify

**Commands**:
```bash
# Run new tests
go test -v -run TestTokenExchange_BoundIssuer ./...
go test -v -run TestTokenExchange_BoundAudience ./...

# Run all tests to ensure no regressions
go test -v ./...
```

**Expected**: All new tests pass, existing tests remain passing

---

### Phase 2: Replace `obo` Claim with RFC 8693 `act` Claim

**Priority**: HIGH
**Rationale**: Core RFC 8693 compliance requirement
**Location**: `path_token_handlers.go:298-302`
**Test-Driven**: Yes

#### 2.1 Write Token Format Tests

**File**: `path_token_test.go`

**Test: Validate `act` claim structure**
```go
// TestTokenExchange_ActClaimStructure tests that generated tokens have RFC 8693 compliant act claim
func TestTokenExchange_ActClaimStructure(t *testing.T) {
    b, storage := getTestBackend(t)

    // Generate test key pair and JWKS server
    privateKey, privateKeyPEM := generateTestKeyPair(t)
    testKID := "test-key-1"
    jwksServer := createMockJWKSServer(t, &privateKey.PublicKey, testKID)
    defer jwksServer.Close()

    // Configure plugin
    configReq := &logical.Request{
        Operation: logical.UpdateOperation,
        Path:      "config",
        Storage:   storage,
        Data: map[string]any{
            "issuer":           "https://vault.example.com",
            "subject_jwks_uri": jwksServer.URL,
            "signing_key":      privateKeyPEM,
            "default_ttl":      "1h",
        },
    }
    _, err := b.HandleRequest(context.Background(), configReq)
    require.NoError(t, err)

    // Create role
    roleReq := &logical.Request{
        Operation: logical.CreateOperation,
        Path:      "role/test-role",
        Storage:   storage,
        Data: map[string]any{
            "name":             "test-role",
            "ttl":              "1h",
            "actor_template":   `{}`,  // Empty template to use default
            "subject_template": `{"department": "IT"}`,
            "context":          []string{"urn:documents:read", "urn:images:write"},
        },
    }
    _, err = b.HandleRequest(context.Background(), roleReq)
    require.NoError(t, err)

    // Generate subject token
    subjectClaims := map[string]any{
        "sub":   "user-123",
        "email": "user@example.com",
        "iss":   "https://idp.example.com",
        "aud":   []string{"service-a"},
        "exp":   time.Now().Add(1 * time.Hour).Unix(),
        "iat":   time.Now().Unix(),
    }
    subjectToken := generateTestJWT(t, privateKey, testKID, subjectClaims)

    // Exchange token
    tokenReq := &logical.Request{
        Operation: logical.UpdateOperation,
        Path:      "token/test-role",
        Storage:   storage,
        EntityID:  "test-entity-456",
        Data: map[string]any{
            "subject_token": subjectToken,
        },
    }
    resp, err := b.HandleRequest(context.Background(), tokenReq)
    require.NoError(t, err)
    require.NotNil(t, resp)
    require.False(t, resp.IsError())

    // Parse generated token
    generatedToken := resp.Data["token"].(string)
    parsedToken, err := jwt.ParseSigned(generatedToken, []jose.SignatureAlgorithm{jose.RS256})
    require.NoError(t, err)

    claims := make(map[string]any)
    err = parsedToken.Claims(&privateKey.PublicKey, &claims)
    require.NoError(t, err)

    // Verify RFC 8693 compliant structure
    // 1. Subject is the user (not the actor)
    require.Equal(t, "user-123", claims["sub"], "Subject should be the user")

    // 2. act claim exists with actor identity
    act, ok := claims["act"].(map[string]any)
    require.True(t, ok, "Should have act claim")

    actSub, ok := act["sub"].(string)
    require.True(t, ok, "act.sub should be a string")
    require.NotEmpty(t, actSub, "act.sub should not be empty")
    require.Contains(t, actSub, "test-entity-456", "act.sub should contain entity ID")

    // 3. Optional: act.iss if present should be a string
    if actIss, ok := act["iss"]; ok {
        _, ok := actIss.(string)
        require.True(t, ok, "act.iss should be a string if present")
    }

    // 4. act claim should NOT contain non-identity claims
    _, hasExp := act["exp"]
    require.False(t, hasExp, "act should not contain exp claim")

    _, hasAud := act["aud"]
    require.False(t, hasAud, "act should not contain aud claim")

    _, hasIat := act["iat"]
    require.False(t, hasIat, "act should not contain iat claim")

    // 5. Scope claim should be space-delimited string
    scope, ok := claims["scope"].(string)
    require.True(t, ok, "scope should be a string")
    require.Contains(t, scope, " ", "scope should be space-delimited")
    require.Equal(t, "urn:documents:read urn:images:write", scope, "scope should be space-delimited")

    // 6. obo claim should NOT exist (deprecated)
    _, hasObo := claims["obo"]
    require.False(t, hasObo, "obo claim should not exist (replaced by act)")
}
```

**Test: Verify actor metadata is optional and separate**
```go
// TestTokenExchange_ActorMetadataOptional tests that actor metadata is stored separately from act claim
func TestTokenExchange_ActorMetadataOptional(t *testing.T) {
    b, storage := getTestBackend(t)

    // Generate test key pair and JWKS server
    privateKey, privateKeyPEM := generateTestKeyPair(t)
    testKID := "test-key-1"
    jwksServer := createMockJWKSServer(t, &privateKey.PublicKey, testKID)
    defer jwksServer.Close()

    // Configure plugin
    configReq := &logical.Request{
        Operation: logical.UpdateOperation,
        Path:      "config",
        Storage:   storage,
        Data: map[string]any{
            "issuer":           "https://vault.example.com",
            "subject_jwks_uri": jwksServer.URL,
            "signing_key":      privateKeyPEM,
            "default_ttl":      "1h",
        },
    }
    _, err := b.HandleRequest(context.Background(), configReq)
    require.NoError(t, err)

    // Create role with actor metadata in template
    roleReq := &logical.Request{
        Operation: logical.CreateOperation,
        Path:      "role/test-role",
        Storage:   storage,
        Data: map[string]any{
            "name": "test-role",
            "ttl":  "1h",
            "actor_template": `{
                "actor_metadata": {
                    "entity_id": "{{identity.entity.id}}",
                    "entity_name": "{{identity.entity.name}}",
                    "department": "AI Services"
                }
            }`,
            "subject_template": `{"department": "IT"}`,
            "context":          []string{"urn:documents:read"},
        },
    }
    _, err = b.HandleRequest(context.Background(), roleReq)
    require.NoError(t, err)

    // Generate subject token
    subjectClaims := map[string]any{
        "sub": "user-123",
        "iss": "https://idp.example.com",
        "aud": []string{"service-a"},
        "exp": time.Now().Add(1 * time.Hour).Unix(),
        "iat": time.Now().Unix(),
    }
    subjectToken := generateTestJWT(t, privateKey, testKID, subjectClaims)

    // Exchange token
    tokenReq := &logical.Request{
        Operation: logical.UpdateOperation,
        Path:      "token/test-role",
        Storage:   storage,
        EntityID:  "test-entity-456",
        Data: map[string]any{
            "subject_token": subjectToken,
        },
    }
    resp, err := b.HandleRequest(context.Background(), tokenReq)
    require.NoError(t, err)
    require.NotNil(t, resp)
    require.False(t, resp.IsError())

    // Parse generated token
    generatedToken := resp.Data["token"].(string)
    parsedToken, err := jwt.ParseSigned(generatedToken, []jose.SignatureAlgorithm{jose.RS256})
    require.NoError(t, err)

    claims := make(map[string]any)
    err = parsedToken.Claims(&privateKey.PublicKey, &claims)
    require.NoError(t, err)

    // Verify act claim contains ONLY identity
    act, ok := claims["act"].(map[string]any)
    require.True(t, ok, "Should have act claim")
    require.Contains(t, act, "sub", "act should have sub")
    require.NotContains(t, act, "entity_id", "act should not contain metadata")
    require.NotContains(t, act, "department", "act should not contain metadata")

    // Verify actor metadata is in separate namespace
    actorMetadata, ok := claims["actor_metadata"].(map[string]any)
    require.True(t, ok, "Should have actor_metadata namespace")
    require.Contains(t, actorMetadata, "entity_id", "actor_metadata should contain entity_id")
    require.Contains(t, actorMetadata, "department", "actor_metadata should contain department")
    require.Equal(t, "AI Services", actorMetadata["department"], "actor_metadata should have correct values")
}
```

#### 2.2 Implement Token Generation Changes

**File**: `path_token_handlers.go`

**Update generateToken function** (replace lines 298-302):

**BEFORE (lines 272-302)**:
```go
// Build claims
now := time.Now()
claims := make(map[string]any)

// Standard claims
claims["iss"] = config.Issuer
claims["sub"] = subjectID // Subject from the original user token
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
    // Don't allow overriding reserved claims
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

**AFTER** (lines 272-320):
```go
// Build claims
now := time.Now()
claims := make(map[string]any)

// Standard claims (RFC 8693)
claims["iss"] = config.Issuer
claims["sub"] = subjectID // Subject from the original user token
claims["iat"] = now.Unix()
claims["exp"] = now.Add(role.TTL).Unix()

// Add audience if present
if aud, ok := actorClaims["aud"]; ok {
    claims["aud"] = aud
}

// Add RFC 8693 actor claim (delegation)
// The act claim contains ONLY the actor's identity
// Extract entity ID from actorClaims if present, otherwise construct from entity
actorSubject := ""
if actSub, ok := actorClaims["act"].(map[string]any); ok {
    if sub, ok := actSub["sub"].(string); ok {
        actorSubject = sub
    }
}
// If no actor subject in template, use entity ID as fallback
if actorSubject == "" {
    // Entity ID should be in request context, construct actor identity
    // This is a fallback - templates should provide actor identity
    actorSubject = fmt.Sprintf("entity:%s", req.EntityID)
}

claims["act"] = map[string]any{
    "sub": actorSubject,
    "iss": config.Issuer, // Optional: issuer of actor identity
}

// Add RFC 8693 scope claim (space-delimited)
if len(role.Context) > 0 {
    claims["scope"] = strings.Join(role.Context, " ")
}

// Add subject claims under "subject_claims" key (optional extension)
if len(subjectClaims) > 0 {
    claims["subject_claims"] = subjectClaims
}

// Merge actor claims (for optional actor_metadata extension)
// This allows templates to add actor metadata outside the act claim
for key, value := range actorClaims {
    // Don't allow overriding reserved claims or act claim
    if key != "iss" && key != "sub" && key != "iat" && key != "exp" && key != "aud" && key != "act" {
        claims[key] = value
    }
}
```

**Wait, there's an issue**: We don't have `req` in the `generateToken` function signature. Let me fix that.

**Update generateToken signature** (line 262):

**BEFORE**:
```go
func generateToken(config *Config, role *Role, subjectID string, actorClaims, subjectClaims map[string]any, signingKey *rsa.PrivateKey) (string, error) {
```

**AFTER**:
```go
func generateToken(config *Config, role *Role, subjectID string, actorClaims, subjectClaims map[string]any, signingKey *rsa.PrivateKey, entityID string) (string, error) {
```

**Update caller in pathTokenExchange** (line 105):

**BEFORE**:
```go
newToken, err := generateToken(config, role, originalSubjectClaims["sub"].(string), actorClaims, subjectClaims, signingKey)
```

**AFTER**:
```go
newToken, err := generateToken(config, role, originalSubjectClaims["sub"].(string), actorClaims, subjectClaims, signingKey, req.EntityID)
```

**Now update generateToken implementation** (lines 272-320):
```go
// Build claims
now := time.Now()
claims := make(map[string]any)

// Standard claims (RFC 8693)
claims["iss"] = config.Issuer
claims["sub"] = subjectID // Subject from the original user token
claims["iat"] = now.Unix()
claims["exp"] = now.Add(role.TTL).Unix()

// Add audience if present
if aud, ok := actorClaims["aud"]; ok {
    claims["aud"] = aud
}

// Add RFC 8693 actor claim (delegation)
// The act claim contains ONLY the actor's identity (sub, iss)
actorSubject := ""

// Check if actor_template provided act.sub
if actClaimRaw, ok := actorClaims["act"]; ok {
    if actClaimMap, ok := actClaimRaw.(map[string]any); ok {
        if sub, ok := actClaimMap["sub"].(string); ok {
            actorSubject = sub
        }
    }
}

// If no actor subject in template, construct from entity ID
if actorSubject == "" {
    actorSubject = fmt.Sprintf("entity:%s", entityID)
}

claims["act"] = map[string]any{
    "sub": actorSubject,
    "iss": config.Issuer, // Optional: issuer of actor identity
}

// Add RFC 8693 scope claim (space-delimited)
if len(role.Context) > 0 {
    claims["scope"] = strings.Join(role.Context, " ")
}

// Add subject claims under "subject_claims" key (optional extension)
if len(subjectClaims) > 0 {
    claims["subject_claims"] = subjectClaims
}

// Merge actor claims for optional extensions (e.g., actor_metadata)
// This allows templates to add custom actor metadata outside the act claim
for key, value := range actorClaims {
    // Don't allow overriding reserved claims or act claim
    if key != "iss" && key != "sub" && key != "iat" && key != "exp" && key != "aud" && key != "act" {
        claims[key] = value
    }
}
```

#### 2.3 Run Tests and Verify

**Commands**:
```bash
# Run new tests
go test -v -run TestTokenExchange_ActClaimStructure ./...
go test -v -run TestTokenExchange_ActorMetadataOptional ./...

# Run all tests to ensure no regressions
go test -v ./...
```

**Expected**: All new tests pass, existing tests may fail (need update)

#### 2.4 Update Existing Tests

**File**: `path_token_test.go`

**Update TestTokenExchange_VerifyGeneratedToken** (lines 467-469):

**BEFORE**:
```go
// Verify template claims were applied
act, ok := claims["act"].(map[string]any)
require.True(t, ok, "Should have act claim from template")
require.Equal(t, "agent-123", act["sub"], "Agent sub should match template")
```

**AFTER**:
```go
// Verify RFC 8693 act claim
act, ok := claims["act"].(map[string]any)
require.True(t, ok, "Should have RFC 8693 act claim")
require.Contains(t, act, "sub", "act claim should have sub")
require.NotEmpty(t, act["sub"], "act.sub should not be empty")

// Verify scope claim (space-delimited)
scope, ok := claims["scope"].(string)
require.True(t, ok, "Should have scope claim")
require.Equal(t, "urn:documents:read", scope, "scope should match role context")

// Verify obo claim does NOT exist (deprecated)
_, hasObo := claims["obo"]
require.False(t, hasObo, "obo claim should not exist (replaced by act/scope)")
```

**Update test role configurations** to use new actor_template format:

**Example update for TestTokenExchange_Success** (line 109):

**BEFORE**:
```go
"actor_template": `{"act": {"sub": "{{identity.entity.id}}"} }`,
```

**AFTER** (if you want metadata):
```go
"actor_template": `{
    "act": {"sub": "entity:{{identity.entity.id}}"},
    "actor_metadata": {
        "entity_id": "{{identity.entity.id}}",
        "entity_name": "{{identity.entity.name}}"
    }
}`,
```

**OR** (if you want minimal):
```go
"actor_template": `{"act": {"sub": "entity:{{identity.entity.id}}"}}`,
```

#### 2.5 Update Documentation

**File**: `path_role.go` (line 61)

**BEFORE**:
```go
"context": {
    Type:        framework.TypeCommaStringSlice,
    Description: "List of permitted delegate scopes to map to the on-behalf-of 'ctx' claim in the generated token, delegate scopes restrict the permissions of the generated token. i.e 'urn:documents.service:read,urn:images.service:write'",
    Required:    true,
},
```

**AFTER**:
```go
"context": {
    Type:        framework.TypeCommaStringSlice,
    Description: "List of permitted scopes for the delegated token (RFC 8693). Maps to 'scope' claim as space-delimited string. Example: 'urn:documents.service:read,urn:images.service:write' becomes 'urn:documents.service:read urn:images.service:write'",
    Required:    true,
},
```

**File**: `path_role.go` (line 51)

**BEFORE**:
```go
"actor_template": {
    Type:        framework.TypeString,
    Description: "JSON template for additional claims in the generated token, claims are added to the main token claims",
    Required:    true,
},
```

**AFTER**:
```go
"actor_template": {
    Type:        framework.TypeString,
    Description: "JSON template for actor-related claims (RFC 8693). Should include 'act' claim with actor identity. Optional 'actor_metadata' for additional actor context. Example: {\"act\": {\"sub\": \"{{identity.entity.id}}\"}, \"actor_metadata\": {\"department\": \"IT\"}}",
    Required:    true,
},
```

---

### Phase 3: Add Comprehensive Token Format Validation Tests

**Priority**: MEDIUM
**Rationale**: Ensure RFC 8693 compliance is thoroughly tested
**Test-Driven**: Tests only (validation already in Phase 2)

#### 3.1 Add RFC 8693 Compliance Test Suite

**File**: `path_token_rfc8693_test.go` (NEW FILE)

```go
package tokenexchange

import (
    "context"
    "testing"
    "time"

    "github.com/go-jose/go-jose/v4"
    "github.com/go-jose/go-jose/v4/jwt"
    "github.com/hashicorp/vault/sdk/logical"
    "github.com/stretchr/testify/require"
)

// TestRFC8693_TokenStructure validates complete RFC 8693 token structure
func TestRFC8693_TokenStructure(t *testing.T) {
    b, storage := getTestBackend(t)

    // Setup
    privateKey, privateKeyPEM := generateTestKeyPair(t)
    testKID := "test-key-1"
    jwksServer := createMockJWKSServer(t, &privateKey.PublicKey, testKID)
    defer jwksServer.Close()

    configReq := &logical.Request{
        Operation: logical.UpdateOperation,
        Path:      "config",
        Storage:   storage,
        Data: map[string]any{
            "issuer":           "https://vault.example.com",
            "subject_jwks_uri": jwksServer.URL,
            "signing_key":      privateKeyPEM,
            "default_ttl":      "1h",
        },
    }
    _, err := b.HandleRequest(context.Background(), configReq)
    require.NoError(t, err)

    roleReq := &logical.Request{
        Operation: logical.CreateOperation,
        Path:      "role/test-role",
        Storage:   storage,
        Data: map[string]any{
            "name": "test-role",
            "ttl":  "1h",
            "actor_template": `{
                "act": {"sub": "agent:{{identity.entity.id}}"},
                "actor_metadata": {
                    "entity_id": "{{identity.entity.id}}",
                    "department": "AI Services"
                }
            }`,
            "subject_template": `{"email": "{{identity.subject.email}}"}`,
            "context":          []string{"urn:documents:read", "urn:images:write"},
        },
    }
    _, err = b.HandleRequest(context.Background(), roleReq)
    require.NoError(t, err)

    subjectClaims := map[string]any{
        "sub":   "user-123",
        "email": "user@example.com",
        "iss":   "https://idp.example.com",
        "aud":   []string{"service-a"},
        "exp":   time.Now().Add(1 * time.Hour).Unix(),
        "iat":   time.Now().Unix(),
    }
    subjectToken := generateTestJWT(t, privateKey, testKID, subjectClaims)

    tokenReq := &logical.Request{
        Operation: logical.UpdateOperation,
        Path:      "token/test-role",
        Storage:   storage,
        EntityID:  "entity-456",
        Data: map[string]any{
            "subject_token": subjectToken,
        },
    }
    resp, err := b.HandleRequest(context.Background(), tokenReq)
    require.NoError(t, err)
    require.NotNil(t, resp)
    require.False(t, resp.IsError())

    // Parse token
    generatedToken := resp.Data["token"].(string)
    parsedToken, err := jwt.ParseSigned(generatedToken, []jose.SignatureAlgorithm{jose.RS256})
    require.NoError(t, err)

    claims := make(map[string]any)
    err = parsedToken.Claims(&privateKey.PublicKey, &claims)
    require.NoError(t, err)

    // RFC 8693 Required Standard Claims
    t.Run("StandardClaims", func(t *testing.T) {
        require.Contains(t, claims, "iss", "Must have iss claim")
        require.Equal(t, "https://vault.example.com", claims["iss"], "iss must match config")

        require.Contains(t, claims, "sub", "Must have sub claim")
        require.Equal(t, "user-123", claims["sub"], "sub must be user identity")

        require.Contains(t, claims, "iat", "Must have iat claim")
        require.Contains(t, claims, "exp", "Must have exp claim")
    })

    // RFC 8693 Delegation Claims
    t.Run("DelegationClaims", func(t *testing.T) {
        // act claim must exist
        require.Contains(t, claims, "act", "Must have act claim for delegation")

        act, ok := claims["act"].(map[string]any)
        require.True(t, ok, "act must be an object")

        // act.sub is required
        require.Contains(t, act, "sub", "act must have sub claim")
        actSub, ok := act["sub"].(string)
        require.True(t, ok, "act.sub must be a string")
        require.NotEmpty(t, actSub, "act.sub must not be empty")
        require.Contains(t, actSub, "entity-456", "act.sub should contain entity ID")

        // act.iss is optional but if present must be string
        if actIss, ok := act["iss"]; ok {
            _, ok := actIss.(string)
            require.True(t, ok, "act.iss must be a string if present")
        }

        // act claim must NOT contain non-identity claims
        require.NotContains(t, act, "exp", "act must not contain exp")
        require.NotContains(t, act, "iat", "act must not contain iat")
        require.NotContains(t, act, "aud", "act must not contain aud")
        require.NotContains(t, act, "nbf", "act must not contain nbf")

        // Scope claim (recommended)
        require.Contains(t, claims, "scope", "Should have scope claim")
        scope, ok := claims["scope"].(string)
        require.True(t, ok, "scope must be a string")
        require.Equal(t, "urn:documents:read urn:images:write", scope, "scope must be space-delimited")
    })

    // Optional Extensions (Not RFC 8693)
    t.Run("OptionalExtensions", func(t *testing.T) {
        // actor_metadata is optional custom extension
        if actorMeta, ok := claims["actor_metadata"]; ok {
            actorMetaMap, ok := actorMeta.(map[string]any)
            require.True(t, ok, "actor_metadata should be an object if present")
            require.NotContains(t, claims["act"], "department", "Metadata should NOT be in act claim")
            require.Contains(t, actorMetaMap, "department", "Metadata should be in actor_metadata")
        }

        // subject_claims is optional custom extension
        if subjectClaims, ok := claims["subject_claims"]; ok {
            subjectClaimsMap, ok := subjectClaims.(map[string]any)
            require.True(t, ok, "subject_claims should be an object if present")
            require.Contains(t, subjectClaimsMap, "email", "subject_claims should contain processed template data")
        }
    })

    // Prohibited Claims
    t.Run("ProhibitedClaims", func(t *testing.T) {
        // obo claim must NOT exist (replaced by act)
        require.NotContains(t, claims, "obo", "obo claim must not exist (use act instead)")
    })
}

// TestRFC8693_UserCentricSemantics validates user-centric delegation semantics
func TestRFC8693_UserCentricSemantics(t *testing.T) {
    b, storage := getTestBackend(t)

    privateKey, privateKeyPEM := generateTestKeyPair(t)
    testKID := "test-key-1"
    jwksServer := createMockJWKSServer(t, &privateKey.PublicKey, testKID)
    defer jwksServer.Close()

    configReq := &logical.Request{
        Operation: logical.UpdateOperation,
        Path:      "config",
        Storage:   storage,
        Data: map[string]any{
            "issuer":           "https://vault.example.com",
            "subject_jwks_uri": jwksServer.URL,
            "signing_key":      privateKeyPEM,
            "default_ttl":      "1h",
        },
    }
    _, err := b.HandleRequest(context.Background(), configReq)
    require.NoError(t, err)

    roleReq := &logical.Request{
        Operation: logical.CreateOperation,
        Path:      "role/test-role",
        Storage:   storage,
        Data: map[string]any{
            "name":             "test-role",
            "ttl":              "1h",
            "actor_template":   `{"act": {"sub": "agent:{{identity.entity.id}}"}}`,
            "subject_template": `{}`,
            "context":          []string{"urn:documents:read"},
        },
    }
    _, err = b.HandleRequest(context.Background(), roleReq)
    require.NoError(t, err)

    // User is "alice@example.com"
    // Agent is "ai-agent-007"
    subjectClaims := map[string]any{
        "sub": "alice@example.com",
        "iss": "https://idp.example.com",
        "aud": []string{"service-a"},
        "exp": time.Now().Add(1 * time.Hour).Unix(),
        "iat": time.Now().Unix(),
    }
    subjectToken := generateTestJWT(t, privateKey, testKID, subjectClaims)

    tokenReq := &logical.Request{
        Operation: logical.UpdateOperation,
        Path:      "token/test-role",
        Storage:   storage,
        EntityID:  "ai-agent-007",
        Data: map[string]any{
            "subject_token": subjectToken,
        },
    }
    resp, err := b.HandleRequest(context.Background(), tokenReq)
    require.NoError(t, err)
    require.NotNil(t, resp)
    require.False(t, resp.IsError())

    generatedToken := resp.Data["token"].(string)
    parsedToken, err := jwt.ParseSigned(generatedToken, []jose.SignatureAlgorithm{jose.RS256})
    require.NoError(t, err)

    claims := make(map[string]any)
    err = parsedToken.Claims(&privateKey.PublicKey, &claims)
    require.NoError(t, err)

    // Verify user-centric semantics
    // Token represents USER's authority, with AGENT acting on behalf

    // 1. Subject is the USER (not the agent)
    require.Equal(t, "alice@example.com", claims["sub"],
        "Token subject must be the user (RFC 8693 user-centric delegation)")

    // 2. Actor is the AGENT
    act := claims["act"].(map[string]any)
    actSub := act["sub"].(string)
    require.Contains(t, actSub, "ai-agent-007",
        "Actor must be the agent")

    // 3. This represents "agent acting on behalf of user", NOT "user acting as agent"
    require.NotEqual(t, claims["sub"], actSub,
        "Subject and actor must be different (delegation, not impersonation)")
}

// TestRFC8693_ScopeFormat validates space-delimited scope format
func TestRFC8693_ScopeFormat(t *testing.T) {
    testCases := []struct {
        name           string
        contextInput   []string
        expectedScope  string
    }{
        {
            name:          "Single scope",
            contextInput:  []string{"urn:documents:read"},
            expectedScope: "urn:documents:read",
        },
        {
            name:          "Multiple scopes",
            contextInput:  []string{"urn:documents:read", "urn:images:write", "urn:users:admin"},
            expectedScope: "urn:documents:read urn:images:write urn:users:admin",
        },
        {
            name:          "Empty scopes",
            contextInput:  []string{},
            expectedScope: "",
        },
    }

    for _, tc := range testCases {
        t.Run(tc.name, func(t *testing.T) {
            b, storage := getTestBackend(t)

            privateKey, privateKeyPEM := generateTestKeyPair(t)
            testKID := "test-key-1"
            jwksServer := createMockJWKSServer(t, &privateKey.PublicKey, testKID)
            defer jwksServer.Close()

            configReq := &logical.Request{
                Operation: logical.UpdateOperation,
                Path:      "config",
                Storage:   storage,
                Data: map[string]any{
                    "issuer":           "https://vault.example.com",
                    "subject_jwks_uri": jwksServer.URL,
                    "signing_key":      privateKeyPEM,
                    "default_ttl":      "1h",
                },
            }
            _, err := b.HandleRequest(context.Background(), configReq)
            require.NoError(t, err)

            roleReq := &logical.Request{
                Operation: logical.CreateOperation,
                Path:      "role/test-role",
                Storage:   storage,
                Data: map[string]any{
                    "name":             "test-role",
                    "ttl":              "1h",
                    "actor_template":   `{"act": {"sub": "agent"}}`,
                    "subject_template": `{}`,
                    "context":          tc.contextInput,
                },
            }
            _, err = b.HandleRequest(context.Background(), roleReq)
            if len(tc.contextInput) == 0 {
                // Context is required, should error
                require.Error(t, err)
                return
            }
            require.NoError(t, err)

            subjectClaims := map[string]any{
                "sub": "user-123",
                "iss": "https://idp.example.com",
                "aud": []string{"service-a"},
                "exp": time.Now().Add(1 * time.Hour).Unix(),
                "iat": time.Now().Unix(),
            }
            subjectToken := generateTestJWT(t, privateKey, testKID, subjectClaims)

            tokenReq := &logical.Request{
                Operation: logical.UpdateOperation,
                Path:      "token/test-role",
                Storage:   storage,
                EntityID:  "entity-123",
                Data: map[string]any{
                    "subject_token": subjectToken,
                },
            }
            resp, err := b.HandleRequest(context.Background(), tokenReq)
            require.NoError(t, err)
            require.NotNil(t, resp)
            require.False(t, resp.IsError())

            generatedToken := resp.Data["token"].(string)
            parsedToken, err := jwt.ParseSigned(generatedToken, []jose.SignatureAlgorithm{jose.RS256})
            require.NoError(t, err)

            claims := make(map[string]any)
            err = parsedToken.Claims(&privateKey.PublicKey, &claims)
            require.NoError(t, err)

            // Verify scope format
            if tc.expectedScope == "" {
                // Empty context should not add scope claim
                require.NotContains(t, claims, "scope", "Empty context should not create scope claim")
            } else {
                scope, ok := claims["scope"].(string)
                require.True(t, ok, "scope must be a string")
                require.Equal(t, tc.expectedScope, scope, "scope must be space-delimited")

                // Verify no commas (old format)
                require.NotContains(t, scope, ",", "scope must not contain commas (use spaces)")
            }
        })
    }
}
```

#### 3.2 Run Comprehensive Test Suite

**Commands**:
```bash
# Run RFC 8693 compliance tests
go test -v -run TestRFC8693 ./...

# Run all tests
go test -v ./...

# Run with coverage
go test -v -cover ./...
```

---

## Test Strategy

### Unit Test Coverage

**Existing Tests to Update**:
1. `TestTokenExchange_Success` - Update to verify RFC 8693 structure
2. `TestTokenExchange_VerifyGeneratedToken` - Update to check act claim and scope
3. All role creation tests - Update templates to new format

**New Tests to Add**:
1. **Phase 1**: Bound issuer/audience validation (6 tests)
2. **Phase 2**: act claim structure (2 tests)
3. **Phase 3**: Comprehensive RFC 8693 compliance (3 test suites)

**Total New Tests**: 11+ test cases

### Test-Driven Development Approach

1. **Write test first** - Define expected behavior
2. **Run test** - Verify it fails (red)
3. **Implement code** - Make test pass (green)
4. **Refactor** - Improve implementation
5. **Run all tests** - Ensure no regressions

### Test Organization

```
path_token_test.go          # Existing token exchange tests (updated)
path_token_rfc8693_test.go  # NEW: RFC 8693 compliance test suite
path_role_test.go           # Existing role tests (no changes needed)
path_config_test.go         # Existing config tests (no changes needed)
```

---

## Success Criteria

### Automated Verification

1. ✅ All existing tests pass with updated token format
2. ✅ All new tests pass (bound validation, act claim, RFC compliance)
3. ✅ Test coverage remains above 80%
4. ✅ `go vet` passes with no warnings
5. ✅ `gofmt` shows no formatting issues

### Manual Verification

1. ✅ Generated tokens validate against RFC 8693 structure
2. ✅ Bound issuer validation rejects wrong issuers
3. ✅ Bound audience validation rejects wrong audiences
4. ✅ Token contains `act` claim with actor identity only
5. ✅ Token contains space-delimited `scope` claim
6. ✅ Token does NOT contain deprecated `obo` claim
7. ✅ Optional `actor_metadata` is separate from `act` claim
8. ✅ Subject is user, actor is agent (user-centric delegation)

### Integration Testing

**Manual Test Scenario**:
```bash
# 1. Configure plugin
vault write token-exchange/config \
    issuer="https://vault.example.com" \
    subject_jwks_uri="https://idp.example.com/.well-known/jwks.json" \
    signing_key=@signing_key.pem \
    default_ttl="1h"

# 2. Create role with bounds
vault write token-exchange/role/ai-agent \
    ttl="1h" \
    bound_issuer="https://trusted-idp.example.com" \
    bound_audiences="api-service,data-service" \
    actor_template='{"act": {"sub": "agent:{{identity.entity.id}}"}, "actor_metadata": {"department": "AI"}}' \
    subject_template='{"email": "{{identity.subject.email}}"}' \
    context="urn:documents:read,urn:images:write"

# 3. Exchange token
vault write token-exchange/token/ai-agent \
    subject_token="<USER_JWT_TOKEN>"

# 4. Decode generated token
TOKEN=$(vault write -field=token token-exchange/token/ai-agent subject_token="<JWT>")
echo $TOKEN | jwt decode -

# 5. Verify structure:
# - Has "sub": "<user-id>" (user identity)
# - Has "act": {"sub": "agent:...", "iss": "..."} (actor identity only)
# - Has "scope": "urn:documents:read urn:images:write" (space-delimited)
# - Has "actor_metadata": {...} (optional, separate from act)
# - Does NOT have "obo" claim
```

---

## Migration Considerations

### Breaking Changes

**Token Format Changes**:
1. `obo` claim removed → replaced with `act` and `scope`
2. `obo.ctx` (comma-delimited) → `scope` (space-delimited)
3. `obo.prn` → `sub` remains user (no change)
4. Actor identity → `act.sub` (was implied or in top-level claims)

**Impact**: Resource servers validating token structure will need updates

### Backward Compatibility Strategy

**Option 1: Hard cutover (RECOMMENDED)**
- Implement RFC 8693 format completely
- Update resource servers before plugin upgrade
- Clean break, no legacy support

**Option 2: Dual format (NOT RECOMMENDED)**
- Emit both `obo` and `act` claims temporarily
- Adds complexity and confusion
- Delays full RFC compliance

**Recommendation**: Option 1 (Hard cutover)
- Current plugin is not widely deployed (based on context)
- RFC 8693 is the standard going forward
- Clean implementation is better than legacy support

### Client Migration Guide

**For Resource Servers**:

**BEFORE** (validating old format):
```go
// Extract user identity
obo := claims["obo"].(map[string]any)
userID := obo["prn"].(string)

// Extract scopes
scopesStr := obo["ctx"].(string)
scopes := strings.Split(scopesStr, ",")
```

**AFTER** (validating RFC 8693 format):
```go
// Extract user identity
userID := claims["sub"].(string)

// Extract actor identity
act := claims["act"].(map[string]any)
actorID := act["sub"].(string)

// Extract scopes
scopesStr := claims["scope"].(string)
scopes := strings.Split(scopesStr, " ")

// Optional: Extract actor metadata
if actorMeta, ok := claims["actor_metadata"].(map[string]any); ok {
    department := actorMeta["department"].(string)
}
```

---

## Implementation Timeline

### Phase 1: Security Fix (CRITICAL)
**Estimated Time**: 4-6 hours
- Write validation tests (2 hours)
- Implement validation logic (1 hour)
- Run tests and fix issues (1-2 hours)
- Manual verification (1 hour)

### Phase 2: RFC 8693 Compliance (HIGH)
**Estimated Time**: 6-8 hours
- Write token format tests (2 hours)
- Update generateToken function (2 hours)
- Update existing tests (1 hour)
- Update documentation (1 hour)
- Run tests and fix issues (2 hours)

### Phase 3: Comprehensive Testing (MEDIUM)
**Estimated Time**: 3-4 hours
- Write RFC 8693 test suite (2 hours)
- Run full test suite (1 hour)
- Integration testing (1 hour)

**Total Estimated Time**: 13-18 hours

---

## Dependencies

### Go Packages
- `github.com/stretchr/testify/require` - Test assertions
- `github.com/go-jose/go-jose/v4` - JWT parsing/validation
- `github.com/go-jose/go-jose/v4/jwt` - JWT claims
- `github.com/hashicorp/vault/sdk/framework` - Vault plugin framework
- `github.com/hashicorp/vault/sdk/logical` - Vault logical backend

### External Dependencies
- JWKS endpoint for subject token validation
- RSA private key for token signing
- Vault entity for actor identity

### No New Dependencies Required
All existing dependencies support RFC 8693 implementation.

---

## Risks and Mitigations

### Risk 1: Breaking Changes for Existing Deployments
**Impact**: HIGH
**Probability**: MEDIUM
**Mitigation**:
- Document migration guide
- Provide before/after examples
- Update all example configurations
- Consider version tagging for breaking change

### Risk 2: Test Coverage Gaps
**Impact**: MEDIUM
**Probability**: LOW
**Mitigation**:
- Comprehensive test suite in Phase 3
- Manual integration testing
- RFC 8693 compliance validation tests

### Risk 3: Performance Impact of Validation
**Impact**: LOW
**Probability**: LOW
**Mitigation**:
- Validation is simple string/array comparison
- No additional network calls
- Negligible performance impact

### Risk 4: Template Complexity
**Impact**: MEDIUM
**Probability**: MEDIUM
**Mitigation**:
- Provide clear template examples
- Document common patterns
- Create template validation tests
- Fallback to entity ID if template fails

---

## Future Enhancements (Out of Scope)

These are NOT part of this implementation but could be considered later:

1. **Full HTTP API RFC 8693 Compliance**
   - Accept `grant_type` parameter
   - Return `access_token`, `issued_token_type`, `token_type`
   - Use RFC error codes

2. **Actor Token Parameter**
   - Accept explicit `actor_token` parameter
   - Validate actor token signature
   - Extract actor identity from token

3. **may_act Claim Support**
   - Pre-authorization validation
   - Check if actor is permitted to delegate

4. **Delegation Chains**
   - Support nested `act` claims
   - Multi-hop service delegation

5. **JWKS Caching**
   - Cache JWKS for performance
   - Implement TTL and refresh logic

---

## References

- **RFC 8693**: OAuth 2.0 Token Exchange - https://www.rfc-editor.org/rfc/rfc8693.html
- **Section 4.1**: Actor Claim - https://www.rfc-editor.org/rfc/rfc8693.html#section-4.1
- **Gap Analysis**: `.docs/adhoc/rfc-8693-gap-analysis/rfc-8693-gap-analysis-plan.md`
- **Architecture**: `.docs/knowledge/architecture/token-format-rfc8693.md`
- **Go Dev Guidelines**: `go-dev-guidelines` skill

---

## Appendix: Code Change Summary

### Files Modified

1. **path_token_handlers.go**
   - Add `validateBoundIssuer` function (~20 lines)
   - Add `validateBoundAudiences` function (~40 lines)
   - Update `pathTokenExchange` to call validation (~10 lines)
   - Update `generateToken` signature (~1 line)
   - Replace `obo` claim generation with `act` and `scope` (~30 lines)
   - **Total**: ~100 lines changed

2. **path_token_test.go**
   - Add bound issuer tests (~100 lines)
   - Add bound audience tests (~150 lines)
   - Add act claim tests (~80 lines)
   - Update existing test (~10 lines)
   - **Total**: ~340 lines added/changed

3. **path_token_rfc8693_test.go** (NEW)
   - RFC 8693 compliance test suite
   - **Total**: ~400 lines new

4. **path_role.go**
   - Update field descriptions (~10 lines)
   - **Total**: ~10 lines changed

### Total Code Changes
- **Lines Added**: ~840
- **Lines Modified**: ~100
- **Lines Deleted**: ~30
- **Net Change**: ~910 lines

### Test Coverage Impact
- **Before**: ~80% coverage
- **After**: ~85%+ coverage (estimated)
- **New Test Cases**: 11+
