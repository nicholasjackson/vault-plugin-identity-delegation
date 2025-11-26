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

func TestContextMapsToScope(t *testing.T) {
	b, storage := getTestBackend(t)

	privateKey, privateKeyPEM := generateTestKeyPair(t)
	createTestKey(t, b, storage, "test-key", privateKeyPEM)
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

	// Create role with context
	roleReq := &logical.Request{
		Operation: logical.CreateOperation,
		Path:      "role/test-role",
		Storage:   storage,
		Data: map[string]any{
			"name":             "test-role",
			"ttl":              "1h",
   "key":              "test-key",
			"actor_template":   `{"act": {"sub": "agent"}}`,
			"subject_template": `{}`,
			"context":          []string{"urn:scope1", "urn:scope2", "urn:scope3"},
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
		EntityID:  "entity-123",
		Data: map[string]any{
			"subject_token": subjectToken,
		},
	}
	resp, err := b.HandleRequest(context.Background(), tokenReq)
	require.NoError(t, err)
	require.NotNil(t, resp)
	require.False(t, resp.IsError())

	// Parse token and verify scope
	generatedToken := resp.Data["token"].(string)
	parsedToken, err := jwt.ParseSigned(generatedToken, []jose.SignatureAlgorithm{jose.RS256})
	require.NoError(t, err)

	claims := make(map[string]any)
	err = parsedToken.Claims(&privateKey.PublicKey, &claims)
	require.NoError(t, err)

	// Verify scope exists and is space-delimited
	scope, ok := claims["scope"].(string)
	require.True(t, ok, "scope claim must exist")
	require.Equal(t, "urn:scope1 urn:scope2 urn:scope3", scope, "scope must be space-delimited")
	t.Logf("SUCCESS: scope claim is present: %s", scope)
}

// TestContextToScopeEndToEnd validates the complete flow from role creation to token generation
func TestContextToScopeEndToEnd(t *testing.T) {
	b, storage := getTestBackend(t)

	privateKey, privateKeyPEM := generateTestKeyPair(t)
	createTestKey(t, b, storage, "test-key", privateKeyPEM)
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
	require.NoError(t, err, "Config should be created")

	// Test Case 1: Create role with context (comma-delimited input)
	roleReq := &logical.Request{
		Operation: logical.CreateOperation,
		Path:      "role/test-role",
		Storage:   storage,
		Data: map[string]any{
			"name":             "test-role",
			"ttl":              "1h",
   "key":              "test-key",
			"actor_template":   `{"act": {"sub": "agent-id"}}`,
			"subject_template": `{}`,
			"context":          []string{"urn:docs:read", "urn:docs:write", "urn:images:delete"},
		},
	}
	_, err = b.HandleRequest(context.Background(), roleReq)
	require.NoError(t, err, "Role should be created")

	// Test Case 2: Read role back and verify context is stored
	readRoleReq := &logical.Request{
		Operation: logical.ReadOperation,
		Path:      "role/test-role",
		Storage:   storage,
	}
	readResp, err := b.HandleRequest(context.Background(), readRoleReq)
	require.NoError(t, err, "Role should be readable")
	require.NotNil(t, readResp)

	contextFromRole := readResp.Data["context"].([]string)
	require.Equal(t, []string{"urn:docs:read", "urn:docs:write", "urn:images:delete"}, contextFromRole, "Context should match input")
	t.Logf("✅ Step 1: Context stored in role: %v", contextFromRole)

	// Test Case 3: Generate token
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
	tokenResp, err := b.HandleRequest(context.Background(), tokenReq)
	require.NoError(t, err, "Token exchange should succeed")
	require.NotNil(t, tokenResp)
	require.False(t, tokenResp.IsError())

	// Test Case 4: Parse token and verify scope claim (space-delimited output)
	generatedToken := tokenResp.Data["token"].(string)
	parsedToken, err := jwt.ParseSigned(generatedToken, []jose.SignatureAlgorithm{jose.RS256})
	require.NoError(t, err)

	claims := make(map[string]any)
	err = parsedToken.Claims(&privateKey.PublicKey, &claims)
	require.NoError(t, err)

	scope, ok := claims["scope"].(string)
	require.True(t, ok, "scope claim must exist")
	require.Equal(t, "urn:docs:read urn:docs:write urn:images:delete", scope, "scope must be space-delimited per RFC 8693")
	t.Logf("✅ Step 2: Context converted to scope claim: %s", scope)

	// Test Case 5: Verify RFC 8693 compliance - no old obo claim
	_, hasObo := claims["obo"]
	require.False(t, hasObo, "obo claim should not exist (replaced by scope)")
	t.Logf("✅ Step 3: RFC 8693 compliant - no deprecated obo claim")

	t.Log("\n✅ END-TO-END VERIFICATION PASSED:")
	t.Log("   Input:  context=[\"urn:docs:read\", \"urn:docs:write\", \"urn:images:delete\"]")
	t.Log("   Output: scope=\"urn:docs:read urn:docs:write urn:images:delete\"")
	t.Log("   Format: Space-delimited per RFC 8693 ✓")
}
