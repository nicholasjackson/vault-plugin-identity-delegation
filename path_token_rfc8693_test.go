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

	// Create test key with this private key
	createTestKey(t, b, storage, "test-key", privateKeyPEM)
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
   "key":              "test-key",
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

	testEntityID := "test-entity-rfc8693"
	tokenReq := &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "token/test-role",
		Storage:   storage,
		EntityID:  testEntityID,
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
		// Verify it follows the agent:entity-id pattern
		require.Contains(t, actSub, "agent:", "act.sub should start with agent: prefix")

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
	createTestKey(t, b, storage, "test-key", privateKeyPEM)
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
   "key":              "test-key",
			"actor_template":   `{"act": {"sub": "agent:{{identity.entity.id}}"}}`,
			"subject_template": `{}`,
			"context":          []string{"urn:documents:read"},
		},
	}
	_, err = b.HandleRequest(context.Background(), roleReq)
	require.NoError(t, err)

	// User is "alice@example.com"
	// Agent is "ai-agent-007"
	testAgentID := "ai-agent-007"
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
		EntityID:  testAgentID,
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
	require.Contains(t, actSub, "agent:", "Actor identity should start with agent: prefix")
	require.NotEmpty(t, actSub, "Actor identity must not be empty")

	// 3. This represents "agent acting on behalf of user", NOT "user acting as agent"
	require.NotEqual(t, claims["sub"], actSub,
		"Subject and actor must be different (delegation, not impersonation)")
}

// TestRFC8693_ScopeFormat validates space-delimited scope format
func TestRFC8693_ScopeFormat(t *testing.T) {
	testCases := []struct {
		name          string
		contextInput  []string
		expectedScope string
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
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			b, storage := getTestBackend(t)

			privateKey, privateKeyPEM := generateTestKeyPair(t)
			createTestKey(t, b, storage, "test-key", privateKeyPEM)
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
     "key":              "test-key",
					"actor_template":   `{"act": {"sub": "agent"}}`,
					"subject_template": `{}`,
					"context":          tc.contextInput,
				},
			}
			_, err = b.HandleRequest(context.Background(), roleReq)
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
			scope, ok := claims["scope"].(string)
			require.True(t, ok, "scope must be a string")
			require.Equal(t, tc.expectedScope, scope, "scope must be space-delimited")

			// Verify no commas (old format)
			require.NotContains(t, scope, ",", "scope must not contain commas (use spaces)")
		})
	}
}
