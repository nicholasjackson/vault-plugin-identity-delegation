package tokenexchange

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
	"github.com/hashicorp/vault/sdk/logical"
	"github.com/stretchr/testify/require"
)

// generateTestKeyPair generates a test RSA key pair for signing JWTs
func generateTestKeyPair(t *testing.T) (*rsa.PrivateKey, string) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	privateKeyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(privateKey),
	})

	return privateKey, string(privateKeyPEM)
}

// generateTestJWT generates a test JWT signed with the given private key
func generateTestJWT(t *testing.T, privateKey *rsa.PrivateKey, kid string, claims map[string]any) string {
	signer, err := jose.NewSigner(
		jose.SigningKey{Algorithm: jose.RS256, Key: privateKey},
		(&jose.SignerOptions{}).WithType("JWT").WithHeader("kid", kid),
	)
	require.NoError(t, err)

	builder := jwt.Signed(signer).Claims(claims)
	token, err := builder.Serialize()
	require.NoError(t, err)

	return token
}

// createMockJWKSServer creates a test HTTP server that serves a JWKS endpoint
func createMockJWKSServer(t *testing.T, publicKey *rsa.PublicKey, kid string) *httptest.Server {
	// Create JWK from public key
	jwk := jose.JSONWebKey{
		Key:       publicKey,
		KeyID:     kid,
		Algorithm: string(jose.RS256),
		Use:       "sig",
	}

	// Create JWKS
	jwks := jose.JSONWebKeySet{
		Keys: []jose.JSONWebKey{jwk},
	}

	// Create test server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		err := json.NewEncoder(w).Encode(jwks)
		require.NoError(t, err)
	}))

	return server
}

// TestTokenExchange_Success tests successful token exchange
func TestTokenExchange_Success(t *testing.T) {
	b, storage := getTestBackend(t)

	// Generate test key pair
	privateKey, privateKeyPEM := generateTestKeyPair(t)

	// Create mock JWKS server
	testKID := "test-key-1"
	jwksServer := createMockJWKSServer(t, &privateKey.PublicKey, testKID)
	defer jwksServer.Close()

	// Configure plugin
	configReq := &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "config",
		Storage:   storage,
		Data: map[string]any{
			"issuer":            "https://vault.example.com",
			"delegate_jwks_uri": jwksServer.URL,
			"signing_key":       privateKeyPEM,
			"default_ttl":       "1h",
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
			"subject_template": `{"act": {"sub": "{{identity.subject.email}}"} }`,
			"actor_template":   `{"act": {"sub": "{{identity.entity.id}}"} }`,
			"context":          "urn:documents.service:read,urn:images.service:write",
		},
	}
	resp, err := b.HandleRequest(context.Background(), roleReq)
	require.NoError(t, err)

	respErr := resp.Error()
	require.NoError(t, respErr)

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
		Data: map[string]any{
			"subject_token": subjectToken,
		},
		EntityID: "test_entity",
	}
	resp, err = b.HandleRequest(context.Background(), tokenReq)

	require.NoError(t, err, "Token exchange should succeed")
	require.NotNil(t, resp, "Should return response")
	require.NotNil(t, resp.Data, "Response should have data")
	require.Contains(t, resp.Data, "token", "Response should contain token")
	require.NotEmpty(t, resp.Data["token"], "Token should not be empty")
}

// TestTokenExchange_MissingSubjectToken tests validation of required subject_token
func TestTokenExchange_MissingSubjectToken(t *testing.T) {
	b, storage := getTestBackend(t)

	// Configure plugin
	_, privateKeyPEM := generateTestKeyPair(t)
	configReq := &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "config",
		Storage:   storage,
		Data: map[string]any{
			"issuer":      "https://vault.example.com",
			"signing_key": privateKeyPEM,
			"default_ttl": "1h",
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
			"name":     "test-role",
			"ttl":      "1h",
			"template": `{"act": {"sub": "agent-123"}}`,
		},
	}
	_, err = b.HandleRequest(context.Background(), roleReq)
	require.NoError(t, err)

	// Exchange token without subject_token
	tokenReq := &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "token/test-role",
		Storage:   storage,
		Data:      map[string]any{
			// Missing subject_token
		},
	}
	resp, err := b.HandleRequest(context.Background(), tokenReq)

	require.NoError(t, err, "Handler should not error")
	require.NotNil(t, resp, "Should return error response")
	require.True(t, resp.IsError(), "Response should be an error")
	require.Contains(t, resp.Error().Error(), "subject_token", "Error should mention missing subject_token")
}

// TestTokenExchange_InvalidJWT tests handling of invalid JWT
func TestTokenExchange_InvalidJWT(t *testing.T) {
	b, storage := getTestBackend(t)

	// Configure plugin
	_, privateKeyPEM := generateTestKeyPair(t)
	configReq := &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "config",
		Storage:   storage,
		Data: map[string]any{
			"issuer":      "https://vault.example.com",
			"signing_key": privateKeyPEM,
			"default_ttl": "1h",
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
			"name":     "test-role",
			"ttl":      "1h",
			"template": `{"act": {"sub": "agent-123"}}`,
		},
	}
	_, err = b.HandleRequest(context.Background(), roleReq)
	require.NoError(t, err)

	// Exchange with invalid JWT
	tokenReq := &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "token/test-role",
		Storage:   storage,
		Data: map[string]any{
			"subject_token": "invalid.jwt.token",
		},
	}
	resp, err := b.HandleRequest(context.Background(), tokenReq)

	require.NoError(t, err, "Handler should not error")
	require.NotNil(t, resp, "Should return error response")
	require.True(t, resp.IsError(), "Response should be an error")
}

// TestTokenExchange_ExpiredToken tests handling of expired JWT
func TestTokenExchange_ExpiredToken(t *testing.T) {
	b, storage := getTestBackend(t)

	// Generate test key pair
	privateKey, privateKeyPEM := generateTestKeyPair(t)

	// Create mock JWKS server
	testKID := "test-key-1"
	jwksServer := createMockJWKSServer(t, &privateKey.PublicKey, testKID)
	defer jwksServer.Close()

	// Configure plugin
	configReq := &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "config",
		Storage:   storage,
		Data: map[string]any{
			"issuer":            "https://vault.example.com",
			"delegate_jwks_uri": jwksServer.URL,
			"signing_key":       privateKeyPEM,
			"default_ttl":       "1h",
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
			"name":     "test-role",
			"ttl":      "1h",
			"template": `{"act": {"sub": "agent-123"}}`,
		},
	}
	_, err = b.HandleRequest(context.Background(), roleReq)
	require.NoError(t, err)

	// Generate expired subject token
	expiredClaims := map[string]any{
		"sub": "user-123",
		"iss": "https://idp.example.com",
		"aud": []string{"service-a"},
		"exp": time.Now().Add(-1 * time.Hour).Unix(), // Expired 1 hour ago
		"iat": time.Now().Add(-2 * time.Hour).Unix(),
	}
	expiredToken := generateTestJWT(t, privateKey, testKID, expiredClaims)

	// Exchange expired token
	tokenReq := &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "token/test-role",
		Storage:   storage,
		Data: map[string]any{
			"subject_token": expiredToken,
		},
	}
	resp, err := b.HandleRequest(context.Background(), tokenReq)

	require.NoError(t, err, "Handler should not error")
	require.NotNil(t, resp, "Should return error response")
	require.True(t, resp.IsError(), "Response should be an error")
	require.Contains(t, resp.Error().Error(), "expired", "Error should mention expired token")
}

// TestTokenExchange_RoleNotFound tests handling when role doesn't exist
func TestTokenExchange_RoleNotFound(t *testing.T) {
	b, storage := getTestBackend(t)

	// Configure plugin
	privateKey, privateKeyPEM := generateTestKeyPair(t)

	// Create mock JWKS server
	testKID := "test-key-1"
	jwksServer := createMockJWKSServer(t, &privateKey.PublicKey, testKID)
	defer jwksServer.Close()

	configReq := &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "config",
		Storage:   storage,
		Data: map[string]any{
			"issuer":            "https://vault.example.com",
			"delegate_jwks_uri": jwksServer.URL,
			"signing_key":       privateKeyPEM,
			"default_ttl":       "1h",
		},
	}
	_, err := b.HandleRequest(context.Background(), configReq)
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

	// Exchange token with non-existent role
	tokenReq := &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "token/nonexistent-role",
		Storage:   storage,
		Data: map[string]any{
			"subject_token": subjectToken,
		},
	}
	resp, err := b.HandleRequest(context.Background(), tokenReq)

	require.NoError(t, err, "Handler should not error")
	require.NotNil(t, resp, "Should return error response")
	require.True(t, resp.IsError(), "Response should be an error")
	require.Contains(t, resp.Error().Error(), "role", "Error should mention role not found")
}

// TestTokenExchange_VerifyGeneratedToken tests that the generated token is valid
func TestTokenExchange_VerifyGeneratedToken(t *testing.T) {
	b, storage := getTestBackend(t)

	// Generate test key pair
	privateKey, privateKeyPEM := generateTestKeyPair(t)

	// Create mock JWKS server
	testKID := "test-key-1"
	jwksServer := createMockJWKSServer(t, &privateKey.PublicKey, testKID)
	defer jwksServer.Close()

	// Configure plugin
	configReq := &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "config",
		Storage:   storage,
		Data: map[string]any{
			"issuer":            "https://vault.example.com",
			"delegate_jwks_uri": jwksServer.URL,
			"signing_key":       privateKeyPEM,
			"default_ttl":       "1h",
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
			"name":     "test-role",
			"ttl":      "1h",
			"template": `{"act": {"sub": "agent-123"}}`,
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
		Data: map[string]any{
			"subject_token": subjectToken,
		},
	}
	resp, err := b.HandleRequest(context.Background(), tokenReq)
	require.NoError(t, err)

	// Verify the generated token
	generatedToken := resp.Data["token"].(string)
	require.NotEmpty(t, generatedToken)

	// Parse and verify the token
	parsedToken, err := jwt.ParseSigned(generatedToken, []jose.SignatureAlgorithm{jose.RS256})
	require.NoError(t, err, "Generated token should be valid JWT")

	claims := make(map[string]any)
	err = parsedToken.Claims(&privateKey.PublicKey, &claims)
	require.NoError(t, err, "Should be able to verify signature with public key")

	// Verify standard claims
	require.Equal(t, "https://vault.example.com", claims["iss"], "Issuer should match config")
	require.NotNil(t, claims["exp"], "Should have expiration")
	require.NotNil(t, claims["iat"], "Should have issued at")
	require.Equal(t, "user-123", claims["sub"], "Subject should be from original token")

	// Verify template claims were applied
	act, ok := claims["act"].(map[string]any)
	require.True(t, ok, "Should have act claim from template")
	require.Equal(t, "agent-123", act["sub"], "Agent sub should match template")
}
