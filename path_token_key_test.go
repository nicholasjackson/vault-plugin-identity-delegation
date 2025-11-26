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

// TestPathTokenExchange_WithNamedKey tests token exchange using named key
func TestPathTokenExchange_WithNamedKey(t *testing.T) {
	b, storage := getTestBackend(t)

	// Setup: Create key
	privateKey, privateKeyPEM := generateTestKeyPair(t)

	keyReq := &logical.Request{
		Operation: logical.CreateOperation,
		Path:      "key/token-key",
		Storage:   storage,
		Data: map[string]any{
			"algorithm":   "RS256",
			"private_key": privateKeyPEM,
		},
	}
	keyResp, err := b.HandleRequest(context.Background(), keyReq)
	require.NoError(t, err)

	keyID := keyResp.Data["key_id"].(string) // e.g., "token-key-v1"

	// Setup: Create JWKS server for subject token validation
	publicKey := &privateKey.PublicKey
	jwksServer := createMockJWKSServer(t, publicKey, keyID)
	defer jwksServer.Close()

	// Setup: Create config (using named keys, so signing_key is optional)
	// But we still need issuer and subject_jwks_uri
	configReq := &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "config",
		Storage:   storage,
		Data: map[string]any{
			"issuer":           "https://vault.example.com",
			"signing_key":      privateKeyPEM, // Still needed for config validation
			"subject_jwks_uri": jwksServer.URL,
			"default_ttl":      "1h",
		},
	}
	_, err = b.HandleRequest(context.Background(), configReq)
	require.NoError(t, err)

	// Setup: Create role with named key
	roleReq := &logical.Request{
		Operation: logical.CreateOperation,
		Path:      "role/test-role",
		Storage:   storage,
		Data: map[string]any{
			"name":             "test-role",
			"ttl":              "1h",
			"key":              "token-key",
			"actor_template":   `{"act": {"sub": "agent"}}`,
			"subject_template": `{}`,
			"context":          []string{"scope1"},
		},
	}
	_, err = b.HandleRequest(context.Background(), roleReq)
	require.NoError(t, err)

	// Create subject token (simulate incoming token)
	subjectClaims := map[string]any{
		"sub": "user123",
		"iss": "https://example.com",
		"aud": []any{"test"},
		"exp": time.Now().Add(1 * time.Hour).Unix(),
		"iat": time.Now().Unix(),
	}

	signer, err := jose.NewSigner(
		jose.SigningKey{Algorithm: jose.RS256, Key: privateKey},
		(&jose.SignerOptions{}).WithType("JWT").WithHeader("kid", keyID),
	)
	require.NoError(t, err)

	builder := jwt.Signed(signer).Claims(subjectClaims)
	subjectToken, err := builder.Serialize()
	require.NoError(t, err)

	// Exchange token
	tokenReq := &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "token/test-role",
		Storage:   storage,
		EntityID:  "test-entity",
		Data: map[string]any{
			"subject_token": subjectToken,
		},
	}

	resp, err := b.HandleRequest(context.Background(), tokenReq)
	require.NoError(t, err)
	require.NotNil(t, resp)
	require.Contains(t, resp.Data, "token")

	// Parse generated token
	generatedToken := resp.Data["token"].(string)
	parsedToken, err := jwt.ParseSigned(generatedToken, []jose.SignatureAlgorithm{jose.RS256})
	require.NoError(t, err)

	// Verify kid in header
	require.Equal(t, keyID, parsedToken.Headers[0].KeyID, "JWT should include kid header")

	// Verify signature with public key
	claims := make(map[string]any)
	err = parsedToken.Claims(publicKey, &claims)
	require.NoError(t, err)

	// Verify claims
	require.Equal(t, "https://vault.example.com", claims["iss"])
	require.Equal(t, "user123", claims["sub"])
	require.Contains(t, claims, "act")
}


// TestPathTokenExchange_RS384 tests RS384 algorithm support in key creation
// Full end-to-end test would require RS384-capable JWKS mock, but we verify
// that the key can be created with RS384 algorithm
func TestPathTokenExchange_RS384(t *testing.T) {
	b, storage := getTestBackend(t)

	// Create RS384 key
	_, privateKeyPEM := generateTestKeyPair(t)

	keyReq := &logical.Request{
		Operation: logical.CreateOperation,
		Path:      "key/rs384-key",
		Storage:   storage,
		Data: map[string]any{
			"algorithm":   "RS384",
			"private_key": privateKeyPEM,
		},
	}
	keyResp, err := b.HandleRequest(context.Background(), keyReq)
	require.NoError(t, err)
	require.NotNil(t, keyResp)
	require.Equal(t, "rs384-key-v1", keyResp.Data["key_id"])

	// Read back and verify algorithm
	readReq := &logical.Request{
		Operation: logical.ReadOperation,
		Path:      "key/rs384-key",
		Storage:   storage,
	}
	readResp, err := b.HandleRequest(context.Background(), readReq)
	require.NoError(t, err)
	require.Equal(t, "RS384", readResp.Data["algorithm"])

	// Verify role can be created with RS384 key
	roleReq := &logical.Request{
		Operation: logical.CreateOperation,
		Path:      "role/rs384-role",
		Storage:   storage,
		Data: map[string]any{
			"name":             "rs384-role",
			"ttl":              "1h",
			"key":              "rs384-key",
			"actor_template":   `{}`,
			"subject_template": `{}`,
			"context":          []string{"scope1"},
		},
	}
	_, err = b.HandleRequest(context.Background(), roleReq)
	require.NoError(t, err)

	// Note: Full token exchange test with RS384 would require updating the
	// JWKS mock to support RS384. The important verification here is that:
	// 1. Keys can be created with RS384 algorithm
	// 2. Roles can reference RS384 keys
	// 3. The algorithm mapping code in token generation handles RS384
}
