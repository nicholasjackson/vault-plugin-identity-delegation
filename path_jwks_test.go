package tokenexchange

import (
	"context"
	"encoding/base64"
	"math/big"
	"testing"

	"github.com/hashicorp/vault/sdk/logical"
	"github.com/stretchr/testify/require"
)

// TestPathJWKSRead tests reading the JWKS endpoint
func TestPathJWKSRead(t *testing.T) {
	b, storage := getTestBackend(t)

	// Create multiple keys
	_, privateKeyPEM1 := generateTestKeyPair(t)
	_, privateKeyPEM2 := generateTestKeyPair(t)

	keyReq1 := &logical.Request{
		Operation: logical.CreateOperation,
		Path:      "key/key1",
		Storage:   storage,
		Data: map[string]any{
			"algorithm":   "RS256",
			"private_key": privateKeyPEM1,
		},
	}
	_, err := b.HandleRequest(context.Background(), keyReq1)
	require.NoError(t, err)

	keyReq2 := &logical.Request{
		Operation: logical.CreateOperation,
		Path:      "key/key2",
		Storage:   storage,
		Data: map[string]any{
			"algorithm":   "RS384",
			"private_key": privateKeyPEM2,
		},
	}
	_, err = b.HandleRequest(context.Background(), keyReq2)
	require.NoError(t, err)

	// Read JWKS
	jwksReq := &logical.Request{
		Operation: logical.ReadOperation,
		Path:      "jwks",
		Storage:   storage,
	}

	resp, err := b.HandleRequest(context.Background(), jwksReq)
	require.NoError(t, err)
	require.NotNil(t, resp)
	require.Contains(t, resp.Data, "keys")

	keys := resp.Data["keys"].([]map[string]any)
	require.Len(t, keys, 2, "Should return both keys")

	// Verify JWK structure
	for _, jwk := range keys {
		require.Equal(t, "RSA", jwk["kty"], "Key type should be RSA")
		require.Equal(t, "sig", jwk["use"], "Use should be sig")
		require.Contains(t, jwk, "kid", "Should include kid")
		require.Contains(t, jwk, "alg", "Should include alg")
		require.Contains(t, jwk, "n", "Should include modulus n")
		require.Contains(t, jwk, "e", "Should include exponent e")

		// Verify n and e are base64url encoded
		_, err := base64.RawURLEncoding.DecodeString(jwk["n"].(string))
		require.NoError(t, err, "n should be valid base64url")
		_, err = base64.RawURLEncoding.DecodeString(jwk["e"].(string))
		require.NoError(t, err, "e should be valid base64url")
	}

	// Verify different algorithms
	algs := []string{}
	for _, jwk := range keys {
		algs = append(algs, jwk["alg"].(string))
	}
	require.Contains(t, algs, "RS256")
	require.Contains(t, algs, "RS384")
}

// TestPathJWKSRead_FilterByKid tests filtering JWKS by kid
func TestPathJWKSRead_FilterByKid(t *testing.T) {
	b, storage := getTestBackend(t)

	// Create two keys
	_, privateKeyPEM1 := generateTestKeyPair(t)
	_, privateKeyPEM2 := generateTestKeyPair(t)

	keyReq1 := &logical.Request{
		Operation: logical.CreateOperation,
		Path:      "key/key1",
		Storage:   storage,
		Data: map[string]any{
			"algorithm":   "RS256",
			"private_key": privateKeyPEM1,
		},
	}
	resp1, err := b.HandleRequest(context.Background(), keyReq1)
	require.NoError(t, err)
	kid1 := resp1.Data["key_id"].(string)

	keyReq2 := &logical.Request{
		Operation: logical.CreateOperation,
		Path:      "key/key2",
		Storage:   storage,
		Data: map[string]any{
			"algorithm":   "RS384",
			"private_key": privateKeyPEM2,
		},
	}
	_, err = b.HandleRequest(context.Background(), keyReq2)
	require.NoError(t, err)

	// Read JWKS with kid filter
	jwksReq := &logical.Request{
		Operation: logical.ReadOperation,
		Path:      "jwks",
		Storage:   storage,
		Data: map[string]any{
			"kid": kid1,
		},
	}

	resp, err := b.HandleRequest(context.Background(), jwksReq)
	require.NoError(t, err)
	require.NotNil(t, resp)

	keys := resp.Data["keys"].([]map[string]any)
	require.Len(t, keys, 1, "Should return only filtered key")
	require.Equal(t, kid1, keys[0]["kid"])
	require.Equal(t, "RS256", keys[0]["alg"])
}

// TestPathJWKSRead_Empty tests JWKS with no keys
func TestPathJWKSRead_Empty(t *testing.T) {
	b, storage := getTestBackend(t)

	// Read JWKS without any keys
	jwksReq := &logical.Request{
		Operation: logical.ReadOperation,
		Path:      "jwks",
		Storage:   storage,
	}

	resp, err := b.HandleRequest(context.Background(), jwksReq)
	require.NoError(t, err)
	require.NotNil(t, resp)
	require.Contains(t, resp.Data, "keys")

	keys := resp.Data["keys"].([]map[string]any)
	require.Len(t, keys, 0, "Should return empty keys array")
}

// TestPathJWKSRead_ValidFormat tests that JWKS conforms to RFC 7517
func TestPathJWKSRead_ValidFormat(t *testing.T) {
	b, storage := getTestBackend(t)

	// Create a key
	privateKey, privateKeyPEM := generateTestKeyPair(t)

	keyReq := &logical.Request{
		Operation: logical.CreateOperation,
		Path:      "key/test-key",
		Storage:   storage,
		Data: map[string]any{
			"algorithm":   "RS256",
			"private_key": privateKeyPEM,
		},
	}
	_, err := b.HandleRequest(context.Background(), keyReq)
	require.NoError(t, err)

	// Read JWKS
	jwksReq := &logical.Request{
		Operation: logical.ReadOperation,
		Path:      "jwks",
		Storage:   storage,
	}

	resp, err := b.HandleRequest(context.Background(), jwksReq)
	require.NoError(t, err)

	keys := resp.Data["keys"].([]map[string]any)
	require.Len(t, keys, 1)

	jwk := keys[0]

	// Decode and verify n (modulus)
	nBytes, err := base64.RawURLEncoding.DecodeString(jwk["n"].(string))
	require.NoError(t, err)
	nBigInt := new(big.Int).SetBytes(nBytes)
	require.Equal(t, privateKey.PublicKey.N, nBigInt, "Modulus should match")

	// Decode and verify e (exponent)
	eBytes, err := base64.RawURLEncoding.DecodeString(jwk["e"].(string))
	require.NoError(t, err)
	eBigInt := new(big.Int).SetBytes(eBytes)
	require.Equal(t, int64(privateKey.PublicKey.E), eBigInt.Int64(), "Exponent should match")
}
