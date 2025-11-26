package tokenexchange

import (
	"context"
	"encoding/base64"
	"fmt"
	"math/big"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

// pathJWKSRead handles reading the JWKS endpoint
func (b *Backend) pathJWKSRead(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	// Get optional kid filter from query params
	kidFilter, _ := data.GetOk("kid")
	var kidFilterStr string
	if kidFilter != nil {
		kidFilterStr = kidFilter.(string)
	}

	// List all keys
	keyNames, err := req.Storage.List(ctx, keyStoragePrefix)
	if err != nil {
		return nil, fmt.Errorf("failed to list keys: %w", err)
	}

	// Build JWKS
	jwks := map[string]any{
		"keys": []map[string]any{},
	}

	keys := jwks["keys"].([]map[string]any)

	for _, keyName := range keyNames {
		key, err := b.getKey(ctx, req.Storage, keyName)
		if err != nil {
			return nil, fmt.Errorf("failed to load key %q: %w", keyName, err)
		}

		if key == nil {
			continue
		}

		// Apply kid filter if specified
		if kidFilterStr != "" && key.KeyID != kidFilterStr {
			continue
		}

		// Extract public key
		publicKey, err := publicKeyFromPrivate(key.PrivateKey)
		if err != nil {
			return nil, fmt.Errorf("failed to extract public key from %q: %w", keyName, err)
		}

		// Convert to JWK format (RFC 7517)
		jwk := map[string]any{
			"kty": "RSA",
			"use": "sig",
			"alg": key.Algorithm,
			"kid": key.KeyID,
			"n":   base64.RawURLEncoding.EncodeToString(publicKey.N.Bytes()),
			"e":   base64.RawURLEncoding.EncodeToString(big.NewInt(int64(publicKey.E)).Bytes()),
		}

		keys = append(keys, jwk)
	}

	jwks["keys"] = keys

	return &logical.Response{
		Data: jwks,
	}, nil
}
