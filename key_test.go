package tokenexchange

import (
	"context"
	"testing"

	"github.com/hashicorp/vault/sdk/logical"
	"github.com/stretchr/testify/require"
)

func TestPathKeyWrite_AutoGenerate(t *testing.T) {
	// This test should FAIL initially (key.go doesn't exist yet)
	b, storage := getTestBackend(t)

	req := &logical.Request{
		Operation: logical.CreateOperation,
		Path:      "key/test-key",
		Storage:   storage,
		Data: map[string]any{
			"algorithm": "RS256",
			"key_size":  2048,
		},
	}

	resp, err := b.HandleRequest(context.Background(), req)
	require.NoError(t, err)
	require.NotNil(t, resp)
	require.Equal(t, "test-key", resp.Data["name"])
	require.Equal(t, "test-key-v1", resp.Data["key_id"])
	require.Equal(t, 1, resp.Data["version"])
}

func TestPathKeyWrite_InvalidAlgorithm(t *testing.T) {
	// Negative test: invalid algorithm
	b, storage := getTestBackend(t)

	req := &logical.Request{
		Operation: logical.CreateOperation,
		Path:      "key/bad-key",
		Storage:   storage,
		Data: map[string]any{
			"algorithm": "ES256", // Not supported in Phase 1
		},
	}

	resp, err := b.HandleRequest(context.Background(), req)
	require.NoError(t, err)
	require.True(t, resp.IsError())
	require.Contains(t, resp.Error().Error(), "must be RS256, RS384, or RS512")
}

func TestPathKeyRead(t *testing.T) {
	// Test reading key metadata
	b, storage := getTestBackend(t)

	// Create key first
	createReq := &logical.Request{
		Operation: logical.CreateOperation,
		Path:      "key/read-test",
		Storage:   storage,
		Data: map[string]any{
			"algorithm": "RS256",
		},
	}
	_, err := b.HandleRequest(context.Background(), createReq)
	require.NoError(t, err)

	// Read key
	readReq := &logical.Request{
		Operation: logical.ReadOperation,
		Path:      "key/read-test",
		Storage:   storage,
	}

	resp, err := b.HandleRequest(context.Background(), readReq)
	require.NoError(t, err)
	require.NotNil(t, resp)
	require.Equal(t, "read-test", resp.Data["name"])
	require.Equal(t, "RS256", resp.Data["algorithm"])
	require.Contains(t, resp.Data, "public_key")
	require.NotContains(t, resp.Data, "private_key") // MUST NOT return private key
}

func TestPathKeyList(t *testing.T) {
	// Test listing keys
	b, storage := getTestBackend(t)

	// Create multiple keys
	for _, name := range []string{"key1", "key2", "key3"} {
		req := &logical.Request{
			Operation: logical.CreateOperation,
			Path:      "key/" + name,
			Storage:   storage,
			Data: map[string]any{
				"algorithm": "RS256",
			},
		}
		_, err := b.HandleRequest(context.Background(), req)
		require.NoError(t, err)
	}

	// List keys
	listReq := &logical.Request{
		Operation: logical.ListOperation,
		Path:      "key/",
		Storage:   storage,
	}

	resp, err := b.HandleRequest(context.Background(), listReq)
	require.NoError(t, err)
	require.NotNil(t, resp)
	require.Len(t, resp.Data["keys"], 3)
}

func TestPathKeyDelete(t *testing.T) {
	// Test deleting a key
	b, storage := getTestBackend(t)

	// Create key
	createReq := &logical.Request{
		Operation: logical.CreateOperation,
		Path:      "key/delete-me",
		Storage:   storage,
		Data: map[string]any{
			"algorithm": "RS256",
		},
	}
	_, err := b.HandleRequest(context.Background(), createReq)
	require.NoError(t, err)

	// Delete key
	deleteReq := &logical.Request{
		Operation: logical.DeleteOperation,
		Path:      "key/delete-me",
		Storage:   storage,
	}

	resp, err := b.HandleRequest(context.Background(), deleteReq)
	require.NoError(t, err)
	require.Nil(t, resp)

	// Verify key is gone
	readReq := &logical.Request{
		Operation: logical.ReadOperation,
		Path:      "key/delete-me",
		Storage:   storage,
	}

	resp, err = b.HandleRequest(context.Background(), readReq)
	require.NoError(t, err)
	require.Nil(t, resp)
}

func TestPathKeyWrite_DuplicateName(t *testing.T) {
	// Negative test: prevent duplicate key names
	b, storage := getTestBackend(t)

	req := &logical.Request{
		Operation: logical.CreateOperation,
		Path:      "key/dup-key",
		Storage:   storage,
		Data: map[string]any{
			"algorithm": "RS256",
		},
	}

	// First creation should succeed
	resp, err := b.HandleRequest(context.Background(), req)
	require.NoError(t, err)
	require.NotNil(t, resp)

	// Second creation should fail
	resp, err = b.HandleRequest(context.Background(), req)
	require.NoError(t, err)
	require.True(t, resp.IsError())
	require.Contains(t, resp.Error().Error(), "already exists")
}
