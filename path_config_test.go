package tokenexchange

import (
	"context"
	"testing"

	"github.com/hashicorp/go-hclog"
	"github.com/hashicorp/vault/sdk/logical"
	"github.com/stretchr/testify/require"
)

// getTestBackend creates a test backend for testing
func getTestBackend(t *testing.T) (*Backend, logical.Storage) {
	config := &logical.BackendConfig{
		Logger:      hclog.NewNullLogger(),
		System:      &logical.StaticSystemView{},
		StorageView: &logical.InmemStorage{},
	}

	b, err := Factory(context.Background(), config)
	require.NoError(t, err)

	return b.(*Backend), config.StorageView
}

// Test RSA private key for testing
const testRSAPrivateKey = `-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEA0Z3VS5JJcds3xfn/ygWyF/rLcXbq8B2dbABdKyN4cYVmT7X0
rH3YDm9lcrw0B6BaCXRPLzN8smOHhM7cQ8VkAHPTl5kNKQSq/lCCxZxVB3JsLGgr
aEHEK7DZ5uDxY0kCxBLZZ0j7Wqj8WzFGK7Tt4TGGOXqXEHp5Gvn3kzHOxBV/FgTT
wMjMHLdlJK5FvN7D0X7VYjfbdCRq0eXPtHQXJ0g2gNxHC/iT7S7GqKNLMqN+V7xT
gCJN1PqQW0X5GThZA8IiGwvC3qM5gSHkjjQ9IhBQxHoqXDKGF+F8O1Hv0y/fH5Iq
RJxFI8vJMdKZaHKMR8fAFvyPmVLKnqqK3PiFXQIDAQABAoIBADqXX5KZ2R3jPKxb
1y7gLNqR0tUEQ3b4B+fsdqNNiLF/dYOXMQCcFZJaL6mJRhYYKGKKq6vLdV0VZoWc
9L1sO2x1vL3tqDPxNqCPEEXq2HQqWC0lhVv5x0NfBf0nE3Q2M4xM6g4cJZvBtZ5U
QWH/LTMWn1qE3Lz8F9EY0x9r8EQPqB1KCtEKhw8YqPQFMlV3UFqJ8m7pVVXvJBiQ
TZq1LB2UxMjNMZJqtE4Q3YWqMKJLQT3NHYE6NvE5XaQ6jHLKxL7oxLkJ7YFhYLWq
bC8qCZQ+HkHxQ4LmGmL7fHQF8qKCWCl3AZqLzDqH9L5qHV5YV6hxPZ4PqJ2CKZ5L
pz8cQgECgYEA7+3Q2Y5LqPxPNqH9xV5KFqYnWyP7oXZPMQHQHY5qVvYU3PqxMdqN
o3tPQzHh3xHqQxQQVqLxhLZqQ2CqPqxQqZL5HqQZpQxPqQNpQqQxPqQ5qQ3PqQxP
qQNpQqQxPqQ5qQ3PqQxPqQNpQqQxPqQ5qQ3PqQxPqQNpQqQxPqQ5qQECgYEA38+q
KpQ3qH9L5qHV5YV6hxPZ4PqJ2CKZ5Lpz8cQgE7+3Q2Y5LqPxPNqH9xV5KFqYnWyP
7oXZPMQHQHY5qVvYU3PqxMdqNo3tPQzHh3xHqQxQQVqLxhLZqQ2CqPqxQqZL5HqQ
ZpQxPqQNpQqQxPqQ5qQ3PqQxPqQNpQqQxPqQ5qQ3PqQxPqQNpQqQxPqQ5qQ0CQYD
pz8cQgE7+3Q2Y5LqPxPNqH9xV5KFqYnWyP7oXZPMQHQHY5qVvYU3PqxMdqNo3tP
QzHh3xHqQxQQVqLxhLZqQ2CqPqxQqZL5HqQZpQxPqQNpQqQxPqQ5qQ3PqQxPqQNp
QqQxPqQ5qQ3PqQxPqQNpQqQxPqQ5qQ3PqQxPqQNpQqQxPqQ5qQECgYEAo3tPQzHh
3xHqQxQQVqLxhLZqQ2CqPqxQqZL5HqQZpQxPqQNpQqQxPqQ5qQ3PqQxPqQNpQqQx
PqQ5qQ3PqQxPqQNpQqQxPqQ5qQ3PqQxPqQNpQqQxPqQ5qQE7+3Q2Y5LqPxPNqH9x
V5KFqYnWyP7oXZPMQHQHY5qVvYU3PqxMdqNo3tPQzHh3xHqQxQQVqLxhLZqQ2Cq
PqxQqZL5HqQZpQxPqQNpQqQxPqQ5qQ3PqQxPqQNpQqQxPqQ5qQECgYBo3tPQzHh
3xHqQxQQVqLxhLZqQ2CqPqxQqZL5HqQZpQxPqQNpQqQxPqQ5qQ3PqQxPqQNpQqQx
PqQ5qQ3PqQxPqQNpQqQxPqQ5qQ3PqQxPqQNpQqQxPqQ5qQE7+3Q2Y5LqPxPNqH9x
V5KFqYnWyP7oXZPMQHQHY5qVvYU3PqxMdqN=
-----END RSA PRIVATE KEY-----`

// TestConfigRead_NotConfigured tests reading when no config exists
func TestConfigRead_NotConfigured(t *testing.T) {
	b, storage := getTestBackend(t)

	req := &logical.Request{
		Operation: logical.ReadOperation,
		Path:      "config",
		Storage:   storage,
	}

	resp, err := b.HandleRequest(context.Background(), req)

	require.NoError(t, err, "Read should not error when no config exists")
	require.Nil(t, resp, "Response should be nil when no config exists")
}

// TestConfigWrite_Success tests writing valid configuration
func TestConfigWrite_Success(t *testing.T) {
	b, storage := getTestBackend(t)

	req := &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "config",
		Storage:   storage,
		Data: map[string]any{
			"issuer":            "https://vault.example.com",
			"signing_key":       testRSAPrivateKey,
			"default_ttl":       "24h",
			"delegate_jwks_uri": "https://vault.example.com/.well-known/jwks.json",
		},
	}

	resp, err := b.HandleRequest(context.Background(), req)

	require.NoError(t, err, "Write should succeed with valid config")
	require.Nil(t, resp, "Write should return nil response on success")

	// Verify config was stored
	entry, err := storage.Get(context.Background(), "config")
	require.NoError(t, err)
	require.NotNil(t, entry, "Config should be stored")
}

// TestConfigWrite_MissingIssuer tests validation of required fields
func TestConfigWrite_MissingIssuer(t *testing.T) {
	b, storage := getTestBackend(t)

	req := &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "config",
		Storage:   storage,
		Data: map[string]any{
			"signing_key": testRSAPrivateKey,
			"default_ttl": "24h",
			// Missing issuer
		},
	}

	resp, err := b.HandleRequest(context.Background(), req)

	require.NoError(t, err, "Handler should not error")
	require.NotNil(t, resp, "Should return error response")
	require.True(t, resp.IsError(), "Response should be an error")
	require.Contains(t, resp.Error().Error(), "issuer", "Error should mention missing issuer")
}

// TestConfigRead_AfterWrite tests reading configuration after writing
func TestConfigRead_AfterWrite(t *testing.T) {
	b, storage := getTestBackend(t)

	// Write config
	writeReq := &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "config",
		Storage:   storage,
		Data: map[string]any{
			"issuer":            "https://vault.example.com",
			"signing_key":       testRSAPrivateKey,
			"default_ttl":       "24h",
			"delegate_jwks_uri": "https://vault.example.com/.well-known/jwks.json",
		},
	}
	_, err := b.HandleRequest(context.Background(), writeReq)
	require.NoError(t, err)

	// Read config
	readReq := &logical.Request{
		Operation: logical.ReadOperation,
		Path:      "config",
		Storage:   storage,
	}
	resp, err := b.HandleRequest(context.Background(), readReq)

	require.NoError(t, err, "Read should succeed")
	require.NotNil(t, resp, "Should return response")
	require.NotNil(t, resp.Data, "Response should have data")
	require.Equal(t, "https://vault.example.com", resp.Data["issuer"])
	require.Equal(t, "24h0m0s", resp.Data["default_ttl"])
	require.Equal(t, "https://vault.example.com/.well-known/jwks.json", resp.Data["delegate_jwks_uri"])
	// Note: signing_key should not be returned (sensitive)
	require.NotContains(t, resp.Data, "signing_key", "Should not return signing key")
}

// TestConfigDelete tests deleting configuration
func TestConfigDelete(t *testing.T) {
	b, storage := getTestBackend(t)

	// Write config first
	writeReq := &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "config",
		Storage:   storage,
		Data: map[string]any{
			"issuer":      "https://vault.example.com",
			"signing_key": testRSAPrivateKey,
			"default_ttl": "24h",
		},
	}
	_, err := b.HandleRequest(context.Background(), writeReq)
	require.NoError(t, err)

	// Delete config
	deleteReq := &logical.Request{
		Operation: logical.DeleteOperation,
		Path:      "config",
		Storage:   storage,
	}
	resp, err := b.HandleRequest(context.Background(), deleteReq)

	require.NoError(t, err, "Delete should succeed")
	require.Nil(t, resp, "Delete should return nil response")

	// Verify config is gone
	entry, err := storage.Get(context.Background(), "config")
	require.NoError(t, err)
	require.Nil(t, entry, "Config should be deleted")
}
