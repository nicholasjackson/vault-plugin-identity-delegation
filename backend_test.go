package tokenexchange

import (
	"context"
	"testing"

	"github.com/hashicorp/go-hclog"
	"github.com/hashicorp/vault/sdk/logical"
	"github.com/stretchr/testify/require"
)

// TestBackendFactory tests that the Factory function creates a valid backend
func TestBackendFactory(t *testing.T) {
	config := &logical.BackendConfig{
		Logger:      hclog.NewNullLogger(),
		System:      &logical.StaticSystemView{},
		StorageView: &logical.InmemStorage{},
	}

	backend, err := Factory(context.Background(), config)

	require.NoError(t, err, "Factory should not return an error")
	require.NotNil(t, backend, "Factory should return a non-nil backend")
}

// TestBackendFactory_NilConfig tests error handling for nil config
func TestBackendFactory_NilConfig(t *testing.T) {
	_, err := Factory(context.Background(), nil)

	require.Error(t, err, "Factory should return error for nil config")
	require.Contains(t, err.Error(), "config", "Error should mention config")
}

// TestBackend_PathsRegistered tests that expected paths are registered
func TestBackend_PathsRegistered(t *testing.T) {
	b := NewBackend()

	require.NotNil(t, b.Backend.Paths, "Backend should have paths")
	require.NotEmpty(t, b.Backend.Paths, "Backend should register at least one path")

	// Check for expected path patterns
	pathPatterns := make([]string, 0, len(b.Backend.Paths))
	for _, path := range b.Backend.Paths {
		pathPatterns = append(pathPatterns, path.Pattern)
	}

	require.Contains(t, pathPatterns, "config", "Should register config path")
}

// TestBackend_Type tests that backend identifies as correct type
func TestBackend_Type(t *testing.T) {
	b := NewBackend()

	require.Equal(t, logical.TypeLogical, b.BackendType, "Should be TypeLogical (secrets engine)")
}

// TestBackend_Help tests that backend provides help text
func TestBackend_Help(t *testing.T) {
	b := NewBackend()

	require.NotEmpty(t, b.Help, "Backend should provide help text")
	require.Contains(t, b.Help, "token exchange", "Help should mention token exchange")
}
