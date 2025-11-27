package tokenexchange

import (
	"context"
	"fmt"
	"sync"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

// Backend implements the logical.Backend interface for token exchange
type Backend struct {
	*framework.Backend

	// lock protects access to backend fields
	lock sync.RWMutex
}

// Factory creates a new Backend instance
func Factory(ctx context.Context, conf *logical.BackendConfig) (logical.Backend, error) {
	if conf == nil {
		return nil, fmt.Errorf("configuration passed into backend is nil")
	}

	b := NewBackend()

	if err := b.Setup(ctx, conf); err != nil {
		return nil, err
	}

	return b, nil
}

// NewBackend creates a new Backend with paths and configuration
func NewBackend() *Backend {
	b := &Backend{}

	b.Backend = &framework.Backend{
		Help: "The token exchange plugin implements OAuth 2.0 Token Exchange (RFC 8693) " +
			"for 'on behalf of' scenarios. It accepts existing OIDC tokens and generates " +
			"new JWTs with delegated authority claims.",

		// Register all path handlers
		Paths: []*framework.Path{
			pathConfig(b),
			pathRole(b),
			pathRoleList(b),
			pathToken(b),
			pathKey(b),     // New: key CRUD
			pathKeyList(b), // New: key listing
			pathJWKS(b),    // New: JWKS endpoint
		},

		// Define paths that should be encrypted in storage
		PathsSpecial: &logical.Paths{
			SealWrapStorage: []string{
				"config",  // Config contains signing keys
				"roles/*", // Roles may contain sensitive templates
				"keys/*",  // Named keys contain private keys (NEW)
			},
			Unauthenticated: []string{
				"jwks",    // JWKS endpoint must be publicly accessible for JWT verification
			},
		},

		// Secrets: Not used for this plugin (generates tokens, doesn't manage secrets)
		// InvalidateFunc: Not needed initially

		BackendType: logical.TypeLogical,
	}

	return b
}
