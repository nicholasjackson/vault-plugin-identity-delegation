package tokenexchange

import (
	"context"
	"fmt"
	"time"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

// pathConfigExistenceCheck checks if the config exists
func (b *Backend) pathConfigExistenceCheck(ctx context.Context, req *logical.Request, data *framework.FieldData) (bool, error) {
	config, err := b.getConfig(ctx, req.Storage)
	if err != nil {
		return false, err
	}

	return config != nil, nil
}

// pathConfigRead handles reading the configuration
func (b *Backend) pathConfigRead(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	config, err := b.getConfig(ctx, req.Storage)
	if err != nil {
		return nil, err
	}

	if config == nil {
		return nil, nil
	}

	return &logical.Response{
		Data: map[string]any{
			"issuer":           config.Issuer,
			"default_ttl":      config.DefaultTTL.String(),
			"subject_jwks_uri": config.SubjectJWKSURI,
			// Note: Do NOT return signing_key (sensitive)
		},
	}, nil
}

// pathConfigWrite handles writing the configuration
func (b *Backend) pathConfigWrite(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	config := &Config{}

	// Get issuer (required)
	issuer, ok := data.GetOk("issuer")
	if !ok {
		return logical.ErrorResponse("issuer is required"), nil
	}
	config.Issuer = issuer.(string)

	// Get signing key (required)
	signingKey, ok := data.GetOk("signing_key")
	if !ok {
		return logical.ErrorResponse("signing_key is required"), nil
	}
	config.SigningKey = signingKey.(string)

	// Validate signing key is valid PEM
	// (TODO: Add actual PEM validation in future - keep simple for scaffold)

	// Get default TTL (optional, has default)
	if ttl, ok := data.GetOk("default_ttl"); ok {
		config.DefaultTTL = time.Duration(ttl.(int)) * time.Second
	} else {
		config.DefaultTTL = 24 * time.Hour // Default
	}

	// Get subject_jwks_uri (required)
	if subjectJWKSURI, ok := data.GetOk("subject_jwks_uri"); ok {
		config.SubjectJWKSURI = subjectJWKSURI.(string)
	}

	// Store configuration
	entry, err := logical.StorageEntryJSON(configStoragePath, config)
	if err != nil {
		return nil, fmt.Errorf("failed to create storage entry: %w", err)
	}

	if err := req.Storage.Put(ctx, entry); err != nil {
		return nil, fmt.Errorf("failed to write configuration: %w", err)
	}

	return nil, nil
}

// pathConfigDelete handles deleting the configuration
func (b *Backend) pathConfigDelete(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	if err := req.Storage.Delete(ctx, configStoragePath); err != nil {
		return nil, fmt.Errorf("failed to delete configuration: %w", err)
	}

	return nil, nil
}

// getConfig retrieves the configuration from storage
func (b *Backend) getConfig(ctx context.Context, storage logical.Storage) (*Config, error) {
	entry, err := storage.Get(ctx, configStoragePath)
	if err != nil {
		return nil, fmt.Errorf("failed to read configuration: %w", err)
	}

	if entry == nil {
		return nil, nil
	}

	config := &Config{}
	if err := entry.DecodeJSON(config); err != nil {
		return nil, fmt.Errorf("failed to decode configuration: %w", err)
	}

	return config, nil
}
