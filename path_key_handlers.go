package tokenexchange

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"time"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

// pathKeyExistenceCheck checks if a key exists
func (b *Backend) pathKeyExistenceCheck(ctx context.Context, req *logical.Request, data *framework.FieldData) (bool, error) {
	name := data.Get("name").(string)
	key, err := b.getKey(ctx, req.Storage, name)
	if err != nil {
		return false, err
	}
	return key != nil, nil
}

// pathKeyRead handles reading a key's metadata
func (b *Backend) pathKeyRead(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	name := data.Get("name").(string)

	key, err := b.getKey(ctx, req.Storage, name)
	if err != nil {
		return nil, err
	}

	if key == nil {
		return nil, nil
	}

	// Extract public key for response
	publicKey, err := publicKeyFromPrivate(key.PrivateKey)
	if err != nil {
		return nil, fmt.Errorf("failed to extract public key: %w", err)
	}

	// Encode public key to PEM
	pubKeyBytes := x509.MarshalPKCS1PublicKey(publicKey)
	pubKeyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PUBLIC KEY",
		Bytes: pubKeyBytes,
	})

	return &logical.Response{
		Data: map[string]any{
			"name":       key.Name,
			"key_id":     key.KeyID,
			"algorithm":  key.Algorithm,
			"public_key": string(pubKeyPEM),
			"created_at": key.CreatedAt.Format(time.RFC3339),
			"rotated_at": key.RotatedAt.Format(time.RFC3339),
			"version":    key.Version,
			// Note: private_key is NEVER returned
		},
	}, nil
}

// pathKeyWrite handles creating or updating a key
func (b *Backend) pathKeyWrite(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	name := data.Get("name").(string)

	// Check if key already exists
	existingKey, err := b.getKey(ctx, req.Storage, name)
	if err != nil {
		return nil, err
	}

	if existingKey != nil {
		return logical.ErrorResponse("key %q already exists. To rotate, use POST /key/%s/rotate", name, name), nil
	}

	// Get algorithm
	algorithm := data.Get("algorithm").(string)
	if algorithm != AlgorithmRS256 && algorithm != AlgorithmRS384 && algorithm != AlgorithmRS512 {
		return logical.ErrorResponse("algorithm must be RS256, RS384, or RS512"), nil
	}

	// Generate new key
	keySize := data.Get("key_size").(int)
	if keySize != 2048 && keySize != 3072 && keySize != 4096 {
		return logical.ErrorResponse("key_size must be 2048, 3072, or 4096"), nil
	}

	privateKey, err := generateRSAKey(keySize)
	if err != nil {
		return nil, fmt.Errorf("failed to generate RSA key: %w", err)
	}

	privateKeyPEM := encodePrivateKeyPEM(privateKey)

	// Create key object
	now := time.Now()
	key := &Key{
		Name:       name,
		KeyID:      generateKeyID(name, 1), // Version 1
		Algorithm:  algorithm,
		PrivateKey: privateKeyPEM,
		CreatedAt:  now,
		RotatedAt:  now,
		Version:    1,
	}

	// Store key
	entry, err := logical.StorageEntryJSON(keyStoragePrefix+name, key)
	if err != nil {
		return nil, fmt.Errorf("failed to create storage entry: %w", err)
	}

	if err := req.Storage.Put(ctx, entry); err != nil {
		return nil, fmt.Errorf("failed to write key: %w", err)
	}

	return &logical.Response{
		Data: map[string]any{
			"name":    key.Name,
			"key_id":  key.KeyID,
			"version": key.Version,
		},
	}, nil
}

// pathKeyDelete handles deleting a key
func (b *Backend) pathKeyDelete(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	name := data.Get("name").(string)

	// Check if any roles use this key (Phase 2 addition)
	// For now, just delete

	if err := req.Storage.Delete(ctx, keyStoragePrefix+name); err != nil {
		return nil, fmt.Errorf("failed to delete key: %w", err)
	}

	return nil, nil
}

// pathKeyList handles listing all keys
func (b *Backend) pathKeyList(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	keys, err := req.Storage.List(ctx, keyStoragePrefix)
	if err != nil {
		return nil, fmt.Errorf("failed to list keys: %w", err)
	}

	if len(keys) == 0 {
		return nil, nil
	}

	return logical.ListResponse(keys), nil
}

// getKey retrieves a key from storage (helper)
func (b *Backend) getKey(ctx context.Context, storage logical.Storage, name string) (*Key, error) {
	entry, err := storage.Get(ctx, keyStoragePrefix+name)
	if err != nil {
		return nil, fmt.Errorf("failed to read key: %w", err)
	}

	if entry == nil {
		return nil, nil
	}

	key := &Key{}
	if err := entry.DecodeJSON(key); err != nil {
		return nil, fmt.Errorf("failed to decode key: %w", err)
	}

	return key, nil
}
