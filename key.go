package tokenexchange

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"time"
)

// Key represents a named signing key
type Key struct {
	Name       string    `json:"name"`        // Key name (e.g., "prod-key")
	KeyID      string    `json:"key_id"`      // Unique identifier (kid)
	Algorithm  string    `json:"algorithm"`   // RS256, RS384, or RS512
	PrivateKey string    `json:"private_key"` // PEM-encoded RSA private key
	CreatedAt  time.Time `json:"created_at"`  // Creation timestamp
	RotatedAt  time.Time `json:"rotated_at"`  // Last rotation timestamp
	Version    int       `json:"version"`     // Key version (increments on rotation)
}

const (
	keyStoragePrefix = "keys/"

	// Supported algorithms
	AlgorithmRS256 = "RS256"
	AlgorithmRS384 = "RS384"
	AlgorithmRS512 = "RS512"

	// Default RSA key size
	DefaultKeySize = 2048
)

// generateKeyID creates a unique key ID
func generateKeyID(name string, version int) string {
	return fmt.Sprintf("%s-v%d", name, version)
}

// generateRSAKey generates a new RSA private key
func generateRSAKey(bits int) (*rsa.PrivateKey, error) {
	return rsa.GenerateKey(rand.Reader, bits)
}

// encodePrivateKeyPEM encodes RSA private key to PEM format
func encodePrivateKeyPEM(key *rsa.PrivateKey) string {
	keyBytes := x509.MarshalPKCS1PrivateKey(key)
	block := &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: keyBytes,
	}
	return string(pem.EncodeToMemory(block))
}

// publicKeyFromPrivate extracts public key from private key
func publicKeyFromPrivate(privateKeyPEM string) (*rsa.PublicKey, error) {
	privateKey, err := parsePrivateKey(privateKeyPEM)
	if err != nil {
		return nil, err
	}
	return &privateKey.PublicKey, nil
}
