package tokenexchange

import (
	"time"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

// Config represents the plugin configuration stored in Vault
type Config struct {
	// Issuer is the JWT issuer claim (iss) for generated tokens
	Issuer string `json:"issuer"`

	// SigningKey is the PEM-encoded private key for signing JWTs
	SigningKey string `json:"signing_key"`

	// DefaultTTL is the default time-to-live for generated tokens
	DefaultTTL time.Duration `json:"default_ttl"`
}

// Storage key for configuration
const configStoragePath = "config"

// pathConfig returns the path configuration for /config endpoint
func pathConfig(b *Backend) *framework.Path {
	return &framework.Path{
		Pattern: "config",

		ExistenceCheck: b.pathConfigExistenceCheck,

		Fields: map[string]*framework.FieldSchema{
			"issuer": {
				Type:        framework.TypeString,
				Description: "The issuer (iss) claim for generated tokens",
				Required:    true,
			},
			"signing_key": {
				Type:        framework.TypeString,
				Description: "PEM-encoded RSA private key for signing tokens",
				Required:    true,
				DisplayAttrs: &framework.DisplayAttributes{
					Sensitive: true,
				},
			},
			"default_ttl": {
				Type:        framework.TypeDurationSecond,
				Description: "Default TTL for generated tokens (e.g., '24h', '1h')",
				Default:     "24h",
			},
		},

		Operations: map[logical.Operation]framework.OperationHandler{
			logical.ReadOperation: &framework.PathOperation{
				Callback: b.pathConfigRead,
				Summary:  "Read the token exchange plugin configuration",
			},
			logical.UpdateOperation: &framework.PathOperation{
				Callback: b.pathConfigWrite,
				Summary:  "Configure the token exchange plugin",
			},
			logical.CreateOperation: &framework.PathOperation{
				Callback: b.pathConfigWrite,
				Summary:  "Configure the token exchange plugin",
			},
			logical.DeleteOperation: &framework.PathOperation{
				Callback: b.pathConfigDelete,
				Summary:  "Delete the token exchange plugin configuration",
			},
		},

		HelpSynopsis:    "Configure the token exchange plugin",
		HelpDescription: "Configures the issuer, signing keys, and default TTL for token generation.",
	}
}
