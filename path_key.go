package tokenexchange

import (
	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

// pathKey returns path configuration for /key/:name endpoint
func pathKey(b *Backend) *framework.Path {
	return &framework.Path{
		Pattern: "key/" + framework.GenericNameRegex("name"),

		ExistenceCheck: b.pathKeyExistenceCheck,

		Fields: map[string]*framework.FieldSchema{
			"name": {
				Type:        framework.TypeString,
				Description: "Name of the signing key",
				Required:    true,
			},
			"algorithm": {
				Type:        framework.TypeString,
				Description: "Signing algorithm: RS256, RS384, or RS512",
				Default:     AlgorithmRS256,
			},
			"key_size": {
				Type:        framework.TypeInt,
				Description: "RSA key size in bits (2048, 3072, or 4096)",
				Default:     DefaultKeySize,
			},
			"private_key": {
				Type:        framework.TypeString,
				Description: "Optional: Provide your own PEM-encoded RSA private key. If not provided, a key will be generated.",
				DisplayAttrs: &framework.DisplayAttributes{
					Sensitive: true,
				},
			},
		},

		Operations: map[logical.Operation]framework.OperationHandler{
			logical.ReadOperation: &framework.PathOperation{
				Callback: b.pathKeyRead,
				Summary:  "Read a signing key's metadata (private key not returned)",
			},
			logical.UpdateOperation: &framework.PathOperation{
				Callback: b.pathKeyWrite,
				Summary:  "Create or update a signing key",
			},
			logical.CreateOperation: &framework.PathOperation{
				Callback: b.pathKeyWrite,
				Summary:  "Create a new signing key",
			},
			logical.DeleteOperation: &framework.PathOperation{
				Callback: b.pathKeyDelete,
				Summary:  "Delete a signing key",
			},
		},

		HelpSynopsis:    "Manage named signing keys for token generation",
		HelpDescription: "Create, read, and delete RSA signing keys. Keys can be auto-generated or provided. The private key is never returned in read operations.",
	}
}

// pathKeyList returns path configuration for /key endpoint (list)
func pathKeyList(b *Backend) *framework.Path {
	return &framework.Path{
		Pattern: "key/?$",

		Operations: map[logical.Operation]framework.OperationHandler{
			logical.ListOperation: &framework.PathOperation{
				Callback: b.pathKeyList,
				Summary:  "List all signing keys",
			},
		},

		HelpSynopsis:    "List signing keys",
		HelpDescription: "List all configured signing keys with metadata.",
	}
}
