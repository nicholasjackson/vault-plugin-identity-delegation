package tokenexchange

import (
	"time"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

// Role represents a token exchange role configuration
type Role struct {
	Name           string        `json:"name"`
	TTL            time.Duration `json:"ttl"`
	Template       string        `json:"template"`
	BoundAudiences []string      `json:"bound_audiences"`
	BoundIssuer    string        `json:"bound_issuer"`
}

const roleStoragePrefix = "roles/"

// pathRole returns the path configuration for /role/:name endpoint
func pathRole(b *Backend) *framework.Path {
	return &framework.Path{
		Pattern: "role/" + framework.GenericNameRegex("name"),

		ExistenceCheck: b.pathRoleExistenceCheck,

		Fields: map[string]*framework.FieldSchema{
			"name": {
				Type:        framework.TypeString,
				Description: "Name of the role",
				Required:    true,
			},
			"ttl": {
				Type:        framework.TypeDurationSecond,
				Description: "TTL for tokens generated with this role",
				Required:    true,
			},
			"template": {
				Type:        framework.TypeString,
				Description: "JSON template for additional claims in the generated token",
				Required:    true,
			},
			"bound_audiences": {
				Type:        framework.TypeCommaStringSlice,
				Description: "Comma-separated list of valid audiences for the subject token",
			},
			"bound_issuer": {
				Type:        framework.TypeString,
				Description: "Required issuer for the subject token",
			},
		},

		Operations: map[logical.Operation]framework.OperationHandler{
			logical.ReadOperation: &framework.PathOperation{
				Callback: b.pathRoleRead,
				Summary:  "Read a token exchange role",
			},
			logical.UpdateOperation: &framework.PathOperation{
				Callback: b.pathRoleWrite,
				Summary:  "Create or update a token exchange role",
			},
			logical.CreateOperation: &framework.PathOperation{
				Callback: b.pathRoleWrite,
				Summary:  "Create a token exchange role",
			},
			logical.DeleteOperation: &framework.PathOperation{
				Callback: b.pathRoleDelete,
				Summary:  "Delete a token exchange role",
			},
		},

		HelpSynopsis:    "Manage token exchange roles",
		HelpDescription: "Create, read, update, and delete token exchange roles that define how tokens are generated.",
	}
}

// pathRoleList returns the path configuration for /role endpoint (list)
func pathRoleList(b *Backend) *framework.Path {
	return &framework.Path{
		Pattern: "role/?$",

		Operations: map[logical.Operation]framework.OperationHandler{
			logical.ListOperation: &framework.PathOperation{
				Callback: b.pathRoleList,
				Summary:  "List all token exchange roles",
			},
		},

		HelpSynopsis:    "List token exchange roles",
		HelpDescription: "List all configured token exchange roles.",
	}
}
