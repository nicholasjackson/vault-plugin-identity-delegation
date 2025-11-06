package tokenexchange

import (
	"time"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

// Role represents a token exchange role configuration
type Role struct {
	Name            string        `json:"name"`
	TTL             time.Duration `json:"ttl"`
	BoundAudiences  []string      `json:"bound_audiences"`
	BoundIssuer     string        `json:"bound_issuer"`
	ActorTemplate   string        `json:"actor_template"`
	SubjectTemplate string        `json:"subject_template"`
	Context         []string      `json:"context"`
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
			"bound_audiences": {
				Type:        framework.TypeCommaStringSlice,
				Description: "Comma-separated list of valid audiences for the subject token",
			},
			"bound_issuer": {
				Type:        framework.TypeString,
				Description: "Required issuer for the subject token",
			},
			"actor_template": {
				Type:        framework.TypeString,
				Description: "JSON template for actor-related claims (RFC 8693). Should include 'act' claim with actor identity. Optional 'actor_metadata' for additional actor context. Example: {\"act\": {\"sub\": \"{{identity.entity.id}}\"}, \"actor_metadata\": {\"department\": \"IT\"}}",
				Required:    true,
			},
			"subject_template": {
				Type:        framework.TypeString,
				Description: "JSON template for additional claims in the generated token, claims are added under 'subject_claims' key",
				Required:    true,
			},
			"context": {
				Type:        framework.TypeCommaStringSlice,
				Description: "List of permitted scopes for the delegated token (RFC 8693). Maps to 'scope' claim as space-delimited string. Example: 'urn:documents.service:read,urn:images.service:write' becomes 'urn:documents.service:read urn:images.service:write'",
				Required:    true,
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
