package tokenexchange

import (
	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

// pathToken returns the path configuration for /token/:name endpoint
func pathToken(b *Backend) *framework.Path {
	return &framework.Path{
		Pattern: "token/" + framework.GenericNameRegex("name"),

		Fields: map[string]*framework.FieldSchema{
			"name": {
				Type:        framework.TypeString,
				Description: "Name of the role to use for token exchange",
				Required:    true,
			},
			"subject_token": {
				Type:        framework.TypeString,
				Description: "The subject token (JWT) to exchange",
				Required:    true,
			},
		},

		Operations: map[logical.Operation]framework.OperationHandler{
			logical.UpdateOperation: &framework.PathOperation{
				Callback: b.pathTokenExchange,
				Summary:  "Exchange a subject token for a new token with delegated claims",
			},
		},

		HelpSynopsis:    "Exchange tokens using a configured role",
		HelpDescription: "Accepts a subject token (JWT) and generates a new token with claims from the role template.",
	}
}
