package tokenexchange

import (
	"context"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"strings"
	"time"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
	"gopkg.in/square/go-jose.v2"
	"gopkg.in/square/go-jose.v2/jwt"
)

// pathTokenExchange handles the token exchange request
func (b *Backend) pathTokenExchange(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	// Get role name
	roleName := data.Get("name").(string)

	// Get subject token
	subjectToken, ok := data.GetOk("subject_token")
	if !ok {
		return logical.ErrorResponse("subject_token is required"), nil
	}
	subjectTokenStr := subjectToken.(string)

	// Load role
	role, err := b.getRole(ctx, req.Storage, roleName)
	if err != nil {
		return nil, err
	}
	if role == nil {
		return logical.ErrorResponse("role %q not found", roleName), nil
	}

	// Load config
	config, err := b.getConfig(ctx, req.Storage)
	if err != nil {
		return nil, err
	}
	if config == nil {
		return logical.ErrorResponse("plugin not configured"), nil
	}

	// Parse signing key
	signingKey, err := parsePrivateKey(config.SigningKey)
	if err != nil {
		return nil, fmt.Errorf("failed to parse signing key: %w", err)
	}

	// Validate and parse subject token
	claims, err := validateAndParseClaims(subjectTokenStr, &signingKey.PublicKey)
	if err != nil {
		return logical.ErrorResponse("failed to validate subject token: %v", err), nil
	}

	// Check expiration
	if err := checkExpiration(claims); err != nil {
		return logical.ErrorResponse("subject token expired: %v", err), nil
	}

	// Process template to create additional claims
	templateClaims, err := processTemplate(role.Template, claims)
	if err != nil {
		return nil, fmt.Errorf("failed to process template: %w", err)
	}

	// Generate new token
	newToken, err := generateToken(config, role, claims, templateClaims, signingKey)
	if err != nil {
		return nil, fmt.Errorf("failed to generate token: %w", err)
	}

	return &logical.Response{
		Data: map[string]any{
			"token": newToken,
		},
	}, nil
}

// parsePrivateKey parses a PEM-encoded RSA private key
func parsePrivateKey(pemKey string) (*rsa.PrivateKey, error) {
	block, _ := pem.Decode([]byte(pemKey))
	if block == nil {
		return nil, fmt.Errorf("failed to decode PEM block")
	}

	privateKey, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse private key: %w", err)
	}

	return privateKey, nil
}

// validateAndParseClaims validates the JWT signature and parses claims
func validateAndParseClaims(tokenStr string, publicKey *rsa.PublicKey) (map[string]any, error) {
	// Parse the JWT
	parsedToken, err := jwt.ParseSigned(tokenStr)
	if err != nil {
		return nil, fmt.Errorf("failed to parse JWT: %w", err)
	}

	// Verify signature and extract claims
	claims := make(map[string]any)
	if err := parsedToken.Claims(publicKey, &claims); err != nil {
		return nil, fmt.Errorf("failed to verify signature: %w", err)
	}

	return claims, nil
}

// checkExpiration checks if the token is expired
func checkExpiration(claims map[string]any) error {
	exp, ok := claims["exp"]
	if !ok {
		return fmt.Errorf("token missing exp claim")
	}

	var expTime int64
	switch v := exp.(type) {
	case float64:
		expTime = int64(v)
	case int64:
		expTime = v
	case json.Number:
		expInt, err := v.Int64()
		if err != nil {
			return fmt.Errorf("invalid exp claim format")
		}
		expTime = expInt
	default:
		return fmt.Errorf("invalid exp claim type")
	}

	if time.Now().Unix() > expTime {
		return fmt.Errorf("token expired at %v", time.Unix(expTime, 0))
	}

	return nil
}

// processTemplate processes the role template and returns additional claims
func processTemplate(template string, claims map[string]any) (map[string]any, error) {
	// For scaffold: Simple JSON parsing and basic substitution
	// In a full implementation, this would use a proper template engine

	var templateClaims map[string]any
	if err := json.Unmarshal([]byte(template), &templateClaims); err != nil {
		return nil, fmt.Errorf("failed to parse template: %w", err)
	}

	// Process template substitutions (simple string replacement for scaffold)
	processedClaims := processTemplateSubstitutions(templateClaims, claims)

	return processedClaims, nil
}

// processTemplateSubstitutions performs simple template variable substitution
func processTemplateSubstitutions(template, claims map[string]any) map[string]any {
	result := make(map[string]any)

	for key, value := range template {
		switch v := value.(type) {
		case string:
			// Replace {{.claim.name}} with actual claim values
			processed := v
			for claimKey, claimValue := range claims {
				placeholder := fmt.Sprintf("{{.user.%s}}", claimKey)
				if strings.Contains(processed, placeholder) {
					processed = strings.ReplaceAll(processed, placeholder, fmt.Sprintf("%v", claimValue))
				}
			}
			result[key] = processed
		case map[string]any:
			// Recursively process nested maps
			result[key] = processTemplateSubstitutions(v, claims)
		default:
			result[key] = value
		}
	}

	return result
}

// generateToken generates a new JWT with the merged claims
func generateToken(config *Config, role *Role, originalClaims, templateClaims map[string]any, signingKey *rsa.PrivateKey) (string, error) {
	// Create signer
	signer, err := jose.NewSigner(
		jose.SigningKey{Algorithm: jose.RS256, Key: signingKey},
		(&jose.SignerOptions{}).WithType("JWT"),
	)
	if err != nil {
		return "", fmt.Errorf("failed to create signer: %w", err)
	}

	// Build claims
	now := time.Now()
	claims := make(map[string]any)

	// Standard claims
	claims["iss"] = config.Issuer
	claims["sub"] = originalClaims["sub"] // Subject from original token
	claims["iat"] = now.Unix()
	claims["exp"] = now.Add(role.TTL).Unix()

	// Add audience if present in original token
	if aud, ok := originalClaims["aud"]; ok {
		claims["aud"] = aud
	}

	// Merge template claims
	for key, value := range templateClaims {
		// Don't allow overriding reserved claims
		if key != "iss" && key != "sub" && key != "iat" && key != "exp" && key != "aud" {
			claims[key] = value
		}
	}

	// Build and sign token
	builder := jwt.Signed(signer).Claims(claims)
	token, err := builder.CompactSerialize()
	if err != nil {
		return "", fmt.Errorf("failed to serialize token: %w", err)
	}

	return token, nil
}
