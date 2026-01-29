package tokenexchange

import (
	"context"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"html"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
	"github.com/hoisie/mustache"
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

	// Load config (needed for issuer and subject_jwks_uri)
	config, err := b.getConfig(ctx, req.Storage)
	if err != nil {
		return nil, err
	}
	if config == nil {
		return logical.ErrorResponse("plugin not configured"), nil
	}

	// Load role-specified key (required)
	key, err := b.getKey(ctx, req.Storage, role.Key)
	if err != nil {
		return nil, fmt.Errorf("failed to load key %q: %w", role.Key, err)
	}
	if key == nil {
		return logical.ErrorResponse("key %q not found", role.Key), nil
	}

	// Parse private key
	signingKey, err := parsePrivateKey(key.PrivateKey)
	if err != nil {
		return nil, fmt.Errorf("failed to parse signing key: %w", err)
	}

	keyID := key.KeyID

	// Map algorithm string to jose constant
	var algorithm jose.SignatureAlgorithm
	switch key.Algorithm {
	case AlgorithmRS256:
		algorithm = jose.RS256
	case AlgorithmRS384:
		algorithm = jose.RS384
	case AlgorithmRS512:
		algorithm = jose.RS512
	default:
		return nil, fmt.Errorf("unsupported algorithm: %s", key.Algorithm)
	}

	// Validate and parse subject token
	originalSubjectClaims, err := validateAndParseClaims(subjectTokenStr, config.SubjectJWKSURI)
	if err != nil {
		return logical.ErrorResponse("failed to validate subject token: %v", err), nil
	}

	// Check expiration
	if err := checkExpiration(originalSubjectClaims); err != nil {
		return logical.ErrorResponse("subject token expired: %v", err), nil
	}

	// Validate bound issuer
	if err := validateBoundIssuer(originalSubjectClaims, role.BoundIssuer); err != nil {
		return logical.ErrorResponse("failed to validate issuer: %v", err), nil
	}

	// Validate bound audiences
	if err := validateBoundAudiences(originalSubjectClaims, role.BoundAudiences); err != nil {
		return logical.ErrorResponse("failed to validate audience: %v", err), nil
	}

	// Fetch entity
	b.Logger().Info("Get EntityID", "entity_id", req.EntityID)
	entity, err := fetchEntity(req, b.System())
	if err != nil {
		return nil, err
	}

	// Process template to create additional claims
	im := map[string]any{
		"identity": map[string]map[string]any{
			"entity": {
				"id":           entity.ID,
				"name":         entity.Name,
				"namespace_id": entity.NamespaceID,
				"metadata":     entity.Metadata,
			},
		},
	}

	actorClaims, err := processTemplate(role.ActorTemplate, im)
	if err != nil {
		return nil, fmt.Errorf("failed to process template: %w", err)
	}

	sm := map[string]any{
		"identity": map[string]map[string]any{
			"subject": originalSubjectClaims,
		},
	}

	subjectClaims, err := processTemplate(role.SubjectTemplate, sm)
	if err != nil {
		return nil, fmt.Errorf("failed to process template: %w", err)
	}

	// Generate new token with keyID
	newToken, err := generateToken(config, role, originalSubjectClaims["sub"].(string), actorClaims, subjectClaims, signingKey, keyID, algorithm, req.EntityID)
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

	switch block.Type {
	case "RSA PRIVATE KEY":
		privateKey, err := x509.ParsePKCS1PrivateKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("failed to parse private key: %w", err)
		}
		return privateKey, nil
	case "PRIVATE KEY":
		privateKey, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("failed to parse private key: %w", err)
		}
		return privateKey.(*rsa.PrivateKey), nil
	default:
		return nil, fmt.Errorf("unsupported signing key: %s", block.Type)
	}
}

// validateAndParseClaims validates the JWT signature and parses claims
func validateAndParseClaims(tokenStr string, jwksURI string) (map[string]any, error) {
	// fetch JWKS
	// TODO: Cache JWKS for performance
	jwks, err := fetchJWKS(jwksURI)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch JWKS: %w", err)
	}

	// Parse the JWT
	parsedToken, err := jwt.ParseSigned(tokenStr, []jose.SignatureAlgorithm{jose.RS256})
	if err != nil {
		return nil, fmt.Errorf("failed to parse JWT: %w", err)
	}

	// Find the key id from the token header
	kid := parsedToken.Headers[0].KeyID
	key := jwks.Key(kid)
	if len(key) == 0 {
		return nil, fmt.Errorf("key not found in JWKS, kid: %s, jwks: %s", kid, jwksURI)
	}

	// Verify signature and extract claims
	claims := make(map[string]any)
	if err := parsedToken.Claims(key[0], &claims); err != nil {
		return nil, fmt.Errorf("failed to verify signature: %w", err)
	}

	return claims, nil
}

func fetchJWKS(url string) (*jose.JSONWebKeySet, error) {
	resp, err := http.Get(url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("failed to fetch jwks: %s, status %d", url, resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("unable to read response from jwks, %s", err)
	}

	var jwks jose.JSONWebKeySet
	if err := json.Unmarshal(body, &jwks); err != nil {
		return nil, err
	}

	return &jwks, nil
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

// validateBoundIssuer checks if the token issuer matches the role's bound issuer
func validateBoundIssuer(claims map[string]any, boundIssuer string) error {
	if boundIssuer == "" {
		return nil // No bound issuer configured, skip validation
	}

	iss, ok := claims["iss"]
	if !ok {
		return fmt.Errorf("token missing iss claim")
	}

	issStr, ok := iss.(string)
	if !ok {
		return fmt.Errorf("invalid iss claim type")
	}

	if issStr != boundIssuer {
		return fmt.Errorf("token issuer %q does not match bound_issuer %q", issStr, boundIssuer)
	}

	return nil
}

// validateBoundAudiences checks if the token audience matches any of the role's bound audiences
func validateBoundAudiences(claims map[string]any, boundAudiences []string) error {
	if len(boundAudiences) == 0 {
		return nil // No bound audiences configured, skip validation
	}

	aud, ok := claims["aud"]
	if !ok {
		return fmt.Errorf("token missing aud claim")
	}

	// JWT aud claim can be string or []string
	var tokenAudiences []string
	switch v := aud.(type) {
	case string:
		tokenAudiences = []string{v}
	case []interface{}:
		for _, audVal := range v {
			if audStr, ok := audVal.(string); ok {
				tokenAudiences = append(tokenAudiences, audStr)
			}
		}
	case []string:
		tokenAudiences = v
	default:
		return fmt.Errorf("invalid aud claim type")
	}

	// Check if any token audience matches any bound audience
	for _, tokenAud := range tokenAudiences {
		for _, boundAud := range boundAudiences {
			if tokenAud == boundAud {
				return nil // Match found
			}
		}
	}

	return fmt.Errorf("token audience does not match any bound_audiences")
}

// fetchEntity retrieves the entity associated with the request
func fetchEntity(req *logical.Request, system logical.SystemView) (*logical.Entity, error) {
	entityID := req.EntityID
	if entityID == "" {
		return nil, fmt.Errorf("no entity ID in request")
	}

	entity, err := system.EntityInfo(entityID)
	if err != nil {
		return nil, fmt.Errorf("failed to get entity info: %w", err)
	}

	return entity, nil
}

// jsonifyClaimsMap recursively walks a claims map and converts any slice or
// nested map values into their JSON string representation. This ensures that
// when mustache renders {{some.array.claim}}, it produces valid JSON (e.g.
// ["read:customers","write:customers"]) instead of Go's default fmt.Sprint
// format ([read:customers write:customers]).
func jsonifyClaimsMap(m map[string]any) map[string]any {
	out := make(map[string]any, len(m))
	for k, v := range m {
		out[k] = jsonifyValue(v)
	}
	return out
}

func jsonifyValue(v any) any {
	switch val := v.(type) {
	case map[string]any:
		return jsonifyClaimsMap(val)
	case map[string]map[string]any:
		out := make(map[string]any, len(val))
		for k, inner := range val {
			out[k] = jsonifyClaimsMap(inner)
		}
		return out
	case []any:
		b, err := json.Marshal(val)
		if err != nil {
			return v
		}
		return string(b)
	case []string:
		b, err := json.Marshal(val)
		if err != nil {
			return v
		}
		return string(b)
	default:
		return v
	}
}

// processTemplate processes the role template and returns additional claims
func processTemplate(template string, claims map[string]any) (map[string]any, error) {
	tmpl, err := mustache.ParseString(template)
	if err != nil {
		return nil, fmt.Errorf("failed to parse template: %w", err)
	}

	// Pre-process claims to JSON-serialize non-scalar values (slices, maps)
	// so mustache renders them as valid JSON rather than Go's default format
	jsonClaims := jsonifyClaimsMap(claims)

	// Mustache HTML-escapes {{var}} output by default (e.g. " becomes &quot;).
	// Since templates produce JSON (not HTML), unescape the rendered output.
	mo := html.UnescapeString(tmpl.Render(jsonClaims))

	// parse the string as json and return as a map
	ret := map[string]any{}
	err = json.Unmarshal([]byte(mo), &ret)
	if err != nil {
		return nil, fmt.Errorf("unable to process template: %s", err)
	}

	return ret, nil
}

// generateToken generates a new JWT with the merged claims
func generateToken(config *Config, role *Role, subjectID string, actorClaims, subjectClaims map[string]any, signingKey *rsa.PrivateKey, keyID string, algorithm jose.SignatureAlgorithm, entityID string) (string, error) {
	// Create signer with kid in header
	signerOpts := (&jose.SignerOptions{}).WithType("JWT")

	if keyID != "" {
		signerOpts = signerOpts.WithHeader("kid", keyID) // NEW: include kid
	}

	signer, err := jose.NewSigner(
		jose.SigningKey{Algorithm: algorithm, Key: signingKey}, // Use role's algorithm
		signerOpts,
	)
	if err != nil {
		return "", fmt.Errorf("failed to create signer: %w", err)
	}

	// Build claims
	now := time.Now()
	claims := make(map[string]any)

	// Standard claims
	claims["iss"] = config.Issuer
	claims["sub"] = subjectID // Subject from the original user token
	claims["iat"] = now.Unix()
	claims["exp"] = now.Add(role.TTL).Unix()

	// Add audience if present
	if aud, ok := actorClaims["aud"]; ok {
		claims["aud"] = aud
	}

	// Add RFC 8693 actor claim (delegation)
	// The act claim contains ONLY the actor's identity (sub, iss)
	actorSubject := ""

	// Check if actor_template provided act.sub
	if actClaimRaw, ok := actorClaims["act"]; ok {
		if actClaimMap, ok := actClaimRaw.(map[string]any); ok {
			if sub, ok := actClaimMap["sub"].(string); ok {
				actorSubject = sub
			}
		}
	}

	// If no actor subject in template, construct from entity ID
	if actorSubject == "" {
		actorSubject = fmt.Sprintf("entity:%s", entityID)
	}

	claims["act"] = map[string]any{
		"sub": actorSubject,
		"iss": config.Issuer, // Optional: issuer of actor identity
	}

	// Add RFC 8693 scope claim (space-delimited)
	if len(role.Context) > 0 {
		claims["scope"] = strings.Join(role.Context, " ")
	}

	// Add subject claims under "subject_claims" key (optional extension)
	if len(subjectClaims) > 0 {
		claims["subject_claims"] = subjectClaims
	}

	// Merge actor claims for optional extensions (e.g., actor_metadata)
	// This allows templates to add custom actor metadata outside the act claim
	for key, value := range actorClaims {
		// Don't allow overriding reserved claims or act claim
		if key != "iss" && key != "sub" && key != "iat" && key != "exp" && key != "aud" && key != "act" {
			claims[key] = value
		}
	}

	// Build and sign token
	builder := jwt.Signed(signer).Claims(claims)
	token, err := builder.Serialize()
	if err != nil {
		return "", fmt.Errorf("failed to serialize token: %w", err)
	}

	return token, nil
}
