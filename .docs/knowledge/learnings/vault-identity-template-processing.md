# Vault Identity OIDC Template Processing

Date: 2025-11-04

## Overview

This document explains how HashiCorp Vault's identity endpoint processes templates for OIDC token generation. This information is based on research of the Vault source code and is useful for implementing similar templating functionality in custom plugins.

## Templating Package

**Package**: Vault uses a **custom template engine**, not Go's standard text/template or html/template packages.

- **Import Path**: `github.com/hashicorp/vault/sdk/helper/identitytpl`
- **Source File**: `vault/sdk/helper/identitytpl/templating.go`
- **Main Entry Point**: `identitytpl.PopulateString()`

### Key Imports

```go
import (
    "encoding/json"
    "strconv"
    "strings"
    "time"

    "github.com/hashicorp/vault/sdk/logical"
)
```

## Template Syntax

### Delimiter Syntax

Templates use double curly braces as delimiters: `{{` and `}}`

### Template Modes

The system supports two processing modes:

1. **`ACLTemplating`** (mode 0): For policy paths - returns strings verbatim, no JSON formatting
2. **`JSONTemplating`** (mode 1): For OIDC tokens - wraps strings in quotes, marshals arrays/maps as JSON

### Template Encoding

Templates can be provided as:
- Plain JSON string
- Base64-encoded string (common in CLI usage)

Example from integration test:
```bash
vault write identity/oidc/role/user \
  key="user-key" \
  template="$(echo ${TEMPLATE} | base64)" \
  ttl=3600
```

## How Templates Are Processed

### Processing Flow

1. **Split on delimiters**: String is split by `{{` markers
2. **Extract template variables**: Content between `{{` and `}}` is extracted
3. **Route to handlers**: Based on prefix (`identity.entity.`, `identity.groups.`, `time.`)
4. **Resolve values**: Looks up values from Entity/Groups data structures
5. **Format output**: Mode-specific handler formats the result (quoted strings for JSON, raw for ACL)
6. **Merge results**: Populated template is merged with base claims

### Main Entry Point

```go
_, populatedTemplate, err := identitytpl.PopulateString(
    identitytpl.PopulateStringInput{
        Mode:        identitytpl.JSONTemplating,
        String:      role.Template,
        Entity:      identity.ToSDKEntity(e),
        Groups:      identity.ToSDKGroups(groups),
        NamespaceID: ns.ID,
    })
```

### Context Provided

- **Entity**: `*logical.Entity` containing ID, Name, Metadata, Aliases
- **Groups**: `[]*logical.Group` containing group memberships
- **NamespaceID**: Current namespace context
- **Now**: Optional timestamp (defaults to `time.Now()`)

## Available Template Variables

### Identity Entity Templates (`identity.entity.*`)

#### Basic Fields

```
{{identity.entity.id}}              - Entity's unique identifier
{{identity.entity.name}}            - Entity's display name
{{identity.entity.metadata}}        - Complete metadata map (JSON mode only)
{{identity.entity.metadata.<key>}}  - Specific metadata value
```

#### Group Membership

```
{{identity.entity.groups.names}}    - Array of group names
{{identity.entity.groups.ids}}      - Array of group IDs
```

#### Alias Fields

Requires mount accessor to identify which auth method's alias to use:

```
{{identity.entity.aliases.<mount_accessor>.id}}                     - Alias ID
{{identity.entity.aliases.<mount_accessor>.name}}                   - Alias name (username)
{{identity.entity.aliases.<mount_accessor>.metadata}}               - Complete alias metadata
{{identity.entity.aliases.<mount_accessor>.metadata.<key>}}         - Specific alias metadata
{{identity.entity.aliases.<mount_accessor>.custom_metadata}}        - Complete custom metadata
{{identity.entity.aliases.<mount_accessor>.custom_metadata.<key>}}  - Specific custom metadata
```

#### Implementation Reference

From `performEntityTemplating()` function in `templating.go`:

```go
switch {
case trimmed == "id":
    return p.templateHandler(p.Entity.ID)

case trimmed == "name":
    return p.templateHandler(p.Entity.Name)

case trimmed == "metadata":
    return p.templateHandler(p.Entity.Metadata)

case strings.HasPrefix(trimmed, "metadata."):
    split := strings.SplitN(trimmed, ".", 2)
    return p.templateHandler(p.Entity.Metadata, split[1])

case trimmed == "groups.names":
    return p.templateHandler(p.groupNames)

case trimmed == "groups.ids":
    return p.templateHandler(p.groupIDs)

case strings.HasPrefix(trimmed, "aliases."):
    // Alias resolution logic...
}
```

### Identity Groups Templates (`identity.groups.*`)

#### Access by Group Name

```
{{identity.groups.names.<group_name>.id}}              - Group ID
{{identity.groups.names.<group_name>.name}}            - Group name
{{identity.groups.names.<group_name>.metadata.<key>}}  - Group metadata value
```

#### Access by Group ID

```
{{identity.groups.ids.<group_id>.name}}                - Group name
{{identity.groups.ids.<group_id>.metadata.<key>}}      - Group metadata value
```

#### Implementation Reference

From `performGroupsTemplating()` function:

```go
switch {
case trimmed == "id":
    return found.ID, nil

case trimmed == "name":
    if found.Name == "" {
        return "", ErrTemplateValueNotFound
    }
    return found.Name, nil

case strings.HasPrefix(trimmed, "metadata."):
    val, ok := found.Metadata[strings.TrimPrefix(trimmed, "metadata.")]
    if !ok {
        return "", ErrTemplateValueNotFound
    }
    return val, nil
}
```

### Time Templates (`time.*`)

```
{{time.now}}                       - Current Unix timestamp
{{time.now.plus.<duration>}}       - Future timestamp (e.g., 5h, 30m, 1d)
{{time.now.minus.<duration>}}      - Past timestamp
```

#### Implementation Reference

From `performTimeTemplating()` function:

```go
func performTimeTemplating(trimmed string) (string, error) {
    now := p.Now
    if now.IsZero() {
        now = time.Now()
    }

    opsSplit := strings.SplitN(trimmed, ".", 3)

    if opsSplit[0] != "now" {
        return "", fmt.Errorf("invalid time selector %q", opsSplit[0])
    }

    result := now
    switch len(opsSplit) {
    case 1:
        // return current time
    case 3:
        duration, err := parseutil.ParseDurationSecond(opsSplit[2])
        if err != nil {
            return "", errwrap.Wrapf("invalid duration: {{err}}", err)
        }

        switch opsSplit[1] {
        case "plus":
            result = result.Add(duration)
        case "minus":
            result = result.Add(-duration)
        default:
            return "", fmt.Errorf("invalid time operator %q", opsSplit[1])
        }
    }

    return strconv.FormatInt(result.Unix(), 10), nil
}
```

## Mode-Specific Handlers

### JSON Mode Handler (`jsonTemplateHandler`)

Used for OIDC tokens - produces valid JSON:

```go
func jsonTemplateHandler(v interface{}, keys ...string) (string, error) {
    switch t := v.(type) {
    case string:
        return strconv.Quote(t), nil  // Wraps strings in quotes: "value"
    case []string:
        return jsonMarshaller(t)      // Marshals arrays: ["a", "b", "c"]
    case map[string]string:
        if len(keys) > 0 {
            return strconv.Quote(t[keys[0]]), nil
        }
        return jsonMarshaller(t)      // Marshals maps: {"key": "value"}
    }
}
```

### ACL Mode Handler (`aclTemplateHandler`)

Used for policy paths - returns raw strings:

```go
func aclTemplateHandler(v interface{}, keys ...string) (string, error) {
    switch t := v.(type) {
    case string:
        return t, nil                 // Returns verbatim: value
    case []string:
        return "", ErrTemplateValueNotFound  // Arrays not allowed in ACL mode
    case map[string]string:
        if len(keys) > 0 {
            return t[keys[0]], nil    // Returns specific key value
        }
        return "", ErrTemplateValueNotFound
    }
}
```

## Error Handling

The templating engine defines these errors:

- **`ErrUnbalancedTemplatingCharacter`** - Malformed `{{` or `}}` syntax
- **`ErrNoEntityAttachedToToken`** - Using entity template without entity data
- **`ErrNoGroupsAttachedToToken`** - Using groups template without groups data
- **`ErrTemplateValueNotFound`** - Referenced variable doesn't exist

## Graceful Degradation

For OIDC (JSON mode), if an alias doesn't exist, an empty alias with empty metadata is used instead of failing:

```go
if alias == nil {
    if p.Mode == ACLTemplating {
        return "", errors.New("alias not found")
    }
    // An empty alias is sufficient for generating defaults in JSON mode
    alias = &logical.Alias{
        Metadata: make(map[string]string),
        CustomMetadata: make(map[string]string)
    }
}
```

This allows templates to gracefully handle missing aliases when generating tokens.

## Protected Claims (OIDC)

When merging templates into OIDC tokens, these reserved claims cannot be overridden by templates:

- `iat` - Issued At
- `aud` - Audience
- `exp` - Expiration
- `iss` - Issuer
- `sub` - Subject
- `namespace` - Vault namespace
- `nonce` - OIDC nonce
- `auth_time` - Authentication time
- `at_hash` - Access token hash
- `c_hash` - Code hash

## Practical Example

### Template Definition

From the integration test (`scripts/integration-test.sh`):

```json
{
  "username": {{identity.entity.aliases.<mount accessor>.name}},
  "email": {{identity.entity.metadata.email}},
  "role": {{identity.entity.metadata.role}},
  "department": {{identity.entity.metadata.department}},
  "manager": {{identity.entity.metadata.manager}},
  "nbf": {{time.now}}
}
```

### Processing Steps

1. **`{{identity.entity.aliases.<mount accessor>.name}}`**
   - Resolves to alias name (e.g., "admin")
   - JSON handler wraps in quotes: `"admin"`

2. **`{{identity.entity.metadata.email}}`**
   - Resolves to metadata value: "admin@example.com"
   - JSON handler wraps in quotes: `"admin@example.com"`

3. **`{{identity.entity.metadata.role}}`**
   - Resolves to metadata value: "administrator"
   - JSON handler wraps in quotes: `"administrator"`

4. **`{{time.now}}`**
   - Resolves to current Unix timestamp: 1730736000
   - JSON handler returns as number (not quoted)

### Final Output

```json
{
  "username": "admin",
  "email": "admin@example.com",
  "role": "administrator",
  "department": "IT",
  "manager": "nic@email.com",
  "nbf": 1730736000
}
```

## Implementing in Custom Plugins

### Current Implementation (Simple Approach)

Our current implementation in `path_token_handlers.go:197-238` uses simple string replacement:

```go
func processTemplate(template string, claims map[string]any) (map[string]any, error) {
    // Simple JSON parsing and string replacement
    var templateClaims map[string]any
    if err := json.Unmarshal([]byte(template), &templateClaims); err != nil {
        return nil, fmt.Errorf("failed to parse template: %w", err)
    }

    // Process template substitutions (simple string replacement)
    processedClaims := processTemplateSubstitutions(templateClaims, claims)

    return processedClaims, nil
}
```

**Limitations**:
- Only supports simple `{{.user.claimname}}` syntax
- No access to entity metadata, groups, or time functions
- Limited to claims from the incoming JWT

### Using Vault's Templating (Advanced Approach)

To leverage Vault's full templating capabilities:

```go
import (
    "encoding/json"

    "github.com/hashicorp/vault/sdk/helper/identitytpl"
    "github.com/hashicorp/vault/sdk/logical"
)

func processTemplate(template string, entity *logical.Entity, groups []*logical.Group) (map[string]any, error) {
    // Use Vault's identity templating engine
    _, populated, err := identitytpl.PopulateString(identitytpl.PopulateStringInput{
        Mode:   identitytpl.JSONTemplating,
        String: template,
        Entity: entity,
        Groups: groups,
    })
    if err != nil {
        return nil, fmt.Errorf("failed to populate template: %w", err)
    }

    // Parse the populated JSON template
    var result map[string]any
    if err := json.Unmarshal([]byte(populated), &result); err != nil {
        return nil, fmt.Errorf("failed to parse populated template: %w", err)
    }

    return result, nil
}
```

**Benefits**:
- Full access to entity metadata, aliases, custom metadata
- Group membership information
- Time functions (now, plus, minus)
- Proper JSON formatting and escaping
- Consistent with Vault's OIDC behavior
- Graceful handling of missing values

### Getting Entity and Groups Data

To use Vault's templating, you need entity and groups data:

```go
func (b *Backend) pathTokenExchange(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
    // ... validation and setup ...

    // Get entity information
    var entity *logical.Entity
    var groups []*logical.Group

    entityID := req.EntityID
    if entityID != "" {
        var err error
        entity, err = req.System().EntityInfo(entityID)
        if err != nil {
            return nil, fmt.Errorf("failed to get entity info: %w", err)
        }

        // Optionally get groups
        groupInfos, err := req.System().GroupsForEntity(entityID)
        if err != nil {
            b.Logger().Warn("failed to get groups for entity", "error", err)
        } else {
            groups = groupInfos
        }
    }

    // Process template with entity and groups data
    templateClaims, err := processTemplate(role.Template, entity, groups)
    if err != nil {
        return nil, fmt.Errorf("failed to process template: %w", err)
    }

    // ... generate token with enriched claims ...
}
```

## Source Code References

### Primary Implementation

**`vault/sdk/helper/identitytpl/templating.go`** - Complete templating engine
- Lines 1-100: Constants, errors, data structures, mode handlers
- Lines 100-150: `PopulateString()` main entry point and template splitting
- Lines 150-200: `performTemplating()` dispatcher function
- Lines 200-250: `performEntityTemplating()` - handles `identity.entity.*` variables
- Lines 250-300: `performGroupsTemplating()` - handles `identity.groups.*` variables
- Lines 300-350: `performTimeTemplating()` - handles `time.*` variables

### OIDC Integration

**`vault/vault/identity_store_oidc.go`**
- `generatePayload()` function: Creates token with required claims
- `mergeJSONTemplates()` function: Merges populated templates into token
- Template population call using `identitytpl.PopulateString()`

## Key Takeaways

1. **Custom Engine**: Vault uses a custom templating engine, not Go's text/template
2. **Two Modes**: ACL mode for policies (raw strings), JSON mode for tokens (proper JSON formatting)
3. **Rich Context**: Templates have access to entity metadata, aliases, groups, and time functions
4. **Graceful Degradation**: Missing values are handled gracefully in JSON mode
5. **Protected Claims**: Certain OIDC claims cannot be overridden by templates
6. **Reusable**: The `identitytpl` package is part of the SDK and can be imported by plugins
7. **Mode Matters**: Choose the right mode for your use case (JSON for tokens, ACL for paths)

## Next Steps for Implementation

To enhance the token exchange plugin with Vault's templating:

1. Import `github.com/hashicorp/vault/sdk/helper/identitytpl` package
2. Modify `pathTokenExchange()` to get entity and groups data via `req.System().EntityInfo()` and `req.System().GroupsForEntity()`
3. Update `processTemplate()` to use `identitytpl.PopulateString()` with `JSONTemplating` mode
4. Update template documentation to explain available variables (`identity.entity.*`, `identity.groups.*`, `time.*`)
5. Add tests that verify entity metadata, groups, and time functions work correctly
6. Consider error handling for cases where entity data is not available
7. Update integration tests to demonstrate advanced template features

## References

- [Vault SDK identitytpl package source](https://github.com/hashicorp/vault/blob/main/sdk/helper/identitytpl/templating.go)
- [Vault identity OIDC implementation](https://github.com/hashicorp/vault/blob/main/vault/identity_store_oidc.go)
- [Identity templating documentation](https://developer.hashicorp.com/vault/docs/secrets/identity/identity-token#templated-policies)
