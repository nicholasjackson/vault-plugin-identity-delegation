# Accessing Entity Information in Vault Plugin SDK

Date: 2025-11-04

## Overview

This document explains how to access entity information within a Vault plugin using the HashiCorp Vault SDK.

## Background

When building Vault plugins, you often need to access information about the entity (user/service) making the request. The Vault SDK provides entity information through the `logical.Request` object that's passed to your path handlers.

## Entity ID Access

### Direct Access via Request Object

The `logical.Request` struct has an `EntityID` field that contains the identity of the caller extracted from the token used to make the request:

```go
func (b *Backend) pathTokenExchange(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
    // Access the entity ID directly from the request
    entityID := req.EntityID

    // entityID is a string containing the identity of the caller
    // extracted from the token used to make the request
    if entityID != "" {
        // Use the entity ID in your logic
        b.Logger().Info("request from entity", "entity_id", entityID)
    }

    // ... rest of handler logic
}
```

### Key Request Fields

The `logical.Request` struct provides several identity-related fields:

1. **`req.EntityID`** - The identity of the caller extracted from the token. This is the primary field for entity identification.

2. **`req.ClientID`** - The identity of the caller. If the token is associated with an entity, this will be the same as `EntityID`.

3. **`req.ClientToken`** - The hashed token used for identity verification and ACL application.

4. **`req.ClientTokenAccessor`** - The token accessor, used primarily for audit logging.

## Getting Full Entity Information

If you need more than just the entity ID (such as entity metadata, name, aliases, etc.), you can use the `SystemView.EntityInfo()` method:

```go
func (b *Backend) pathTokenExchange(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
    entityID := req.EntityID

    if entityID == "" {
        // No entity associated with this request
        return logical.ErrorResponse("no entity associated with token"), nil
    }

    // Get full entity information using SystemView
    entity, err := req.System().EntityInfo(entityID)
    if err != nil {
        return nil, fmt.Errorf("failed to get entity info: %w", err)
    }

    if entity == nil {
        return logical.ErrorResponse("entity not found"), nil
    }

    // Access entity fields
    b.Logger().Info("entity details",
        "name", entity.Name,
        "id", entity.ID,
        "metadata", entity.Metadata,
        "namespace_id", entity.NamespaceID,
    )

    // Use entity metadata in your logic
    if email, ok := entity.Metadata["email"]; ok {
        b.Logger().Info("user email", "email", email)
    }

    // ... rest of handler logic
}
```

## Entity Object Structure

The `Entity` object returned by `EntityInfo()` contains the following fields:

- **`ID`** (string) - The unique entity identifier
- **`Name`** (string) - The human-readable entity name
- **`Metadata`** (map[string]string) - Key-value pairs of metadata associated with the entity
- **`Aliases`** ([]*Alias) - List of entity aliases (each with mount accessor, ID, name, etc.)
- **`Disabled`** (bool) - Whether the entity is disabled
- **`NamespaceID`** (string) - The namespace the entity belongs to

## Use Cases for This Plugin

For the token exchange plugin, entity information can be used to:

1. **Include entity metadata in generated tokens** - Add user information like email, department, role from entity metadata into the exchanged token claims

2. **Audit and logging** - Track which entities are performing token exchanges

3. **Authorization decisions** - Make role-based decisions based on entity metadata or group memberships

4. **Token customization** - Use entity information to customize the token template processing

## Example: Using Entity Metadata in Token Exchange

```go
func (b *Backend) pathTokenExchange(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
    // ... validation and setup code ...

    // Get entity information
    entityID := req.EntityID
    var entityMetadata map[string]string

    if entityID != "" {
        entity, err := req.System().EntityInfo(entityID)
        if err != nil {
            b.Logger().Warn("failed to get entity info", "error", err)
        } else if entity != nil {
            entityMetadata = entity.Metadata
        }
    }

    // Process template with both token claims and entity metadata
    templateClaims, err := processTemplate(role.Template, claims, entityMetadata)
    if err != nil {
        return nil, fmt.Errorf("failed to process template: %w", err)
    }

    // ... generate token with enriched claims ...
}
```

## References

- [Vault SDK logical.Request source](https://github.com/hashicorp/vault/blob/main/sdk/logical/request.go)
- [Vault SDK logical package documentation](https://pkg.go.dev/github.com/hashicorp/vault/sdk/logical)
- [Vault Identity Entities documentation](https://developer.hashicorp.com/vault/tutorials/auth-methods/identity)

## Implementation Notes

- Always check if `EntityID` is empty before using it - not all requests will have an associated entity
- Handle errors gracefully when calling `EntityInfo()` - the entity might not exist or be accessible
- Consider caching entity information if you need to access it multiple times in a single request
- Be mindful of namespace boundaries when working with entities in Vault Enterprise

## Next Steps

To implement this in the token exchange plugin:

1. Modify `pathTokenExchange()` to extract entity information
2. Update `processTemplate()` to accept and use entity metadata
3. Extend template processing to support entity metadata variables (e.g., `{{.entity.metadata.email}}`)
4. Add tests that verify entity information is properly included in exchanged tokens
5. Update documentation to explain how entity metadata can be used in templates
