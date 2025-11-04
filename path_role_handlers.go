package tokenexchange

import (
	"context"
	"fmt"
	"time"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

// pathRoleExistenceCheck checks if a role exists
func (b *Backend) pathRoleExistenceCheck(ctx context.Context, req *logical.Request, data *framework.FieldData) (bool, error) {
	name := data.Get("name").(string)
	role, err := b.getRole(ctx, req.Storage, name)
	if err != nil {
		return false, err
	}

	return role != nil, nil
}

// pathRoleRead handles reading a role
func (b *Backend) pathRoleRead(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	name := data.Get("name").(string)

	role, err := b.getRole(ctx, req.Storage, name)
	if err != nil {
		return nil, err
	}

	if role == nil {
		return nil, nil
	}

	return &logical.Response{
		Data: map[string]any{
			"name":            role.Name,
			"ttl":             role.TTL.String(),
			"template":        role.Template,
			"bound_audiences": role.BoundAudiences,
			"bound_issuer":    role.BoundIssuer,
		},
	}, nil
}

// pathRoleWrite handles creating or updating a role
func (b *Backend) pathRoleWrite(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	name := data.Get("name").(string)

	role := &Role{
		Name: name,
	}

	// Get TTL (required)
	ttl, ok := data.GetOk("ttl")
	if !ok {
		return logical.ErrorResponse("ttl is required"), nil
	}
	role.TTL = time.Duration(ttl.(int)) * time.Second

	// Get template (required)
	template, ok := data.GetOk("template")
	if !ok {
		return logical.ErrorResponse("template is required"), nil
	}
	role.Template = template.(string)

	// Get bound audiences (optional)
	if audiences, ok := data.GetOk("bound_audiences"); ok {
		role.BoundAudiences = audiences.([]string)
	}

	// Get bound issuer (optional)
	if issuer, ok := data.GetOk("bound_issuer"); ok {
		role.BoundIssuer = issuer.(string)
	}

	// Store role
	entry, err := logical.StorageEntryJSON(roleStoragePrefix+name, role)
	if err != nil {
		return nil, fmt.Errorf("failed to create storage entry: %w", err)
	}

	if err := req.Storage.Put(ctx, entry); err != nil {
		return nil, fmt.Errorf("failed to write role: %w", err)
	}

	return nil, nil
}

// pathRoleDelete handles deleting a role
func (b *Backend) pathRoleDelete(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	name := data.Get("name").(string)

	if err := req.Storage.Delete(ctx, roleStoragePrefix+name); err != nil {
		return nil, fmt.Errorf("failed to delete role: %w", err)
	}

	return nil, nil
}

// pathRoleList handles listing all roles
func (b *Backend) pathRoleList(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	roles, err := req.Storage.List(ctx, roleStoragePrefix)
	if err != nil {
		return nil, fmt.Errorf("failed to list roles: %w", err)
	}

	if len(roles) == 0 {
		return nil, nil
	}

	return logical.ListResponse(roles), nil
}

// getRole retrieves a role from storage
func (b *Backend) getRole(ctx context.Context, storage logical.Storage, name string) (*Role, error) {
	entry, err := storage.Get(ctx, roleStoragePrefix+name)
	if err != nil {
		return nil, fmt.Errorf("failed to read role: %w", err)
	}

	if entry == nil {
		return nil, nil
	}

	role := &Role{}
	if err := entry.DecodeJSON(role); err != nil {
		return nil, fmt.Errorf("failed to decode role: %w", err)
	}

	return role, nil
}
