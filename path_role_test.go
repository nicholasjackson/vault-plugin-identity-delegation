package tokenexchange

import (
	"context"
	"testing"

	"github.com/hashicorp/vault/sdk/logical"
	"github.com/stretchr/testify/require"
)

// TestRoleWrite_Success tests creating a role with valid data
func TestRoleWrite_Success(t *testing.T) {
	b, storage := getTestBackend(t)

	req := &logical.Request{
		Operation: logical.CreateOperation,
		Path:      "role/test-role",
		Storage:   storage,
		Data: map[string]any{
			"name":             "test-role",
			"ttl":              "1h",
			"actor_template":   `{"act": {"sub": "agent-123"}}`,
			"subject_template": `{"department": "{{.identity.subject.department}}"}`,
			"context":          []string{"urn:documents:read"},
			"bound_audiences":  []string{"service-a", "service-b"},
			"bound_issuer":     "https://idp.example.com",
		},
	}

	resp, err := b.HandleRequest(context.Background(), req)

	require.NoError(t, err, "Create should succeed")
	require.Nil(t, resp, "Create should return nil response on success")

	// Verify role was stored
	entry, err := storage.Get(context.Background(), "roles/test-role")
	require.NoError(t, err)
	require.NotNil(t, entry, "Role should be stored")
}

// TestRoleWrite_MissingTTL tests validation of required TTL field
func TestRoleWrite_MissingTTL(t *testing.T) {
	b, storage := getTestBackend(t)

	req := &logical.Request{
		Operation: logical.CreateOperation,
		Path:      "role/test-role",
		Storage:   storage,
		Data: map[string]any{
			"name":             "test-role",
			"actor_template":   `{"act": {"sub": "agent-123"}}`,
			"subject_template": `{"department": "{{.identity.subject.department}}"}`,
			"context":          []string{"urn:documents:read"},
			// Missing ttl
		},
	}

	resp, err := b.HandleRequest(context.Background(), req)

	require.NoError(t, err, "Handler should not error")
	require.NotNil(t, resp, "Should return error response")
	require.True(t, resp.IsError(), "Response should be an error")
	require.Contains(t, resp.Error().Error(), "ttl", "Error should mention missing ttl")
}

// TestRoleWrite_MissingTemplate tests validation of required template fields
func TestRoleWrite_MissingTemplate(t *testing.T) {
	b, storage := getTestBackend(t)

	req := &logical.Request{
		Operation: logical.CreateOperation,
		Path:      "role/test-role",
		Storage:   storage,
		Data: map[string]any{
			"name":    "test-role",
			"ttl":     "1h",
			"context": []string{"urn:documents:read"},
			// Missing actor_template and subject_template
		},
	}

	resp, err := b.HandleRequest(context.Background(), req)

	require.NoError(t, err, "Handler should not error")
	require.NotNil(t, resp, "Should return error response")
	require.True(t, resp.IsError(), "Response should be an error")
	// Should mention missing template (either actor_template or subject_template)
	require.Contains(t, resp.Error().Error(), "template", "Error should mention missing template")
}

// TestRoleRead_Success tests reading an existing role
func TestRoleRead_Success(t *testing.T) {
	b, storage := getTestBackend(t)

	// Create role first
	writeReq := &logical.Request{
		Operation: logical.CreateOperation,
		Path:      "role/test-role",
		Storage:   storage,
		Data: map[string]any{
			"name":             "test-role",
			"ttl":              "1h",
			"actor_template":   `{"act": {"sub": "agent-123"}}`,
			"subject_template": `{"department": "{{.identity.subject.department}}"}`,
			"context":          []string{"urn:documents:read"},
			"bound_audiences":  []string{"service-a", "service-b"},
			"bound_issuer":     "https://idp.example.com",
		},
	}
	_, err := b.HandleRequest(context.Background(), writeReq)
	require.NoError(t, err)

	// Read role
	readReq := &logical.Request{
		Operation: logical.ReadOperation,
		Path:      "role/test-role",
		Storage:   storage,
	}
	resp, err := b.HandleRequest(context.Background(), readReq)

	require.NoError(t, err, "Read should succeed")
	require.NotNil(t, resp, "Should return response")
	require.NotNil(t, resp.Data, "Response should have data")
	require.Equal(t, "test-role", resp.Data["name"])
	require.Equal(t, "1h0m0s", resp.Data["ttl"])
	require.Equal(t, `{"act": {"sub": "agent-123"}}`, resp.Data["actor_template"])
	require.Equal(t, `{"department": "{{.identity.subject.department}}"}`, resp.Data["subject_template"])
	require.Equal(t, []string{"urn:documents:read"}, resp.Data["context"])
	require.Equal(t, []string{"service-a", "service-b"}, resp.Data["bound_audiences"])
	require.Equal(t, "https://idp.example.com", resp.Data["bound_issuer"])
}

// TestRoleRead_NotFound tests reading a non-existent role
func TestRoleRead_NotFound(t *testing.T) {
	b, storage := getTestBackend(t)

	req := &logical.Request{
		Operation: logical.ReadOperation,
		Path:      "role/nonexistent",
		Storage:   storage,
	}

	resp, err := b.HandleRequest(context.Background(), req)

	require.NoError(t, err, "Read should not error")
	require.Nil(t, resp, "Response should be nil for non-existent role")
}

// TestRoleUpdate_Success tests updating an existing role
func TestRoleUpdate_Success(t *testing.T) {
	b, storage := getTestBackend(t)

	// Create role first
	writeReq := &logical.Request{
		Operation: logical.CreateOperation,
		Path:      "role/test-role",
		Storage:   storage,
		Data: map[string]any{
			"name":             "test-role",
			"ttl":              "1h",
			"actor_template":   `{"act": {"sub": "agent-123"}}`,
			"subject_template": `{"department": "{{.identity.subject.department}}"}`,
			"context":          []string{"urn:documents:read"},
		},
	}
	_, err := b.HandleRequest(context.Background(), writeReq)
	require.NoError(t, err)

	// Update role
	updateReq := &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "role/test-role",
		Storage:   storage,
		Data: map[string]any{
			"name":             "test-role",
			"ttl":              "2h",
			"actor_template":   `{"act": {"sub": "agent-456", "name": "Updated Agent"}}`,
			"subject_template": `{"department": "{{.identity.subject.department}}", "role": "{{.identity.subject.role}}"}`,
			"context":          []string{"urn:documents:read", "urn:documents:write"},
		},
	}
	resp, err := b.HandleRequest(context.Background(), updateReq)

	require.NoError(t, err, "Update should succeed")
	require.Nil(t, resp, "Update should return nil response on success")

	// Read to verify update
	readReq := &logical.Request{
		Operation: logical.ReadOperation,
		Path:      "role/test-role",
		Storage:   storage,
	}
	resp, err = b.HandleRequest(context.Background(), readReq)
	require.NoError(t, err)
	require.Equal(t, "2h0m0s", resp.Data["ttl"])
	require.Equal(t, `{"act": {"sub": "agent-456", "name": "Updated Agent"}}`, resp.Data["actor_template"])
	require.Equal(t, `{"department": "{{.identity.subject.department}}", "role": "{{.identity.subject.role}}"}`, resp.Data["subject_template"])
	require.Equal(t, []string{"urn:documents:read", "urn:documents:write"}, resp.Data["context"])
}

// TestRoleDelete_Success tests deleting a role
func TestRoleDelete_Success(t *testing.T) {
	b, storage := getTestBackend(t)

	// Create role first
	writeReq := &logical.Request{
		Operation: logical.CreateOperation,
		Path:      "role/test-role",
		Storage:   storage,
		Data: map[string]any{
			"name":             "test-role",
			"ttl":              "1h",
			"actor_template":   `{"act": {"sub": "agent-123"}}`,
			"subject_template": `{"department": "{{.identity.subject.department}}"}`,
			"context":          []string{"urn:documents:read"},
		},
	}
	_, err := b.HandleRequest(context.Background(), writeReq)
	require.NoError(t, err)

	// Delete role
	deleteReq := &logical.Request{
		Operation: logical.DeleteOperation,
		Path:      "role/test-role",
		Storage:   storage,
	}
	resp, err := b.HandleRequest(context.Background(), deleteReq)

	require.NoError(t, err, "Delete should succeed")
	require.Nil(t, resp, "Delete should return nil response")

	// Verify role is gone
	entry, err := storage.Get(context.Background(), "roles/test-role")
	require.NoError(t, err)
	require.Nil(t, entry, "Role should be deleted")
}

// TestRoleList_Success tests listing roles
func TestRoleList_Success(t *testing.T) {
	b, storage := getTestBackend(t)

	// Create multiple roles
	roles := []string{"role-1", "role-2", "role-3"}
	for _, roleName := range roles {
		req := &logical.Request{
			Operation: logical.CreateOperation,
			Path:      "role/" + roleName,
			Storage:   storage,
			Data: map[string]any{
				"name":             roleName,
				"ttl":              "1h",
				"actor_template":   `{"act": {"sub": "agent-123"}}`,
				"subject_template": `{"department": "{{.identity.subject.department}}"}`,
				"context":          []string{"urn:documents:read"},
			},
		}
		_, err := b.HandleRequest(context.Background(), req)
		require.NoError(t, err)
	}

	// List roles
	listReq := &logical.Request{
		Operation: logical.ListOperation,
		Path:      "role/",
		Storage:   storage,
	}
	resp, err := b.HandleRequest(context.Background(), listReq)

	require.NoError(t, err, "List should succeed")
	require.NotNil(t, resp, "Should return response")
	require.NotNil(t, resp.Data, "Response should have data")

	keys, ok := resp.Data["keys"].([]string)
	require.True(t, ok, "Response should have keys as []string")
	require.Len(t, keys, 3, "Should list all 3 roles")
	require.Contains(t, keys, "role-1")
	require.Contains(t, keys, "role-2")
	require.Contains(t, keys, "role-3")
}

// TestRoleList_Empty tests listing when no roles exist
func TestRoleList_Empty(t *testing.T) {
	b, storage := getTestBackend(t)

	req := &logical.Request{
		Operation: logical.ListOperation,
		Path:      "role/",
		Storage:   storage,
	}

	resp, err := b.HandleRequest(context.Background(), req)

	require.NoError(t, err, "List should not error")
	require.Nil(t, resp, "Response should be nil when no roles exist")
}
