# Vault Plugin Scaffold - Task Checklist

**Last Updated**: 2025-11-04
**Status**: Not Started

## Phase 1: Project Initialization

- [ ] **Task 1.1**: Initialize Go module
  - Command: `go mod init github.com/nicholasjackson/vault-plugin-token-exchange`
  - Effort: S
  - Dependencies: None
  - Acceptance: go.mod file created with correct module path

- [ ] **Task 1.2**: Add Vault SDK dependencies
  - Commands: `go get github.com/hashicorp/vault/sdk@v0.17.0` and other dependencies
  - Effort: S
  - Dependencies: Task 1.1
  - Acceptance: All required dependencies in go.mod, `go mod tidy` succeeds

- [ ] **Task 1.3**: Create directory structure
  - Command: `mkdir -p cmd/vault-plugin-token-exchange .github/workflows`
  - Effort: S
  - Dependencies: None
  - Acceptance: Directories exist and match standard Go layout

- [ ] **Task 1.4**: Populate .gitignore
  - File: `.gitignore`
  - Effort: S
  - Dependencies: None
  - Acceptance: .gitignore contains Go-specific patterns

- [ ] **Task 1.5**: Create README.md
  - File: `README.md`
  - Effort: S
  - Dependencies: None
  - Acceptance: README contains project description, build instructions, usage

### Phase 1 Verification
- [ ] Run: `go mod download` - Downloads all dependencies successfully
- [ ] Run: `go mod tidy` - No changes needed
- [ ] Verify: Directory structure matches plan
- [ ] Verify: .gitignore works (build binary, check git status)

---

## Phase 2: Backend Core

- [ ] **Task 2.1**: Write backend initialization tests FIRST
  - File: `backend_test.go`
  - Effort: M
  - Dependencies: Phase 1 complete
  - Acceptance: Tests written for Factory, backend type, paths registered, help text
  - Tests should FAIL initially (TDD)

- [ ] **Task 2.2**: Implement Backend struct and Factory
  - File: `backend.go`
  - Effort: M
  - Dependencies: Task 2.1 (tests must exist first)
  - Acceptance: Backend embeds framework.Backend, Factory creates backend, tests PASS

- [ ] **Task 2.3**: Create stub config path
  - File: `path_config.go`
  - Effort: S
  - Dependencies: Task 2.2
  - Acceptance: Stub path allows backend to compile, registers in Paths()

### Phase 2 Verification
- [ ] Run: `go test ./... -v` - All tests pass
- [ ] Run: `go build ./...` - Compiles successfully
- [ ] Run: `go vet ./...` - No vet warnings
- [ ] Verify: Backend follows identity engine pattern

---

## Phase 3: Configuration Path

- [ ] **Task 3.1**: Define Config struct
  - File: `path_config.go`
  - Effort: S
  - Dependencies: Phase 2 complete
  - Acceptance: Config struct with Issuer, SigningKey, DefaultTTL fields

- [ ] **Task 3.2**: Write config path tests FIRST
  - File: `path_config_test.go`
  - Effort: M
  - Dependencies: Task 3.1
  - Acceptance: Tests for Read (not configured), Write (success), Write (validation), Read (after write), Delete
  - Tests should FAIL initially (TDD)

- [ ] **Task 3.3**: Implement config path handlers
  - File: `path_config.go` - Complete implementation
  - Effort: L
  - Dependencies: Task 3.2 (tests must exist first)
  - Acceptance: Full CRUD handlers implemented, all tests PASS

- [ ] **Task 3.4**: Implement getConfig helper
  - File: `path_config.go`
  - Effort: S
  - Dependencies: Task 3.3
  - Acceptance: getConfig retrieves config from storage, returns nil if not found

### Phase 3 Verification
- [ ] Run: `go test ./... -v` - All tests pass
- [ ] Run: `go test -cover ./...` - Coverage > 80%
- [ ] Verify: Config CRUD operations work
- [ ] Verify: Signing key NOT returned on read (security)
- [ ] Verify: Required field validation works

---

## Phase 4: Role Path

- [ ] **Task 4.1**: Define Role struct
  - File: `path_role.go` (new)
  - Effort: S
  - Dependencies: Phase 3 complete
  - Acceptance: Role struct with Name, TTL, Template, BoundAudiences, BoundIssuer

- [ ] **Task 4.2**: Write role path tests FIRST
  - File: `path_role_test.go` (new)
  - Effort: L
  - Dependencies: Task 4.1
  - Acceptance: Tests for Create, Read, Update, Delete, List roles
  - Tests should FAIL initially (TDD)

- [ ] **Task 4.3**: Implement role path handlers
  - File: `path_role.go`
  - Effort: L
  - Dependencies: Task 4.2 (tests must exist first)
  - Acceptance: Full CRUD handlers for roles, all tests PASS

- [ ] **Task 4.4**: Implement getRole helper
  - File: `path_role.go`
  - Effort: S
  - Dependencies: Task 4.3
  - Acceptance: getRole retrieves role from storage

- [ ] **Task 4.5**: Register role path in backend
  - File: `backend.go`
  - Effort: S
  - Dependencies: Task 4.3
  - Acceptance: pathRole(b) added to Paths slice

### Phase 4 Verification
- [ ] Run: `go test ./... -v` - All tests pass
- [ ] Run: `go test -cover ./...` - Coverage > 80%
- [ ] Verify: Role CRUD operations work
- [ ] Verify: Template validation works
- [ ] Verify: Role list operation works

---

## Phase 5: Token Exchange Path

- [ ] **Task 5.1**: Write token exchange tests FIRST
  - File: `path_token_test.go` (new)
  - Effort: L
  - Dependencies: Phase 4 complete
  - Acceptance: Tests for token generation, JWT validation, error cases
  - Tests should FAIL initially (TDD)

- [ ] **Task 5.2**: Implement JWT validation logic
  - File: `path_token.go` (new)
  - Effort: M
  - Dependencies: Task 5.1
  - Acceptance: Validates JWT signature, expiration, issuer, audience

- [ ] **Task 5.3**: Implement JWT claim extraction
  - File: `path_token.go`
  - Effort: M
  - Dependencies: Task 5.2
  - Acceptance: Extracts claims from validated JWT

- [ ] **Task 5.4**: Implement template processing
  - File: `path_token.go`
  - Effort: M
  - Dependencies: Task 5.3
  - Acceptance: Processes role template with JWT claims, handles placeholders

- [ ] **Task 5.5**: Implement JWT signing
  - File: `path_token.go`
  - Effort: M
  - Dependencies: Task 5.4
  - Acceptance: Signs new JWT with config signing key, returns compact JWS

- [ ] **Task 5.6**: Implement token exchange handler
  - File: `path_token.go`
  - Effort: L
  - Dependencies: Tasks 5.2-5.5
  - Acceptance: Full token exchange flow, all tests PASS

- [ ] **Task 5.7**: Register token path in backend
  - File: `backend.go`
  - Effort: S
  - Dependencies: Task 5.6
  - Acceptance: pathToken(b) added to Paths slice

### Phase 5 Verification
- [ ] Run: `go test ./... -v` - All tests pass
- [ ] Run: `go test -cover ./...` - Coverage > 80%
- [ ] Verify: Token exchange accepts JWT input
- [ ] Verify: Token validation works (signature, expiration)
- [ ] Verify: Template processing works
- [ ] Verify: Generated JWT is valid and signed

---

## Phase 6: Main Entry Point

- [ ] **Task 6.1**: Implement main.go
  - File: `cmd/vault-plugin-token-exchange/main.go`
  - Effort: M
  - Dependencies: Phase 5 complete
  - Acceptance: Uses plugin.ServeMultiplex(), TLS config, error handling

- [ ] **Task 6.2**: Test plugin build
  - Command: `go build -o vault-plugin-token-exchange cmd/vault-plugin-token-exchange/main.go`
  - Effort: S
  - Dependencies: Task 6.1
  - Acceptance: Binary builds successfully, no errors

### Phase 6 Verification
- [ ] Run: `go build -o vault-plugin-token-exchange cmd/vault-plugin-token-exchange/main.go` - Builds successfully
- [ ] Run: `./vault-plugin-token-exchange` - Starts but waits for Vault connection (expected)
- [ ] Verify: Binary size is reasonable (< 50MB)
- [ ] Verify: No hardcoded secrets or debug code

---

## Phase 7: GitHub Actions CI/CD

- [ ] **Task 7.1**: Create GitHub Actions workflow
  - File: `.github/workflows/test.yml`
  - Effort: M
  - Dependencies: Phase 6 complete
  - Acceptance: Workflow with build, test, lint, coverage jobs

- [ ] **Task 7.2**: Configure Go setup in workflow
  - File: `.github/workflows/test.yml`
  - Effort: S
  - Dependencies: Task 7.1
  - Acceptance: Uses Go 1.23, caches dependencies

- [ ] **Task 7.3**: Add test job
  - File: `.github/workflows/test.yml`
  - Effort: S
  - Dependencies: Task 7.2
  - Acceptance: Runs `go test -v -cover ./...`, uploads coverage

- [ ] **Task 7.4**: Add lint job
  - File: `.github/workflows/test.yml`
  - Effort: M
  - Dependencies: Task 7.2
  - Acceptance: Runs golangci-lint and go vet

- [ ] **Task 7.5**: Add build job
  - File: `.github/workflows/test.yml`
  - Effort: S
  - Dependencies: Task 7.2
  - Acceptance: Builds plugin binary, uploads artifact

### Phase 7 Verification
- [ ] Commit and push changes
- [ ] Verify: GitHub Actions workflow triggers
- [ ] Verify: All jobs pass (build, test, lint)
- [ ] Verify: Coverage report generated
- [ ] Verify: Build artifact available

---

## Final Integration Testing

- [ ] **Task 8.1**: Start Vault dev server
  - Command: `vault server -dev -dev-plugin-dir=./`
  - Effort: S
  - Dependencies: Phase 7 complete
  - Acceptance: Vault starts successfully, plugin directory recognized

- [ ] **Task 8.2**: Register plugin with Vault
  - Commands: Calculate SHA256, `vault plugin register ...`
  - Effort: S
  - Dependencies: Task 8.1
  - Acceptance: Plugin registered successfully

- [ ] **Task 8.3**: Enable plugin as secrets engine
  - Command: `vault secrets enable -path=token-exchange vault-plugin-token-exchange`
  - Effort: S
  - Dependencies: Task 8.2
  - Acceptance: Plugin enabled at /token-exchange path

- [ ] **Task 8.4**: Configure plugin
  - Command: `vault write token-exchange/config issuer=... signing_key=... default_ttl=24h`
  - Effort: S
  - Dependencies: Task 8.3
  - Acceptance: Config written successfully

- [ ] **Task 8.5**: Create test role
  - Command: `vault write token-exchange/role/test ttl=1h template=... bound_issuer=...`
  - Effort: S
  - Dependencies: Task 8.4
  - Acceptance: Role created successfully

- [ ] **Task 8.6**: Exchange token
  - Command: `vault write token-exchange/token/test subject_token=<test-jwt>`
  - Effort: M
  - Dependencies: Task 8.5
  - Acceptance: New JWT returned, validates correctly

- [ ] **Task 8.7**: Verify end-to-end flow
  - Effort: M
  - Dependencies: Task 8.6
  - Acceptance: Complete flow works (config → role → token exchange)

### Final Verification

#### Automated Checks:
- [ ] All tests pass: `go test -v ./...`
- [ ] All tests pass with race detector: `go test -race ./...`
- [ ] Linting passes: `golangci-lint run`
- [ ] Vet passes: `go vet ./...`
- [ ] Build succeeds: `go build ./...`
- [ ] Coverage > 80%: `go test -cover ./...`

#### Manual Checks:
- [ ] Plugin registers with Vault
- [ ] Plugin enables as secrets engine
- [ ] Config path works (write, read, delete)
- [ ] Role path works (create, read, update, delete, list)
- [ ] Token exchange path works (accepts JWT, returns new JWT)
- [ ] Generated JWT is valid (signature, expiration, claims)
- [ ] Error handling works (missing config, invalid JWT, etc.)
- [ ] GitHub Actions passes on push/PR

#### Documentation Checks:
- [ ] README.md is accurate and helpful
- [ ] CLAUDE.md reflects actual implementation
- [ ] Code has godoc comments for exported types/functions
- [ ] Plan files reflect what was actually built

## Notes Section

### Implementation Notes
(Add notes here during implementation about decisions, blockers, or discoveries)

### Deviations from Plan
(Document any deviations from the original plan and reasoning)

### Future Improvements
(Track ideas for future enhancements beyond scaffold)
- Dedicated key management paths (`/key/:name`)
- Full OIDC discovery support
- Key rotation functionality
- Token introspection endpoint
- Performance optimizations (caching, connection pooling)
- Metrics and telemetry
- Multiple signing algorithm support
