```markdown
# wasi-auth Development Patterns

> Auto-generated skill from repository analysis

## Overview

This skill teaches you the core development patterns, coding conventions, and common workflows for contributing to the `wasi-auth` Rust codebase. The repository is organized around modular middleware components, with a focus on security, extensibility, and supply chain integrity. You'll learn how to add new middleware, fix or enhance components, prepare releases, update CI/CD and supply chain scripts, maintain documentation, and manage test fixtures.

## Coding Conventions

**File Naming:**  
- Use `camelCase` for file and directory names.  
  _Example:_ `requestId.rs`, `securityHeaders.rs`

**Import Style:**  
- Use relative imports within modules.
  ```rust
  // In components/requestId/src/lib.rs
  mod utils;
  use crate::utils::generate_id;
  ```

**Export Style:**  
- Use named exports.
  ```rust
  pub fn handle_request(...) { ... }
  pub struct MiddlewareConfig { ... }
  ```

**Commit Messages:**  
- Follow [Conventional Commits](https://www.conventionalcommits.org/) with prefixes:  
  `feat`, `chore`, `ci`, `fix`, `test`, `docs`, `refactor`, `perf`
  _Example:_  
  ```
  feat(cors): add CORS middleware component
  fix(requestId): ensure unique IDs per request
  ```

## Workflows

### Add New Middleware Component
**Trigger:** When introducing a new reusable middleware component (e.g., CORS, security headers, request ID).  
**Command:** `/new-middleware-component`

1. Create a new directory under `components/` (e.g., `components/cors/`).
2. Add a `Cargo.toml` and `src/lib.rs` for the new component.
3. Update the root `Cargo.toml` and `Cargo.lock` to include the new component.
4. Optionally, add related test-components for the middleware.
5. Optionally, update scripts or reports if needed.

_Example:_
```
components/cors/Cargo.toml
components/cors/src/lib.rs
Cargo.toml
Cargo.lock
```

### Middleware Component Bugfix or Enhancement
**Trigger:** When fixing bugs or enhancing existing middleware logic or contracts.  
**Command:** `/fix-middleware`

1. Edit `src/lib.rs` for one or more components under `components/`.
2. Edit shared crates (e.g., `crates/component-support`, `crates/policy-core`) if needed.
3. Update `Cargo.toml` and `Cargo.lock` if dependencies change.
4. Optionally, update related scripts or reports.

_Example:_
```rust
// Fixing a bug in components/requestId/src/lib.rs
pub fn generate_id() -> String {
    // Improved logic for unique IDs
}
```

### Middleware Release Preparation
**Trigger:** When preparing for a new alpha or production middleware release.  
**Command:** `/release-prepare`

1. Update `CHANGELOG.md` and/or `MIGRATION.md`.
2. Update `compatibility.toml`.
3. Update `artifacts/SHA256SUMS` and SBOM files in `artifacts/sbom/`.
4. Update `Cargo.toml` and `Cargo.lock`.
5. Optionally, update `.github/workflows/ci.yml` and scripts.

_Example:_
```
CHANGELOG.md
MIGRATION.md
compatibility.toml
artifacts/SHA256SUMS
artifacts/sbom/*.cdx.json
Cargo.toml
Cargo.lock
.github/workflows/ci.yml
```

### Update or Add CI and Supply Chain Scripts
**Trigger:** When improving CI/CD or supply chain security.  
**Command:** `/update-ci`

1. Edit or add `.github/workflows/ci.yml`.
2. Edit or add scripts in `scripts/` (e.g., `generate-sbom.sh`, `generate-checksums.sh`, `dry-run-supply-chain.sh`).
3. Optionally, update `.gitignore` or `deny.toml`.

_Example:_
```
.github/workflows/ci.yml
scripts/generate-sbom.sh
scripts/generate-checksums.sh
.gitignore
deny.toml
```

### Documentation and Trust Boundary Update
**Trigger:** When documenting new features, changes, or clarifying trust boundaries.  
**Command:** `/update-docs`

1. Edit one or more `docs/*.md` files.
2. Edit `README.md`, `SECURITY.md`, or license files if needed.
3. Optionally, update `CHANGELOG.md`.

_Example:_
```
docs/architecture.md
README.md
SECURITY.md
LICENSE-APACHE
LICENSE-MIT
CHANGELOG.md
```

### Test Component and Fixture Update
**Trigger:** When adding or updating test components and Spin/Wasmtime fixtures for end-to-end or compatibility testing.  
**Command:** `/update-test-fixtures`

1. Edit or add `test-components/*/Cargo.toml` and `src/lib.rs`.
2. Edit or add `fixtures/spin/*.toml`.
3. Update or add scripts for testing (e.g., `run-spin-e2e.sh`, `test_audit_spin_manifest.py`).

_Example:_
```
test-components/cors/Cargo.toml
test-components/cors/src/lib.rs
fixtures/spin/cors.toml
scripts/run-spin-e2e.sh
scripts/test_audit_spin_manifest.py
```

## Testing Patterns

- Test files follow the `*.test.*` pattern, typically placed alongside source files or in dedicated test directories.
- The testing framework is not explicitly specified, but Rust's built-in test framework is likely used.

_Example:_
```rust
// In components/requestId/src/lib.test.rs
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_id_is_unique() {
        let id1 = generate_id();
        let id2 = generate_id();
        assert_ne!(id1, id2);
    }
}
```

## Commands

| Command                    | Purpose                                                        |
|----------------------------|----------------------------------------------------------------|
| /new-middleware-component  | Scaffold a new middleware component                            |
| /fix-middleware            | Fix or enhance existing middleware components                  |
| /release-prepare           | Prepare repository for a new middleware release                |
| /update-ci                 | Add or update CI and supply chain scripts                      |
| /update-docs               | Update documentation and trust boundary information            |
| /update-test-fixtures      | Add or update test components and Spin/Wasmtime fixtures       |
```
