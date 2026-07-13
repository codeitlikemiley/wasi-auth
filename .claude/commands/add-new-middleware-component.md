---
name: add-new-middleware-component
description: Workflow command scaffold for add-new-middleware-component in wasi-auth.
allowed_tools: ["Bash", "Read", "Write", "Grep", "Glob"]
---

# /add-new-middleware-component

Use this workflow when working on **add-new-middleware-component** in `wasi-auth`.

## Goal

Adds a new middleware component (e.g., CORS, security headers, request ID) to the codebase.

## Common Files

- `components/<component-name>/Cargo.toml`
- `components/<component-name>/src/lib.rs`
- `Cargo.toml`
- `Cargo.lock`

## Suggested Sequence

1. Understand the current state and failure mode before editing.
2. Make the smallest coherent change that satisfies the workflow goal.
3. Run the most relevant verification for touched files.
4. Summarize what changed and what still needs review.

## Typical Commit Signals

- Create new component directory under components/ with Cargo.toml and src/lib.rs
- Update Cargo.toml and Cargo.lock at the root
- Optionally add related test-components for the middleware
- Optionally update scripts or reports if needed

## Notes

- Treat this as a scaffold, not a hard-coded script.
- Update the command if the workflow evolves materially.