# warrant-core — Agent Rules

## What This Crate Does

Core policy engine library for the Warrant ecosystem. Parses, verifies, and evaluates signed capability policies ("warrants"). Intentionally UI/framework neutral — no CLI, no prompting, no I/O beyond reading key files from disk.

This crate is used by warrant-shell (the CLI), and will be used by warrant-exchange (the multi-agent trust daemon) and any future Warrant products.

## Architecture

**Modules:**

| Module | Purpose |
|--------|---------|
| `engine.rs` | `check()` — the policy evaluation engine. Takes a `ParsedWarrant`, a capability name, and a `CheckContext` (scope values). Returns `Decision::Allow` or `Decision::Deny(reason)`. This is THE core function. |
| `model.rs` | `ParsedWarrant`, `WarrantMeta`, `SignatureBlock` — the in-memory representation of a signed warrant. |
| `parser.rs` | `parse_toml_warrant()` — parses a TOML warrant document into `ParsedWarrant`. |
| `crypto.rs` | Ed25519 signature verification via `ed25519-dalek`. |
| `canonical.rs` | Canonical JSON serialization for deterministic signing. |
| `lock.rs` | `lock_warrant_from_draft_path/toml()` — compiles a draft policy into a signed warrant. `review_lock_from_draft_path/toml()` — diff before locking. `load_installed_warrant()` — read from disk. |
| `store.rs` | Read signing/verifying keys from disk. Key generation. |
| `paths.rs` | `ToolPaths` — resolves directory locations for warrants, keys, drafts, cache. `ToolId` — namespaced tool identifier. |
| `elevation.rs` | Temporary privilege elevation: create/clear/check session. Host binding for session tokens. |
| `payload.rs` | Unsigned payload construction for signing. |
| `error.rs` | `Error` enum and `Result` type. All errors are typed, not strings. |

## Public API

```rust
// Parse and verify in one step
pub fn verify_toml_warrant(input: &str) -> Result<ParsedWarrant>;

// Parse only (no signature check)
pub fn parse_toml_warrant(input: &str) -> Result<ParsedWarrant>;

// Evaluate a capability against a warrant
pub fn check(warrant: &ParsedWarrant, ctx: &CheckContext) -> Decision;

// Lock/review
pub fn lock_warrant_from_draft_path(draft_path, paths) -> Result<LockResult>;
pub fn review_lock_from_draft_path(draft_path, paths) -> Result<LockReview>;
pub fn load_installed_warrant(paths) -> Result<ParsedWarrant>;
pub fn load_installed_warrant_for_tool(paths, tool) -> Result<ParsedWarrant>;

// Crypto
pub fn verify_ed25519_signature(public_key_b64, message, signature_b64) -> Result<()>;

// Elevation
pub fn create_elevation_session(options) -> Result<()>;
pub fn clear_elevation_session(paths) -> Result<()>;
pub fn is_elevated(paths) -> bool;

// Keys
pub fn read_signing_key(paths) -> Result<SigningKey>;
pub fn read_verifying_key(paths) -> Result<VerifyingKey>;
```

## The `check()` Function

This is the heart of Warrant. It evaluates whether a specific capability is allowed by the installed warrant.

**Inputs:**
- `warrant: &ParsedWarrant` — the signed policy
- `ctx: &CheckContext` — capability name + scope key-value pairs

**Output:** `Decision::Allow` or `Decision::Deny(DenyReason)`

**Deny reasons (all typed, not strings):**
- `MissingCapability` — capability not in warrant at all
- `ExplicitDeny` — capability explicitly set to `false`
- `InvalidGrantType` — capability value is wrong type (not bool or table)
- `MissingScopedAllow` — scoped grant missing `allow = true/false`
- `MissingScope` — check context missing a required scope key
- `ScopeMismatch` — scope value doesn't match policy constraint

## How to Run Tests

```bash
# All tests
cargo test -p warrant-core

# Specific test
cargo test -p warrant-core -- test_name
```

**Test count must not decrease.** Do not delete or disable tests to fix failures. All tests are inline `#[cfg(test)]` modules within source files.

**Test isolation:** Tests use `tempfile::tempdir()`. Never write to real system directories.

## Design Principles

1. **No I/O in the policy engine.** `check()` takes in-memory data and returns a decision. It does not read files, write logs, or prompt users.
2. **All errors are typed.** The `Error` enum covers every failure mode. No `anyhow`, no string errors.
3. **Canonical JSON for signing.** Keys sorted alphabetically, no trailing commas, deterministic. This ensures the same payload always produces the same signature.
4. **Ed25519 only.** We use `ed25519-dalek` 2.2. Do not introduce alternative signing schemes without discussion.
5. **The warrant format is TOML.** Human-readable, human-editable. The `[signature]` block is appended by the lock step.

## Common Mistakes

- **DO NOT** add CLI/TUI code here. Core is a library. Interactive features belong in warrant-shell.
- **DO NOT** switch cryptographic libraries. We use `ed25519-dalek` 2.2, `sha2` 0.10, `hmac` 0.12. These are deliberate choices.
- **DO NOT** change the canonical JSON algorithm without understanding the signing implications. Any change breaks all existing signatures.
- **DO NOT** add `println!` or `eprintln!`. Return typed errors; let the caller handle display.
- **DO NOT** add async. Core is synchronous by design.

## Key Dependency Choices

Do not switch these without discussion — they are deliberate architectural decisions:
- **`ed25519-dalek`** for all signing/verification. Not `ring`, not `openssl`.
- **`sha2`** for hash chains. Not another SHA implementation.
- **Canonical JSON** (hand-rolled in `canonical.rs`) for deterministic signing payloads. Not `serde_json` default serialization.

Everything else (versions, full dependency list) is in `Cargo.toml`.
