<p align="center">
  <img src="docs/logo.jpg" alt="Warrant" width="120">
</p>

<h1 align="center">warrant-core</h1>

<p align="center">
  Core Rust library for signed Warrant capability policies.
</p>

`warrant-core` is the policy engine under the Warrant stack. It parses warrant TOML, canonicalizes the unsigned payload, verifies Ed25519 signatures, evaluates capability checks, and provides lock/install and elevation-session primitives.

It does not include CLI UX, shell wrapping, registry access, or manifest editing. Those belong in higher-level tools such as `wsh`.

## What it provides

- TOML parsing for warrant documents
- Deterministic canonical JSON payload generation
- Ed25519 signature verification
- Capability evaluation with actionable deny reasons
- Signed warrant locking and installation
- Version-state tracking and rollback protection
- Host-bound elevation session create/check/clear helpers
- Cross-platform tool path resolution

## Quick example

```rust
use warrant_core::{CheckContext, Decision, check, verify_toml_warrant};

let warrant_toml = std::fs::read_to_string("/etc/mytool/warrant.toml")?;
let warrant = verify_toml_warrant(&warrant_toml)?;

let ctx = CheckContext::new().with_str("to_domains", "alice@example.com");
match check(&warrant, "send", &ctx) {
    Decision::Allow => println!("allowed"),
    Decision::Deny(reason) => eprintln!("denied: {reason}"),
}
# Ok::<(), Box<dyn std::error::Error>>(())
```

There is also a complete signing example in [examples/minimal_check.rs](/home/pete/Work/projects/warrant/warrant-core/examples/minimal_check.rs).

## Public API surface

Primary types and functions exported by the crate:

- `parse_toml_warrant`
- `verify_toml_warrant`
- `canonical_json_bytes`
- `verify_ed25519_signature`
- `check`
- `CheckContext`
- `Decision`
- `DenyReason`
- `ParsedWarrant`
- `WarrantMeta`
- `SignatureBlock`
- `ToolId`
- `ToolPaths`
- `LockOptions`
- `LockResult`
- `LockReview`
- `ReviewDiffEntry`
- `ReviewDiffKind`
- `lock_warrant_from_draft_path`
- `lock_warrant_from_draft_toml`
- `review_lock_from_draft_path`
- `review_lock_from_draft_toml`
- `load_installed_warrant`
- `load_installed_warrant_for_tool`
- `ElevationOptions`
- `create_elevation_session`
- `is_elevated`
- `clear_elevation_session`
- `current_host_binding`
- `read_signing_key`
- `read_verifying_key`

## Warrant document model

The parser expects a TOML document with:

- `[warrant]`
- `[capabilities]`
- `[signature]`

Required metadata fields under `[warrant]`:

- `version`
- `tool`
- `created`
- `issuer`

Required fields under `[signature]`:

- `algorithm`
- `public_key`
- `value`

The unsigned payload is the entire TOML document except `[signature]`. That payload is converted to canonical JSON and signed or verified against the embedded Ed25519 signature.

## Policy types

Capability grants are evaluated from the JSON representation of `[capabilities]`. The current engine supports three effective policy shapes:

### Boolean grant

```toml
[capabilities]
read = true
delete = false
```

- `true` means allow
- `false` means explicit deny

### Scoped object grant

```toml
[capabilities.send]
allow = true
to_domains = ["*@example.com"]
```

Rules for scoped objects:

- `allow` is required
- every other field is treated as a required scope match
- missing scope values deny the check
- string scopes support simple `*` wildcard matching
- arrays can express sets of allowed patterns

At runtime, callers provide scope values with `CheckContext`.

## Locking and installation

`warrant-core` can review and lock unsigned draft TOML into an installed signed warrant.

The lock flow:

1. Read the draft TOML
2. Validate required sections and the expected tool ID
3. Enforce strictly increasing version numbers
4. Canonicalize the unsigned payload
5. Sign it with the tool's Ed25519 private key
6. Write the installed warrant and version state

Protections in the current implementation:

- rejects non-incremental versions
- rejects versions above the hard limit
- rejects tool mismatches
- rejects rollback against stored version state
- verifies installed signatures when loading

`LockReview` exposes a simple diff between the installed unsigned payload and the incoming one before you commit a new lock.

## Elevation sessions

The crate also exposes short-lived elevation helpers for tools that want explicit privileged approval windows.

Current properties:

- host-bound HMAC on session tokens
- explicit expiry
- clock-rollback detection
- clear create/check/remove primitives

On Unix-like systems, the library also enforces file permission checks for signing keys, host secrets, and session artifacts.

## Platform behavior

`ToolPaths::for_tool` resolves different default locations by OS:

- Linux and other Unix-like systems: `/etc/<tool>` and `/run/<tool>`
- macOS: `/Library/Application Support/<tool>`
- Windows: `C:\ProgramData\<tool>`

Current limitation: Windows permission hardening is still stubbed with warnings rather than full ACL enforcement. Treat that as a known security gap.

## Current status

The crate is implemented and actively exercised by tests.

As of this README update:

- 40 tests are listed by `cargo test -- --list`
- signature verification, canonicalization, lock/install, rollback checks, and elevation flows are covered

## License

Licensed under either of [Apache License, Version 2.0](LICENSE-APACHE) or [MIT License](LICENSE), at your option.
