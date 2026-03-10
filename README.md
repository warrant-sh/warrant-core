<p align="center">
  <img src="docs/logo.jpg" alt="Warrant" width="120">
</p>

<h1 align="center">warrant-core</h1>

<p align="center">
  Core Rust engine for Warrant signed capability policies.
</p>

`warrant-core` is intentionally framework-neutral:
- parse TOML warrant files
- verify Ed25519 signatures over canonical JSON payload bytes
- evaluate capability decisions (deny-by-default)
- lock/install signed warrants with monotonic versioning
- manage explicit elevation session tokens

It does not include CLI prompting/UI helpers. Those belong in `wsh` (warrant-shell).

**Design principle across the stack:** policy authority comes from TOML warrants/manifests, not hardcoded runtime rules.

## Quick Example

```rust
use warrant_core::{CheckContext, Decision, check, verify_toml_warrant};

let warrant_toml = std::fs::read_to_string("/etc/mytool/warrant.toml")?;
let warrant = verify_toml_warrant(&warrant_toml)?;

let ctx = CheckContext::new().with_str("to_domains", "alice@example.com");
match check(&warrant, "send", &ctx) {
    Decision::Allow => {
        // execute protected action
    }
    Decision::Deny(reason) => {
        eprintln!("warrant denied: {reason}");
        std::process::exit(1);
    }
}
# Ok::<(), Box<dyn std::error::Error>>(())
```

## Status

Implemented:
- signature verification
- canonical JSON payload generation
- capability/scoped checks
- lock/install with version state
- explicit elevation session create/check/clear
- versioned signing key file metadata (`[signing_key]`, `format_version = 1`)

Planned:
- lock review/diff helpers
- full Windows ACL enforcement (current behavior is warning-only stubs)
- integration docs/examples

## Platform Note

On Windows, file/directory permission enforcement currently emits a warning and does not apply ACL hardening. Treat this as a known security limitation until full ACL support lands.

## License
## License

Licensed under either of [Apache License, Version 2.0](LICENSE-APACHE) or [MIT License](LICENSE), at your option.
