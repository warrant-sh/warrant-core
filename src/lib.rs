//! Core engine for Warrant signed capability policies.
//!
//! This crate is intentionally UI/framework neutral: it parses, verifies, and evaluates
//! policies, and provides lock/elevation state primitives. Interactive prompting belongs
//! in higher-level integration crates.

mod canonical;
mod crypto;
mod elevation;
mod engine;
mod error;
mod lock;
mod model;
mod parser;
mod paths;
mod payload;
mod store;

pub use canonical::canonical_json_bytes;
pub use crypto::verify_ed25519_signature;
pub use elevation::{
    ElevationOptions, clear_elevation_session, create_elevation_session, current_host_binding,
    is_elevated,
};
pub use engine::{CheckContext, Decision, DenyReason, check};
pub use error::{Error, Result};
pub use lock::{
    LockOptions, LockResult, LockReview, ReviewDiffEntry, ReviewDiffKind, load_installed_warrant,
    load_installed_warrant_for_tool, lock_warrant_from_draft_path, lock_warrant_from_draft_toml,
    review_lock_from_draft_path, review_lock_from_draft_toml,
};
pub use model::{ParsedWarrant, SignatureBlock, WarrantMeta};
pub use parser::parse_toml_warrant;
pub use paths::{ToolId, ToolPaths};
pub use store::{read_signing_key, read_verifying_key};

/// Parse and verify a warrant TOML document in one step.
pub fn verify_toml_warrant(input: &str) -> Result<ParsedWarrant> {
    let parsed = parse_toml_warrant(input)?;
    parsed.verify_signature()?;
    Ok(parsed)
}
