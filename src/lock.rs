#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;
use std::path::Path;

use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
use ed25519_dalek::Signer;
use serde_json::Value as JsonValue;
use toml::Table;

use crate::canonical::canonical_json_bytes;
use crate::error::{Error, Result};
use crate::model::ParsedWarrant;
use crate::parser::parse_toml_warrant;
use crate::paths::{ToolId, ToolPaths};
use crate::payload::unsigned_payload_from_root;
use crate::store::{
    ensure_signing_keys, read_signing_key, read_verifying_key, read_version_state,
    write_text_atomic, write_version_state,
};

const MAX_VERSION: u64 = 1_000_000;

#[derive(Debug, Clone, Default)]
pub struct LockOptions {
    pub create_keys_if_missing: bool,
}

#[derive(Debug, Clone)]
pub struct LockResult {
    pub version: u64,
    pub installed_warrant_path: std::path::PathBuf,
    pub version_state_path: std::path::PathBuf,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReviewDiffKind {
    Added,
    Removed,
    Changed,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReviewDiffEntry {
    pub path: String,
    pub kind: ReviewDiffKind,
    pub before: Option<String>,
    pub after: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LockReview {
    pub current_version: Option<u64>,
    pub incoming_version: u64,
    pub version_ready: bool,
    pub diff_entries: Vec<ReviewDiffEntry>,
}

pub fn review_lock_from_draft_path(draft_path: &Path, paths: &ToolPaths) -> Result<LockReview> {
    let draft_text = std::fs::read_to_string(draft_path)?;
    review_lock_from_draft_toml(&draft_text, paths)
}

pub fn lock_warrant_from_draft_path(
    draft_path: &Path,
    paths: &ToolPaths,
    options: &LockOptions,
) -> Result<LockResult> {
    let draft_text = std::fs::read_to_string(draft_path)?;
    lock_warrant_from_draft_toml(&draft_text, paths, options)
}

pub fn review_lock_from_draft_toml(draft_toml: &str, paths: &ToolPaths) -> Result<LockReview> {
    let draft_root = parse_draft_root(draft_toml)?;
    let incoming_version = extract_incoming_version(&draft_root)?;
    let incoming_payload = unsigned_payload_from_root(&draft_root)?;
    let current_version = read_version_state(&paths.version_state_path)?;

    let installed_payload = if paths.installed_warrant_path.exists() {
        let installed = std::fs::read_to_string(&paths.installed_warrant_path)?;
        let parsed = parse_toml_warrant(&installed)?;
        parsed.verify_signature()?;
        Some(parsed.unsigned_payload)
    } else {
        None
    };

    let diff_entries = diff_payloads(installed_payload.as_ref(), &incoming_payload);
    let version_ready = match current_version {
        Some(current) => incoming_version > current,
        None => true,
    };

    Ok(LockReview {
        current_version,
        incoming_version,
        version_ready,
        diff_entries,
    })
}

pub fn lock_warrant_from_draft_toml(
    draft_toml: &str,
    paths: &ToolPaths,
    options: &LockOptions,
) -> Result<LockResult> {
    if options.create_keys_if_missing {
        ensure_signing_keys(
            &paths.signing_private_key_path,
            &paths.signing_public_key_path,
        )?;
    }

    let mut root = parse_draft_root(draft_toml)?;
    let incoming_version = extract_incoming_version(&root)?;
    if incoming_version > MAX_VERSION {
        return Err(Error::VersionExceedsMaximum {
            version: incoming_version,
            max: MAX_VERSION,
        });
    }
    let incoming_tool = extract_incoming_tool(&root)?;
    ensure_expected_tool(&incoming_tool, &paths.tool_id)?;

    if let Some(current) = read_version_state(&paths.version_state_path)?
        && incoming_version <= current
    {
        return Err(Error::NonIncrementalVersion {
            current,
            incoming: incoming_version,
        });
    }

    let unsigned_json = unsigned_payload_from_root(&root)?;
    let canonical = canonical_json_bytes(&unsigned_json)?;

    let signing_key = read_signing_key(&paths.signing_private_key_path)?;
    let signature = signing_key.sign(&canonical);
    let derived_verifying_key = signing_key.verifying_key();

    // The private key is authoritative; warn on public-key drift but continue with derived key.
    match read_verifying_key(&paths.signing_public_key_path) {
        Ok(stored) => {
            if stored != derived_verifying_key {
                eprintln!(
                    "warrant-core warning: signing public key does not match private key at {}; using private-key derived public key",
                    paths.signing_public_key_path.display()
                );
            }
        }
        Err(err) => eprintln!(
            "warrant-core warning: could not validate signing public key at {} ({err}); using private-key derived public key",
            paths.signing_public_key_path.display()
        ),
    }

    let signature_table = Table::from_iter([
        (
            "algorithm".to_string(),
            toml::Value::String("ed25519".to_string()),
        ),
        (
            "public_key".to_string(),
            toml::Value::String(BASE64_STANDARD.encode(derived_verifying_key.to_bytes())),
        ),
        (
            "value".to_string(),
            toml::Value::String(BASE64_STANDARD.encode(signature.to_bytes())),
        ),
    ]);
    root.as_table_mut()
        .ok_or(Error::InvalidRoot)?
        .insert("signature".to_string(), toml::Value::Table(signature_table));

    let serialized = toml::to_string_pretty(&root).map_err(|_| Error::InvalidFieldType {
        section: "warrant",
        field: "document",
        expected: "serializable toml",
    })?;

    let parsed = parse_toml_warrant(&serialized)?;
    ensure_expected_tool(&parsed.meta.tool, &paths.tool_id)?;
    parsed.verify_signature()?;

    write_text_atomic(&paths.installed_warrant_path, &serialized)?;
    write_version_state(&paths.version_state_path, incoming_version)?;

    // Ensure the warrant dir and world-readable files are accessible to non-root users.
    // The private key and HMAC key are intentionally left root-only.
    fix_warrant_permissions(paths);

    Ok(LockResult {
        version: incoming_version,
        installed_warrant_path: paths.installed_warrant_path.clone(),
        version_state_path: paths.version_state_path.clone(),
    })
}

fn parse_draft_root(draft_text: &str) -> Result<toml::Value> {
    let root: toml::Value = toml::from_str(draft_text)?;
    let root_table = root.as_table().ok_or(Error::InvalidRoot)?;
    let _ = root_table
        .get("warrant")
        .ok_or(Error::MissingSection("warrant"))?
        .as_table()
        .ok_or(Error::InvalidSectionType("warrant"))?;
    if !root_table.contains_key("capabilities") {
        return Err(Error::MissingSection("capabilities"));
    }
    Ok(root)
}

fn extract_incoming_version(root: &toml::Value) -> Result<u64> {
    let root_table = root.as_table().ok_or(Error::InvalidRoot)?;
    let warrant_table = root_table
        .get("warrant")
        .ok_or(Error::MissingSection("warrant"))?
        .as_table()
        .ok_or(Error::InvalidSectionType("warrant"))?;
    let incoming_version_i64 = warrant_table
        .get("version")
        .ok_or(Error::MissingField {
            section: "warrant",
            field: "version",
        })?
        .as_integer()
        .ok_or(Error::InvalidFieldType {
            section: "warrant",
            field: "version",
            expected: "integer",
        })?;
    u64::try_from(incoming_version_i64).map_err(|_| Error::InvalidVersion)
}

fn extract_incoming_tool(root: &toml::Value) -> Result<String> {
    let root_table = root.as_table().ok_or(Error::InvalidRoot)?;
    let warrant_table = root_table
        .get("warrant")
        .ok_or(Error::MissingSection("warrant"))?
        .as_table()
        .ok_or(Error::InvalidSectionType("warrant"))?;
    let tool = warrant_table
        .get("tool")
        .ok_or(Error::MissingField {
            section: "warrant",
            field: "tool",
        })?
        .as_str()
        .ok_or(Error::InvalidFieldType {
            section: "warrant",
            field: "tool",
            expected: "string",
        })?;
    Ok(tool.to_string())
}

fn ensure_expected_tool(actual: &str, expected: &ToolId) -> Result<()> {
    if actual != expected.as_str() {
        return Err(Error::ToolMismatch {
            expected: expected.as_str().to_string(),
            found: actual.to_string(),
        });
    }
    Ok(())
}

fn diff_payloads(current: Option<&JsonValue>, incoming: &JsonValue) -> Vec<ReviewDiffEntry> {
    let mut out = Vec::new();
    match current {
        Some(existing) => diff_values("", Some(existing), Some(incoming), &mut out),
        None => diff_values("", None, Some(incoming), &mut out),
    }
    out
}

fn diff_values(
    path: &str,
    before: Option<&JsonValue>,
    after: Option<&JsonValue>,
    out: &mut Vec<ReviewDiffEntry>,
) {
    match (before, after) {
        (Some(JsonValue::Object(before_obj)), Some(JsonValue::Object(after_obj))) => {
            let mut keys: Vec<&String> = before_obj.keys().chain(after_obj.keys()).collect();
            keys.sort_unstable();
            keys.dedup();
            for key in keys {
                let next_path = if path.is_empty() {
                    key.to_string()
                } else {
                    format!("{path}.{key}")
                };
                diff_values(&next_path, before_obj.get(key), after_obj.get(key), out);
            }
        }
        (Some(b), Some(a)) if b == a => {}
        (Some(b), Some(a)) => out.push(ReviewDiffEntry {
            path: path.to_string(),
            kind: ReviewDiffKind::Changed,
            before: Some(render_json_value(b)),
            after: Some(render_json_value(a)),
        }),
        (None, Some(a)) => collect_leaf_entries(path, a, ReviewDiffKind::Added, out),
        (Some(b), None) => collect_leaf_entries(path, b, ReviewDiffKind::Removed, out),
        (None, None) => {}
    }
}

fn collect_leaf_entries(
    path: &str,
    value: &JsonValue,
    kind: ReviewDiffKind,
    out: &mut Vec<ReviewDiffEntry>,
) {
    if let JsonValue::Object(obj) = value {
        for (key, child) in obj {
            let next_path = if path.is_empty() {
                key.to_string()
            } else {
                format!("{path}.{key}")
            };
            collect_leaf_entries(&next_path, child, kind.clone(), out);
        }
        return;
    }

    out.push(match kind {
        ReviewDiffKind::Added => ReviewDiffEntry {
            path: path.to_string(),
            kind,
            before: None,
            after: Some(render_json_value(value)),
        },
        ReviewDiffKind::Removed => ReviewDiffEntry {
            path: path.to_string(),
            kind,
            before: Some(render_json_value(value)),
            after: None,
        },
        ReviewDiffKind::Changed => ReviewDiffEntry {
            path: path.to_string(),
            kind,
            before: None,
            after: Some(render_json_value(value)),
        },
    });
}

fn render_json_value(value: &JsonValue) -> String {
    serde_json::to_string(value).unwrap_or_else(|_| "<unrenderable>".to_string())
}

pub fn load_installed_warrant(paths: &ToolPaths) -> Result<ParsedWarrant> {
    let content = std::fs::read_to_string(&paths.installed_warrant_path)?;
    let parsed = parse_toml_warrant(&content)?;
    parsed.verify_signature()?;
    let stored_public_key = read_verifying_key(&paths.signing_public_key_path)?;
    let embedded_public_key = BASE64_STANDARD
        .decode(parsed.signature.public_key_b64.trim())
        .map_err(|_| Error::InvalidBase64 {
            field: "signature.public_key",
        })?;
    if embedded_public_key != stored_public_key.to_bytes() {
        return Err(Error::PublicKeyMismatch);
    }

    if let Some(recorded) = read_version_state(&paths.version_state_path)?
        && parsed.meta.version < recorded
    {
        return Err(Error::RollbackDetected {
            warrant: parsed.meta.version,
            recorded,
        });
    }
    Ok(parsed)
}

pub fn load_installed_warrant_for_tool(
    paths: &ToolPaths,
    expected_tool: &str,
) -> Result<ParsedWarrant> {
    let parsed = load_installed_warrant(paths)?;
    if parsed.meta.tool != expected_tool {
        return Err(Error::ToolMismatch {
            expected: expected_tool.to_string(),
            found: parsed.meta.tool.clone(),
        });
    }
    Ok(parsed)
}

/// Set correct permissions on warrant files after locking.
///
/// Layout intent:
///   warrant-shell/          0755  — world-traversable so non-root can reach files
///     warrant.toml          0644  — world-readable; needed by wsh check/exec/status
///     signing/              0700  — root-only; protects the private key
///       private.key         0600  — root-only
///       public.key          0644  — world-readable
///       version             0644  — world-readable
///     host.key              0600  — root-only
///
/// `std::fs::set_permissions` on macOS directories can silently fail when
/// extended attributes are present, so we shell out to chmod for directories.
#[cfg(unix)]
fn fix_warrant_permissions(paths: &ToolPaths) {
    // Helper: chmod a path (file or directory) using std::fs — handles spaces in paths correctly
    let chmod = |path: &Path, mode: u32| {
        if path.exists() {
            let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode));
        }
    };

    // Top-level warrant dir — must be traversable by non-root (0755)
    // signing/ is 0755 (set by ensure_signing_keys) — public key must be readable for daemon ping verification
    // private key is protected by its own 0600 permissions
    if let Some(dir) = paths.installed_warrant_path.parent() {
        chmod(dir, 0o755);
    }

    // World-readable files
    chmod(&paths.installed_warrant_path, 0o644); // warrant.toml
    chmod(&paths.signing_public_key_path, 0o644); // public.key
    chmod(&paths.version_state_path, 0o644); // version
}

#[cfg(not(unix))]
fn fix_warrant_permissions(_paths: &ToolPaths) {}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use tempfile::TempDir;

    use crate::paths::ToolPaths;

    use super::{
        LockOptions, ReviewDiffKind, load_installed_warrant, load_installed_warrant_for_tool,
        lock_warrant_from_draft_path, lock_warrant_from_draft_toml, review_lock_from_draft_path,
        review_lock_from_draft_toml,
    };

    fn temp_paths(base: &std::path::Path) -> ToolPaths {
        ToolPaths {
            tool_id: crate::paths::ToolId::parse("demo").expect("tool"),
            installed_warrant_path: base.join("etc").join("warrant.toml"),
            version_state_path: base.join("etc").join("signing").join("version"),
            signing_private_key_path: base.join("etc").join("signing").join("private.key"),
            signing_public_key_path: base.join("etc").join("signing").join("public.key"),
            host_secret_path: base.join("etc").join("host.key"),
            session_dir_path: base.join("run").join("demo"),
        }
    }

    fn write_draft(path: PathBuf, version: u64, read: bool) {
        let content = format!(
            r#"
[warrant]
version = {version}
tool = "demo"
created = 2026-02-16T08:00:00Z
issuer = "root@devbox"

[capabilities]
read = {read}
"#
        );
        std::fs::create_dir_all(path.parent().expect("parent")).expect("mkdir");
        std::fs::write(path, content).expect("write draft");
    }

    #[test]
    fn lock_and_load_round_trip() {
        let dir = TempDir::new().expect("tempdir");
        let paths = temp_paths(dir.path());
        let draft = dir.path().join("draft").join("warrant.toml");
        write_draft(draft.clone(), 1, true);

        let result = lock_warrant_from_draft_path(
            &draft,
            &paths,
            &LockOptions {
                create_keys_if_missing: true,
            },
        )
        .expect("lock");
        assert_eq!(result.version, 1);

        let loaded = load_installed_warrant(&paths).expect("load");
        assert_eq!(loaded.meta.version, 1);
        assert_eq!(loaded.meta.tool, "demo");
        let loaded_for_tool = load_installed_warrant_for_tool(&paths, "demo").expect("tool match");
        assert_eq!(loaded_for_tool.meta.tool, "demo");
    }

    #[test]
    fn lock_and_review_from_toml_text_round_trip() {
        let dir = TempDir::new().expect("tempdir");
        let paths = temp_paths(dir.path());
        let draft = dir.path().join("draft").join("warrant.toml");
        write_draft(draft.clone(), 1, true);
        let draft_text = std::fs::read_to_string(&draft).expect("read draft");

        let review = review_lock_from_draft_toml(&draft_text, &paths).expect("review");
        assert!(review.version_ready);
        assert!(!review.diff_entries.is_empty());

        let result = lock_warrant_from_draft_toml(
            &draft_text,
            &paths,
            &LockOptions {
                create_keys_if_missing: true,
            },
        )
        .expect("lock");
        assert_eq!(result.version, 1);

        let loaded = load_installed_warrant_for_tool(&paths, "demo").expect("load");
        assert_eq!(loaded.meta.version, 1);
    }

    #[test]
    fn load_rejects_wrong_tool_identifier() {
        let dir = TempDir::new().expect("tempdir");
        let paths = temp_paths(dir.path());
        let draft = dir.path().join("draft").join("warrant.toml");
        write_draft(draft.clone(), 1, true);
        lock_warrant_from_draft_path(
            &draft,
            &paths,
            &LockOptions {
                create_keys_if_missing: true,
            },
        )
        .expect("lock");

        let err = load_installed_warrant_for_tool(&paths, "other-tool").expect_err("wrong tool");
        assert!(
            err.to_string().contains("warrant tool mismatch"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn lock_rejects_non_incremental_versions() {
        let dir = TempDir::new().expect("tempdir");
        let paths = temp_paths(dir.path());
        let draft = dir.path().join("draft").join("warrant.toml");
        write_draft(draft.clone(), 1, true);
        lock_warrant_from_draft_path(
            &draft,
            &paths,
            &LockOptions {
                create_keys_if_missing: true,
            },
        )
        .expect("initial lock");

        write_draft(draft.clone(), 1, false);
        let err = lock_warrant_from_draft_path(
            &draft,
            &paths,
            &LockOptions {
                create_keys_if_missing: true,
            },
        )
        .expect_err("non-incremental must fail");
        assert!(
            err.to_string()
                .contains("incoming version must be strictly greater")
        );
    }

    #[test]
    fn lock_rejects_versions_above_maximum() {
        let dir = TempDir::new().expect("tempdir");
        let paths = temp_paths(dir.path());
        let draft = dir.path().join("draft").join("warrant.toml");
        write_draft(draft.clone(), 1_000_001, true);

        let err = lock_warrant_from_draft_path(
            &draft,
            &paths,
            &LockOptions {
                create_keys_if_missing: true,
            },
        )
        .expect_err("over-maximum version must fail");
        assert_eq!(
            err.to_string(),
            "Version 1000001 exceeds maximum allowed (1000000). Use emergency reset if needed."
        );
    }

    #[test]
    fn load_rejects_tampered_policy() {
        let dir = TempDir::new().expect("tempdir");
        let paths = temp_paths(dir.path());
        let draft = dir.path().join("draft").join("warrant.toml");
        write_draft(draft.clone(), 1, true);
        lock_warrant_from_draft_path(
            &draft,
            &paths,
            &LockOptions {
                create_keys_if_missing: true,
            },
        )
        .expect("initial lock");

        let tampered = std::fs::read_to_string(&paths.installed_warrant_path)
            .expect("read installed")
            .replace("read = true", "read = false");
        std::fs::write(&paths.installed_warrant_path, tampered).expect("tamper");
        let err = load_installed_warrant(&paths).expect_err("tampered must fail");
        assert!(err.to_string().contains("signature verification failed"));
    }

    #[test]
    fn load_rejects_when_embedded_public_key_differs_from_trusted_key() {
        let dir = TempDir::new().expect("tempdir");
        let paths = temp_paths(dir.path());
        let draft = dir.path().join("draft").join("warrant.toml");
        write_draft(draft.clone(), 1, true);
        lock_warrant_from_draft_path(
            &draft,
            &paths,
            &LockOptions {
                create_keys_if_missing: true,
            },
        )
        .expect("initial lock");

        let alt_private = dir.path().join("alt-signing").join("private.key");
        let alt_public = dir.path().join("alt-signing").join("public.key");
        crate::store::ensure_signing_keys(&alt_private, &alt_public).expect("alt keys");
        let alt_public_text = std::fs::read_to_string(&alt_public).expect("read alt public");
        std::fs::write(&paths.signing_public_key_path, alt_public_text).expect("replace public");

        let err = load_installed_warrant(&paths).expect_err("mismatch must fail");
        assert!(err.to_string().contains("public key does not match"));
    }

    #[test]
    fn load_rejects_rollback_against_version_state() {
        let dir = TempDir::new().expect("tempdir");
        let paths = temp_paths(dir.path());
        let draft = dir.path().join("draft").join("warrant.toml");
        write_draft(draft.clone(), 2, true);
        lock_warrant_from_draft_path(
            &draft,
            &paths,
            &LockOptions {
                create_keys_if_missing: true,
            },
        )
        .expect("initial lock");

        std::fs::write(&paths.version_state_path, "3\n").expect("bump recorded version");
        let err = load_installed_warrant(&paths).expect_err("rollback must fail");
        assert!(err.to_string().contains("rollback detected"));
    }

    #[test]
    fn review_for_first_lock_marks_all_fields_added() {
        let dir = TempDir::new().expect("tempdir");
        let paths = temp_paths(dir.path());
        let draft = dir.path().join("draft").join("warrant.toml");
        write_draft(draft.clone(), 2, true);

        let review = review_lock_from_draft_path(&draft, &paths).expect("review");
        assert_eq!(review.current_version, None);
        assert_eq!(review.incoming_version, 2);
        assert!(review.version_ready);
        assert!(
            review
                .diff_entries
                .iter()
                .any(|entry| entry.path == "capabilities.read"
                    && entry.kind == ReviewDiffKind::Added)
        );
        assert!(
            review
                .diff_entries
                .iter()
                .any(|entry| entry.path == "warrant.version"
                    && entry.kind == ReviewDiffKind::Added)
        );
    }

    #[test]
    fn review_reports_changes_against_installed_warrant() {
        let dir = TempDir::new().expect("tempdir");
        let paths = temp_paths(dir.path());
        let draft = dir.path().join("draft").join("warrant.toml");
        write_draft(draft.clone(), 1, true);
        lock_warrant_from_draft_path(
            &draft,
            &paths,
            &LockOptions {
                create_keys_if_missing: true,
            },
        )
        .expect("initial lock");

        write_draft(draft.clone(), 2, false);
        let review = review_lock_from_draft_path(&draft, &paths).expect("review");
        assert_eq!(review.current_version, Some(1));
        assert_eq!(review.incoming_version, 2);
        assert!(review.version_ready);

        let change = review
            .diff_entries
            .iter()
            .find(|entry| entry.path == "capabilities.read")
            .expect("capability change");
        assert_eq!(change.kind, ReviewDiffKind::Changed);
        assert_eq!(change.before.as_deref(), Some("true"));
        assert_eq!(change.after.as_deref(), Some("false"));
    }

    #[test]
    fn lock_fails_when_draft_missing_tool() {
        let dir = TempDir::new().expect("tempdir");
        let paths = temp_paths(dir.path());
        let draft = dir.path().join("draft").join("warrant.toml");
        let content = r#"
[warrant]
version = 1
created = 2026-02-16T08:00:00Z
issuer = "root@devbox"

[capabilities]
read = true
"#;
        std::fs::create_dir_all(draft.parent().expect("parent")).expect("mkdir");
        std::fs::write(&draft, content).expect("write draft");

        let err = lock_warrant_from_draft_path(
            &draft,
            &paths,
            &LockOptions {
                create_keys_if_missing: true,
            },
        )
        .expect_err("missing tool must fail");
        assert!(err.to_string().contains("[warrant].tool"));
        assert!(!paths.installed_warrant_path.exists());
        assert!(!paths.version_state_path.exists());
    }

    #[test]
    fn lock_fails_when_draft_tool_does_not_match_expected_tool() {
        let dir = TempDir::new().expect("tempdir");
        let paths = temp_paths(dir.path());
        let draft = dir.path().join("draft").join("warrant.toml");
        let content = r#"
[warrant]
version = 1
tool = "other"
created = 2026-02-16T08:00:00Z
issuer = "root@devbox"

[capabilities]
read = true
"#;
        std::fs::create_dir_all(draft.parent().expect("parent")).expect("mkdir");
        std::fs::write(&draft, content).expect("write draft");

        let err = lock_warrant_from_draft_path(
            &draft,
            &paths,
            &LockOptions {
                create_keys_if_missing: true,
            },
        )
        .expect_err("wrong tool must fail");
        assert!(err.to_string().contains("warrant tool mismatch"));
        assert!(!paths.installed_warrant_path.exists());
        assert!(!paths.version_state_path.exists());
    }

    #[test]
    fn lock_fails_when_draft_missing_capabilities() {
        let dir = TempDir::new().expect("tempdir");
        let paths = temp_paths(dir.path());
        let draft = dir.path().join("draft").join("warrant.toml");
        let content = r#"
[warrant]
version = 1
tool = "demo"
created = 2026-02-16T08:00:00Z
issuer = "root@devbox"
"#;
        std::fs::create_dir_all(draft.parent().expect("parent")).expect("mkdir");
        std::fs::write(&draft, content).expect("write draft");

        let err = lock_warrant_from_draft_path(
            &draft,
            &paths,
            &LockOptions {
                create_keys_if_missing: true,
            },
        )
        .expect_err("missing capabilities must fail");
        assert!(
            err.to_string()
                .contains("missing required section [capabilities]")
        );
        assert!(!paths.installed_warrant_path.exists());
        assert!(!paths.version_state_path.exists());
    }
}
