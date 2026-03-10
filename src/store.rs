use std::fs::OpenOptions;
use std::io::Write;
use std::path::Path;
#[cfg(target_os = "windows")]
use std::sync::Once;

use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
use ed25519_dalek::{SigningKey, VerifyingKey};
use rand::RngCore;
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};

use crate::error::{Error, Result};

const KEY_FILE_FORMAT_VERSION: u64 = 1;
const KEY_FILE_ALGORITHM: &str = "ed25519";
const KEY_FILE_ENCODING: &str = "base64";
const KEY_KIND_PRIVATE: &str = "private";
const KEY_KIND_PUBLIC: &str = "public";

#[derive(Debug, Clone, Serialize, Deserialize)]
struct SigningKeyFile {
    format_version: u64,
    algorithm: String,
    kind: String,
    encoding: String,
    value: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct SigningKeyFileRoot {
    signing_key: SigningKeyFile,
}

pub fn write_text_atomic(path: &Path, content: &str) -> Result<()> {
    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    std::fs::create_dir_all(parent)?;
    sync_dir(parent)?;

    let stem = path.file_name().and_then(|n| n.to_str()).unwrap_or("tmp");
    for _ in 0..32 {
        let mut nonce = [0_u8; 8];
        OsRng.fill_bytes(&mut nonce);
        let tmp_name = format!(".{stem}.{:016x}.tmp", u64::from_be_bytes(nonce));
        let tmp_path = parent.join(tmp_name);

        let mut file = match OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&tmp_path)
        {
            Ok(file) => file,
            Err(err) if err.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(err) => return Err(err.into()),
        };

        if let Err(err) = file.write_all(content.as_bytes()) {
            let _ = std::fs::remove_file(&tmp_path);
            return Err(err.into());
        }
        if let Err(err) = file.sync_all() {
            let _ = std::fs::remove_file(&tmp_path);
            return Err(err.into());
        }
        drop(file);

        if let Err(err) = std::fs::rename(&tmp_path, path) {
            let _ = std::fs::remove_file(&tmp_path);
            return Err(err.into());
        }
        if let Err(err) = sync_dir(parent) {
            let _ = std::fs::remove_file(&tmp_path);
            return Err(err);
        }

        return Ok(());
    }

    Err(std::io::Error::new(
        std::io::ErrorKind::AlreadyExists,
        format!("failed to allocate unique temp file for {}", path.display()),
    )
    .into())
}

pub fn read_version_state(path: &Path) -> Result<Option<u64>> {
    if !path.exists() {
        return Ok(None);
    }
    let raw = std::fs::read_to_string(path)?;
    let parsed = raw
        .trim()
        .parse::<u64>()
        .map_err(|_| Error::InvalidFieldType {
            section: "version_state",
            field: "version",
            expected: "u64 integer",
        })?;
    Ok(Some(parsed))
}

pub fn write_version_state(path: &Path, version: u64) -> Result<()> {
    write_text_atomic(path, &format!("{version}\n"))
}

pub fn ensure_signing_keys(private_key_path: &Path, public_key_path: &Path) -> Result<()> {
    if private_key_path.exists() && public_key_path.exists() {
        set_private_file_permissions(private_key_path)?;
        set_public_file_permissions(public_key_path)?;
        verify_private_file_permissions(private_key_path)?;
        verify_public_file_permissions(public_key_path)?;
        return Ok(());
    }
    let parent = private_key_path.parent().unwrap_or_else(|| Path::new("."));
    std::fs::create_dir_all(parent)?;
    set_owner_dir_permissions(parent)?;
    verify_owner_dir_permissions(parent)?;

    let mut secret = [0_u8; 32];
    OsRng.fill_bytes(&mut secret);
    let signing_key = SigningKey::from_bytes(&secret);
    let verifying_key = signing_key.verifying_key();

    write_key_file(private_key_path, KEY_KIND_PRIVATE, &signing_key.to_bytes())?;
    set_private_file_permissions(private_key_path)?;
    verify_private_file_permissions(private_key_path)?;

    write_key_file(public_key_path, KEY_KIND_PUBLIC, &verifying_key.to_bytes())?;
    set_public_file_permissions(public_key_path)?;
    verify_public_file_permissions(public_key_path)?;

    Ok(())
}

pub fn read_signing_key(path: &Path) -> Result<SigningKey> {
    if !path.exists() {
        return Err(Error::MissingPrivateKey(path.display().to_string()));
    }
    verify_private_file_permissions(path)?;
    let key_bytes = read_key_bytes(path, KEY_KIND_PRIVATE)?;
    Ok(SigningKey::from_bytes(&key_bytes))
}

pub fn read_verifying_key(path: &Path) -> Result<VerifyingKey> {
    if !path.exists() {
        return Err(Error::MissingPublicKey(path.display().to_string()));
    }
    verify_public_file_permissions(path)?;
    let key_bytes = read_key_bytes(path, KEY_KIND_PUBLIC)?;
    VerifyingKey::from_bytes(&key_bytes)
        .map_err(|_| Error::InvalidKeyFile(path.display().to_string()))
}

pub fn set_owner_dir_permissions(path: &Path) -> Result<()> {
    #[cfg(all(not(target_os = "windows"), unix))]
    {
        use std::os::unix::fs::PermissionsExt;
        // 0o755: directory must be traversable by non-root so the public key
        // can be read for daemon ping verification. Private key is protected
        // by its own 0o600 permissions.
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o755))?;
    }
    #[cfg(target_os = "windows")]
    {
        warn_windows_permission_stub("directory permissions");
    }
    let _ = path;
    Ok(())
}

pub fn set_private_file_permissions(path: &Path) -> Result<()> {
    #[cfg(all(not(target_os = "windows"), unix))]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
    }
    #[cfg(target_os = "windows")]
    {
        warn_windows_permission_stub("private file permissions");
    }
    let _ = path;
    Ok(())
}

pub fn set_public_file_permissions(path: &Path) -> Result<()> {
    #[cfg(all(not(target_os = "windows"), unix))]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o644))?;
    }
    #[cfg(target_os = "windows")]
    {
        warn_windows_permission_stub("public file permissions");
    }
    let _ = path;
    Ok(())
}

pub fn verify_owner_dir_permissions(path: &Path) -> Result<()> {
    #[cfg(all(not(target_os = "windows"), unix))]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(path)?.permissions().mode() & 0o777;
        // Allow 0o755 (traversable) — private key is protected by its own 0o600.
        // Reject any write access by group/other.
        if mode & 0o022 != 0 {
            return Err(Error::InsecurePermissions {
                path: path.display().to_string(),
                details: format!("directory must not be writable by group/other (got {mode:o})"),
            });
        }
    }
    #[cfg(target_os = "windows")]
    {
        warn_windows_permission_stub("directory verification");
    }
    let _ = path;
    Ok(())
}

pub fn verify_private_file_permissions(path: &Path) -> Result<()> {
    #[cfg(all(not(target_os = "windows"), unix))]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(path)?.permissions().mode() & 0o777;
        if mode & 0o077 != 0 {
            return Err(Error::InsecurePermissions {
                path: path.display().to_string(),
                details: format!("expected private file (mode 0600), got {mode:o}"),
            });
        }
    }
    #[cfg(target_os = "windows")]
    {
        warn_windows_permission_stub("private file verification");
    }
    let _ = path;
    Ok(())
}

pub fn verify_public_file_permissions(path: &Path) -> Result<()> {
    #[cfg(all(not(target_os = "windows"), unix))]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(path)?.permissions().mode() & 0o777;
        if mode & 0o022 != 0 {
            return Err(Error::InsecurePermissions {
                path: path.display().to_string(),
                details: format!(
                    "expected non-world-writable public key (mode 0644), got {mode:o}"
                ),
            });
        }
    }
    #[cfg(target_os = "windows")]
    {
        warn_windows_permission_stub("public file verification");
    }
    let _ = path;
    Ok(())
}

fn write_key_file(path: &Path, kind: &str, key_bytes: &[u8; 32]) -> Result<()> {
    let root = SigningKeyFileRoot {
        signing_key: SigningKeyFile {
            format_version: KEY_FILE_FORMAT_VERSION,
            algorithm: KEY_FILE_ALGORITHM.to_string(),
            kind: kind.to_string(),
            encoding: KEY_FILE_ENCODING.to_string(),
            value: BASE64_STANDARD.encode(key_bytes),
        },
    };
    let toml = toml::to_string_pretty(&root)
        .map_err(|_| Error::InvalidKeyFile(path.display().to_string()))?;
    write_text_atomic(path, &toml)
}

fn read_key_bytes(path: &Path, expected_kind: &'static str) -> Result<[u8; 32]> {
    let raw = std::fs::read_to_string(path)?;
    // Primary format: versioned metadata TOML.
    if let Ok(root) = toml::from_str::<SigningKeyFileRoot>(&raw) {
        return validate_key_root(path, &root, expected_kind);
    }
    // Backward compatibility: legacy plain base64 file contents.
    decode_key_bytes(path, raw.trim())
}

fn validate_key_root(
    path: &Path,
    root: &SigningKeyFileRoot,
    expected_kind: &'static str,
) -> Result<[u8; 32]> {
    let key = &root.signing_key;
    if key.format_version != KEY_FILE_FORMAT_VERSION {
        return Err(Error::UnsupportedKeyFormatVersion {
            path: path.display().to_string(),
            version: key.format_version,
        });
    }
    if !key.algorithm.eq_ignore_ascii_case(KEY_FILE_ALGORITHM) {
        return Err(Error::KeyAlgorithmMismatch {
            path: path.display().to_string(),
            expected: KEY_FILE_ALGORITHM,
            actual: key.algorithm.clone(),
        });
    }
    if !key.kind.eq_ignore_ascii_case(expected_kind) {
        return Err(Error::KeyKindMismatch {
            path: path.display().to_string(),
            expected: expected_kind,
            actual: key.kind.clone(),
        });
    }
    if !key.encoding.eq_ignore_ascii_case(KEY_FILE_ENCODING) {
        return Err(Error::InvalidKeyFile(path.display().to_string()));
    }
    decode_key_bytes(path, &key.value)
}

fn decode_key_bytes(path: &Path, encoded: &str) -> Result<[u8; 32]> {
    let bytes = BASE64_STANDARD
        .decode(encoded.trim())
        .map_err(|_| Error::InvalidKeyFile(path.display().to_string()))?;
    bytes
        .as_slice()
        .try_into()
        .map_err(|_| Error::InvalidKeyFile(path.display().to_string()))
}

#[cfg(not(target_os = "windows"))]
fn sync_dir(path: &Path) -> Result<()> {
    let dir = std::fs::File::open(path)?;
    dir.sync_all()?;
    Ok(())
}

#[cfg(target_os = "windows")]
fn sync_dir(path: &Path) -> Result<()> {
    let _ = path;
    Ok(())
}

#[cfg(target_os = "windows")]
fn warn_windows_permission_stub(scope: &str) {
    static ONCE: Once = Once::new();
    ONCE.call_once(|| {
        eprintln!(
            "warrant-core warning: Windows ACL enforcement is not implemented ({}); permission checks are stubbed",
            scope
        );
    });
}

#[cfg(test)]
mod tests {
    use tempfile::TempDir;

    use super::{ensure_signing_keys, read_signing_key, read_verifying_key};

    #[test]
    fn keypair_files_are_created_with_metadata() {
        let dir = TempDir::new().expect("tempdir");
        let private = dir.path().join("signing").join("private.key");
        let public = dir.path().join("signing").join("public.key");
        ensure_signing_keys(&private, &public).expect("keys");
        assert!(private.exists());
        assert!(public.exists());

        let private_text = std::fs::read_to_string(&private).expect("private text");
        assert!(private_text.contains("format_version = 1"));
        assert!(private_text.contains("algorithm = \"ed25519\""));
        assert!(private_text.contains("kind = \"private\""));

        let public_text = std::fs::read_to_string(&public).expect("public text");
        assert!(public_text.contains("kind = \"public\""));
    }

    #[test]
    fn key_files_can_be_read_back() {
        let dir = TempDir::new().expect("tempdir");
        let private = dir.path().join("signing").join("private.key");
        let public = dir.path().join("signing").join("public.key");
        ensure_signing_keys(&private, &public).expect("keys");
        let _ = read_signing_key(&private).expect("read signing key");
        let _ = read_verifying_key(&public).expect("read verifying key");
    }
}
