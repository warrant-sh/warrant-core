use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use hmac::{Hmac, Mac};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use sha2::Sha256;

use crate::error::{Error, Result};
use crate::paths::ToolPaths;
use crate::store::{
    set_owner_dir_permissions, set_private_file_permissions, verify_owner_dir_permissions,
    verify_private_file_permissions, write_text_atomic,
};

type HmacSha256 = Hmac<Sha256>;

#[derive(Debug, Clone, Serialize, Deserialize)]
struct SessionToken {
    uid: u32,
    created_at_epoch_secs: u64,
    expires_at_epoch_secs: u64,
    #[serde(default)]
    last_seen_epoch_secs: Option<u64>,
    mac: Option<String>,
}

#[derive(Debug, Clone, Copy)]
pub struct ElevationOptions {
    pub duration: Duration,
}

impl Default for ElevationOptions {
    fn default() -> Self {
        Self {
            duration: Duration::from_secs(30 * 60),
        }
    }
}

pub fn create_elevation_session(
    paths: &ToolPaths,
    uid: u32,
    options: ElevationOptions,
) -> Result<()> {
    let host_secret = load_or_create_host_secret(paths)?;
    let now = now_epoch_secs();
    let duration_secs = options.duration.as_secs();
    let expires_at_epoch_secs = now.saturating_add(duration_secs);
    let token = SessionToken {
        uid,
        created_at_epoch_secs: now,
        expires_at_epoch_secs,
        last_seen_epoch_secs: Some(now),
        mac: Some(compute_mac_hex(
            &host_secret,
            uid,
            expires_at_epoch_secs,
            &current_host_binding(),
        )?),
    };
    let path = session_token_path(paths, uid);
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
        set_owner_dir_permissions(parent)?;
        verify_owner_dir_permissions(parent)?;
    }
    write_session_token(&path, &token)?;
    Ok(())
}

pub fn clear_elevation_session(paths: &ToolPaths, uid: u32) -> Result<()> {
    let path = session_token_path(paths, uid);
    if path.exists() {
        std::fs::remove_file(path)?;
    }
    Ok(())
}

pub fn is_elevated(paths: &ToolPaths, uid: u32) -> Result<bool> {
    let path = session_token_path(paths, uid);
    if !path.exists() {
        return Ok(false);
    }
    let Some(host_secret) = load_host_secret_if_exists(paths)? else {
        return Ok(false);
    };
    verify_private_file_permissions(&path)?;
    let mut token = match read_session_token(&path) {
        Ok(token) => token,
        Err(err) => {
            eprintln!(
                "warrant-core warning: failed to parse elevation token at {}: {err}",
                path.display()
            );
            return Ok(false);
        }
    };
    if token.uid != uid {
        return Ok(false);
    }
    let Some(mac_hex) = token.mac.as_deref() else {
        eprintln!(
            "warrant-core warning: elevation token at {} is missing mac",
            path.display()
        );
        return Ok(false);
    };
    let host_binding = current_host_binding();
    if !verify_mac_hex(
        &host_secret,
        token.uid,
        token.expires_at_epoch_secs,
        &host_binding,
        mac_hex,
    )? {
        eprintln!(
            "warrant-core warning: elevation token at {} has invalid mac",
            path.display()
        );
        return Ok(false);
    }
    let now = now_epoch_secs();
    let last_seen = token
        .last_seen_epoch_secs
        .unwrap_or(token.created_at_epoch_secs);
    if now < last_seen {
        eprintln!(
            "warrant-core warning: elevation token at {} failed clock rollback check (now={} < last_seen={})",
            path.display(),
            now,
            last_seen
        );
        return Ok(false);
    }
    if now > token.expires_at_epoch_secs {
        return Ok(false);
    }
    if now > last_seen {
        token.last_seen_epoch_secs = Some(now);
        write_session_token(&path, &token)?;
    }
    Ok(true)
}

fn read_session_token(path: &Path) -> Result<SessionToken> {
    let raw = std::fs::read_to_string(path)?;
    let token: SessionToken =
        serde_json::from_str(&raw).map_err(|_| std::io::Error::other("json decode"))?;
    Ok(token)
}

fn write_session_token(path: &Path, token: &SessionToken) -> Result<()> {
    let text =
        serde_json::to_string_pretty(token).map_err(|_| std::io::Error::other("json encode"))?;
    write_text_atomic(path, &text)?;
    set_private_file_permissions(path)?;
    verify_private_file_permissions(path)?;
    Ok(())
}

fn session_token_path(paths: &ToolPaths, uid: u32) -> PathBuf {
    paths.session_dir_path.join(format!("session-{uid}"))
}

fn host_secret_path(paths: &ToolPaths) -> &Path {
    &paths.host_secret_path
}

fn load_or_create_host_secret(paths: &ToolPaths) -> Result<Vec<u8>> {
    if let Some(secret) = load_host_secret_if_exists(paths)? {
        return Ok(secret);
    }
    if !is_root_user() {
        return Err(Error::HostSecretMissing);
    }
    let path = host_secret_path(paths);
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
        set_owner_dir_permissions(parent)?;
        verify_owner_dir_permissions(parent)?;
    }
    let mut secret = [0_u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut secret);
    let encoded = hex_encode(&secret);
    write_text_atomic(path, &encoded)?;
    set_private_file_permissions(path)?;
    verify_private_file_permissions(path)?;
    Ok(secret.to_vec())
}

fn load_host_secret_if_exists(paths: &ToolPaths) -> Result<Option<Vec<u8>>> {
    let path = host_secret_path(paths);
    if !path.exists() {
        return Ok(None);
    }
    verify_private_file_permissions(path)?;
    let text = std::fs::read_to_string(path)?;
    let decoded =
        hex_decode(text.trim()).map_err(|_| std::io::Error::other("invalid host secret"))?;
    if decoded.len() != 32 {
        return Err(std::io::Error::other("invalid host secret length").into());
    }
    Ok(Some(decoded))
}

fn compute_mac_hex(
    secret: &[u8],
    uid: u32,
    expires_at_epoch_secs: u64,
    host_binding: &str,
) -> Result<String> {
    let payload = format!("{uid}:{expires_at_epoch_secs}:{host_binding}");
    let mut mac = HmacSha256::new_from_slice(secret)
        .map_err(|_| std::io::Error::other("invalid hmac key"))?;
    mac.update(payload.as_bytes());
    Ok(hex_encode(&mac.finalize().into_bytes()))
}

fn verify_mac_hex(
    secret: &[u8],
    uid: u32,
    expires_at_epoch_secs: u64,
    host_binding: &str,
    mac_hex: &str,
) -> Result<bool> {
    let payload = format!("{uid}:{expires_at_epoch_secs}:{host_binding}");
    let provided = match hex_decode(mac_hex) {
        Ok(bytes) => bytes,
        Err(_) => return Ok(false),
    };
    let mut mac = HmacSha256::new_from_slice(secret)
        .map_err(|_| std::io::Error::other("invalid hmac key"))?;
    mac.update(payload.as_bytes());
    Ok(mac.verify_slice(&provided).is_ok())
}

fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn hex_decode(text: &str) -> std::result::Result<Vec<u8>, ()> {
    if !text.len().is_multiple_of(2) {
        return Err(());
    }
    let mut out = Vec::with_capacity(text.len() / 2);
    let chars = text.as_bytes().chunks_exact(2);
    for chunk in chars {
        let hi = hex_nibble(chunk[0]).ok_or(())?;
        let lo = hex_nibble(chunk[1]).ok_or(())?;
        out.push((hi << 4) | lo);
    }
    Ok(out)
}

fn hex_nibble(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

fn is_root_user() -> bool {
    #[cfg(unix)]
    {
        // SAFETY: libc call has no preconditions.
        unsafe { libc::geteuid() == 0 }
    }
    #[cfg(not(unix))]
    {
        false
    }
}

fn now_epoch_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or(Duration::from_secs(0))
        .as_secs()
}

pub fn current_host_binding() -> String {
    machine_id()
        .or_else(hostname)
        .unwrap_or_else(|| "unknown-host".to_string())
}

fn machine_id() -> Option<String> {
    const CANDIDATES: [&str; 2] = ["/etc/machine-id", "/var/lib/dbus/machine-id"];
    for path in CANDIDATES {
        if let Ok(text) = std::fs::read_to_string(path) {
            let trimmed = text.trim();
            if !trimmed.is_empty() {
                return Some(trimmed.to_string());
            }
        }
    }
    None
}

fn hostname() -> Option<String> {
    #[cfg(unix)]
    {
        let mut buf = [0_u8; 256];
        // SAFETY: gethostname writes at most buf.len() bytes to the provided pointer.
        let rc = unsafe { libc::gethostname(buf.as_mut_ptr().cast::<libc::c_char>(), buf.len()) };
        if rc == 0 {
            let len = buf.iter().position(|b| *b == 0).unwrap_or(buf.len());
            if len > 0 {
                return String::from_utf8(buf[..len].to_vec()).ok();
            }
        }
    }
    if let Some(value) = std::env::var_os("HOSTNAME") {
        let value = value.to_string_lossy().trim().to_string();
        if !value.is_empty() {
            return Some(value);
        }
    }
    if let Some(value) = std::env::var_os("COMPUTERNAME") {
        let value = value.to_string_lossy().trim().to_string();
        if !value.is_empty() {
            return Some(value);
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use tempfile::TempDir;

    use crate::paths::ToolPaths;

    use super::{ElevationOptions, clear_elevation_session, create_elevation_session, is_elevated};

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

    fn write_host_key(paths: &ToolPaths, hex_byte: &str) {
        super::write_text_atomic(&paths.host_secret_path, &hex_byte.repeat(32)).expect("host key");
        super::set_private_file_permissions(&paths.host_secret_path).expect("chmod");
    }

    #[test]
    fn create_and_clear_session() {
        let dir = TempDir::new().expect("tempdir");
        let paths = temp_paths(dir.path());
        let uid = 1000;
        write_host_key(&paths, "11");

        assert!(!is_elevated(&paths, uid).expect("not elevated"));
        create_elevation_session(
            &paths,
            uid,
            ElevationOptions {
                duration: Duration::from_secs(120),
            },
        )
        .expect("create session");
        assert!(is_elevated(&paths, uid).expect("elevated"));

        clear_elevation_session(&paths, uid).expect("clear");
        assert!(!is_elevated(&paths, uid).expect("not elevated"));
    }

    #[test]
    fn expired_session_is_not_elevated() {
        let dir = TempDir::new().expect("tempdir");
        let paths = temp_paths(dir.path());
        let uid = 1000;
        write_host_key(&paths, "22");
        create_elevation_session(
            &paths,
            uid,
            ElevationOptions {
                duration: Duration::from_secs(120),
            },
        )
        .expect("create session");

        let session_path = super::session_token_path(&paths, uid);
        std::fs::write(
            session_path,
            r#"{"uid":1000,"created_at_epoch_secs":0,"expires_at_epoch_secs":0,"mac":"00"}"#,
        )
        .expect("rewrite token as expired");

        assert!(!is_elevated(&paths, uid).expect("expired session should not elevate"));
    }

    #[test]
    fn corrupt_session_token_is_not_elevated() {
        let dir = TempDir::new().expect("tempdir");
        let paths = temp_paths(dir.path());
        let uid = 1000;
        write_host_key(&paths, "33");
        create_elevation_session(
            &paths,
            uid,
            ElevationOptions {
                duration: Duration::from_secs(120),
            },
        )
        .expect("create session");

        let session_path = super::session_token_path(&paths, uid);
        std::fs::write(session_path, "{not-json").expect("corrupt token");
        assert!(!is_elevated(&paths, uid).expect("corrupt session should not elevate"));
    }

    #[test]
    fn created_session_token_contains_mac() {
        let dir = TempDir::new().expect("tempdir");
        let paths = temp_paths(dir.path());
        let uid = 1000;
        write_host_key(&paths, "44");

        create_elevation_session(
            &paths,
            uid,
            ElevationOptions {
                duration: Duration::from_secs(120),
            },
        )
        .expect("create session");

        let text =
            std::fs::read_to_string(super::session_token_path(&paths, uid)).expect("read token");
        assert!(text.contains("\"mac\""));
    }

    #[test]
    fn tampered_mac_is_not_elevated() {
        let dir = TempDir::new().expect("tempdir");
        let paths = temp_paths(dir.path());
        let uid = 1000;
        write_host_key(&paths, "55");
        create_elevation_session(
            &paths,
            uid,
            ElevationOptions {
                duration: Duration::from_secs(120),
            },
        )
        .expect("create session");

        let session_path = super::session_token_path(&paths, uid);
        let text = std::fs::read_to_string(&session_path).expect("read token");
        let tampered = text.replace("\"mac\": \"", "\"mac\": \"deadbeef");
        std::fs::write(session_path, tampered).expect("tamper");
        assert!(!is_elevated(&paths, uid).expect("tampered mac should fail"));
    }

    #[test]
    fn tampered_expiry_is_not_elevated() {
        let dir = TempDir::new().expect("tempdir");
        let paths = temp_paths(dir.path());
        let uid = 1000;
        write_host_key(&paths, "66");
        create_elevation_session(
            &paths,
            uid,
            ElevationOptions {
                duration: Duration::from_secs(120),
            },
        )
        .expect("create session");

        let session_path = super::session_token_path(&paths, uid);
        let mut token: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(&session_path).expect("read token"))
                .expect("json");
        token["expires_at_epoch_secs"] = serde_json::Value::from(4_000_000_000_u64);
        std::fs::write(
            session_path,
            serde_json::to_string_pretty(&token).expect("serialize"),
        )
        .expect("tamper");
        assert!(!is_elevated(&paths, uid).expect("tampered expiry should fail"));
    }

    #[test]
    fn missing_mac_is_not_elevated() {
        let dir = TempDir::new().expect("tempdir");
        let paths = temp_paths(dir.path());
        let uid = 1000;
        write_host_key(&paths, "77");
        create_elevation_session(
            &paths,
            uid,
            ElevationOptions {
                duration: Duration::from_secs(120),
            },
        )
        .expect("create session");

        let session_path = super::session_token_path(&paths, uid);
        let mut token: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(&session_path).expect("read token"))
                .expect("json");
        token.as_object_mut().expect("object").remove("mac");
        std::fs::write(
            session_path,
            serde_json::to_string_pretty(&token).expect("serialize"),
        )
        .expect("rewrite");
        assert!(!is_elevated(&paths, uid).expect("missing mac should fail"));
    }

    #[test]
    fn clock_rollback_rejects_session() {
        let dir = TempDir::new().expect("tempdir");
        let paths = temp_paths(dir.path());
        let uid = 1000;
        write_host_key(&paths, "88");
        create_elevation_session(
            &paths,
            uid,
            ElevationOptions {
                duration: Duration::from_secs(120),
            },
        )
        .expect("create session");

        let session_path = super::session_token_path(&paths, uid);
        let mut token: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(&session_path).expect("read token"))
                .expect("json");
        token["last_seen_epoch_secs"] = serde_json::Value::from(u64::MAX);
        std::fs::write(
            session_path,
            serde_json::to_string_pretty(&token).expect("serialize"),
        )
        .expect("rewrite");

        assert!(!is_elevated(&paths, uid).expect("rollback check should fail"));
    }
}
