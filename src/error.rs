use thiserror::Error;

pub type Result<T> = std::result::Result<T, Error>;

#[derive(Debug, Error)]
pub enum Error {
    #[error("warrant document must be a TOML table")]
    InvalidRoot,
    #[error("invalid tool identifier \"{0}\"")]
    InvalidToolId(String),
    #[error("missing required section [{0}]")]
    MissingSection(&'static str),
    #[error("section [{0}] must be a TOML table")]
    InvalidSectionType(&'static str),
    #[error("missing required field [{section}].{field}")]
    MissingField {
        section: &'static str,
        field: &'static str,
    },
    #[error("invalid field type for [{section}].{field}: expected {expected}")]
    InvalidFieldType {
        section: &'static str,
        field: &'static str,
        expected: &'static str,
    },
    #[error("warrant version must be non-negative")]
    InvalidVersion,
    #[error("unsupported signature algorithm: {0}")]
    UnsupportedAlgorithm(String),
    #[error("base64 decode failed for {field}")]
    InvalidBase64 { field: &'static str },
    #[error("invalid ed25519 public key length")]
    InvalidPublicKeyLength,
    #[error("invalid ed25519 signature")]
    InvalidSignatureBytes,
    #[error("signature verification failed")]
    SignatureVerificationFailed,
    #[error("warrant signature public key does not match trusted signing/public.key")]
    PublicKeyMismatch,
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("signing private key is missing at {0}")]
    MissingPrivateKey(String),
    #[error("signing public key is missing at {0}")]
    MissingPublicKey(String),
    #[error("invalid signing key file format at {0}")]
    InvalidKeyFile(String),
    #[error("unsupported key file format version {version} at {path}")]
    UnsupportedKeyFormatVersion { path: String, version: u64 },
    #[error("key file algorithm mismatch at {path}: expected {expected}, got {actual}")]
    KeyAlgorithmMismatch {
        path: String,
        expected: &'static str,
        actual: String,
    },
    #[error("key file kind mismatch at {path}: expected {expected}, got {actual}")]
    KeyKindMismatch {
        path: String,
        expected: &'static str,
        actual: String,
    },
    #[error("insecure file permissions at {path}: {details}")]
    InsecurePermissions { path: String, details: String },
    #[error(
        "incoming version must be strictly greater than installed version (current={current}, incoming={incoming})"
    )]
    NonIncrementalVersion { current: u64, incoming: u64 },
    #[error("Version {version} exceeds maximum allowed ({max}). Use emergency reset if needed.")]
    VersionExceedsMaximum { version: u64, max: u64 },
    #[error(
        "rollback detected: installed warrant version {warrant} is less than recorded version {recorded}"
    )]
    RollbackDetected { warrant: u64, recorded: u64 },
    #[error("Host secret not found. Run: sudo wsh elevate")]
    HostSecretMissing,
    #[error(
        "warrant tool mismatch: expected \"{expected}\" but installed warrant is for \"{found}\"; lock and install a warrant for the correct tool"
    )]
    ToolMismatch { expected: String, found: String },
    #[error("cannot parse TOML: {0}")]
    TomlParse(#[from] toml::de::Error),
    #[error("invalid JSON number in canonical payload")]
    InvalidJsonNumber,
}
