use serde_json::Value;

use crate::canonical::canonical_json_bytes;
use crate::crypto::verify_ed25519_signature;
use crate::error::{Error, Result};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WarrantMeta {
    pub version: u64,
    pub tool: String,
    pub created: String,
    pub issuer: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignatureBlock {
    pub algorithm: String,
    pub public_key_b64: String,
    pub value_b64: String,
}

#[derive(Debug, Clone, PartialEq)]
pub struct ParsedWarrant {
    pub meta: WarrantMeta,
    pub capabilities: Value,
    /// Canonicalization source object, excluding `[signature]`.
    pub unsigned_payload: Value,
    pub signature: SignatureBlock,
}

impl ParsedWarrant {
    pub fn canonical_payload_bytes(&self) -> Result<Vec<u8>> {
        canonical_json_bytes(&self.unsigned_payload)
    }

    pub fn verify_signature(&self) -> Result<()> {
        if !self.signature.algorithm.eq_ignore_ascii_case("ed25519") {
            return Err(Error::UnsupportedAlgorithm(
                self.signature.algorithm.clone(),
            ));
        }
        let payload = self.canonical_payload_bytes()?;
        verify_ed25519_signature(
            &self.signature.public_key_b64,
            &payload,
            &self.signature.value_b64,
        )
    }

    pub(crate) fn new(
        meta: WarrantMeta,
        capabilities: Value,
        signature: SignatureBlock,
        unsigned_payload: Value,
    ) -> Result<Self> {
        if !unsigned_payload.is_object() {
            return Err(Error::InvalidRoot);
        }
        Ok(Self {
            meta,
            capabilities,
            unsigned_payload,
            signature,
        })
    }
}
