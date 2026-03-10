use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
use ed25519_dalek::{Signature, VerifyingKey};

use crate::error::{Error, Result};

pub fn verify_ed25519_signature(
    public_key_b64: &str,
    message: &[u8],
    signature_b64: &str,
) -> Result<()> {
    let public_key_bytes =
        BASE64_STANDARD
            .decode(public_key_b64.trim())
            .map_err(|_| Error::InvalidBase64 {
                field: "signature.public_key",
            })?;
    let signature_bytes =
        BASE64_STANDARD
            .decode(signature_b64.trim())
            .map_err(|_| Error::InvalidBase64 {
                field: "signature.value",
            })?;

    let public_key_array: [u8; 32] = public_key_bytes
        .as_slice()
        .try_into()
        .map_err(|_| Error::InvalidPublicKeyLength)?;
    let verifying_key =
        VerifyingKey::from_bytes(&public_key_array).map_err(|_| Error::InvalidPublicKeyLength)?;
    let signature = Signature::try_from(signature_bytes.as_slice())
        .map_err(|_| Error::InvalidSignatureBytes)?;

    verifying_key
        .verify_strict(message, &signature)
        .map_err(|_| Error::SignatureVerificationFailed)
}

#[cfg(test)]
mod tests {
    use super::verify_ed25519_signature;
    use base64::Engine;
    use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
    use ed25519_dalek::{Signer, SigningKey};

    #[test]
    fn verifies_valid_signature() {
        let signing_key = SigningKey::from_bytes(&[42u8; 32]);
        let message = b"warrant payload";
        let signature = signing_key.sign(message);
        let public_key_b64 = BASE64_STANDARD.encode(signing_key.verifying_key().to_bytes());
        let signature_b64 = BASE64_STANDARD.encode(signature.to_bytes());

        verify_ed25519_signature(&public_key_b64, message, &signature_b64)
            .expect("valid signature should verify");
    }

    #[test]
    fn rejects_signature_for_different_message() {
        let signing_key = SigningKey::from_bytes(&[99u8; 32]);
        let message = b"warrant payload";
        let signature = signing_key.sign(message);
        let public_key_b64 = BASE64_STANDARD.encode(signing_key.verifying_key().to_bytes());
        let signature_b64 = BASE64_STANDARD.encode(signature.to_bytes());

        verify_ed25519_signature(&public_key_b64, b"different payload", &signature_b64)
            .expect_err("signature must fail on different message");
    }
}
