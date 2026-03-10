use crate::error::{Error, Result};
use crate::model::{ParsedWarrant, SignatureBlock, WarrantMeta};
use crate::payload::{section_to_json, unsigned_payload_from_root};

pub fn parse_toml_warrant(input: &str) -> Result<ParsedWarrant> {
    let root_toml: toml::Value = toml::from_str(input)?;
    let root_table = root_toml.as_table().ok_or(Error::InvalidRoot)?;

    let warrant_table = root_table
        .get("warrant")
        .ok_or(Error::MissingSection("warrant"))?
        .as_table()
        .ok_or(Error::InvalidSectionType("warrant"))?;
    if !root_table.contains_key("capabilities") {
        return Err(Error::MissingSection("capabilities"));
    }
    let signature_table = root_table
        .get("signature")
        .ok_or(Error::MissingSection("signature"))?
        .as_table()
        .ok_or(Error::InvalidSectionType("signature"))?;

    let version_i64 = warrant_table
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
    let version = u64::try_from(version_i64).map_err(|_| Error::InvalidVersion)?;

    let tool = required_string(warrant_table, "warrant", "tool")?;
    let created = required_string_or_datetime(warrant_table, "warrant", "created")?;
    let issuer = required_string(warrant_table, "warrant", "issuer")?;

    let signature = SignatureBlock {
        algorithm: required_string(signature_table, "signature", "algorithm")?,
        public_key_b64: required_string(signature_table, "signature", "public_key")?,
        value_b64: required_string(signature_table, "signature", "value")?,
    };

    let capabilities = section_to_json(&root_toml, "capabilities")?;
    let unsigned_payload = unsigned_payload_from_root(&root_toml)?;

    let meta = WarrantMeta {
        version,
        tool,
        created,
        issuer,
    };

    ParsedWarrant::new(meta, capabilities, signature, unsigned_payload)
}

fn required_string(
    table: &toml::value::Table,
    section: &'static str,
    field: &'static str,
) -> Result<String> {
    let value = table
        .get(field)
        .ok_or(Error::MissingField { section, field })?;
    value
        .as_str()
        .map(ToOwned::to_owned)
        .ok_or(Error::InvalidFieldType {
            section,
            field,
            expected: "string",
        })
}

fn required_string_or_datetime(
    table: &toml::value::Table,
    section: &'static str,
    field: &'static str,
) -> Result<String> {
    let value = table
        .get(field)
        .ok_or(Error::MissingField { section, field })?;
    if let Some(s) = value.as_str() {
        return Ok(s.to_owned());
    }
    if let toml::Value::Datetime(dt) = value {
        return Ok(dt.to_string());
    }
    Err(Error::InvalidFieldType {
        section,
        field,
        expected: "string or datetime",
    })
}

#[cfg(test)]
mod tests {
    use base64::Engine;
    use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
    use ed25519_dalek::{Signer, SigningKey};

    use crate::{canonical_json_bytes, parse_toml_warrant, verify_toml_warrant};

    fn sign_unsigned(unsigned: &str) -> String {
        let pubkey_placeholder = BASE64_STANDARD.encode([0_u8; 32]);
        let sig_placeholder = BASE64_STANDARD.encode([0_u8; 64]);
        let template = format!(
            r#"{unsigned}

[signature]
algorithm = "ed25519"
public_key = "{pubkey}"
value = "{sig}"
"#,
            pubkey = pubkey_placeholder,
            sig = sig_placeholder
        );

        let parsed = parse_toml_warrant(&template).expect("parse with placeholders");
        let payload = canonical_json_bytes(&parsed.unsigned_payload).expect("canonical payload");

        let secret = [7_u8; 32];
        let signing_key = SigningKey::from_bytes(&secret);
        let verify_key = signing_key.verifying_key();
        let sig = signing_key.sign(&payload);

        format!(
            r#"{unsigned}

[signature]
algorithm = "ed25519"
public_key = "{}"
value = "{}"
"#,
            BASE64_STANDARD.encode(verify_key.as_bytes()),
            BASE64_STANDARD.encode(sig.to_bytes())
        )
    }

    fn signed_doc() -> String {
        let unsigned = r#"
[warrant]
version = 1
tool = "ratmail"
created = 2026-02-16T08:00:00Z
issuer = "root@devbox"

[capabilities]
read = true
delete = false
accounts = ["Personal", "Work"]
"#;

        sign_unsigned(unsigned)
    }

    #[test]
    fn parse_and_verify_success() {
        let input = signed_doc();
        let parsed = verify_toml_warrant(&input).expect("verify");
        assert_eq!(parsed.meta.tool, "ratmail");
        assert_eq!(parsed.meta.version, 1);
    }

    #[test]
    fn verify_detects_tampering() {
        let input = signed_doc().replace("delete = false", "delete = true");
        let err = verify_toml_warrant(&input).expect_err("must fail");
        assert_eq!(err.to_string(), "signature verification failed");
    }

    #[test]
    fn canonical_payload_is_order_independent() {
        let first = r#"
[warrant]
version = 1
tool = "t"
created = 2026-02-16T08:00:00Z
issuer = "root"

[capabilities]
b = true
a = false

[signature]
algorithm = "ed25519"
public_key = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
value = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=="
"#;
        let second = r#"
[capabilities]
a = false
b = true

[warrant]
issuer = "root"
tool = "t"
version = 1
created = 2026-02-16T08:00:00Z

[signature]
algorithm = "ed25519"
public_key = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
value = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=="
"#;

        let one = parse_toml_warrant(first).expect("parse");
        let two = parse_toml_warrant(second).expect("parse");
        let one_bytes = canonical_json_bytes(&one.unsigned_payload).expect("canonical");
        let two_bytes = canonical_json_bytes(&two.unsigned_payload).expect("canonical");
        assert_eq!(one_bytes, two_bytes);
    }

    #[test]
    fn signature_covers_extension_sections() {
        let unsigned = r#"
[warrant]
version = 1
tool = "ratmail"
created = 2026-02-16T08:00:00Z
issuer = "root@devbox"

[capabilities]
read = true

[ratmail]
profile = "safe"
"#;
        let signed_with_extension = sign_unsigned(unsigned);
        verify_toml_warrant(&signed_with_extension).expect("extension included in signed payload");

        let tampered = signed_with_extension.replace("profile = \"safe\"", "profile = \"unsafe\"");
        let err = verify_toml_warrant(&tampered).expect_err("extension tamper must fail");
        assert_eq!(err.to_string(), "signature verification failed");
    }
}
