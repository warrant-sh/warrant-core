use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
use ed25519_dalek::{Signer, SigningKey};
use warrant_core::{CheckContext, Decision, check, parse_toml_warrant, verify_toml_warrant};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let unsigned = r#"
[warrant]
version = 1
tool = "demo"
created = 2026-02-16T08:00:00Z
issuer = "root@devbox"

[capabilities]
read = true
send = { allow = true, to_domains = ["*@example.com"] }
"#;

    let with_placeholder = format!(
        r#"{unsigned}

[signature]
algorithm = "ed25519"
public_key = "{}"
value = "{}"
"#,
        BASE64_STANDARD.encode([0_u8; 32]),
        BASE64_STANDARD.encode([0_u8; 64]),
    );

    let parsed = parse_toml_warrant(&with_placeholder)?;
    let payload = parsed.canonical_payload_bytes()?;

    let signing_key = SigningKey::from_bytes(&[42_u8; 32]);
    let verifying_key = signing_key.verifying_key();
    let signature = signing_key.sign(&payload);

    let signed = format!(
        r#"{unsigned}

[signature]
algorithm = "ed25519"
public_key = "{}"
value = "{}"
"#,
        BASE64_STANDARD.encode(verifying_key.to_bytes()),
        BASE64_STANDARD.encode(signature.to_bytes()),
    );

    let warrant = verify_toml_warrant(&signed)?;
    let ctx = CheckContext::new().with_str("to_domains", "alice@example.com");
    match check(&warrant, "send", &ctx) {
        Decision::Allow => println!("allowed"),
        Decision::Deny(reason) => println!("denied: {reason}"),
    }

    Ok(())
}
