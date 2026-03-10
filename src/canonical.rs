use serde_json::{Map, Value};

use crate::error::{Error, Result};

/// Produce deterministic canonical JSON bytes.
///
/// Objects are emitted with lexicographically sorted keys and no whitespace.
pub fn canonical_json_bytes(value: &Value) -> Result<Vec<u8>> {
    let mut out = String::new();
    write_value(value, &mut out)?;
    Ok(out.into_bytes())
}

fn write_value(value: &Value, out: &mut String) -> Result<()> {
    match value {
        Value::Null => out.push_str("null"),
        Value::Bool(b) => out.push_str(if *b { "true" } else { "false" }),
        Value::Number(n) => {
            if let Some(f) = n.as_f64()
                && !f.is_finite()
            {
                return Err(Error::InvalidJsonNumber);
            }
            out.push_str(&n.to_string());
        }
        Value::String(s) => {
            out.push_str(&serde_json::to_string(s).map_err(|_| Error::InvalidJsonNumber)?)
        }
        Value::Array(values) => {
            out.push('[');
            for (idx, item) in values.iter().enumerate() {
                if idx > 0 {
                    out.push(',');
                }
                write_value(item, out)?;
            }
            out.push(']');
        }
        Value::Object(map) => write_object(map, out)?,
    }
    Ok(())
}

fn write_object(map: &Map<String, Value>, out: &mut String) -> Result<()> {
    out.push('{');
    let mut keys: Vec<&String> = map.keys().collect();
    keys.sort_unstable();
    for (idx, key) in keys.iter().enumerate() {
        if idx > 0 {
            out.push(',');
        }
        out.push_str(&serde_json::to_string(key).map_err(|_| Error::InvalidJsonNumber)?);
        out.push(':');
        write_value(&map[*key], out)?;
    }
    out.push('}');
    Ok(())
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::canonical_json_bytes;

    #[test]
    fn canonical_json_sorts_keys_recursively() {
        let value = json!({
            "z": 1,
            "a": { "d": true, "b": [3, 2, 1] },
            "m": "ok"
        });
        let canonical = canonical_json_bytes(&value).expect("canonicalize");
        assert_eq!(
            String::from_utf8(canonical).expect("utf8"),
            r#"{"a":{"b":[3,2,1],"d":true},"m":"ok","z":1}"#
        );
    }
}
