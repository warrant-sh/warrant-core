use serde_json::{Map, Number, Value};

use crate::error::{Error, Result};

pub(crate) fn toml_to_json(value: &toml::Value) -> Result<Value> {
    match value {
        toml::Value::String(s) => Ok(Value::String(s.clone())),
        toml::Value::Integer(i) => Ok(Value::Number(Number::from(*i))),
        toml::Value::Float(f) => {
            let n = Number::from_f64(*f).ok_or(Error::InvalidJsonNumber)?;
            Ok(Value::Number(n))
        }
        toml::Value::Boolean(b) => Ok(Value::Bool(*b)),
        toml::Value::Datetime(dt) => Ok(Value::String(dt.to_string())),
        toml::Value::Array(values) => {
            let mut out = Vec::with_capacity(values.len());
            for item in values {
                out.push(toml_to_json(item)?);
            }
            Ok(Value::Array(out))
        }
        toml::Value::Table(table) => {
            let mut out = Map::new();
            for (k, v) in table {
                out.insert(k.clone(), toml_to_json(v)?);
            }
            Ok(Value::Object(out))
        }
    }
}

pub(crate) fn section_to_json(root: &toml::Value, section: &'static str) -> Result<Value> {
    let root_table = root.as_table().ok_or(Error::InvalidRoot)?;
    let table = root_table
        .get(section)
        .ok_or(Error::MissingSection(section))?
        .as_table()
        .ok_or(Error::InvalidSectionType(section))?;
    toml_to_json(&toml::Value::Table(table.clone()))
}

pub(crate) fn unsigned_payload_from_root(root: &toml::Value) -> Result<Value> {
    let mut out = toml_to_json(root)?;
    let obj = out.as_object_mut().ok_or(Error::InvalidRoot)?;
    obj.remove("signature");
    Ok(out)
}
