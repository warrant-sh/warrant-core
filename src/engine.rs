use std::collections::HashMap;
use std::fmt;

use serde_json::{Map, Value};

use crate::model::ParsedWarrant;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DenyReason {
    MissingCapability {
        capability: String,
    },
    ExplicitDeny {
        capability: String,
    },
    InvalidGrantType {
        capability: String,
    },
    MissingScopedAllow {
        capability: String,
    },
    MissingScope {
        capability: String,
        scope: String,
    },
    ScopeMismatch {
        capability: String,
        scope: String,
        expected: String,
        actual: String,
    },
}

impl fmt::Display for DenyReason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            DenyReason::MissingCapability { capability } => write!(
                f,
                "capability \"{capability}\" is not granted; add it under [capabilities] and re-lock the warrant"
            ),
            DenyReason::ExplicitDeny { capability } => write!(
                f,
                "capability \"{capability}\" is explicitly denied; set it to true (or allow it in a scoped object) and re-lock the warrant"
            ),
            DenyReason::InvalidGrantType { capability } => write!(
                f,
                "capability \"{capability}\" has an invalid grant type; expected bool or table (for scoped grants)"
            ),
            DenyReason::MissingScopedAllow { capability } => write!(
                f,
                "capability \"{capability}\" scoped grant is missing required allow=true/false; add it and re-lock the warrant"
            ),
            DenyReason::MissingScope { capability, scope } => write!(
                f,
                "capability \"{capability}\" requires scope \"{scope}\" in check context; provide that scope value when calling check()"
            ),
            DenyReason::ScopeMismatch {
                capability,
                scope,
                expected,
                actual,
            } => write!(
                f,
                "capability \"{capability}\" is scoped to {scope}={expected} but request used {actual}; change the target or update and re-lock the warrant"
            ),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Decision {
    Allow,
    Deny(DenyReason),
}

#[derive(Debug, Clone, Default)]
pub struct CheckContext {
    values: HashMap<String, Value>,
}

impl CheckContext {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_json(mut self, key: impl Into<String>, value: Value) -> Self {
        self.values.insert(key.into(), value);
        self
    }

    pub fn with_str(self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.with_json(key, Value::String(value.into()))
    }

    pub fn with_strs<I, S>(self, key: impl Into<String>, values: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        let array = values
            .into_iter()
            .map(|s| Value::String(s.into()))
            .collect::<Vec<_>>();
        self.with_json(key, Value::Array(array))
    }

    pub fn get(&self, key: &str) -> Option<&Value> {
        self.values.get(key)
    }
}

pub fn check(warrant: &ParsedWarrant, capability: &str, ctx: &CheckContext) -> Decision {
    let Some(grant) = warrant.capabilities.get(capability) else {
        return Decision::Deny(DenyReason::MissingCapability {
            capability: capability.to_owned(),
        });
    };

    match grant {
        Value::Bool(true) => Decision::Allow,
        Value::Bool(false) => Decision::Deny(DenyReason::ExplicitDeny {
            capability: capability.to_owned(),
        }),
        Value::Object(scope) => check_scoped_object(capability, scope, ctx),
        _ => Decision::Deny(DenyReason::InvalidGrantType {
            capability: capability.to_owned(),
        }),
    }
}

fn check_scoped_object(
    capability: &str,
    scope: &Map<String, Value>,
    ctx: &CheckContext,
) -> Decision {
    let Some(allow) = scope.get("allow") else {
        return Decision::Deny(DenyReason::MissingScopedAllow {
            capability: capability.to_owned(),
        });
    };
    match allow {
        Value::Bool(true) => {}
        Value::Bool(false) => {
            return Decision::Deny(DenyReason::ExplicitDeny {
                capability: capability.to_owned(),
            });
        }
        _ => {
            return Decision::Deny(DenyReason::InvalidGrantType {
                capability: capability.to_owned(),
            });
        }
    }

    for (scope_key, expected) in scope {
        if scope_key == "allow" {
            continue;
        }
        let Some(actual) = ctx.get(scope_key) else {
            return Decision::Deny(DenyReason::MissingScope {
                capability: capability.to_owned(),
                scope: scope_key.clone(),
            });
        };
        if !scope_match(expected, actual) {
            return Decision::Deny(DenyReason::ScopeMismatch {
                capability: capability.to_owned(),
                scope: scope_key.clone(),
                expected: expected.to_string(),
                actual: actual.to_string(),
            });
        }
    }

    Decision::Allow
}

fn scope_match(expected: &Value, actual: &Value) -> bool {
    match (expected, actual) {
        (Value::String(pattern), Value::String(value)) => wildcard_match(pattern, value),
        (Value::Array(expected_list), Value::String(value)) => expected_list
            .iter()
            .filter_map(Value::as_str)
            .any(|pattern| wildcard_match(pattern, value)),
        // When caller provides multiple values, each value must satisfy policy.
        (Value::Array(expected_list), Value::Array(actual_list)) => {
            let expected_patterns: Vec<&str> =
                expected_list.iter().filter_map(Value::as_str).collect();
            !expected_patterns.is_empty()
                && !actual_list.is_empty()
                && actual_list.iter().filter_map(Value::as_str).all(|value| {
                    expected_patterns
                        .iter()
                        .any(|pattern| wildcard_match(pattern, value))
                })
        }
        _ => expected == actual,
    }
}

fn wildcard_match(pattern: &str, value: &str) -> bool {
    if pattern == "*" {
        return true;
    }
    let pattern = pattern.to_ascii_lowercase();
    let value = value.to_ascii_lowercase();
    let mut remainder = value.as_str();
    let mut first = true;

    for part in pattern.split('*') {
        if part.is_empty() {
            continue;
        }
        let Some(idx) = remainder.find(part) else {
            return false;
        };
        if first && !pattern.starts_with('*') && idx != 0 {
            return false;
        }
        remainder = &remainder[idx + part.len()..];
        first = false;
    }

    if !pattern.ends_with('*') && !remainder.is_empty() {
        return false;
    }
    true
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use crate::model::{ParsedWarrant, SignatureBlock, WarrantMeta};

    use super::{CheckContext, Decision, DenyReason, check};

    fn sample_warrant(capabilities: serde_json::Value) -> ParsedWarrant {
        ParsedWarrant::new(
            WarrantMeta {
                version: 1,
                tool: "demo".to_string(),
                created: "2026-02-16T08:00:00Z".to_string(),
                issuer: "root@host".to_string(),
            },
            capabilities.clone(),
            SignatureBlock {
                algorithm: "ed25519".to_string(),
                public_key_b64: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=".to_string(),
                value_b64: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=="
                    .to_string(),
            },
            json!({
                "warrant": {
                    "version": 1,
                    "tool": "demo",
                    "created": "2026-02-16T08:00:00Z",
                    "issuer": "root@host"
                },
                "capabilities": capabilities
            }),
        )
        .expect("parsed warrant")
    }

    #[test]
    fn missing_capability_denied() {
        let warrant = sample_warrant(json!({"read": true}));
        assert_eq!(
            check(&warrant, "send", &CheckContext::new()),
            Decision::Deny(DenyReason::MissingCapability {
                capability: "send".to_string()
            })
        );
    }

    #[test]
    fn bool_allow_and_explicit_deny() {
        let warrant = sample_warrant(json!({"read": true, "delete": false}));
        assert_eq!(
            check(&warrant, "read", &CheckContext::new()),
            Decision::Allow
        );
        assert_eq!(
            check(&warrant, "delete", &CheckContext::new()),
            Decision::Deny(DenyReason::ExplicitDeny {
                capability: "delete".to_string()
            })
        );
    }

    #[test]
    fn scoped_string_wildcard_match() {
        let warrant = sample_warrant(json!({
            "send": { "allow": true, "to_domains": "*@example.com" }
        }));
        let allow_ctx = CheckContext::new().with_str("to_domains", "alice@example.com");
        let deny_ctx = CheckContext::new().with_str("to_domains", "alice@other.com");

        assert_eq!(check(&warrant, "send", &allow_ctx), Decision::Allow);
        assert!(matches!(
            check(&warrant, "send", &deny_ctx),
            Decision::Deny(DenyReason::ScopeMismatch { .. })
        ));
    }

    #[test]
    fn scoped_array_matches_single_and_multi_values() {
        let warrant = sample_warrant(json!({
            "send": {
                "allow": true,
                "to_domains": ["*@example.com", "*@company.org"]
            }
        }));

        let one = CheckContext::new().with_str("to_domains", "alice@example.com");
        assert_eq!(check(&warrant, "send", &one), Decision::Allow);

        let many_ok =
            CheckContext::new().with_strs("to_domains", ["alice@example.com", "bob@company.org"]);
        assert_eq!(check(&warrant, "send", &many_ok), Decision::Allow);

        let many_bad =
            CheckContext::new().with_strs("to_domains", ["alice@example.com", "mallory@evil.org"]);
        assert!(matches!(
            check(&warrant, "send", &many_bad),
            Decision::Deny(DenyReason::ScopeMismatch { .. })
        ));
    }

    #[test]
    fn scoped_array_empty_actual_values_are_denied() {
        let warrant = sample_warrant(json!({
            "send": {
                "allow": true,
                "to_domains": ["*@example.com"]
            }
        }));
        let empty_values = CheckContext::new().with_strs("to_domains", Vec::<String>::new());
        assert!(matches!(
            check(&warrant, "send", &empty_values),
            Decision::Deny(DenyReason::ScopeMismatch { .. })
        ));
    }

    #[test]
    fn missing_scope_is_denied() {
        let warrant = sample_warrant(json!({
            "push": { "allow": true, "branches": ["feature/*"] }
        }));
        assert_eq!(
            check(&warrant, "push", &CheckContext::new()),
            Decision::Deny(DenyReason::MissingScope {
                capability: "push".to_string(),
                scope: "branches".to_string()
            })
        );
    }

    #[test]
    fn scoped_capability_without_allow_defaults_to_deny() {
        let warrant = sample_warrant(json!({
            "send": { "to_domains": "*@example.com" }
        }));
        let ctx = CheckContext::new().with_str("to_domains", "alice@example.com");
        assert_eq!(
            check(&warrant, "send", &ctx),
            Decision::Deny(DenyReason::MissingScopedAllow {
                capability: "send".to_string()
            })
        );
    }

    #[test]
    fn deny_reason_messages_are_actionable() {
        let missing = DenyReason::MissingCapability {
            capability: "send".to_string(),
        };
        assert!(missing.to_string().contains("re-lock the warrant"));

        let mismatch = DenyReason::ScopeMismatch {
            capability: "push".to_string(),
            scope: "branches".to_string(),
            expected: "[\"feature/*\"]".to_string(),
            actual: "\"main\"".to_string(),
        };
        let text = mismatch.to_string();
        assert!(text.contains("change the target"));
        assert!(text.contains("branches"));
    }
}
