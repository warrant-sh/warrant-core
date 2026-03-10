use std::path::{Path, PathBuf};

use crate::error::{Error, Result};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ToolId(String);

impl ToolId {
    pub fn parse(input: &str) -> Result<Self> {
        if input.is_empty() {
            return Err(Error::InvalidToolId(input.to_string()));
        }
        if input == "." || input == ".." {
            return Err(Error::InvalidToolId(input.to_string()));
        }
        if Path::new(input).is_absolute() {
            return Err(Error::InvalidToolId(input.to_string()));
        }
        if input.contains('/') || input.contains('\\') {
            return Err(Error::InvalidToolId(input.to_string()));
        }
        if !input
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-'))
        {
            return Err(Error::InvalidToolId(input.to_string()));
        }

        Ok(Self(input.to_string()))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

#[derive(Debug, Clone)]
pub struct ToolPaths {
    pub tool_id: ToolId,
    pub installed_warrant_path: PathBuf,
    pub version_state_path: PathBuf,
    pub signing_private_key_path: PathBuf,
    pub signing_public_key_path: PathBuf,
    pub host_secret_path: PathBuf,
    pub session_dir_path: PathBuf,
}

impl ToolPaths {
    pub fn for_tool(tool: &str) -> Result<Self> {
        let tool_id = ToolId::parse(tool)?;
        if cfg!(target_os = "macos") {
            let base = PathBuf::from("/Library/Application Support").join(tool_id.as_str());
            Ok(Self {
                tool_id,
                installed_warrant_path: base.join("warrant.toml"),
                version_state_path: base.join("signing").join("version"),
                signing_private_key_path: base.join("signing").join("private.key"),
                signing_public_key_path: base.join("signing").join("public.key"),
                host_secret_path: base.join("host.key"),
                session_dir_path: base.join("sessions"),
            })
        } else if cfg!(target_os = "windows") {
            let base = PathBuf::from(r"C:\ProgramData").join(tool_id.as_str());
            Ok(Self {
                tool_id,
                installed_warrant_path: base.join("warrant.toml"),
                version_state_path: base.join("signing").join("version"),
                signing_private_key_path: base.join("signing").join("private.key"),
                signing_public_key_path: base.join("signing").join("public.key"),
                host_secret_path: base.join("host.key"),
                session_dir_path: base.join("sessions"),
            })
        } else {
            let base = PathBuf::from("/etc").join(tool_id.as_str());
            let session_dir_path = PathBuf::from("/run").join(tool_id.as_str());
            Ok(Self {
                tool_id,
                installed_warrant_path: base.join("warrant.toml"),
                version_state_path: base.join("signing").join("version"),
                signing_private_key_path: base.join("signing").join("private.key"),
                signing_public_key_path: base.join("signing").join("public.key"),
                host_secret_path: base.join("host.key"),
                session_dir_path,
            })
        }
    }
}

#[cfg(test)]
mod tests {
    use super::ToolPaths;

    #[test]
    fn tool_path_rejects_traversal_inputs() {
        for invalid in ["../../etc/passwd", "/etc/shadow", "..", "foo/bar", ""] {
            let err = ToolPaths::for_tool(invalid).expect_err("invalid tool id must fail");
            assert!(err.to_string().contains("invalid tool identifier"));
        }
    }

    #[test]
    fn tool_path_accepts_valid_inputs() {
        ToolPaths::for_tool("valid-tool").expect("valid tool id");
        ToolPaths::for_tool("my_tool.v2").expect("valid tool id");
    }
}
