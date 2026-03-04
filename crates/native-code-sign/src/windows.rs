//! Windows code signing using Microsoft `signtool.exe`.
//!
//! Supports two signing modes:
//!
//! ## Certificate signing (local `.pfx`)
//!
//! - `CODESIGN_CERTIFICATE_PATH`: path to a `.pfx` certificate file
//! - `CODESIGN_CERTIFICATE_PASSWORD`: password for the `.pfx`
//!
//! ## Azure Trusted Signing (cloud HSM)
//!
//! - `CODESIGN_AZURE_DLIB_PATH`: path to `Azure.CodeSigning.Dlib.dll`
//! - `CODESIGN_AZURE_ENDPOINT`: Artifact Signing endpoint (e.g. `https://eus.codesigning.azure.net`)
//! - `CODESIGN_AZURE_ACCOUNT`: `CodeSigningAccountName`
//! - `CODESIGN_AZURE_CERTIFICATE_PROFILE`: `CertificateProfileName`
//! - `CODESIGN_AZURE_CORRELATION_ID`: (optional) `CorrelationId` for tracking
//!
//! Azure auth is handled by the dlib via `DefaultAzureCredential` (supports
//! `az login`, managed identity, environment variables, etc.).
//!
//! ## Shared options
//!
//! - `CODESIGN_TIMESTAMP_URL`: (optional) RFC 3161 timestamp server URL.
//!   Defaults to `http://timestamp.acs.microsoft.com` for Azure Trusted Signing.
//! - `CODESIGN_TOOL_PATH`: (optional) explicit path to `signtool.exe`
//! - `CODESIGN_DESCRIPTION`: (optional) description shown in UAC prompts (`/d`)
//!
//! All variables also support a `_WINDOWS` suffix (e.g. `CODESIGN_CERTIFICATE_PATH_WINDOWS`).

use std::path::{Path, PathBuf};
use std::process::Command;

use thiserror::Error;

use crate::secret::Secret;

const SIGNTOOL_BIN: &str = "signtool.exe";
const WINDOWS_ENV_SUFFIX: &str = "WINDOWS";

/// Read an env var with optional `_WINDOWS` suffix.
fn env_var_windows(name: &str) -> Option<String> {
    let suffixed = format!("{name}_{WINDOWS_ENV_SUFFIX}");
    std::env::var(&suffixed)
        .ok()
        .or_else(|| std::env::var(name).ok())
}

/// Default timestamp server for Azure Trusted Signing.
///
/// Azure certificates have a 3-day validity, so timestamping is mandatory for signatures to
/// remain valid after the certificate expires.
const AZURE_TIMESTAMP_URL: &str = "http://timestamp.acs.microsoft.com";

#[derive(Debug, Error)]
pub enum SigntoolError {
    #[error("signtool failed for `{}`: {source}", path.display())]
    Sign {
        path: PathBuf,
        #[source]
        source: crate::CommandError,
    },
    #[error("path contains non-UTF-8 characters: {}", path.display())]
    NonUtf8Path { path: PathBuf },
    #[error("failed to write Azure metadata file: {0}")]
    AzureMetadataWrite(#[source] std::io::Error),
}

#[derive(Debug, Error)]
pub enum SigntoolConfigError {
    #[error(
        "incomplete Windows signing configuration: set both CODESIGN_CERTIFICATE_PATH and CODESIGN_CERTIFICATE_PASSWORD (missing: {missing})"
    )]
    IncompleteCertificateConfiguration { missing: String },
    #[error(
        "incomplete Azure Trusted Signing configuration: set all of CODESIGN_AZURE_DLIB_PATH, CODESIGN_AZURE_ENDPOINT, CODESIGN_AZURE_ACCOUNT, and CODESIGN_AZURE_CERTIFICATE_PROFILE (missing: {missing})"
    )]
    IncompleteAzureConfiguration { missing: String },
    #[error("failed to prepare Azure Trusted Signing metadata: {0}")]
    AzureMetadataWrite(#[source] std::io::Error),
}

/// The signing method — either a local certificate or Azure Trusted Signing.
#[derive(Debug)]
enum SigningMethod {
    /// Local `.pfx` certificate file.
    Certificate {
        certificate_path: PathBuf,
        certificate_password: Secret<String>,
    },
    /// Azure Trusted Signing via the dlib plugin.
    Azure {
        dlib_path: PathBuf,
        /// Temporary directory holding the generated `metadata.json`.
        /// Kept alive for the lifetime of the signer.
        _metadata_dir: tempfile::TempDir,
        metadata_path: PathBuf,
    },
}

/// Configuration for Windows signtool signing.
#[derive(Debug)]
pub struct WindowsSigner {
    signtool_path: PathBuf,
    method: SigningMethod,
    timestamp_url: Option<String>,
    /// Description shown in UAC prompts (signtool `/d` flag).
    description: Option<String>,
}

impl WindowsSigner {
    /// Construct from environment variables.
    ///
    /// Checks for certificate-based signing first, then Azure Trusted Signing.
    ///
    /// Returns `Ok(None)` when no signing variables are set.
    ///
    /// # Errors
    ///
    /// - [`SigntoolConfigError::IncompleteCertificateConfiguration`] when only some certificate
    ///   variables are set.
    /// - [`SigntoolConfigError::IncompleteAzureConfiguration`] when only some Azure variables
    ///   are set.
    /// - [`SigntoolConfigError::AzureMetadataWrite`] when generating Azure metadata fails.
    pub fn from_env() -> Result<Option<Self>, SigntoolConfigError> {
        // Try certificate-based signing first.
        if let Some(signer) = Self::from_env_certificate()? {
            return Ok(Some(signer));
        }
        // Fall back to Azure Trusted Signing.
        Self::from_env_azure()
    }

    /// Try to construct a certificate-based signer from environment variables.
    fn from_env_certificate() -> Result<Option<Self>, SigntoolConfigError> {
        let certificate_path = env_var_windows("CODESIGN_CERTIFICATE_PATH");
        let certificate_password = env_var_windows("CODESIGN_CERTIFICATE_PASSWORD");

        match (certificate_path, certificate_password) {
            (None, None) => Ok(None),
            (Some(certificate_path), Some(certificate_password)) => {
                let timestamp_url = env_var_windows("CODESIGN_TIMESTAMP_URL");
                let signtool_path = signtool_path_from_env();
                let description = env_var_windows("CODESIGN_DESCRIPTION");

                Ok(Some(Self {
                    signtool_path,
                    method: SigningMethod::Certificate {
                        certificate_path: PathBuf::from(certificate_path),
                        certificate_password: Secret::new(certificate_password),
                    },
                    timestamp_url,
                    description,
                }))
            }
            (path, password) => {
                let mut missing = Vec::new();
                if path.is_none() {
                    missing.push("CODESIGN_CERTIFICATE_PATH");
                }
                if password.is_none() {
                    missing.push("CODESIGN_CERTIFICATE_PASSWORD");
                }
                Err(SigntoolConfigError::IncompleteCertificateConfiguration {
                    missing: missing.join(", "),
                })
            }
        }
    }

    /// Try to construct an Azure Trusted Signing signer from environment variables.
    fn from_env_azure() -> Result<Option<Self>, SigntoolConfigError> {
        let dlib_path = env_var_windows("CODESIGN_AZURE_DLIB_PATH");
        let endpoint = env_var_windows("CODESIGN_AZURE_ENDPOINT");
        let account = env_var_windows("CODESIGN_AZURE_ACCOUNT");
        let cert_profile = env_var_windows("CODESIGN_AZURE_CERTIFICATE_PROFILE");

        match (&dlib_path, &endpoint, &account, &cert_profile) {
            (None, None, None, None) => Ok(None),
            (Some(_), Some(endpoint), Some(account), Some(cert_profile)) => {
                let dlib_path = PathBuf::from(dlib_path.unwrap());
                let correlation_id = env_var_windows("CODESIGN_AZURE_CORRELATION_ID");
                let timestamp_url = env_var_windows("CODESIGN_TIMESTAMP_URL")
                    .or_else(|| Some(AZURE_TIMESTAMP_URL.to_string()));
                let signtool_path = signtool_path_from_env();
                let description = env_var_windows("CODESIGN_DESCRIPTION");

                let metadata = build_azure_metadata(
                    endpoint,
                    account,
                    cert_profile,
                    correlation_id.as_deref(),
                );

                let metadata_dir =
                    tempfile::tempdir().map_err(SigntoolConfigError::AzureMetadataWrite)?;
                let metadata_path = metadata_dir.path().join("metadata.json");
                {
                    use std::io::Write;
                    let mut opts = fs_err::OpenOptions::new();
                    opts.write(true).create_new(true);
                    #[cfg(unix)]
                    {
                        use fs_err::os::unix::fs::OpenOptionsExt;
                        opts.mode(0o600);
                    }
                    let mut file = opts
                        .open(&metadata_path)
                        .map_err(SigntoolConfigError::AzureMetadataWrite)?;
                    file.write_all(metadata.as_bytes())
                        .map_err(SigntoolConfigError::AzureMetadataWrite)?;
                }

                Ok(Some(Self {
                    signtool_path,
                    method: SigningMethod::Azure {
                        dlib_path,
                        _metadata_dir: metadata_dir,
                        metadata_path,
                    },
                    timestamp_url,
                    description,
                }))
            }
            _ => {
                let mut missing = Vec::new();
                if dlib_path.is_none() {
                    missing.push("CODESIGN_AZURE_DLIB_PATH");
                }
                if endpoint.is_none() {
                    missing.push("CODESIGN_AZURE_ENDPOINT");
                }
                if account.is_none() {
                    missing.push("CODESIGN_AZURE_ACCOUNT");
                }
                if cert_profile.is_none() {
                    missing.push("CODESIGN_AZURE_CERTIFICATE_PROFILE");
                }
                Err(SigntoolConfigError::IncompleteAzureConfiguration {
                    missing: missing.join(", "),
                })
            }
        }
    }

    /// Sign a file with signtool.
    ///
    /// If the file is already Authenticode-signed, it is skipped. Unlike macOS `codesign --force`
    /// which replaces existing signatures, `signtool` adds nested signatures — so repeatedly
    /// signing the same file would accumulate signatures and grow the file.
    ///
    /// # Errors
    ///
    /// - [`SigntoolError::NonUtf8Path`] if a path argument is not valid UTF-8.
    /// - [`SigntoolError::Sign`] if signtool cannot be spawned or exits with a non-zero status.
    pub fn sign(&self, path: &Path) -> Result<(), SigntoolError> {
        // Check if the file is already signed to avoid accumulating nested signatures.
        if self.is_signed(path) {
            tracing::debug!("skipping already-signed {}", path.display());
            return Ok(());
        }

        let mut cmd = Command::new(&self.signtool_path);
        cmd.arg("sign");
        cmd.args(["/fd", "sha256"]);

        match &self.method {
            SigningMethod::Certificate {
                certificate_path,
                certificate_password,
            } => {
                let cert_path_str =
                    certificate_path
                        .to_str()
                        .ok_or_else(|| SigntoolError::NonUtf8Path {
                            path: certificate_path.clone(),
                        })?;
                cmd.args(["/f", cert_path_str]);
                cmd.args(["/p", certificate_password.expose().as_str()]);
            }
            SigningMethod::Azure {
                dlib_path,
                metadata_path,
                ..
            } => {
                let dlib_str = dlib_path
                    .to_str()
                    .ok_or_else(|| SigntoolError::NonUtf8Path {
                        path: dlib_path.clone(),
                    })?;
                let metadata_str =
                    metadata_path
                        .to_str()
                        .ok_or_else(|| SigntoolError::NonUtf8Path {
                            path: metadata_path.clone(),
                        })?;
                cmd.args(["/dlib", dlib_str]);
                cmd.args(["/dmdf", metadata_str]);
            }
        }

        if let Some(desc) = &self.description {
            cmd.args(["/d", desc]);
        }

        if let Some(url) = &self.timestamp_url {
            cmd.args(["/tr", url]);
            cmd.args(["/td", "sha256"]);
        }

        cmd.arg(path);

        crate::run_command(&mut cmd).map_err(|source| SigntoolError::Sign {
            path: path.to_path_buf(),
            source,
        })?;

        tracing::debug!("signtool signed {}", path.display());
        Ok(())
    }

    /// Check whether a file already has a valid Authenticode signature.
    ///
    /// Returns `false` if verification fails or signtool cannot be run (e.g., freshly built
    /// binaries). This is a best-effort check to avoid accumulating nested signatures.
    fn is_signed(&self, path: &Path) -> bool {
        let output = Command::new(&self.signtool_path)
            .args(["verify", "/pa"])
            .arg(path)
            .output();

        match output {
            Ok(o) => o.status.success(),
            Err(_) => false,
        }
    }
}

/// Build the Azure Trusted Signing `metadata.json` content.
///
/// We format this manually to avoid a serde dependency for four fields.
fn build_azure_metadata(
    endpoint: &str,
    account: &str,
    cert_profile: &str,
    correlation_id: Option<&str>,
) -> String {
    // Escape JSON string values to handle any special characters.
    let endpoint = escape_json_string(endpoint);
    let account = escape_json_string(account);
    let cert_profile = escape_json_string(cert_profile);

    let mut json = format!(
        "{{\n  \"Endpoint\": \"{endpoint}\",\n  \"CodeSigningAccountName\": \"{account}\",\n  \"CertificateProfileName\": \"{cert_profile}\""
    );

    if let Some(id) = correlation_id {
        use std::fmt::Write;
        let id = escape_json_string(id);
        let _ = write!(json, ",\n  \"CorrelationId\": \"{id}\"");
    }

    json.push_str("\n}");
    json
}

/// Escape a string for safe embedding in a JSON string value.
fn escape_json_string(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if c.is_control() => {
                use std::fmt::Write;
                // Unicode escape for control characters.
                let _ = write!(out, "\\u{:04x}", c as u32);
            }
            c => out.push(c),
        }
    }
    out
}

/// Read `CODESIGN_TOOL_PATH` (optionally with `_WINDOWS` suffix) from the
/// environment or fall back to `signtool.exe`.
fn signtool_path_from_env() -> PathBuf {
    env_var_windows("CODESIGN_TOOL_PATH").map_or_else(|| PathBuf::from(SIGNTOOL_BIN), PathBuf::from)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_from_env_missing_vars() {
        // With no env vars set, strict parsing should return Ok(None).
        // (This test assumes no CODESIGN_* vars are set in the test environment.)
        if std::env::var("CODESIGN_CERTIFICATE_PATH").is_err()
            && std::env::var("CODESIGN_CERTIFICATE_PASSWORD").is_err()
            && std::env::var("CODESIGN_AZURE_DLIB_PATH").is_err()
            && std::env::var("CODESIGN_AZURE_ENDPOINT").is_err()
            && std::env::var("CODESIGN_AZURE_ACCOUNT").is_err()
            && std::env::var("CODESIGN_AZURE_CERTIFICATE_PROFILE").is_err()
            && std::env::var("CODESIGN_CERTIFICATE_PATH_WINDOWS").is_err()
            && std::env::var("CODESIGN_CERTIFICATE_PASSWORD_WINDOWS").is_err()
            && std::env::var("CODESIGN_AZURE_DLIB_PATH_WINDOWS").is_err()
            && std::env::var("CODESIGN_AZURE_ENDPOINT_WINDOWS").is_err()
            && std::env::var("CODESIGN_AZURE_ACCOUNT_WINDOWS").is_err()
            && std::env::var("CODESIGN_AZURE_CERTIFICATE_PROFILE_WINDOWS").is_err()
        {
            assert!(WindowsSigner::from_env().unwrap().is_none());
        }
    }

    #[test]
    fn test_from_env_windows_suffix_vars_are_supported() {
        temp_env::with_vars(
            [
                ("CODESIGN_CERTIFICATE_PATH", None::<&str>),
                ("CODESIGN_CERTIFICATE_PASSWORD", None::<&str>),
                (
                    "CODESIGN_CERTIFICATE_PATH_WINDOWS",
                    Some("C:\\tmp\\cert.pfx"),
                ),
                ("CODESIGN_CERTIFICATE_PASSWORD_WINDOWS", Some("secret")),
                ("CODESIGN_TOOL_PATH_WINDOWS", Some("signtool-custom.exe")),
            ],
            || {
                let signer = WindowsSigner::from_env()
                    .expect("from_env failed")
                    .expect("expected signer from _WINDOWS vars");
                assert_eq!(signer.signtool_path, PathBuf::from("signtool-custom.exe"));
            },
        );
    }

    #[test]
    fn test_build_azure_metadata_basic() {
        let json = build_azure_metadata(
            "https://eus.codesigning.azure.net",
            "my-account",
            "my-profile",
            None,
        );
        assert!(json.contains("\"Endpoint\": \"https://eus.codesigning.azure.net\""));
        assert!(json.contains("\"CodeSigningAccountName\": \"my-account\""));
        assert!(json.contains("\"CertificateProfileName\": \"my-profile\""));
        assert!(!json.contains("CorrelationId"));
    }

    #[test]
    fn test_build_azure_metadata_with_correlation_id() {
        let json = build_azure_metadata(
            "https://eus.codesigning.azure.net",
            "my-account",
            "my-profile",
            Some("build-123"),
        );
        assert!(json.contains("\"CorrelationId\": \"build-123\""));
    }

    #[test]
    fn test_escape_json_string() {
        assert_eq!(escape_json_string("hello"), "hello");
        assert_eq!(escape_json_string("say \"hi\""), "say \\\"hi\\\"");
        assert_eq!(escape_json_string("a\\b"), "a\\\\b");
        assert_eq!(escape_json_string("line\nnewline"), "line\\nnewline");
    }
}
