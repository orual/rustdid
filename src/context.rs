use crate::errors::{SetupError, SetupResult};
use std::path::PathBuf;

pub trait SetupContext<T> {
    fn with_config_context(self, msg: impl Into<String>) -> SetupResult<T>;
    fn with_keypair_context(self, msg: impl Into<String>) -> SetupResult<T>;
    fn with_domain_context(self, msg: impl Into<String>) -> SetupResult<T>;
    fn with_document_context(self, msg: impl Into<String>) -> SetupResult<T>;
    fn with_fs_context(self, path: impl Into<PathBuf>, op: &str) -> SetupResult<T>;
    fn with_input_context(self, field: &str) -> SetupResult<T>;
}

impl<T, E> SetupContext<T> for Result<T, E>
where
    E: std::fmt::Display,
{
    fn with_config_context(self, msg: impl Into<String>) -> SetupResult<T> {
        Ok(self.map_err(|e| {
            let src = format!("Config operation failed: {}", e);
            SetupError::config(msg, &src)
        })?)
    }

    fn with_keypair_context(self, msg: impl Into<String>) -> SetupResult<T> {
        Ok(self.map_err(|e| {
            let src = format!("Key operation failed: {}", e);
            SetupError::keypair(msg, &src)
        })?)
    }

    fn with_domain_context(self, msg: impl Into<String>) -> SetupResult<T> {
        Ok(self.map_err(|e| {
            let src = format!("Domain operation failed: {}", e);
            SetupError::domain(msg, &src)
        })?)
    }

    fn with_document_context(self, msg: impl Into<String>) -> SetupResult<T> {
        Ok(self.map_err(|e| {
            let src = format!("Document operation failed: {}", e);
            SetupError::document(msg, &src)
        })?)
    }

    fn with_fs_context(self, path: impl Into<PathBuf>, op: &str) -> SetupResult<T> {
        let path = path.into();
        Ok(self.map_err(|e| {
            let msg = format!("Failed to {} {}", op, path.display());
            let src = format!("Filesystem operation failed: {}", e);
            SetupError::fs(msg, &src)
        })?)
    }

    fn with_input_context(self, field: &str) -> SetupResult<T> {
        Ok(self.map_err(|e| {
            let msg = format!("Invalid input for field: {}", field);
            let src = format!("Input validation failed: {}", e);
            SetupError::input(msg, &src)
        })?)
    }
}
