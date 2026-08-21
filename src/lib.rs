//! ContextVeil redacts currently resolved values from user-enrolled local
//! sources before they reach a coding agent's model context.
//!
//! The library holds every security-relevant behavior: configuration loading,
//! source resolution, registry composition, and exact-value redaction. Harness
//! adapters translate host protocols only; see `architecture.md`.

pub mod adapter;
pub mod cli;
pub mod config;
pub mod diagnose;
pub mod dotenv;
pub mod integration;
pub mod json;
pub mod matcher;
pub mod paths;
pub mod redact;
pub mod registry;
pub mod sanitize;
pub mod secret;
pub mod setup;
pub mod source;

#[cfg(any(test, feature = "testing"))]
pub mod fuzz;
#[cfg(any(test, feature = "testing"))]
pub mod testing;

/// Version of the running binary, used by `--version` and diagnostics.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");
