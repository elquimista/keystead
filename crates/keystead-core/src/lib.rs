//! Shared core for Keystead, used by the desktop apps, the CLI and the server.

/// Version of this Keystead build, shared by every component in the workspace.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");
