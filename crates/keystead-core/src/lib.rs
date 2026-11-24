//! Shared core for Keystead, used by the desktop apps, the CLI and the server.
//!
//! The data format is specified in `docs/format.md`; this crate is its reference
//! implementation. The server only ever handles the encrypted forms defined here.

pub mod api;
pub mod directory;
pub mod encoding;
pub mod ids;
pub mod items;
pub mod keys;

use std::fmt;

/// Version of this Keystead build, shared by every component in the workspace.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

#[derive(Debug)]
pub enum Error {
    /// Decryption failed: wrong key, wrong context or tampered data.
    Decrypt,
    /// A key's bytes are not a valid key.
    InvalidKey,
    /// A signature didn't verify.
    BadSignature,
    /// The data uses a scheme this build can't handle.
    UnsupportedScheme(keys::WrapScheme),
    /// An item in a format this build doesn't know; a newer Keystead wrote it.
    UnsupportedFormat(u8),
    /// Plaintext inside a ciphertext wasn't valid.
    Encoding(serde_json::Error),
    /// Recovery kit words that don't make up an account secret, and why.
    RecoveryWords(String),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Decrypt => write!(f, "decryption failed"),
            Self::InvalidKey => write!(f, "invalid key"),
            Self::BadSignature => write!(f, "signature did not verify"),
            Self::UnsupportedScheme(scheme) => write!(f, "unsupported scheme {scheme:?}"),
            Self::UnsupportedFormat(format) => write!(
                f,
                "this item is in format {format}, from a newer Keystead; update to open it"
            ),
            Self::Encoding(error) => write!(f, "invalid plaintext: {error}"),
            Self::RecoveryWords(reason) => f.write_str(reason),
        }
    }
}

impl std::error::Error for Error {}

impl From<serde_json::Error> for Error {
    fn from(error: serde_json::Error) -> Self {
        Self::Encoding(error)
    }
}
