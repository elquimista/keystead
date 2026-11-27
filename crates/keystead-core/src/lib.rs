//! Shared core for Keystead, used by the desktop apps, the CLI and the server.
//!
//! The data format is specified in `docs/format.md`; this crate is its reference
//! implementation. The server only ever handles the encrypted forms defined here.

pub mod api;
pub mod directory;
pub mod encoding;
pub mod folders;
pub mod groups;
pub mod ids;
pub mod invites;
pub mod items;
pub mod keys;
pub mod otp;

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
    /// An item whose fields don't fit its format, and how.
    InvalidItem(&'static str),
    /// Plaintext inside a ciphertext wasn't valid: what kind of problem and where, but
    /// never what it said, as serde's own message quotes the content.
    Encoding {
        kind: &'static str,
        line: usize,
        column: usize,
    },
    /// Recovery kit words that don't make up an account secret, and why.
    RecoveryWords(String),
    /// A group's signed entries or keys don't check out, and why.
    InvalidGroup(String),
    /// A folder's signed entries don't check out, and why.
    InvalidFolder(&'static str),
    /// A one-time code setup that can't make codes, and why (never the secret itself).
    OneTimeCode(String),
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
            Self::InvalidItem(reason) => f.write_str(reason),
            Self::Encoding { kind, line, column } => {
                write!(
                    f,
                    "invalid plaintext: {kind} at line {line}, column {column}"
                )
            }
            Self::RecoveryWords(reason) => f.write_str(reason),
            Self::InvalidGroup(reason) => write!(f, "this group can't be trusted: {reason}"),
            Self::InvalidFolder(reason) => {
                write!(f, "this folder's members can't be trusted: {reason}")
            }
            Self::OneTimeCode(reason) => write!(
                f,
                "that isn't a one-time code setup key or otpauth:// link: {reason}"
            ),
        }
    }
}

impl std::error::Error for Error {}

impl From<serde_json::Error> for Error {
    fn from(error: serde_json::Error) -> Self {
        use serde_json::error::Category;
        Self::Encoding {
            kind: match error.classify() {
                Category::Io => "unreadable",
                Category::Syntax => "not JSON",
                Category::Data => "unexpected content",
                Category::Eof => "cut short",
            },
            line: error.line(),
            column: error.column(),
        }
    }
}
