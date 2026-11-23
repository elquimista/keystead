//! The Keystead core, exposed to Swift. UniFFI generates the Swift side from the
//! `#[uniffi::export]` items here; `apps/macos/scripts/build-core.sh` runs the generator.
//!
//! Keep this layer thin: it converts types and errors, and the logic stays in
//! `keystead-core`.

use std::fmt;

use keystead_core::keys::{AccountKeys, AccountSecret};

uniffi::setup_scaffolding!();

#[derive(Debug, uniffi::Error)]
pub enum CoreError {
    InvalidInput { message: String },
}

impl fmt::Display for CoreError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidInput { message } => f.write_str(message),
        }
    }
}

impl std::error::Error for CoreError {}

/// The version of the core this app was built with.
#[uniffi::export]
pub fn core_version() -> String {
    keystead_core::VERSION.to_owned()
}

/// The account's fingerprint, from its 32-byte secret.
#[uniffi::export]
pub fn account_fingerprint(account_secret: Vec<u8>) -> Result<String, CoreError> {
    let bytes: [u8; 32] = account_secret
        .try_into()
        .map_err(|_| CoreError::InvalidInput {
            message: "an account secret is 32 bytes".into(),
        })?;
    let keys = AccountKeys::derive(&AccountSecret::from_bytes(bytes));
    Ok(keys.public().fingerprint())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fingerprint_matches_the_core() {
        let secret = [9u8; 32];
        let expected = AccountKeys::derive(&AccountSecret::from_bytes(secret))
            .public()
            .fingerprint();
        assert_eq!(account_fingerprint(secret.to_vec()).unwrap(), expected);
        assert!(account_fingerprint(vec![1, 2, 3]).is_err());
    }
}
