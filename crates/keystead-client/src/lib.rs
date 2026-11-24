//! The client side of Keystead, shared by the CLI and the desktop apps: enrolling,
//! signing in, syncing and verifying the feed, the local encrypted copy, and every action
//! a member can take.
//!
//! Platform code supplies two things: the account secret (unwrapped however the platform
//! keeps it) and the device's sign-in key, through [`DeviceSigner`]. The CLI uses a
//! software key; macOS uses the Secure Enclave.

pub mod http;
pub mod profile;
mod vault;

pub use vault::{
    DeviceRow, EditOutcome, GroupMemberRow, GroupRow, GroupShareRow, InviteInfo, ItemRow,
    MemberRow, NewAccount, SyncSummary, UserRow, Vault, Whoami, generate_password, join, recover,
    setup,
};

use keystead_core::encoding::Bytes;
use keystead_core::keys::{DevicePublicKey, SoftwareDeviceKey};

/// A device's sign-in key. The private half stays wherever the platform keeps it.
pub trait DeviceSigner: Send + Sync {
    fn public_key(&self) -> DevicePublicKey;
    fn sign(&self, message: &[u8]) -> anyhow::Result<Bytes>;
}

impl DeviceSigner for SoftwareDeviceKey {
    fn public_key(&self) -> DevicePublicKey {
        self.public()
    }

    fn sign(&self, message: &[u8]) -> anyhow::Result<Bytes> {
        Ok(SoftwareDeviceKey::sign(self, message))
    }
}
