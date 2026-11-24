//! Messages exchanged with the server over HTTPS as JSON, under `/v1`.
//!
//! The server and every client use these same types. Anything secret inside them is
//! already encrypted; the server never sees a plaintext name, password or key.

use serde::{Deserialize, Serialize};

use crate::directory::DirectoryEntry;
use crate::encoding::Bytes;
use crate::ids::{DeviceId, FolderId, UserId};
use crate::items::{EncryptedItem, Sealed};
use crate::keys::{AccountPublicKeys, DevicePublicKey, WrappedKey};

/// `GET /v1/health`: answered without signing in.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Health {
    pub status: String,
    pub version: String,
    /// The newest item format the server stores. Servers older than 0.2.0 don't say,
    /// and only store format 1.
    #[serde(default = "item_format_1")]
    pub item_format: u8,
}

fn item_format_1() -> u8 {
    1
}

/// `POST /v1/setup`: the first admin claims a new server with the code it printed.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SetupRequest {
    pub setup_code: String,
    pub name: String,
    pub keys: AccountPublicKeys,
    pub device_id: DeviceId,
    pub device_key: DevicePublicKey,
    /// A name to tell the device apart, like "Ana's MacBook Pro". Optional.
    #[serde(default)]
    pub device_name: String,
    /// The owner's own directory entry signature (the entry gets user id 1).
    pub approval: Bytes,
}

/// Returned by setup and by accepting an invite.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Enrolled {
    pub user_id: UserId,
}

/// `POST /v1/sign-in/challenge`.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ChallengeRequest {
    pub device_id: DeviceId,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Challenge {
    pub challenge: Bytes,
}

/// `POST /v1/sign-in`: the device signs `keys::sign_in_message(device_id, challenge)`.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SignInRequest {
    pub device_id: DeviceId,
    pub challenge: Bytes,
    pub signature: Bytes,
}

/// A short-lived session, sent as `Authorization: Bearer <token>`.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Session {
    pub token: String,
    pub user_id: UserId,
    pub expires_in_seconds: u64,
}

/// `POST /v1/invites` (owner only).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct InviteRequest {
    pub name: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Invite {
    /// Single-use secret for the invitee.
    pub token: String,
}

/// `POST /v1/invites/accept`: the invitee registers their keys and first device.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AcceptInviteRequest {
    pub token: String,
    pub keys: AccountPublicKeys,
    pub device_id: DeviceId,
    pub device_key: DevicePublicKey,
    #[serde(default)]
    pub device_name: String,
}

/// `POST /v1/recover/challenge`: a new device asks to recover the account with these
/// public keys.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RecoveryChallengeRequest {
    pub keys: AccountPublicKeys,
}

/// The answer to `RecoveryChallengeRequest`: a challenge to sign, and the owner's directory
/// entry, so the device can check the owner's fingerprint from the recovery kit before it
/// registers anything.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RecoveryChallenge {
    pub challenge: Bytes,
    pub owner: DirectoryEntry,
}

/// `POST /v1/recover`: registers a new device for an existing account. The account's
/// signing key signs `recovery_message(challenge, device_id, device_key)`, which only
/// someone with the account secret (from a recovery kit) can do. Answered with `Enrolled`.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RecoverRequest {
    pub challenge: Bytes,
    pub device_id: DeviceId,
    pub device_key: DevicePublicKey,
    #[serde(default)]
    pub device_name: String,
    pub signature: Bytes,
}

/// One of the signed-in user's devices.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DeviceInfo {
    pub device_id: DeviceId,
    /// Empty for devices registered before devices had names.
    pub name: String,
    /// Seconds since the Unix epoch; absent for devices registered before this was kept.
    pub added_at: Option<i64>,
    /// The device making this request.
    pub current: bool,
}

/// `GET /v1/devices`: the signed-in user's devices.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DeviceList {
    pub devices: Vec<DeviceInfo>,
}

/// `POST /v1/users/{user_id}/approval` (owner only): the owner's signature over the
/// user's directory entry, given after comparing fingerprints.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ApprovalRequest {
    pub approval: Bytes,
}

/// `GET /v1/directory`.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Directory {
    pub entries: Vec<DirectoryEntry>,
}

/// `POST /v1/folders`: creates a folder with the creator as its first member.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CreateFolderRequest {
    pub folder_id: FolderId,
    pub info: Sealed,
    /// The folder key, wrapped for the creator.
    pub wrapped_key: WrappedKey,
}

/// `POST /v1/folders/{folder_id}/members`.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AddMemberRequest {
    pub user_id: UserId,
    /// The folder key, wrapped for the new member.
    pub wrapped_key: WrappedKey,
}

/// `PUT /v1/items/{item_id}`: saves a new version. `base_version` is the version the
/// edit started from, or `None` for a new item. A stale base gets `409 Conflict` with
/// a [`Conflict`] body. Sharing an item directly is saving a version whose key copies
/// include the new person.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PutItemRequest {
    pub base_version: Option<u64>,
    pub item: EncryptedItem,
}

/// The `409 Conflict` body: someone saved first, and this is their version.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Conflict {
    pub current: EncryptedItem,
}

/// `GET /v1/sync?cursor=N&limit=M`.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SyncPage {
    pub entries: Vec<SyncEntry>,
    /// Where the next sync starts.
    pub cursor: i64,
    /// More entries are waiting; sync again right away.
    pub more: bool,
}

/// One entry of the feed, in change-number order.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum SyncEntry {
    /// The latest version of an item in one of the user's folders, or one they own or
    /// that was shared with them directly.
    Item { seq: i64, item: EncryptedItem },
    /// The user joined a folder. Carries the folder key wrapped for them, the folder's
    /// info, and its items up to the page's cursor.
    Joined {
        seq: i64,
        folder_id: FolderId,
        info: Sealed,
        wrapped_key: WrappedKey,
        items: Vec<EncryptedItem>,
    },
    /// The user lost access to a folder; drop its local copy.
    Left { seq: i64, folder_id: FolderId },
}

impl SyncEntry {
    pub fn seq(&self) -> i64 {
        match self {
            Self::Item { seq, .. } | Self::Joined { seq, .. } | Self::Left { seq, .. } => *seq,
        }
    }
}

/// The body of every error response.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ErrorBody {
    pub error: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sync_entries_are_tagged_by_type() {
        let entry = SyncEntry::Left {
            seq: 7,
            folder_id: FolderId::random(),
        };
        let json = serde_json::to_value(&entry).unwrap();
        assert_eq!(json["type"], "left");
        assert_eq!(json["seq"], 7);
        let decoded: SyncEntry = serde_json::from_value(json).unwrap();
        assert_eq!(decoded.seq(), 7);
    }
}
