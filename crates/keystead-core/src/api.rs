//! Messages exchanged with the server over HTTPS as JSON, under `/v1`.
//!
//! The server and every client use these same types. Anything secret inside them is
//! already encrypted; the server never sees a plaintext name, password or key.

use serde::{Deserialize, Serialize};

use crate::directory::DirectoryEntry;
use crate::encoding::Bytes;
use crate::groups::GroupEntry;
use crate::ids::{DeviceId, FolderId, GroupId, ItemId, UserId};
use crate::items::{EncryptedItem, Sealed};
use crate::keys::{AccountPublicKeys, DevicePublicKey, WrappedKey};

/// What someone may do with a folder or a login they can open. Roles are kept and enforced
/// by the server; what anyone can read comes from the keys they hold.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Role {
    /// Open and copy.
    View,
    /// Also change and delete logins.
    Edit,
    /// Also share, change roles and remove people.
    Manage,
}

impl Role {
    /// What shares made before roles existed get: everyone could do everything then.
    pub fn before_roles() -> Self {
        Self::Manage
    }

    pub fn name(self) -> &'static str {
        match self {
            Self::View => "view",
            Self::Edit => "edit",
            Self::Manage => "manage",
        }
    }

    pub fn from_name(name: &str) -> Option<Self> {
        match name {
            "view" => Some(Self::View),
            "edit" => Some(Self::Edit),
            "manage" => Some(Self::Manage),
            _ => None,
        }
    }
}

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

/// `POST /v1/setup`: whoever runs a new server claims it with the code it printed.
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

/// `POST /v1/folders/{folder_id}/members` (managers).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AddMemberRequest {
    pub user_id: UserId,
    /// The folder key, wrapped for the new member.
    pub wrapped_key: WrappedKey,
    #[serde(default = "Role::before_roles")]
    pub role: Role,
    /// The generation of the folder key that was wrapped; it must still be the current one.
    #[serde(default)]
    pub generation: u32,
}

/// Someone who can open a folder or a login, and their role.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Member {
    pub user_id: UserId,
    pub role: Role,
}

/// A group that can open a folder or a login, and its role there.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct GroupShare {
    pub group_id: GroupId,
    pub role: Role,
}

/// `GET /v1/folders/{folder_id}/members` and `GET /v1/items/{item_id}/people`.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Members {
    pub members: Vec<Member>,
    /// Groups it's shared with. Servers before 0.4.0 don't have groups.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub groups: Vec<GroupShare>,
}

/// `PUT /v1/folders/{folder_id}/members/{user_id}` and
/// `PUT /v1/items/{item_id}/people/{user_id}` (managers): changes someone's role.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RoleRequest {
    pub role: Role,
}

/// One link of a folder's or group's key chain: the key of `generation - 1`, sealed with
/// the key of `generation`. Holding the newest key opens every older one, and so every
/// item.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct KeyLink {
    pub generation: u32,
    pub previous: Sealed,
}

/// A folder key wrapped for one member.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MemberKey {
    pub user_id: UserId,
    pub wrapped_key: WrappedKey,
}

/// A folder key wrapped for one generation of a group's key.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct GroupFolderKey {
    pub group_id: GroupId,
    pub group_generation: u32,
    pub wrapped_key: WrappedKey,
}

/// `POST /v1/folders/{folder_id}/rekey` (managers): gives the folder a new key, after
/// someone lost access to it.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RekeyRequest {
    /// The new key's generation: the current one plus one.
    pub generation: u32,
    /// The new key, wrapped for every current member and nobody else.
    pub wrapped_keys: Vec<MemberKey>,
    /// And for every group the folder is shared with, at the group's current key.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub group_keys: Vec<GroupFolderKey>,
    /// The previous key, sealed with the new one.
    pub previous: Sealed,
    /// The folder's info, sealed with the new key.
    pub info: Sealed,
}

/// `PUT /v1/items/{item_id}`: saves a new version. `base_version` is the version the
/// edit started from, or `None` for a new item. A stale base gets `409 Conflict` with
/// a [`Conflict`] body. Sharing an item directly is saving a version whose key copies
/// include the new person.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PutItemRequest {
    pub base_version: Option<u64>,
    pub item: EncryptedItem,
    /// Roles for the people this version gives a key copy to for the first time.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub roles: Vec<Member>,
    /// Roles for the groups this version gives a key copy to for the first time.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub group_roles: Vec<GroupShare>,
    /// This version has a different password from the one before, so people who lost
    /// access earlier no longer know it: the server drops the item's [`Exposure`]s.
    /// Servers before 0.5.0 ignore it.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub password_changed: bool,
}

/// Someone who could open an item lost access to it, so they may still know its password.
/// It stays until a version with a new password is saved, the item is deleted, someone
/// dismisses it, or they get access again.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Exposure {
    pub item_id: ItemId,
    pub user_id: UserId,
    /// When they last lost access, in seconds since 1970 (UTC).
    pub since: i64,
}

/// `GET /v1/exposures`: the exposures of every item the caller can change (edit or
/// manage). Servers before 0.5.0 answer 404.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct Exposures {
    pub exposures: Vec<Exposure>,
}

/// One version of an item as the server keeps it, with when it was saved.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SavedVersion {
    /// Seconds since 1970 (UTC); absent for versions saved before 0.7.0. Set by the server,
    /// so not signed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub saved_at: Option<i64>,
    pub item: EncryptedItem,
}

/// `GET /v1/items/{item_id}/history` (editors and managers of the item): its current
/// version and the earlier ones the server keeps, newest first. Servers before 0.7.0 keep
/// none and answer 404.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct ItemHistory {
    pub versions: Vec<SavedVersion>,
}

/// `POST /v1/folders/{folder_id}/groups` (folder managers): shares a folder with a group.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AddFolderGroupRequest {
    pub group_id: GroupId,
    /// The folder's current key, wrapped for the group's current key.
    pub wrapped_key: WrappedKey,
    pub group_generation: u32,
    pub role: Role,
    /// The generation of the folder key that was wrapped.
    pub generation: u32,
}

/// A group's secret wrapped for one of its members.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct GroupMemberKey {
    pub user_id: UserId,
    pub wrapped_secret: WrappedKey,
}

/// `POST /v1/groups` (owner): makes a group, with the owner's signed first entry and its
/// secret wrapped for each first member, the owner among them.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CreateGroupRequest {
    pub entry: GroupEntry,
    pub members: Vec<GroupMemberKey>,
}

/// `GET /v1/groups`: every group on the team, so anyone can share with them.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Groups {
    pub groups: Vec<GroupInfo>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct GroupInfo {
    /// Every revision of the group's entry, oldest first; apps check them all.
    pub entries: Vec<GroupEntry>,
    pub members: Vec<UserId>,
    /// Someone left, and the group is waiting for a manager's app to give it a new key.
    #[serde(default)]
    pub needs_rekey: bool,
}

/// `POST /v1/groups/{group_id}/members` (managers in the group): adds someone, with the
/// group's current secret wrapped for them.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AddGroupMemberRequest {
    pub user_id: UserId,
    pub generation: u32,
    pub wrapped_secret: WrappedKey,
}

/// `PUT /v1/groups/{group_id}` (owner and managers): the next revision of the group's
/// entry with the same key, to rename it or change its managers.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct UpdateGroupRequest {
    pub entry: GroupEntry,
}

/// `POST /v1/groups/{group_id}/rekey` (managers in the group): a new secret after someone
/// left: the next entry with its key, the secret wrapped for every current member, and
/// the previous secret sealed under the new one.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct GroupRekeyRequest {
    pub entry: GroupEntry,
    pub members: Vec<GroupMemberKey>,
    pub previous: Sealed,
}

/// Which group key a folder key was wrapped for, when it reaches someone through a group.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ViaGroup {
    pub group_id: GroupId,
    pub generation: u32,
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
    /// Folders this user manages that need a new key, because someone lost access.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub rekey_needed: Vec<FolderId>,
    /// This user's roles, on the last page.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub roles: Option<Roles>,
    /// Groups this user manages that need a new key, because someone left. Folders shared
    /// with them wait for it, and aren't in `rekey_needed` until then.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub group_rekey_needed: Vec<GroupId>,
}

/// A user's role in each folder they're in and on each login shared with them directly,
/// the highest of the ways they reach it: themselves or through a group.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Roles {
    pub folders: Vec<FolderRole>,
    pub items: Vec<ItemRole>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct FolderRole {
    pub folder_id: FolderId,
    pub role: Role,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ItemRole {
    pub item_id: ItemId,
    pub role: Role,
}

/// One entry of the feed, in change-number order.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum SyncEntry {
    /// The latest version of an item in one of the user's folders, or one they own or
    /// that was shared with them directly.
    Item { seq: i64, item: EncryptedItem },
    /// The user joined a folder, themselves or through a group. Carries the folder key
    /// wrapped for them or the group (its current generation, and the chain to older
    /// ones), the folder's info, and its items up to the page's cursor.
    Joined {
        seq: i64,
        folder_id: FolderId,
        info: Sealed,
        wrapped_key: WrappedKey,
        #[serde(default)]
        generation: u32,
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        chain: Vec<KeyLink>,
        /// Set when `wrapped_key` is wrapped for a group's key, not the user's.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        via_group: Option<ViaGroup>,
        items: Vec<EncryptedItem>,
    },
    /// The user lost access to a folder; drop its local copy.
    Left { seq: i64, folder_id: FolderId },
    /// A folder the user is in got a new key: the new one wrapped for them, the whole
    /// chain to older ones, and the info sealed with the new key.
    Rekeyed {
        seq: i64,
        folder_id: FolderId,
        info: Sealed,
        wrapped_key: WrappedKey,
        generation: u32,
        chain: Vec<KeyLink>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        via_group: Option<ViaGroup>,
    },
    /// The user lost direct access to a login; drop it unless a folder still gives it.
    LeftItem { seq: i64, item_id: ItemId },
    /// The user joined a group, or one they're in changed: its entries, its current
    /// secret wrapped for them, and the chain to older secrets. Comes before anything
    /// that needs the group's key.
    Group {
        seq: i64,
        group_id: GroupId,
        entries: Vec<GroupEntry>,
        generation: u32,
        wrapped_secret: WrappedKey,
        chain: Vec<KeyLink>,
    },
    /// The user left a group; forget its keys.
    LeftGroup { seq: i64, group_id: GroupId },
}

impl SyncEntry {
    pub fn seq(&self) -> i64 {
        match self {
            Self::Item { seq, .. }
            | Self::Joined { seq, .. }
            | Self::Left { seq, .. }
            | Self::Rekeyed { seq, .. }
            | Self::LeftItem { seq, .. }
            | Self::Group { seq, .. }
            | Self::LeftGroup { seq, .. } => *seq,
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
