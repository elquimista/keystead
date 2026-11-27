//! Messages exchanged with the server over HTTPS as JSON, under `/v1`.
//!
//! The server and every client use these same types. Anything secret inside them is
//! already encrypted; the server never sees a plaintext name, password or key.

use serde::{Deserialize, Serialize};

use crate::directory::{DirectoryEntry, SignedBefore};
use crate::encoding::{Bytes, Key32};
use crate::folders::FolderEntry;
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
    /// 1 if the server keeps folders' and groups' signed members (0.15.0 and later), 2 if
    /// it keeps folders' signed roles too (0.17.0 and later); 0, or left out, if it only
    /// keeps its own lists.
    #[serde(default)]
    pub membership: u8,
    /// 2 if agreements to escrow sign a number that only goes up (0.18.0 and later); 0, or
    /// left out, before.
    #[serde(default)]
    pub escrow: u8,
    /// Whether the server keeps an invite's nonce and the proof of whoever joined with it,
    /// so the owner's app can approve them on its own (0.18.0 and later).
    #[serde(default)]
    pub invite_keys: bool,
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
    /// The invite's random nonce (`invites::NONCE_LEN` bytes), from which, with the name,
    /// the owner's app made the key on the invite line (0.18.0 and later). The server
    /// keeps it, and lists it with whoever joins with the invite.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub nonce: Option<Bytes>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Invite {
    /// Single-use secret for the invitee.
    pub token: String,
    /// When it stops working, in seconds since 1970 (0.16.0 and later: seven days after
    /// it's made; servers before that don't say, and their invites don't expire).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<i64>,
}

/// `GET /v1/invites` (owner only, 0.16.0 and later): the invites nobody has used yet, that
/// still work, oldest first. `DELETE /v1/invites/{id}` takes one back.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Invites {
    pub invites: Vec<PendingInvite>,
}

/// An invite that hasn't been used: who it was made for, and until when it works. Its
/// token isn't kept anywhere, only a hash of it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PendingInvite {
    pub id: i64,
    pub name: String,
    pub created_at: i64,
    pub expires_at: i64,
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
    /// With an invite whose line carries a key (0.18.0 and later): the key's proof of
    /// `keys`, 32 bytes, which the server lists with the new account until the owner
    /// approves it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub proof: Option<Bytes>,
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

/// `POST /v1/users/{user_id}/recovery` (owner): a one-time token for someone who lost
/// every device and their recovery kit, to send them like an invite.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RecoveryStarted {
    pub token: String,
}

/// `GET /v1/users/{user_id}/recovery` (owner): a recovery waiting for approval.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RecoveryInProgress {
    /// The new keys, once the person has used the token on their new device.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub keys: Option<AccountPublicKeys>,
    /// Their personal key in escrow, wrapped for the owner, if they turned escrow on.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub escrow: Option<WrappedKey>,
    /// Digests of everything the server holds that they signed: every login version,
    /// including history and Recently Deleted, and every group change. The owner's app
    /// adds what it holds and signs the list when approving.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub signed: Vec<Bytes>,
}

/// `POST /v1/recovery/claim`: the new device sends its new keys and its device key. It
/// signs in only once the owner approves them.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ClaimRecoveryRequest {
    pub token: String,
    pub keys: AccountPublicKeys,
    pub device_id: DeviceId,
    pub device_key: DevicePublicKey,
    #[serde(default)]
    pub device_name: String,
}

/// Whose account a recovery token is for.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RecoveryClaimed {
    pub user_id: UserId,
    pub name: String,
}

/// `POST /v1/recovery/state`: whether the owner has approved yet. A cancelled or expired
/// recovery answers 404.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RecoveryTokenRequest {
    pub token: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RecoveryState {
    pub approved: bool,
}

/// `POST /v1/users/{user_id}/recovery/approval` (owner): the owner's signature over the
/// person's entry with the new keys at the next revision, the owner's list of what their
/// old keys had signed, and their escrowed personal key wrapped again for the new keys, if
/// there was one.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ApproveRecoveryRequest {
    pub revision: u32,
    pub approval: Bytes,
    pub signed_before: SignedBefore,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub personal_key: Option<WrappedKey>,
}

/// `PUT /v1/escrow`: this account's personal key, wrapped for the owner, and its
/// agreement, signed with its keys (see `directory::escrow_consent`).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct EscrowRequest {
    pub wrapped_key: WrappedKey,
    pub consent: Bytes,
    /// The number the agreement signs (0.18.0 and later): past the last one this account
    /// used. 0, or left out, for an agreement that signs none, from apps before then.
    #[serde(default, skip_serializing_if = "is_zero_u64")]
    pub sequence: u64,
}

fn is_zero_u64(number: &u64) -> bool {
    *number == 0
}

/// `PUT /v1/folders/{folder_id}/members/{user_id}/key`: a folder member gives someone
/// who recovered a copy of the folder's current key for their new keys.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RestoreFolderKeyRequest {
    pub generation: u32,
    pub wrapped_key: WrappedKey,
}

/// `PUT /v1/groups/{group_id}/members/{user_id}/secret`: a group member gives someone who
/// recovered a copy of the group's current secret for their new keys.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RestoreGroupSecretRequest {
    pub generation: u32,
    pub wrapped_secret: WrappedKey,
}

/// `PUT /v1/folders/{folder_id}/escrow`: the folder's current key sealed with the caller's
/// personal key, for a folder nobody else can open, while the caller has escrow on.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct FolderEscrowRequest {
    pub generation: u32,
    pub sealed: Sealed,
}

/// Copies someone who recovered is waiting for, that this user can give them.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Restore {
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub folders: Vec<FolderMember>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub groups: Vec<GroupMember>,
    /// Logins shared with them directly, to save again with a copy for their new keys.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub items: Vec<ItemId>,
    /// After this user recovered: folders only they could open, with the copy of each
    /// one's key they put in escrow, to give themselves back.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub escrowed: Vec<EscrowedFolder>,
}

impl Restore {
    pub fn is_empty(&self) -> bool {
        self.folders.is_empty()
            && self.groups.is_empty()
            && self.items.is_empty()
            && self.escrowed.is_empty()
    }
}

/// A folder's key at `generation`, sealed with its member's personal key for escrow.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct EscrowedFolder {
    pub folder_id: FolderId,
    pub generation: u32,
    pub sealed: Sealed,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct FolderMember {
    pub folder_id: FolderId,
    pub user_id: UserId,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct GroupMember {
    pub group_id: GroupId,
    pub user_id: UserId,
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
    /// The folder's first signed entry: the creator alone (0.15.0 and later).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub entry: Option<FolderEntry>,
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
    /// The folder's next signed entry, with the new member in it: needed once the folder
    /// has entries (0.15.0 and later).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub entry: Option<FolderEntry>,
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
    /// A folder's signed entries, oldest first (0.15.0 and later); none for an item, or a
    /// folder nobody has signed for yet.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub entries: Vec<FolderEntry>,
}

/// `PUT /v1/folders/{folder_id}/entries` (managers): the first signed entry of a folder
/// from before 0.15.0, naming exactly who it's shared with now; or the first entry with
/// roles of a folder from before 0.17.0, changing nothing else.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct FolderEntryRequest {
    pub entry: FolderEntry,
}

/// `PUT /v1/folders/{folder_id}/members/{user_id}` and
/// `PUT /v1/items/{item_id}/people/{user_id}` (managers): changes someone's role.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RoleRequest {
    pub role: Role,
    /// For a folder: its next signed entry, with the new role (0.17.0 and later). Needed
    /// once the folder's roles are signed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub entry: Option<FolderEntry>,
}

/// `GET /v1/users/{user_id}/removal` (owner): the folders with signed roles that removing
/// this person from the team would leave without a manager (0.17.0 and later).
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct Removal {
    pub folders: Vec<ManagerlessFolder>,
}

/// A folder about to lose its only manager, for the owner to sign someone else in.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ManagerlessFolder {
    pub folder_id: FolderId,
    /// Its signed entries, oldest first.
    pub entries: Vec<FolderEntry>,
    /// Whoever has been in it longest, whom the server suggests.
    pub promote: UserId,
}

/// `POST /v1/users/{user_id}/removal` (owner): removes someone from the team, like
/// `DELETE /v1/users/{user_id}`, with the next entry of each folder they alone managed:
/// its roles, signed by the owner, with a new manager (0.17.0 and later).
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct RemoveUserRequest {
    pub promotions: Vec<FolderEntry>,
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
    /// The folder's next signed entry, for the new key and exactly who gets it: needed
    /// once the folder has entries (0.15.0 and later).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub entry: Option<FolderEntry>,
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

/// `GET /v1/password-ages` (0.13.0 and later): when the password of each live item the
/// caller can open was last set.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct PasswordAges {
    pub items: Vec<PasswordAge>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PasswordAge {
    pub item_id: ItemId,
    /// Seconds since 1970 (UTC), as the server recorded it; unknown for items last saved
    /// before 0.7.0.
    pub since: Option<i64>,
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

/// `POST /v1/device-transfers` (any signed-in device): starts adding a device to the
/// caller's account. The token goes to the new device in a setup line; the transfer
/// expires after `expires_in_seconds`.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DeviceTransfer {
    pub id: String,
    pub token: String,
    pub expires_in_seconds: u64,
}

/// `POST /v1/device-transfers/join` (the new device, without a session): its name, and the
/// one-time key the account secret is to be sealed for. Once per transfer.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct JoinDeviceTransferRequest {
    pub token: String,
    pub device_name: String,
    pub transfer_key: Key32,
}

/// `GET /v1/device-transfers/{id}` (the device that started it): whether the new device
/// has joined yet, and with what.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct DeviceTransferState {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub device_name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub transfer_key: Option<Key32>,
}

/// `PUT /v1/device-transfers/{id}/secret` (the device that started it): the account
/// secret, sealed for the new device's transfer key.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SendAccountSecretRequest {
    pub wrapped_secret: WrappedKey,
}

/// `POST /v1/device-transfers/claim` (the new device, without a session).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ClaimDeviceTransferRequest {
    pub token: String,
}

/// The answer to a claim: the sealed secret once it's there, after which the transfer is
/// gone; until then, nothing.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct ClaimedAccountSecret {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub wrapped_secret: Option<WrappedKey>,
}

/// A deleted item that can still be brought back: its signed deletion marker, and the last
/// version before it.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DeletedItem {
    /// When it was deleted, in seconds since 1970 (UTC). Set by the server.
    pub deleted_at: i64,
    pub deleted: EncryptedItem,
    pub last: EncryptedItem,
}

/// `GET /v1/deleted`: the items deleted in the last 30 days that the caller can change
/// (edit or manage), newest first. Servers before 0.9.0 answer 404.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct DeletedItems {
    pub items: Vec<DeletedItem>,
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
    /// The folder's next signed entry, with the group in it: needed once the folder has
    /// entries (0.15.0 and later).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub entry: Option<FolderEntry>,
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
    /// The signed entries of groups since deleted (0.15.0 and later): folder entries
    /// their members signed are still checked against them.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub former: Vec<Vec<GroupEntry>>,
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
    /// The group's next signed entry, with the new member in it: needed once the group's
    /// members are signed (0.15.0 and later).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub entry: Option<GroupEntry>,
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
    /// This page is part of a folder too big for one, and the cursor hasn't moved: pass
    /// this back as `resume` for the next part (0.17.0 and later).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub resume: Option<String>,
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
    /// Copies this user can give people who recovered with the owner's help (0.13.0 and
    /// later).
    #[serde(default, skip_serializing_if = "Restore::is_empty")]
    pub restore: Restore,
    /// After this user recovered with the owner's help: their earlier personal key,
    /// wrapped for their current keys, if it was in escrow.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub recovered_key: Option<WrappedKey>,
    /// This user has escrow on, but no personal key for their current keys is in escrow
    /// (after a recovery).
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub escrow_needed: bool,
    /// This user has escrow on, and these folders only they can open have no copy of
    /// their current key in escrow.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub escrow_folders: Vec<FolderId>,
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
        /// The folder's signed entries, oldest first (0.15.0 and later).
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        entries: Vec<FolderEntry>,
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
        /// The folder's signed entries, oldest first (0.15.0 and later).
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        entries: Vec<FolderEntry>,
    },
    /// The user lost direct access to a login; drop it unless a folder still gives it. With
    /// `moved`, it went to a folder they can't open (or out of folders), so drop it even
    /// if the copy they have says it's in one of theirs.
    LeftItem {
        seq: i64,
        item_id: ItemId,
        #[serde(default, skip_serializing_if = "std::ops::Not::not")]
        moved: bool,
    },
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
