//! Data made by Keystead 0.19.0 (`fixtures/0.19.0.json`), which every later build must
//! still read: an account's and a group's keys as their secrets derive them, keys wrapped
//! for the account and for the group, logins sealed with them, and a Secure Enclave-style
//! sign-in signature. Upgrading a cryptography crate mustn't change any of it.

use keystead_core::encoding::{Bytes, Key32};
use keystead_core::ids::{FolderId, GroupId, UserId};
use keystead_core::items::{EncryptedItem, FolderInfo, Sealed};
use keystead_core::keys::{
    AccountKeys, AccountPublicKeys, AccountSecret, DevicePublicKey, GroupKeys, WrappedKey,
};
use serde::Deserialize;

#[derive(Deserialize)]
struct Fixtures {
    account_secret: Vec<u8>,
    public: AccountPublicKeys,
    fingerprint: String,
    group_id: GroupId,
    group_generation: u32,
    group_secret: WrappedKey,
    group_public: Key32,
    folder_id: FolderId,
    folder_key: WrappedKey,
    folder_key_for_group: WrappedKey,
    folder_pin: Key32,
    folder_info: Sealed,
    item: EncryptedItem,
    own_item: EncryptedItem,
    personal_key: WrappedKey,
    device: DevicePublicKey,
    device_message: String,
    device_signature: Bytes,
}

#[test]
fn data_from_0_19_0_still_reads() {
    let f: Fixtures = serde_json::from_str(include_str!("fixtures/0.19.0.json")).unwrap();
    let secret: [u8; 32] = f.account_secret.try_into().unwrap();
    let keys = AccountKeys::derive(&AccountSecret::from_bytes(secret));
    let me = UserId(1);

    // The same secret gives the same keys, so everyone keeps their fingerprint.
    assert_eq!(keys.public(), f.public);
    assert_eq!(f.public.fingerprint(), f.fingerprint);

    // A group's secret, wrapped for a member, and the keys it gives.
    let group_secret = keys
        .unwrap_group_secret(&f.group_secret, f.group_id, f.group_generation)
        .unwrap();
    let group = GroupKeys::derive(&group_secret);
    assert_eq!(group.public(), f.group_public);

    // A folder's key, wrapped for the account and for the group.
    let folder_key = keys.unwrap_folder_key(&f.folder_key, f.folder_id).unwrap();
    assert_eq!(folder_key.pin(f.folder_id), f.folder_pin);
    let for_group = group
        .unwrap_folder_key(&f.folder_key_for_group, f.folder_id)
        .unwrap();
    assert_eq!(for_group.pin(f.folder_id), f.folder_pin);
    let info = FolderInfo::open(&f.folder_info, f.folder_id, &folder_key).unwrap();
    assert_eq!(info.name, "Fixture folder");

    // The login, through its folder's key, its copy for the account and its group's copy.
    f.item.verify(&f.public).unwrap();
    let item_keys = [
        f.item.unlock_in_folder(&folder_key).unwrap(),
        keys.unwrap_item_key(&f.item.keys.people[0].wrapped_key, f.item.id)
            .unwrap(),
        group
            .unwrap_item_key(&f.item.keys.groups[0].wrapped_key, f.item.id)
            .unwrap(),
    ];
    for key in &item_keys {
        assert_eq!(
            f.item.open_details(key).unwrap().password,
            "fixture-password"
        );
    }

    // The account's own login, through its personal key as escrow hands it back.
    let personal = keys.unwrap_personal_key(&f.personal_key, me).unwrap();
    let own = f.own_item.unlock_as_owner(&personal, me).unwrap();
    assert_eq!(
        f.own_item.open_details(&own).unwrap().password,
        "fixture-password"
    );

    // A Mac's Secure Enclave sign-in.
    f.device
        .verify(f.device_message.as_bytes(), f.device_signature.as_slice())
        .unwrap();
}
