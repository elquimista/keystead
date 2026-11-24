//! The client library against a real server on a local port, with the two kinds of
//! device key in use: a software Ed25519 key (CLI) and a P-256 key like the Mac's Secure
//! Enclave key.

use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicU32, Ordering};

use keystead_client::http::Client;
use keystead_client::{DeviceSigner, EditOutcome, NewAccount, Vault, join, recover, setup};
use keystead_core::api::{PutItemRequest, Role};
use keystead_core::encoding::Bytes;
use keystead_core::groups::GroupKeyring;
use keystead_core::ids::{DeviceId, ItemId, UserId};
use keystead_core::items::{Details, EncryptedItem, ItemVersion, Overview};
use keystead_core::keys::{
    AccountKeys, AccountSecret, DeviceKeyScheme, DevicePublicKey, SoftwareDeviceKey,
};
use keystead_server::AppState;
use p256::ecdsa::signature::Signer as _;

/// Signs like a Secure Enclave key: ECDSA P-256, SEC1 public key, raw r‖s signature.
struct P256Signer(p256::ecdsa::SigningKey);

impl DeviceSigner for P256Signer {
    fn public_key(&self) -> DevicePublicKey {
        DevicePublicKey {
            scheme: DeviceKeyScheme::EcdsaP256Sha256,
            key: Bytes(
                self.0
                    .verifying_key()
                    .to_encoded_point(false)
                    .as_bytes()
                    .to_vec(),
            ),
        }
    }

    fn sign(&self, message: &[u8]) -> anyhow::Result<Bytes> {
        let signature: p256::ecdsa::Signature = self.0.sign(message);
        Ok(Bytes(signature.to_bytes().to_vec()))
    }
}

struct Fixture {
    _runtime: tokio::runtime::Runtime,
    url: String,
    setup_code: String,
    root: PathBuf,
}

impl Fixture {
    fn start() -> Self {
        static NEXT: AtomicU32 = AtomicU32::new(0);
        let root = std::env::temp_dir().join(format!(
            "keystead-client-test-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir_all(&root).unwrap();
        let runtime = tokio::runtime::Runtime::new().unwrap();
        let (state, setup_code, listener) = runtime.block_on(async {
            let state = AppState::open(&root.join("server.sqlite")).await.unwrap();
            let code = state.pending_setup_code().await.unwrap().unwrap();
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            (state, code, listener)
        });
        let url = format!("http://{}", listener.local_addr().unwrap());
        runtime.spawn(async move {
            axum::serve(listener, keystead_server::router(state))
                .await
                .unwrap();
        });
        Self {
            _runtime: runtime,
            url,
            setup_code,
            root,
        }
    }

    fn profile(&self, who: &str) -> PathBuf {
        self.root.join(who).join("profile.json")
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.root);
    }
}

#[test]
fn a_secure_enclave_style_device_joins_and_syncs() {
    let fixture = Fixture::start();

    let alice_secret = AccountSecret::generate();
    let mut alice = setup(
        &fixture.profile("alice"),
        NewAccount {
            server: &fixture.url,
            secret: &alice_secret,
            device_id: DeviceId::random(),
            device_name: "Test device",
            signer: Arc::new(SoftwareDeviceKey::generate()),
        },
        &fixture.setup_code,
        "Alice",
    )
    .unwrap();
    let invite = alice.invite("Bob").unwrap();

    let bob_secret = AccountSecret::generate();
    let bob_signer: Arc<dyn DeviceSigner> = Arc::new(P256Signer(p256::ecdsa::SigningKey::random(
        &mut rand_core_rng(),
    )));
    let bob = join(
        &fixture.profile("bob"),
        NewAccount {
            server: &invite.server,
            secret: &bob_secret,
            device_id: DeviceId::random(),
            device_name: "Test device",
            signer: bob_signer.clone(),
        },
        &invite.token,
        &invite.owner_fingerprint,
    )
    .unwrap();
    let bob_identity = bob.whoami();
    drop(bob);

    alice
        .approve(bob_identity.user_id, &bob_identity.fingerprint)
        .unwrap();
    alice.create_folder("Production").unwrap();
    alice
        .share_folder("Production", bob_identity.user_id, Role::Edit)
        .unwrap();
    alice
        .add(
            Some("Production"),
            Overview {
                name: "AWS root".into(),
                ..Overview::default()
            },
            Details {
                password: "s3cret".into(),
                notes: String::new(),
                otp: String::new(),
            },
        )
        .unwrap();

    // Bob unlocks again later, as the app does: from the saved profile and his secret.
    let mut bob = Vault::open(&fixture.profile("bob"), &bob_secret, bob_signer).unwrap();
    let summary = bob.sync().unwrap();
    assert_eq!(summary.rejected, 0);
    let rows = bob.list().unwrap();
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].name, "AWS root");
    assert_eq!(bob.open_item(rows[0].id).unwrap().1.password, "s3cret");

    let outcome = bob.edit(rows[0].id, "rotated").unwrap();
    assert!(matches!(outcome, EditOutcome::Saved { version: 2 }));
    alice.sync().unwrap();
    assert_eq!(alice.open_item(rows[0].id).unwrap().1.password, "rotated");
}

#[test]
fn opening_with_the_wrong_secret_cannot_read_items() {
    let fixture = Fixture::start();
    let secret = AccountSecret::generate();
    let signer: Arc<dyn DeviceSigner> = Arc::new(SoftwareDeviceKey::generate());
    let mut alice = setup(
        &fixture.profile("alice"),
        NewAccount {
            server: &fixture.url,
            secret: &secret,
            device_id: DeviceId::random(),
            device_name: "Test device",
            signer: signer.clone(),
        },
        &fixture.setup_code,
        "Alice",
    )
    .unwrap();
    alice.create_folder("Personal").unwrap();
    drop(alice);

    let impostor = Vault::open(
        &fixture.profile("alice"),
        &AccountSecret::generate(),
        signer,
    )
    .unwrap();
    assert!(impostor.folders().is_err());
}

#[test]
fn a_recovery_kit_brings_an_account_back_on_a_new_device() {
    let fixture = Fixture::start();
    let enclave = || -> Arc<dyn DeviceSigner> {
        Arc::new(P256Signer(p256::ecdsa::SigningKey::random(
            &mut rand_core_rng(),
        )))
    };

    // Alice owns the server from her Mac and shares a folder with Bob.
    let alice_secret = AccountSecret::generate();
    let old_mac = enclave();
    let mut alice = setup(
        &fixture.profile("alice-old"),
        NewAccount {
            server: &fixture.url,
            secret: &alice_secret,
            device_id: DeviceId::random(),
            device_name: "Alice's old Mac",
            signer: old_mac.clone(),
        },
        &fixture.setup_code,
        "Alice",
    )
    .unwrap();
    let owner_fingerprint = alice.whoami().owner_fingerprint;
    assert_eq!(owner_fingerprint, alice.whoami().fingerprint);
    alice.create_folder("Production").unwrap();
    alice
        .add(
            Some("Production"),
            Overview {
                name: "AWS root".into(),
                ..Overview::default()
            },
            Details {
                password: "s3cret".into(),
                notes: String::new(),
                otp: String::new(),
            },
        )
        .unwrap();
    drop(alice);

    // Her Mac is gone; she has the words from her recovery kit.
    let words = alice_secret.recovery_words();
    let secret = AccountSecret::from_recovery_words(&words).unwrap();
    let new_device = |name| NewAccount {
        server: &fixture.url,
        secret: &secret,
        device_id: DeviceId::random(),
        device_name: name,
        signer: enclave(),
    };

    // A kit with the wrong owner fingerprint is refused, and nothing is saved.
    let error = recover(
        &fixture.profile("alice-wrong"),
        new_device("Alice's new Mac"),
        Some("0000-0000-0000-0000-0000"),
    )
    .err()
    .unwrap();
    assert!(format!("{error:#}").contains("Don't trust this server"));
    assert!(!fixture.profile("alice-wrong").exists());

    // She's the owner, so the owner's fingerprint can be left out: it's her own.
    let mut alice = recover(
        &fixture.profile("alice-new"),
        new_device("Alice's new Mac"),
        None,
    )
    .unwrap();
    let me = alice.whoami();
    assert!(me.is_owner);
    assert_eq!(me.fingerprint, owner_fingerprint);
    alice.sync().unwrap();
    assert_eq!(alice.folders().unwrap(), ["Production"]);
    let rows = alice.list().unwrap();
    assert_eq!(rows[0].name, "AWS root");
    assert_eq!(alice.open_item(rows[0].id).unwrap().1.password, "s3cret");

    // Both Macs are listed; removing the old one locks it out.
    let devices = alice.devices().unwrap();
    assert_eq!(devices.len(), 2);
    let current = devices.iter().find(|device| device.current).unwrap();
    assert_eq!(current.name, "Alice's new Mac");
    let old = devices.iter().find(|device| !device.current).unwrap();
    assert_eq!(old.name, "Alice's old Mac");
    assert!(
        alice.remove_device(current.id).is_err(),
        "can't remove itself"
    );
    alice.remove_device(old.id).unwrap();
    assert_eq!(alice.devices().unwrap().len(), 1);
    let mut stolen = Vault::open(&fixture.profile("alice-old"), &alice_secret, old_mac).unwrap();
    assert!(stolen.sync().is_err());

    // She's still the owner: she can invite. Bob joins, but recovering his account needs
    // the owner's fingerprint: without it, nothing is registered or saved.
    let invite = alice.invite("Bob").unwrap();
    let bob_secret = AccountSecret::generate();
    let bob_account = |device_name| NewAccount {
        server: &fixture.url,
        secret: &bob_secret,
        device_id: DeviceId::random(),
        device_name,
        signer: enclave(),
    };
    join(
        &fixture.profile("bob"),
        bob_account("Bob's Mac"),
        &invite.token,
        &invite.owner_fingerprint,
    )
    .unwrap();
    let error = recover(
        &fixture.profile("bob-new"),
        bob_account("Bob's new Mac"),
        None,
    )
    .err()
    .unwrap();
    assert!(
        format!("{error:#}").contains("isn't the owner"),
        "{error:#}"
    );
    assert!(!fixture.profile("bob-new").exists());
    let mut bob = recover(
        &fixture.profile("bob-new"),
        bob_account("Bob's new Mac"),
        Some(&owner_fingerprint),
    )
    .unwrap();
    assert_eq!(bob.devices().unwrap().len(), 2);

    // Alice signs out on her new Mac: the server forgets it and its profile is gone.
    assert_eq!(alice.sign_out().unwrap(), None);
    assert!(!fixture.profile("alice-new").exists());
    assert_eq!(
        bob.devices().unwrap().len(),
        2,
        "Bob's devices are untouched"
    );
}

fn login(name: &str, password: &str) -> (Overview, Details) {
    (
        Overview {
            name: name.into(),
            ..Overview::default()
        },
        Details {
            password: password.into(),
            notes: String::new(),
            otp: String::new(),
        },
    )
}

/// A team on a fresh server: Alice the owner, Bob approved, and Carol, who has joined but
/// isn't approved. Returns each vault and Alice's secret and signer.
struct Team {
    alice: Vault,
    bob: Vault,
    carol: Vault,
    alice_secret: AccountSecret,
    alice_signer: Arc<dyn DeviceSigner>,
    bob_secret: AccountSecret,
}

fn team(fixture: &Fixture) -> Team {
    let alice_secret = AccountSecret::generate();
    let alice_signer: Arc<dyn DeviceSigner> = Arc::new(SoftwareDeviceKey::generate());
    let mut alice = setup(
        &fixture.profile("alice"),
        NewAccount {
            server: &fixture.url,
            secret: &alice_secret,
            device_id: DeviceId::random(),
            device_name: "Test device",
            signer: alice_signer.clone(),
        },
        &fixture.setup_code,
        "Alice",
    )
    .unwrap();
    let mut member = |name: &str| {
        let invite = alice.invite(name).unwrap();
        let secret = AccountSecret::generate();
        let vault = join(
            &fixture.profile(name),
            NewAccount {
                server: &invite.server,
                secret: &secret,
                device_id: DeviceId::random(),
                device_name: "Test device",
                signer: Arc::new(SoftwareDeviceKey::generate()),
            },
            &invite.token,
            &invite.owner_fingerprint,
        )
        .unwrap();
        (vault, secret)
    };
    let (bob, bob_secret) = member("Bob");
    let (carol, _) = member("Carol");
    let bob_identity = bob.whoami();
    alice
        .approve(bob_identity.user_id, &bob_identity.fingerprint)
        .unwrap();
    Team {
        alice,
        bob,
        carol,
        alice_secret,
        alice_signer,
        bob_secret,
    }
}

#[test]
fn a_login_outside_folders_is_private_until_shared() {
    let fixture = Fixture::start();
    let Team {
        mut alice,
        mut bob,
        carol,
        ..
    } = team(&fixture);
    let bob_id = bob.whoami().user_id;

    let (overview, details) = login("Bank", "s3cret");
    let bank = alice.add(None, overview, details).unwrap();
    let rows = alice.list().unwrap();
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].folder, None);
    assert_eq!(rows[0].owner, None);
    assert!(rows[0].shared_with.is_empty());
    assert!(!rows[0].shared_with_me);
    bob.sync().unwrap();
    assert!(bob.list().unwrap().is_empty());

    // Only approved people, once each, and not yourself.
    let carol_id = carol.whoami().user_id;
    let error = alice.share_item(bank, carol_id, Role::Edit).unwrap_err();
    assert!(format!("{error:#}").contains("isn't approved"), "{error:#}");
    let me = alice.whoami().user_id;
    assert!(alice.share_item(bank, me, Role::Edit).is_err());
    assert_eq!(alice.share_item(bank, bob_id, Role::Edit).unwrap(), "Bob");
    assert!(alice.share_item(bank, bob_id, Role::Edit).is_err());
    assert_eq!(alice.list().unwrap()[0].shared_with, ["Bob"]);

    bob.sync().unwrap();
    let rows = bob.list().unwrap();
    assert_eq!(rows.len(), 1);
    assert!(rows[0].shared_with_me);
    assert_eq!(rows[0].owner.as_deref(), Some("Alice"));
    assert!(rows[0].shared_with.is_empty());
    assert_eq!(bob.open_item(bank).unwrap().1.password, "s3cret");

    // Bob can change it, and Alice gets his change.
    assert!(matches!(
        bob.edit(bank, "rotated").unwrap(),
        EditOutcome::Saved { version: 3 }
    ));
    alice.sync().unwrap();
    assert_eq!(alice.open_item(bank).unwrap().1.password, "rotated");
}

#[test]
fn one_login_from_a_folder_can_be_shared_alone() {
    let fixture = Fixture::start();
    let Team {
        mut alice,
        mut bob,
        alice_secret,
        alice_signer,
        ..
    } = team(&fixture);
    let bob_id = bob.whoami().user_id;
    alice.create_folder("Production").unwrap();
    let (overview, details) = login("Database", "db-pass");
    alice.add(Some("Production"), overview, details).unwrap();

    // A login saved by Keystead 0.1, in the old format, straight through the API.
    let keys = AccountKeys::derive(&alice_secret);
    let none = GroupKeyring::default();
    let folder_id = alice
        .profile()
        .find_folder(&keys, &none, "Production")
        .unwrap();
    let folder_key = alice.profile().folder_key(&keys, &none, folder_id).unwrap();
    let (overview, details) = login("AWS root", "aws-pass");
    let old = EncryptedItem::seal_format_1(
        ItemVersion {
            id: ItemId::random(),
            folder_id: Some(folder_id),
            owner: None,
            version: 1,
            author: alice.whoami().user_id,
        },
        &folder_key,
        &keys,
        &overview,
        &details,
    )
    .unwrap();
    let mut client = Client::new(&fixture.url);
    client
        .sign_in(alice.profile().device_id, alice_signer.as_ref())
        .unwrap();
    let _: EncryptedItem = client
        .put(
            &format!("/v1/items/{}", old.id),
            &PutItemRequest {
                base_version: None,
                item: old.clone(),
                roles: Vec::new(),
                group_roles: Vec::new(),
                password_changed: false,
            },
        )
        .unwrap();
    alice.sync().unwrap();
    assert_eq!(alice.open_item(old.id).unwrap().1.password, "aws-pass");

    // Sharing it converts it to the new format with a key of its own, in one version.
    alice.share_item(old.id, bob_id, Role::Edit).unwrap();
    let saved = &alice.profile().items[&old.id];
    assert_eq!((saved.format, saved.version), (2, 2));

    // Bob gets that login, not the folder or its other login.
    bob.sync().unwrap();
    let rows = bob.list().unwrap();
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].name, "AWS root");
    assert_eq!(rows[0].folder, None);
    assert!(rows[0].shared_with_me);
    assert!(bob.folders().unwrap().is_empty());
    assert_eq!(bob.open_item(old.id).unwrap().1.password, "aws-pass");

    // Alice still sees both in the folder, and who the one is shared with.
    let rows = alice.list().unwrap();
    assert!(
        rows.iter()
            .all(|row| row.folder.as_deref() == Some("Production"))
    );
    let aws = rows.iter().find(|row| row.name == "AWS root").unwrap();
    assert_eq!(aws.shared_with, ["Bob"]);

    // Deleting removes it for everyone who could open it; after that it can't be saved.
    alice.delete(old.id).unwrap();
    assert!(alice.list().unwrap().iter().all(|row| row.id != old.id));
    bob.sync().unwrap();
    assert!(bob.list().unwrap().is_empty());
    let (overview, details) = login("AWS root", "back");
    assert!(alice.update(old.id, &overview, &details).is_err());

    // A login still in the old format can be deleted too.
    let (overview, details) = login("Legacy", "pw");
    let legacy = EncryptedItem::seal_format_1(
        ItemVersion {
            id: ItemId::random(),
            folder_id: Some(folder_id),
            owner: None,
            version: 1,
            author: alice.whoami().user_id,
        },
        &folder_key,
        &keys,
        &overview,
        &details,
    )
    .unwrap();
    let _: EncryptedItem = client
        .put(
            &format!("/v1/items/{}", legacy.id),
            &PutItemRequest {
                base_version: None,
                item: legacy.clone(),
                roles: Vec::new(),
                group_roles: Vec::new(),
                password_changed: false,
            },
        )
        .unwrap();
    alice.sync().unwrap();
    assert!(matches!(
        alice.delete(legacy.id).unwrap(),
        EditOutcome::Saved { version: 2 }
    ));
    assert!(alice.list().unwrap().iter().all(|row| row.name != "Legacy"));

    // Editing every field keeps the folder and who it's shared with; a name is required.
    let database = alice
        .list()
        .unwrap()
        .into_iter()
        .find(|row| row.name == "Database")
        .unwrap();
    let (mut overview, mut details) = alice.open_item(database.id).unwrap();
    overview.name = "Database (prod)".into();
    overview.url = "postgres://db.example.com".into();
    details.notes = "Rotated monthly".into();
    assert!(matches!(
        alice.update(database.id, &overview, &details).unwrap(),
        EditOutcome::Saved { version: 2 }
    ));
    let (overview, details) = alice.open_item(database.id).unwrap();
    assert_eq!(overview.name, "Database (prod)");
    assert_eq!(details.notes, "Rotated monthly");
    assert_eq!(details.password, "db-pass");
    assert!(
        alice
            .update(database.id, &Overview::default(), &details)
            .is_err()
    );
}

fn rand_core_rng() -> impl p256::elliptic_curve::rand_core::CryptoRngCore {
    p256::elliptic_curve::rand_core::OsRng
}

#[test]
fn someone_removed_from_a_folder_cant_read_what_is_saved_afterwards() {
    let fixture = Fixture::start();
    let Team {
        mut alice,
        mut bob,
        mut carol,
        bob_secret,
        ..
    } = team(&fixture);
    let (bob_id, carol_id) = (bob.whoami().user_id, carol.whoami().user_id);
    let carol_identity = carol.whoami();
    alice
        .approve(carol_id, &carol_identity.fingerprint)
        .unwrap();
    alice.create_folder("Production").unwrap();
    alice
        .share_folder("Production", bob_id, Role::Edit)
        .unwrap();
    alice
        .share_folder("Production", carol_id, Role::View)
        .unwrap();
    let (overview, details) = login("Database", "db-pass");
    let database = alice.add(Some("Production"), overview, details).unwrap();
    bob.sync().unwrap();
    carol.sync().unwrap();
    let folder_id = alice.profile().items[&database].folder_id.unwrap();
    // What Bob holds before he's removed: the folder's key, and his account keys.
    let bob_keys = AccountKeys::derive(&bob_secret);
    let bobs_old_key = bob
        .profile()
        .folder_key(&bob_keys, &GroupKeyring::default(), folder_id)
        .unwrap();

    // Carol, a viewer, can read but not change, share or remove.
    assert_eq!(carol.list().unwrap()[0].role, Role::View);
    assert_eq!(carol.open_item(database).unwrap().1.password, "db-pass");
    assert!(carol.edit(database, "mine").is_err());
    assert!(
        carol
            .share_folder("Production", bob_id, Role::View)
            .is_err()
    );
    assert!(carol.remove_from_folder("Production", bob_id).is_err());
    let members = alice.folder_members("Production").unwrap();
    let roles: Vec<(UserId, Role)> = members.iter().map(|m| (m.user_id, m.role)).collect();
    assert_eq!(
        roles,
        [
            (alice.whoami().user_id, Role::Manage),
            (bob_id, Role::Edit),
            (carol_id, Role::View)
        ]
    );

    // Alice removes Bob: the folder gets a new key at once.
    alice.remove_from_folder("Production", bob_id).unwrap();
    assert_eq!(alice.profile().folders[&folder_id].generation, 1);
    bob.sync().unwrap();
    assert!(bob.list().unwrap().is_empty());
    assert!(bob.folders().unwrap().is_empty());

    // Carol still opens the login saved under the old key, through the chain.
    carol.sync().unwrap();
    assert_eq!(carol.profile().folders[&folder_id].generation, 1);
    assert_eq!(carol.open_item(database).unwrap().1.password, "db-pass");
    assert_eq!(carol.folders().unwrap(), ["Production"]);

    // Alice changes the password: even holding the old folder key, Bob can't open it.
    alice.edit(database, "rotated").unwrap();
    let new_version = alice.profile().items[&database].clone();
    assert!(
        new_version
            .unlock(Some(&bobs_old_key), &bob_keys, bob_id)
            .is_err()
    );
    carol.sync().unwrap();
    assert_eq!(carol.open_item(database).unwrap().1.password, "rotated");

    // Carol leaves; the next sync of Alice, the manager, gives the folder a new key again.
    carol.remove_from_folder("Production", carol_id).unwrap();
    assert!(carol.list().unwrap().is_empty());
    let summary = alice.sync().unwrap();
    assert_eq!((summary.rekeyed, summary.rekey_problems.len()), (1, 0));
    assert_eq!(alice.profile().folders[&folder_id].generation, 2);
    assert_eq!(alice.open_item(database).unwrap().1.password, "rotated");
}

#[test]
fn roles_on_a_login_and_removing_someone_from_the_team() {
    let fixture = Fixture::start();
    let Team {
        mut alice, mut bob, ..
    } = team(&fixture);
    let bob_id = bob.whoami().user_id;
    let (overview, details) = login("Bank", "s3cret");
    let bank = alice.add(None, overview, details).unwrap();

    // Shared with Bob to view: he can open it but not change it.
    alice.share_item(bank, bob_id, Role::View).unwrap();
    bob.sync().unwrap();
    assert_eq!(bob.list().unwrap()[0].role, Role::View);
    assert!(bob.edit(bank, "mine").is_err());
    let people: Vec<(UserId, Role)> = alice
        .item_people(bank)
        .unwrap()
        .iter()
        .map(|person| (person.user_id, person.role))
        .collect();
    assert_eq!(
        people,
        [(alice.whoami().user_id, Role::Manage), (bob_id, Role::View)]
    );

    // Made an editor, he can change it, but not share it or take anyone's copy away.
    alice.set_item_role(bank, bob_id, Role::Edit).unwrap();
    bob.sync().unwrap();
    assert!(matches!(
        bob.edit(bank, "bobs").unwrap(),
        EditOutcome::Saved { .. }
    ));
    assert!(bob.unshare_item(bank, bob_id).is_err());

    // Alice takes his copy away; his devices drop it.
    alice.sync().unwrap();
    alice.unshare_item(bank, bob_id).unwrap();
    bob.sync().unwrap();
    assert!(bob.list().unwrap().is_empty());

    // Shared again, then Bob is removed from the team: his device stops working, he's
    // marked removed, and nobody can share with him again.
    alice.share_item(bank, bob_id, Role::Edit).unwrap();
    assert_eq!(alice.remove_user(bob_id).unwrap(), "Bob");
    assert!(bob.sync().is_err());
    let users = alice.users().unwrap();
    assert!(
        users
            .iter()
            .any(|user| user.user_id == bob_id && user.removed)
    );
    let error = alice.share_item(bank, bob_id, Role::View).unwrap_err();
    assert!(format!("{error:#}").contains("removed"), "{error:#}");
    // His past copy is gone from the login the next time it's saved.
    alice.edit(bank, "after-bob").unwrap();
    let saved = &alice.profile().items[&bank];
    assert!(saved.keys.people.is_empty());
}

#[test]
fn groups_share_folders_and_logins_and_lose_access_when_someone_leaves() {
    let fixture = Fixture::start();
    let Team {
        mut alice,
        mut bob,
        mut carol,
        ..
    } = team(&fixture);
    let bob_id = bob.whoami().user_id;
    let carol_identity = carol.whoami();
    let carol_id = carol_identity.user_id;
    alice
        .approve(carol_id, &carol_identity.fingerprint)
        .unwrap();

    // Only the owner makes groups, each with its own name.
    assert!(bob.create_group("Ops", &[]).is_err());
    let group_id = alice.create_group("Ops", &[bob_id]).unwrap();
    assert!(alice.create_group("Ops", &[]).is_err());

    // A folder and a login shared with the group reach Bob, with the group's roles.
    alice.create_folder("Production").unwrap();
    let (overview, details) = login("Database", "db-pass");
    let database = alice.add(Some("Production"), overview, details).unwrap();
    let folder_id = alice.profile().items[&database].folder_id.unwrap();
    alice
        .share_folder_with_group("Production", "Ops", Role::Edit)
        .unwrap();
    let (overview, details) = login("Pager", "pager-pass");
    let pager = alice.add(None, overview, details).unwrap();
    alice
        .share_item_with_group(pager, "Ops", Role::View)
        .unwrap();
    assert_eq!(alice.profile().items[&pager].format, 3);
    bob.sync().unwrap();
    assert_eq!(bob.open_item(database).unwrap().1.password, "db-pass");
    assert_eq!(bob.open_item(pager).unwrap().1.password, "pager-pass");
    let rows = bob.list().unwrap();
    let row = |id: ItemId| rows.iter().find(|row| row.id == id).unwrap();
    assert_eq!(row(database).role, Role::Edit);
    assert_eq!(row(pager).role, Role::View);
    assert_eq!(row(pager).shared_with_groups, ["Ops"]);
    assert!(matches!(
        bob.edit(database, "db-2").unwrap(),
        EditOutcome::Saved { .. }
    ));
    assert!(bob.edit(pager, "mine").is_err());
    let groups = bob.groups();
    assert_eq!(groups[0].name, "Ops");
    assert!(groups[0].member && !groups[0].can_manage);
    let (_, shares) = alice.folder_sharing("Production").unwrap();
    assert_eq!(
        shares
            .iter()
            .map(|share| (share.name.as_str(), share.role))
            .collect::<Vec<_>>(),
        [("Ops", Role::Edit)]
    );

    // Only managers add people. Carol, added later, gets what the group already had.
    assert!(bob.add_to_group("Ops", carol_id).is_err());
    alice.add_to_group("Ops", carol_id).unwrap();
    carol.sync().unwrap();
    assert_eq!(carol.open_item(database).unwrap().1.password, "db-2");
    assert_eq!(carol.open_item(pager).unwrap().1.password, "pager-pass");

    // Alice takes Bob out. His devices drop what the group gave him, and Alice's app gives
    // the group and then the folder new keys.
    let summary = alice.remove_from_group("Ops", bob_id).unwrap();
    assert_eq!(summary.rekeyed, 2, "{:?}", summary.rekey_problems);
    assert_eq!(alice.profile().groups[&group_id].generation, 2);
    assert_eq!(alice.profile().folders[&folder_id].generation, 1);
    bob.sync().unwrap();
    assert!(bob.list().unwrap().is_empty());
    assert!(!bob.groups()[0].member);

    // Carol still opens everything: the login's copy for the group's first key through
    // the group's chain, and what's saved from now on with the new keys.
    carol.sync().unwrap();
    assert_eq!(carol.profile().groups[&group_id].generation, 2);
    assert_eq!(carol.open_item(pager).unwrap().1.password, "pager-pass");
    alice.edit(database, "db-3").unwrap();
    alice.edit(pager, "pager-2").unwrap();
    carol.sync().unwrap();
    assert_eq!(carol.open_item(database).unwrap().1.password, "db-3");
    assert_eq!(carol.open_item(pager).unwrap().1.password, "pager-2");
    assert_eq!(alice.profile().items[&pager].keys.groups[0].generation, 2);

    // Carol joins the folder herself too. When the group stops having it, she keeps it,
    // and gets its key again as her own.
    alice
        .share_folder("Production", carol_id, Role::View)
        .unwrap();
    carol.sync().unwrap();
    assert!(carol.profile().folders[&folder_id].via_group.is_some());
    alice.remove_group_from_folder("Production", "Ops").unwrap();
    carol.sync().unwrap();
    assert!(carol.profile().folders[&folder_id].via_group.is_none());
    assert_eq!(carol.open_item(database).unwrap().1.password, "db-3");

    // Carol leaves the group herself: the login shared with it goes, her folder stays.
    carol.remove_from_group("Ops", carol_id).unwrap();
    let names: Vec<String> = carol
        .list()
        .unwrap()
        .into_iter()
        .map(|row| row.name)
        .collect();
    assert_eq!(names, ["Database"]);
    assert!(carol.profile().groups.is_empty());

    // Renaming and managers: Alice makes the group's new name stick for everyone.
    alice.rename_group("Ops", "Operations").unwrap();
    bob.sync().unwrap();
    assert_eq!(bob.groups()[0].name, "Operations");
}

#[test]
fn passwords_to_change_after_someone_loses_access() {
    let fixture = Fixture::start();
    let Team {
        mut alice,
        mut bob,
        mut carol,
        ..
    } = team(&fixture);
    let bob_id = bob.whoami().user_id;
    let alice_id = alice.whoami().user_id;
    let carol_identity = carol.whoami();
    alice
        .approve(carol_identity.user_id, &carol_identity.fingerprint)
        .unwrap();
    let names = |vault: &Vault| -> Vec<(String, String)> {
        vault
            .to_change()
            .unwrap()
            .into_iter()
            .map(|row| (row.name, row.user_name))
            .collect()
    };

    // Bob edits in Production and Carol views it; Bob also made a login of his own.
    alice.create_folder("Production").unwrap();
    for (name, password) in [("Database", "db-1"), ("Deploy key", "dk-1")] {
        let (overview, details) = login(name, password);
        alice.add(Some("Production"), overview, details).unwrap();
    }
    alice
        .share_folder("Production", bob_id, Role::Edit)
        .unwrap();
    alice
        .share_folder("Production", carol_identity.user_id, Role::View)
        .unwrap();
    bob.sync().unwrap();
    let (overview, details) = login("VPN", "vpn-1");
    let vpn = bob.add(None, overview, details).unwrap();
    bob.share_item(vpn, alice_id, Role::Edit).unwrap();
    alice.sync().unwrap();
    assert!(names(&alice).is_empty());

    // Bob leaves Production: he could see both passwords. Alice can change them, so she
    // sees them; Carol only views, so she doesn't.
    alice.remove_from_folder("Production", bob_id).unwrap();
    alice.sync().unwrap();
    let rows = alice.to_change().unwrap();
    assert_eq!(rows.len(), 2);
    assert!(rows.iter().all(|row| row.user_id == bob_id
        && row.folder.as_deref() == Some("Production")
        && row.since > 1_700_000_000));
    carol.sync().unwrap();
    assert!(names(&carol).is_empty());

    // Saving without a new password keeps it on the list; a new password takes it off.
    let database = alice.find_item("Database", None).unwrap();
    let (mut overview, details) = alice.open_item(database).unwrap();
    overview.username = "admin".into();
    alice.update(database, &overview, &details).unwrap();
    alice.sync().unwrap();
    assert_eq!(names(&alice).len(), 2);
    alice.edit(database, "db-2").unwrap();
    assert_eq!(names(&alice), [("Deploy key".into(), "Bob".into())]);
    alice.sync().unwrap();
    assert_eq!(names(&alice), [("Deploy key".into(), "Bob".into())]);

    // Dismissed, it's gone for good.
    let deploy_key = alice.find_item("Deploy key", None).unwrap();
    assert!(
        carol.dismiss(deploy_key, bob_id).is_err(),
        "viewers can't dismiss"
    );
    alice.dismiss(deploy_key, bob_id).unwrap();
    alice.sync().unwrap();
    assert!(names(&alice).is_empty());

    // Someone who gets access back isn't listed; removed from the team, they are again,
    // with what they made themselves.
    alice
        .share_folder("Production", bob_id, Role::View)
        .unwrap();
    alice.remove_from_folder("Production", bob_id).unwrap();
    alice
        .share_folder("Production", bob_id, Role::View)
        .unwrap();
    alice.sync().unwrap();
    assert!(names(&alice).is_empty());
    alice.remove_user(bob_id).unwrap();
    let mut listed = names(&alice);
    listed.sort();
    assert_eq!(
        listed,
        [
            ("Database".into(), "Bob".into()),
            ("Deploy key".into(), "Bob".into()),
            ("VPN".into(), "Bob".into()),
        ]
    );

    // Deleting a login takes it off; the rest go in one step.
    alice.delete(vpn).unwrap();
    assert_eq!(names(&alice).len(), 2);
    assert_eq!(alice.dismiss_all(bob_id).unwrap(), 2);
    alice.sync().unwrap();
    assert!(names(&alice).is_empty());
}

#[test]
fn one_time_codes_are_kept_with_a_login_and_shared_with_it() {
    let fixture = Fixture::start();
    let Team {
        mut alice, mut bob, ..
    } = team(&fixture);
    let bob_id = bob.whoami().user_id;

    // A setup key as a site shows it: kept as a link, and the login becomes format 4.
    let (overview, mut details) = login("GitHub", "s3cret");
    details.otp = " jbsw y3dp ehpk 3pxp ".into();
    let github = alice.add(None, overview, details).unwrap();
    let saved = &alice.profile().items[&github];
    assert_eq!(saved.format, 4);
    let (overview, details) = alice.open_item(github).unwrap();
    assert!(overview.one_time_code);
    assert_eq!(details.otp, "otpauth://totp/?secret=JBSWY3DPEHPK3PXP");
    let code = alice.one_time_code(github).unwrap().unwrap();
    assert_eq!(code.code.len(), 6);
    assert!((1..=30).contains(&code.remaining));
    assert!(alice.list().unwrap()[0].has_one_time_code);

    // Whoever it's shared with gets the same codes; saving other changes keeps the code.
    alice.share_item(github, bob_id, Role::Edit).unwrap();
    bob.sync().unwrap();
    assert!(bob.list().unwrap()[0].has_one_time_code);
    assert!(bob.one_time_code(github).unwrap().is_some());
    bob.edit(github, "rotated").unwrap();
    alice.sync().unwrap();
    assert!(alice.one_time_code(github).unwrap().is_some());

    // Something that isn't a setup key is refused, without saving anything.
    let (overview, mut details) = alice.open_item(github).unwrap();
    details.otp = "not a key!".into();
    let error = alice.update(github, &overview, &details).unwrap_err();
    assert!(format!("{error:#}").contains("one-time code"), "{error:#}");

    // Removed, the login goes back to format 2 and has no codes.
    details.otp = String::new();
    alice.update(github, &overview, &details).unwrap();
    assert_eq!(alice.profile().items[&github].format, 2);
    assert!(alice.one_time_code(github).unwrap().is_none());
    assert!(!alice.list().unwrap()[0].has_one_time_code);
    assert_eq!(alice.too_new(), 0);
}

#[test]
fn a_logins_history_shows_what_changed_and_brings_back_old_versions() {
    let fixture = Fixture::start();
    let Team {
        mut alice, mut bob, ..
    } = team(&fixture);
    let bob_id = bob.whoami().user_id;
    let changes = |rows: &[keystead_client::HistoryRow]| -> Vec<(u64, Vec<String>)> {
        rows.iter()
            .map(|row| (row.version, row.changes.clone()))
            .collect()
    };

    // Created, then a new password, then new notes.
    let (overview, details) = login("Bank", "first");
    let bank = alice.add(None, overview, details).unwrap();
    alice.edit(bank, "second").unwrap();
    let (overview, mut details) = alice.open_item(bank).unwrap();
    details.notes = "PIN in the safe".into();
    alice.update(bank, &overview, &details).unwrap();
    let rows = alice.history(bank).unwrap();
    assert_eq!(
        changes(&rows),
        [
            (3, vec!["notes".to_owned()]),
            (2, vec!["password".to_owned()]),
            (1, vec!["created".to_owned()]),
        ]
    );
    assert!(rows[0].current && !rows[1].current);
    assert!(
        rows.iter()
            .all(|row| row.readable && row.saved_at.is_some() && row.author == "Alice")
    );
    assert_eq!(alice.history_version(bank, 1).unwrap().1.password, "first");

    // Bringing back version 1 is a new version with its password and notes.
    alice.restore(bank, 1).unwrap();
    assert_eq!(alice.open_item(bank).unwrap().1.password, "first");
    let rows = alice.history(bank).unwrap();
    assert_eq!(rows[0].version, 4);
    assert_eq!(rows[0].changes, ["password", "notes"]);
    assert!(alice.restore(bank, 4).is_err(), "already current");

    // Viewers can't see the history; an editor added later can't open versions from
    // before it was shared with them.
    alice.share_item(bank, bob_id, Role::View).unwrap();
    bob.sync().unwrap();
    let error = bob.history(bank).unwrap_err();
    assert!(format!("{error:#}").contains("edit"), "{error:#}");
    alice.set_item_role(bank, bob_id, Role::Edit).unwrap();
    bob.sync().unwrap();
    let rows = bob.history(bank).unwrap();
    assert!(rows[0].readable);
    assert!(!rows.iter().find(|row| row.version == 1).unwrap().readable);

    // The server keeps ten earlier versions; deleting the login deletes them.
    for n in 0..12 {
        alice.edit(bank, &format!("p{n}")).unwrap();
    }
    assert_eq!(alice.history(bank).unwrap().len(), 11);
    alice.delete(bank).unwrap();
    assert!(alice.history(bank).is_err());
}

#[test]
fn a_new_device_joins_from_one_the_account_already_has() {
    use keystead_client::{DeviceSetupLine, JoiningDevice};

    let fixture = Fixture::start();
    let Team {
        mut alice,
        alice_secret,
        bob_secret,
        ..
    } = team(&fixture);
    let (overview, details) = login("Bank", "s3cret");
    let bank = alice.add(None, overview, details).unwrap();

    // Alice's Mac starts; the line goes to her new laptop, which joins and shows a code.
    let line = alice.start_adding_device().unwrap();
    assert_eq!(alice.new_device().unwrap(), None);
    let joining =
        JoiningDevice::start(DeviceSetupLine::parse(&line.command()).unwrap(), "Laptop").unwrap();
    assert!(joining.poll().unwrap().is_none(), "nothing sent yet");
    // The line works once.
    assert!(JoiningDevice::start(line.clone(), "Someone else").is_err());
    assert_eq!(alice.new_device().unwrap().as_deref(), Some("Laptop"));

    // A wrong code, or another account's secret, sends nothing.
    let error = alice
        .send_account_to_new_device("0000-0000-0000-0000-0000", &alice_secret)
        .unwrap_err();
    assert!(format!("{error:#}").contains("isn't the code"), "{error:#}");
    assert!(
        alice
            .send_account_to_new_device(joining.code(), &bob_secret)
            .is_err()
    );
    // Typed with spaces and in capitals, it still matches.
    let typed = joining.code().to_uppercase().replace('-', " ");
    assert_eq!(
        alice
            .send_account_to_new_device(&typed, &alice_secret)
            .unwrap(),
        "Laptop"
    );

    // The laptop gets the secret and registers itself as recovery does.
    let secret = joining.poll().unwrap().expect("sent");
    let mut laptop = recover(
        &fixture.profile("alice-laptop"),
        NewAccount {
            server: &joining.line().server,
            secret: &secret,
            device_id: DeviceId::random(),
            device_name: "Laptop",
            signer: Arc::new(SoftwareDeviceKey::generate()),
        },
        Some(&joining.line().owner_fingerprint),
    )
    .unwrap();
    assert_eq!(laptop.whoami().user_id, alice.whoami().user_id);
    laptop.sync().unwrap();
    assert_eq!(laptop.open_item(bank).unwrap().1.password, "s3cret");
    assert_eq!(alice.devices().unwrap().len(), 2);
    // It's done: the transfer is gone.
    assert!(joining.poll().is_err());
}

#[test]
fn a_deleted_login_can_be_brought_back_for_30_days() {
    let fixture = Fixture::start();
    let Team {
        mut alice, mut bob, ..
    } = team(&fixture);
    let bob_id = bob.whoami().user_id;

    // Bank, shared with Bob to edit, gets a new password, then Alice deletes it.
    let (overview, details) = login("Bank", "first");
    let bank = alice.add(None, overview, details).unwrap();
    alice.share_item(bank, bob_id, Role::Edit).unwrap();
    alice.edit(bank, "second").unwrap();
    alice.delete(bank).unwrap();
    bob.sync().unwrap();
    assert!(bob.list().unwrap().is_empty());

    // Both can see it in Recently Deleted, with who deleted it and until when it's kept.
    let rows = alice.deleted().unwrap().unwrap();
    assert_eq!(rows.len(), 1);
    assert_eq!(
        (rows[0].name.as_str(), rows[0].deleted_by.as_str()),
        ("Bank", "Alice")
    );
    assert_eq!(rows[0].kept_until - rows[0].deleted_at, 30 * 86_400);
    let rows = bob.deleted().unwrap().unwrap();
    assert_eq!(rows[0].item_id, bank);

    // Bob brings it back, as it last was; Alice gets it again.
    bob.undelete(bank).unwrap();
    assert_eq!(bob.open_item(bank).unwrap().1.password, "second");
    alice.sync().unwrap();
    assert_eq!(alice.open_item(bank).unwrap().1.password, "second");
    assert!(alice.deleted().unwrap().unwrap().is_empty());
    assert!(alice.history(bank).unwrap().len() >= 3);

    // Deleted again and then for good: it can't come back.
    alice.delete(bank).unwrap();
    assert_eq!(alice.deleted().unwrap().unwrap().len(), 1);
    alice.purge(bank).unwrap();
    assert!(alice.deleted().unwrap().unwrap().is_empty());
    assert!(alice.undelete(bank).is_err());
    bob.sync().unwrap();
    assert!(bob.deleted().unwrap().unwrap().is_empty());
}
