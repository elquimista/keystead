//! The client library against a real server on a local port, with the two kinds of
//! device key in use: a software Ed25519 key (CLI) and a P-256 key like the Mac's Secure
//! Enclave key.

use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicU32, Ordering};

use keystead_client::http::Client;
use keystead_client::{DeviceSigner, EditOutcome, NewAccount, Vault, join, recover, setup};
use keystead_core::api::{ApprovalRequest, EscrowRequest, PutItemRequest, Role};
use keystead_core::directory::{DirectoryEntry, escrow_consent};
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

    /// Changes the server's database behind its back, as a server that lies would have
    /// its lists say something its members never agreed to.
    fn lie(&self, sql: &str) {
        let path = self.root.join("server.sqlite");
        self._runtime.block_on(async {
            let options = sqlx::sqlite::SqliteConnectOptions::new().filename(&path);
            let pool = sqlx::SqlitePool::connect_with(options).await.unwrap();
            sqlx::raw_sql(sql).execute(&pool).await.unwrap();
            pool.close().await;
        });
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
        None,
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
    let mut first = join(
        &fixture.profile("bob"),
        bob_account("Bob's Mac"),
        &invite.token,
        &invite.owner_fingerprint,
        None,
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
    // Nor before the owner has approved him: until then, nothing says the account behind
    // a secret is his and not one the server made up. The device comes off again.
    let error = recover(
        &fixture.profile("bob-new"),
        bob_account("Bob's new Mac"),
        Some(&owner_fingerprint),
    )
    .err()
    .unwrap();
    assert!(
        format!("{error:#}").contains("hasn't approved this account yet"),
        "{error:#}"
    );
    assert!(!fixture.profile("bob-new").exists());
    assert_eq!(first.devices().unwrap().len(), 1);
    let identity = first.whoami();
    alice
        .approve(identity.user_id, &identity.fingerprint)
        .unwrap();
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
    bob_signer: Arc<dyn DeviceSigner>,
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
        let signer: Arc<dyn DeviceSigner> = Arc::new(SoftwareDeviceKey::generate());
        let vault = join(
            &fixture.profile(name),
            NewAccount {
                server: &invite.server,
                secret: &secret,
                device_id: DeviceId::random(),
                device_name: "Test device",
                signer: signer.clone(),
            },
            &invite.token,
            &invite.owner_fingerprint,
            None,
        )
        .unwrap();
        (vault, secret, signer)
    };
    let (bob, bob_secret, bob_signer) = member("Bob");
    let (carol, _, _) = member("Carol");
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
        bob_signer,
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

#[test]
fn deleting_a_group_takes_away_what_only_it_gave() {
    let fixture = Fixture::start();
    let Team {
        mut alice,
        mut bob,
        mut carol,
        ..
    } = team(&fixture);
    let alice_id = alice.whoami().user_id;
    let bob_id = bob.whoami().user_id;
    let carol_identity = carol.whoami();
    alice
        .approve(carol_identity.user_id, &carol_identity.fingerprint)
        .unwrap();

    // Ops (Alice and Bob) edits Production, and has Bank and Production's Database too.
    alice.create_group("Ops", &[bob_id]).unwrap();
    alice.create_folder("Production").unwrap();
    alice
        .share_folder_with_group("Production", "Ops", Role::Edit)
        .unwrap();
    alice
        .share_folder("Production", carol_identity.user_id, Role::Edit)
        .unwrap();
    let (overview, details) = login("Database", "db");
    alice.add(Some("Production"), overview, details).unwrap();
    let database = alice.find_item("Database", None).unwrap();
    alice
        .share_item_with_group(database, "Ops", Role::View)
        .unwrap();
    let (overview, details) = login("Bank", "bank");
    let bank = alice.add(None, overview, details).unwrap();
    alice
        .share_item_with_group(bank, "Ops", Role::Edit)
        .unwrap();
    bob.sync().unwrap();
    assert_eq!(bob.list().unwrap().len(), 2);

    // Not while it's the only manager of a folder: Infra, which Alice left to Ops.
    alice.create_folder("Infra").unwrap();
    alice
        .share_folder_with_group("Infra", "Ops", Role::Manage)
        .unwrap();
    alice.remove_from_folder("Infra", alice_id).unwrap();
    let error = alice.delete_group("Ops").unwrap_err();
    assert!(format!("{error:#}").contains("only manager"), "{error:#}");
    assert!(bob.delete_group("Ops").is_err(), "Bob isn't a manager");
    alice.share_folder("Infra", bob_id, Role::Manage).unwrap();

    // Deleted: Bob keeps Infra (his own now) but loses the rest; Alice's app gives
    // Production a new key.
    let generation = alice
        .profile()
        .folders
        .values()
        .map(|folder| folder.generation)
        .max()
        .unwrap();
    let summary = alice.delete_group("Ops").unwrap();
    assert_eq!(summary.rekey_problems, Vec::<String>::new());
    assert!(alice.groups().is_empty());
    bob.sync().unwrap();
    assert!(bob.list().unwrap().is_empty());
    assert_eq!(bob.folders().unwrap(), ["Infra"]);
    assert!(bob.groups().is_empty());
    assert!(
        alice
            .profile()
            .folders
            .values()
            .any(|folder| folder.generation > generation)
    );

    // Logins that had a copy for Ops lose it when next saved, even by an editor.
    carol.sync().unwrap();
    carol.edit(database, "db-2").unwrap();
    assert!(carol.profile().items[&database].keys.groups.is_empty());
    alice.edit(bank, "bank-2").unwrap();
    assert_eq!(alice.profile().items[&bank].format, 2);
    assert!(
        alice
            .list()
            .unwrap()
            .iter()
            .all(|row| row.shared_with_groups.is_empty())
    );
}

#[test]
fn an_export_from_passbolt_or_keepass_imports_into_folders() {
    use keepass::{Database, DatabaseKey};
    use keystead_client::read_kdbx;

    // A Passbolt-style export: a login at the top, Production with a code as KeePassXC
    // stores it, and Production / Databases with one as KeePass stores it.
    let mut database = Database::new();
    {
        let mut root = database.root_mut();
        {
            let mut wiki = root.add_entry();
            wiki.set_unprotected("Title", "Wiki");
            wiki.set_unprotected("UserName", "alice");
            wiki.set_protected("Password", "wiki-pw");
            wiki.set_unprotected("URL", "https://wiki.example.com");
            wiki.tags = vec!["docs".into()];
        }
        root.add_entry(); // empty: left out
        let mut production = root.add_group();
        production.name = "Production".into();
        {
            let mut aws = production.add_entry();
            aws.set_unprotected("Title", "AWS root");
            aws.set_unprotected("UserName", "root");
            aws.set_protected("Password", "aws-pw");
            aws.set_unprotected("Notes", "Break glass only");
            aws.set_protected(
                "otp",
                "otpauth://totp/AWS:root?secret=JBSWY3DPEHPK3PXP&issuer=AWS",
            );
            aws.set_unprotected("Account ID", "1234");
        }
        let mut databases = production.add_group();
        databases.name = "Databases".into();
        let mut postgres = databases.add_entry();
        postgres.set_unprotected("Title", "Postgres");
        postgres.set_protected("Password", "pg-pw");
        postgres.set_protected("TimeOtp-Secret-Base32", "JBSWY3DPEHPK3PXP");
        postgres.set_unprotected("TimeOtp-Period", "30");
        postgres.set_unprotected("TimeOtp-Length", "8");
        postgres.set_unprotected("TimeOtp-Algorithm", "HMAC-SHA-256");
    }
    let mut file = Vec::new();
    database
        .save(&mut file, DatabaseKey::new().with_password("export-pass"))
        .unwrap();

    let error = read_kdbx(&file, "wrong").err().unwrap();
    assert!(format!("{error:#}").contains("passphrase"), "{error:#}");
    let logins = read_kdbx(&file, "export-pass").unwrap();
    assert_eq!(logins.len(), 3);
    let aws = logins
        .iter()
        .find(|login| login.overview.name == "AWS root")
        .unwrap();
    assert_eq!(aws.folder.as_deref(), Some("Production"));
    assert_eq!(aws.details.notes, "Break glass only\nAccount ID: 1234");
    assert!(aws.details.otp.starts_with("otpauth://totp/AWS:root"));
    let postgres = logins
        .iter()
        .find(|login| login.overview.name == "Postgres")
        .unwrap();
    assert_eq!(postgres.folder.as_deref(), Some("Production / Databases"));
    assert!(postgres.details.otp.contains("digits=8") && postgres.details.otp.contains("SHA256"));
    assert!(
        postgres.details.notes.is_empty(),
        "the code's fields aren't notes"
    );

    // Alice already has Production and her Wiki login: Production is reused, the Wiki
    // login left out, and Production / Databases is new.
    let fixture = Fixture::start();
    let Team {
        mut alice, mut bob, ..
    } = team(&fixture);
    alice.create_folder("Production").unwrap();
    let (overview, details) = login("Wiki", "old");
    let mut overview = overview;
    overview.username = "alice".into();
    alice.add(None, overview, details).unwrap();
    let plan = alice.plan_import(&logins, None).unwrap();
    let folders: Vec<(&str, bool, usize)> = plan
        .folders
        .iter()
        .map(|folder| (folder.name.as_str(), folder.new, folder.logins))
        .collect();
    assert_eq!(
        folders,
        [
            ("Production", false, 1),
            ("Production / Databases", true, 1)
        ]
    );
    assert_eq!((plan.own, plan.duplicates, plan.one_time_codes), (0, 1, 2));

    let summary = alice.import(&logins, None).unwrap();
    assert_eq!(
        (summary.added, summary.folders_created, summary.duplicates),
        (2, 1, 1)
    );
    let rows = alice.list().unwrap();
    let postgres = rows.iter().find(|row| row.name == "Postgres").unwrap();
    assert_eq!(postgres.folder.as_deref(), Some("Production / Databases"));
    assert!(postgres.has_one_time_code);
    assert_eq!(
        alice
            .one_time_code(postgres.id)
            .unwrap()
            .unwrap()
            .code
            .len(),
        8
    );
    // Importing again adds nothing.
    assert_eq!(alice.import(&logins, None).unwrap().added, 0);

    // Bob only views Production: its login is left out for him; the rest goes elsewhere.
    alice
        .share_folder("Production", bob.whoami().user_id, Role::View)
        .unwrap();
    bob.sync().unwrap();
    let plan = bob.plan_import(&logins, Some("Imported")).unwrap();
    assert_eq!(plan.view_only, [("Production".to_owned(), 1)]);
    assert!(
        plan.folders
            .iter()
            .any(|folder| folder.name == "Imported" && folder.new)
    );
}

#[test]
fn a_folder_inside_another_starts_out_shared_like_it() {
    let fixture = Fixture::start();
    let Team {
        mut alice, mut bob, ..
    } = team(&fixture);
    let bob_id = bob.whoami().user_id;

    // Production: Bob edits it, and Ops (Alice and Bob) views it.
    alice.create_folder("Production").unwrap();
    alice
        .share_folder("Production", bob_id, Role::Edit)
        .unwrap();
    alice.create_group("Ops", &[bob_id]).unwrap();
    alice
        .share_folder_with_group("Production", "Ops", Role::View)
        .unwrap();

    let created = alice
        .create_folder_inside("Production", " Databases ", true)
        .unwrap();
    assert_eq!(created.name, "Production / Databases");
    assert_eq!(created.shared_with, ["Bob", "Ops (group)"]);
    assert!(created.problems.is_empty());
    let (people, groups) = alice.folder_sharing("Production / Databases").unwrap();
    let roles: Vec<(String, Role)> = people.into_iter().map(|p| (p.name, p.role)).collect();
    assert_eq!(
        roles,
        [
            ("Alice".to_owned(), Role::Manage),
            ("Bob".to_owned(), Role::Edit)
        ]
    );
    assert_eq!(groups[0].role, Role::View);
    bob.sync().unwrap();
    assert!(
        bob.folders()
            .unwrap()
            .contains(&"Production / Databases".to_owned())
    );

    // Private: only Alice. And the same name twice is refused.
    let private = alice
        .create_folder_inside("Production", "Root keys", false)
        .unwrap();
    assert!(private.shared_with.is_empty());
    bob.sync().unwrap();
    assert!(!bob.folders().unwrap().contains(&private.name));
    assert!(
        alice
            .create_folder_inside("Production", "Databases", true)
            .is_err()
    );
    assert!(alice.create_folder_inside("Nowhere", "X", true).is_err());
}

#[test]
fn a_login_moves_between_folders_and_who_had_it_only_there_loses_it() {
    let fixture = Fixture::start();
    let Team {
        mut alice,
        mut bob,
        mut carol,
        ..
    } = team(&fixture);
    let bob_id = bob.whoami().user_id;
    let carol_identity = carol.whoami();
    alice
        .approve(carol_identity.user_id, &carol_identity.fingerprint)
        .unwrap();
    let carol_id = carol_identity.user_id;

    // Production: Bob views. Staging: only Carol, who edits.
    alice.create_folder("Production").unwrap();
    alice
        .share_folder("Production", bob_id, Role::View)
        .unwrap();
    alice.create_folder("Staging").unwrap();
    alice.share_folder("Staging", carol_id, Role::Edit).unwrap();
    let (overview, details) = login("Database", "db-pw");
    alice.add(Some("Production"), overview, details).unwrap();
    let database = alice.find_item("Database", None).unwrap();
    bob.sync().unwrap();
    assert!(
        bob.move_item(database, Some("Staging")).is_err(),
        "Bob only views it"
    );

    // To Staging: Bob loses it, and it's on Alice's passwords to change for him; Carol,
    // only in Staging, gets it.
    alice.move_item(database, Some("Staging")).unwrap();
    assert!(
        alice.move_item(database, Some("Staging")).is_err(),
        "already there"
    );
    bob.sync().unwrap();
    assert!(bob.list().unwrap().is_empty());
    alice.sync().unwrap();
    alice.sync().unwrap();
    let rows = alice.to_change().unwrap();
    assert_eq!((rows.len(), rows[0].user_name.as_str()), (1, "Bob"));
    carol.sync().unwrap();
    let rows = carol.list().unwrap();
    assert_eq!(rows[0].folder.as_deref(), Some("Staging"));
    assert_eq!(carol.open_item(database).unwrap().1.password, "db-pw");

    // Out of folders, as Alice's own: Carol loses it too, and can't move it back.
    alice.move_item(database, None).unwrap();
    carol.sync().unwrap();
    assert!(carol.list().unwrap().is_empty());
    let row = alice
        .list()
        .unwrap()
        .into_iter()
        .find(|row| row.id == database)
        .unwrap();
    assert_eq!(row.folder, None);
    assert!(carol.move_item(database, Some("Staging")).is_err());

    // Back into Production: Bob has it again, and isn't on the list any more.
    alice.move_item(database, Some("Production")).unwrap();
    bob.sync().unwrap();
    assert_eq!(bob.list().unwrap()[0].folder.as_deref(), Some("Production"));
    alice.sync().unwrap();
    assert!(
        alice
            .to_change()
            .unwrap()
            .iter()
            .all(|row| row.user_name != "Bob")
    );
    assert_eq!(alice.open_item(database).unwrap().1.password, "db-pw");
}

#[test]
fn renaming_a_folder_renames_the_folders_inside_it_for_everyone() {
    let fixture = Fixture::start();
    let Team {
        mut alice, mut bob, ..
    } = team(&fixture);
    let alice_id = alice.whoami().user_id;
    let bob_id = bob.whoami().user_id;

    // Production and Production / Databases, both shared with Bob; Bob's own folder
    // inside, which Alice only views.
    alice.create_folder("Production").unwrap();
    alice
        .share_folder("Production", bob_id, Role::Edit)
        .unwrap();
    alice
        .create_folder_inside("Production", "Databases", true)
        .unwrap();
    let (overview, details) = login("Database", "db-pw");
    alice
        .add(Some("Production / Databases"), overview, details)
        .unwrap();
    bob.sync().unwrap();
    bob.create_folder_inside("Production", "Bob's", false)
        .unwrap();
    bob.share_folder("Production / Bob's", alice_id, Role::View)
        .unwrap();
    assert!(
        bob.rename_folder("Production", "Prod").is_err(),
        "Bob only edits it"
    );

    let renamed = alice.rename_folder("Production", "Prod").unwrap();
    assert_eq!(renamed.name, "Prod");
    assert_eq!(renamed.kept, ["Production / Bob's"]);
    assert!(renamed.problems.is_empty());
    let expected = ["Prod", "Prod / Databases", "Production / Bob's"];
    assert_eq!(alice.folders().unwrap(), expected);

    // Bob's devices pick the new names up, and the logins in them still open.
    bob.sync().unwrap();
    assert_eq!(bob.folders().unwrap(), expected);
    let database = bob.find_item("Database", None).unwrap();
    assert_eq!(
        bob.list().unwrap()[0].folder.as_deref(),
        Some("Prod / Databases")
    );
    assert_eq!(bob.open_item(database).unwrap().1.password, "db-pw");

    // No two folders end up with one name.
    assert!(
        alice
            .rename_folder("Prod / Databases", "Production / Bob's")
            .is_err()
    );
    assert!(alice.rename_folder("Prod", " ").is_err());
}

#[test]
fn deleting_a_folder_deletes_its_logins_for_everyone() {
    let fixture = Fixture::start();
    let Team {
        mut alice,
        mut bob,
        mut carol,
        ..
    } = team(&fixture);
    let bob_id = bob.whoami().user_id;
    let carol_identity = carol.whoami();
    alice
        .approve(carol_identity.user_id, &carol_identity.fingerprint)
        .unwrap();
    let carol_id = carol_identity.user_id;

    // Old has two logins: Bob views the folder, and Carol has Router directly. Carol was
    // in Old too, so Server's password is on the list to change.
    alice.create_folder("Old").unwrap();
    alice.share_folder("Old", bob_id, Role::View).unwrap();
    alice.share_folder("Old", carol_id, Role::View).unwrap();
    alice.create_folder_inside("Old", "Keep", false).unwrap();
    for (name, password) in [("Server", "server-pw"), ("Router", "router-pw")] {
        let (overview, details) = login(name, password);
        alice.add(Some("Old"), overview, details).unwrap();
    }
    let router = alice.find_item("Router", None).unwrap();
    alice.share_item(router, carol_id, Role::View).unwrap();
    alice.remove_from_folder("Old", carol_id).unwrap();

    let plan = alice.folder_deletion("Old").unwrap();
    assert_eq!(
        (plan.logins, plan.to_change, plan.inside.as_slice()),
        (2, 1, ["Old / Keep".to_owned()].as_slice())
    );
    bob.sync().unwrap();
    assert!(bob.delete_folder("Old", 2).is_err(), "Bob only views it");
    assert!(
        alice.delete_folder("Old", 1).is_err(),
        "it has another login than agreed to"
    );
    assert!(alice.folders().unwrap().contains(&"Old".to_owned()));

    alice.delete_folder("Old", plan.logins).unwrap();
    assert_eq!(alice.folders().unwrap(), ["Old / Keep"]);
    assert!(alice.list().unwrap().is_empty());
    assert!(alice.to_change().unwrap().is_empty());
    assert!(
        alice.deleted().unwrap().unwrap().is_empty(),
        "gone for good"
    );

    // Bob loses the folder, and Carol the login she had without it.
    bob.sync().unwrap();
    assert!(bob.folders().unwrap().is_empty());
    assert!(bob.list().unwrap().is_empty());
    carol.sync().unwrap();
    assert!(carol.list().unwrap().is_empty());
}

#[test]
fn an_export_opens_in_keepass_and_imports_back() {
    use keepass::config::KdfConfig;
    use keepass::{Database, DatabaseKey};
    use keystead_client::read_kdbx;

    let fixture = Fixture::start();
    let Team {
        mut alice, mut bob, ..
    } = team(&fixture);
    let alice_id = alice.whoami().user_id;

    // A login with everything in Production / Databases, an empty folder, one of Alice's
    // own, and one Bob shared with her.
    alice.create_folder("Production").unwrap();
    alice
        .create_folder_inside("Production", "Databases", false)
        .unwrap();
    alice.create_folder("Empty").unwrap();
    let (mut overview, mut details) = login("Postgres", "pg-pw");
    overview.username = "admin".into();
    overview.url = "https://db.example.com".into();
    overview.tags = vec!["db".into()];
    details.notes = "Primary\nsecond line".into();
    details.otp = "otpauth://totp/DB:admin?secret=JBSWY3DPEHPK3PXP&issuer=DB".into();
    alice
        .add(Some("Production / Databases"), overview, details)
        .unwrap();
    let (overview, details) = login("Bank", "bank-pw");
    alice.add(None, overview, details).unwrap();
    let (overview, details) = login("Wiki", "wiki-pw");
    bob.add(None, overview, details).unwrap();
    let wiki = bob.find_item("Wiki", None).unwrap();
    bob.share_item(wiki, alice_id, Role::View).unwrap();
    alice.sync().unwrap();

    assert!(
        alice.export_kdbx("too short").is_err(),
        "the file holds every password"
    );
    let export = alice.export_kdbx("correct horse battery").unwrap();
    assert_eq!((export.logins, export.left_out), (3, 0));

    // KeePass sees the folders as groups, even the empty one, and Argon2id over 128 MiB.
    assert!(read_kdbx(&export.file, "wrong passphrase").is_err());
    let database = Database::open(
        &mut &export.file[..],
        DatabaseKey::new().with_password("correct horse battery"),
    )
    .unwrap();
    let groups: Vec<String> = database.root().groups().map(|g| g.name.clone()).collect();
    assert_eq!(groups.len(), 2);
    assert!(groups.contains(&"Production".into()) && groups.contains(&"Empty".into()));
    assert!(matches!(
        database.config.kdf_config,
        KdfConfig::Argon2id { memory, .. } if memory == 128 * 1024 * 1024
    ));

    let mut logins = read_kdbx(&export.file, "correct horse battery").unwrap();
    logins.sort_by(|a, b| a.overview.name.cmp(&b.overview.name));
    let placed: Vec<(&str, Option<&str>)> = logins
        .iter()
        .map(|login| (login.overview.name.as_str(), login.folder.as_deref()))
        .collect();
    assert_eq!(
        placed,
        [
            ("Bank", None),
            ("Postgres", Some("Production / Databases")),
            ("Wiki", None)
        ]
    );
    let postgres = alice.find_item("Postgres", None).unwrap();
    let (overview, details) = alice.open_item(postgres).unwrap();
    assert_eq!(logins[1].overview.username, overview.username);
    assert_eq!(logins[1].overview.url, overview.url);
    assert_eq!(logins[1].overview.tags, overview.tags);
    assert_eq!(
        logins[1].details, details,
        "password, notes and one-time code"
    );

    // Bob imports it: Wiki is already his, the rest is new.
    let summary = bob.import(&logins, None).unwrap();
    assert_eq!((summary.added, summary.duplicates), (2, 1));
    let copy = bob
        .find_item("Postgres", Some("Production / Databases"))
        .unwrap();
    assert_eq!(bob.open_item(copy).unwrap().1, details);
}

/// A new device for an account, with its own secret and key, as recovering makes.
fn new_device<'a>(
    fixture: &'a Fixture,
    secret: &'a AccountSecret,
    device_id: DeviceId,
    signer: Arc<dyn DeviceSigner>,
) -> NewAccount<'a> {
    NewAccount {
        server: &fixture.url,
        secret,
        device_id,
        device_name: "New Mac",
        signer,
    }
}

#[test]
fn recovering_with_the_owners_help_brings_back_what_was_shared_and_own_logins_in_escrow() {
    use keystead_client::{claim_recovery, finish_recovery, recovery_approved};

    let fixture = Fixture::start();
    let Team {
        mut alice,
        mut bob,
        mut carol,
        alice_secret,
        bob_secret,
        ..
    } = team(&fixture);
    let bob_id = bob.whoami().user_id;
    let carol_identity = carol.whoami();
    alice
        .approve(carol_identity.user_id, &carol_identity.fingerprint)
        .unwrap();
    let carol_id = carol_identity.user_id;

    // Bob has Production himself, Staging through the Ops group, which he manages and
    // renamed, Wiki from Carol directly, and Bank of his own; he saved Database's password
    // twice. Escrow is on.
    alice.create_folder("Production").unwrap();
    alice
        .share_folder("Production", bob_id, Role::Edit)
        .unwrap();
    let (overview, details) = login("Database", "db-pw");
    alice.add(Some("Production"), overview, details).unwrap();
    alice.create_group("Ops", &[bob_id, carol_id]).unwrap();
    alice.create_folder("Staging").unwrap();
    alice
        .share_folder_with_group("Staging", "Ops", Role::View)
        .unwrap();
    let (overview, details) = login("Staging DB", "staging-pw");
    alice.add(Some("Staging"), overview, details).unwrap();
    carol.sync().unwrap();
    let (overview, details) = login("Wiki", "wiki-pw");
    carol.add(None, overview, details).unwrap();
    let wiki = carol.find_item("Wiki", None).unwrap();
    carol.share_item(wiki, bob_id, Role::View).unwrap();
    bob.sync().unwrap();
    let (overview, details) = login("Bank", "bank-pw");
    bob.add(None, overview, details).unwrap();
    let database = bob.find_item("Database", None).unwrap();
    bob.edit(database, "db-pw-1b").unwrap();
    bob.edit(database, "db-pw-2").unwrap();
    alice.set_group_manager("Ops", bob_id, true).unwrap();
    bob.rename_group("Ops", "Operations").unwrap();
    bob.set_escrow(true).unwrap();
    assert!(bob.whoami().escrow);
    assert!(
        alice.set_escrow(true).is_err(),
        "the owner has the recovery kit"
    );
    assert_eq!(bob.list().unwrap().len(), 4);

    // Bob loses everything. Alice starts a recovery; his old device hears of it.
    let line = alice.start_recovery(bob_id, false).unwrap();
    assert!(alice.start_recovery(alice.whoami().user_id, false).is_err());
    bob.sync().unwrap();
    assert!(bob.whoami().recovering);

    let secret = AccountSecret::generate();
    let signer: Arc<dyn DeviceSigner> = Arc::new(SoftwareDeviceKey::generate());
    let device_id = DeviceId::random();
    let claim = claim_recovery(
        &line,
        &new_device(&fixture, &secret, device_id, signer.clone()),
    )
    .unwrap();
    assert_eq!((claim.user_id, claim.name.as_str()), (bob_id, "Bob"));
    assert!(!recovery_approved(&line).unwrap());
    let other = AccountSecret::generate();
    let thief = new_device(
        &fixture,
        &other,
        DeviceId::random(),
        Arc::new(SoftwareDeviceKey::generate()),
    );
    assert!(
        claim_recovery(&line, &thief).is_err(),
        "the line works once"
    );
    let waiting = alice.recovery_request(bob_id).unwrap().unwrap();
    assert!(waiting.claimed && waiting.escrow);
    // A wrong fingerprint is refused without showing the right one: the owner hears it
    // from Bob.
    let wrong = alice
        .approve_recovery(bob_id, "0000-0000-0000-0000-0000")
        .unwrap_err();
    assert!(!format!("{wrong:#}").contains(&claim.fingerprint));
    assert!(
        alice
            .approve_recovery(bob_id, "0000-0000-0000-0000-0000")
            .is_err()
    );
    let approved = alice.approve_recovery(bob_id, &claim.fingerprint).unwrap();
    assert!(approved.own_logins);
    assert!(recovery_approved(&line).unwrap());
    assert!(bob.sync().is_err(), "the old devices stop working");

    // The new device has Bob's own login at once, sealed again with his new keys, and
    // escrow on again.
    let mut new_bob = finish_recovery(
        &fixture.profile("new-bob"),
        new_device(&fixture, &secret, device_id, signer),
        &line,
    )
    .unwrap();
    new_bob.sync().unwrap();
    let names = |vault: &Vault| {
        let mut names: Vec<String> = vault
            .list()
            .unwrap()
            .into_iter()
            .map(|row| row.name)
            .collect();
        names.sort();
        names
    };
    assert_eq!(names(&new_bob), ["Bank"]);
    new_bob.sync().unwrap();
    assert!(new_bob.whoami().escrow);

    // Alice's and Carol's apps give him the rest back, with new keys for what he had.
    alice.sync().unwrap();
    alice.sync().unwrap();
    carol.sync().unwrap();
    new_bob.sync().unwrap();
    assert_eq!(names(&new_bob), ["Bank", "Database", "Staging DB", "Wiki"]);
    let password = |vault: &Vault, name: &str| {
        let id = vault.find_item(name, None).unwrap();
        vault.open_item(id).unwrap().1.password.clone()
    };
    assert_eq!(
        password(&new_bob, "Database"),
        "db-pw-2",
        "signed with his old keys"
    );
    assert_eq!(password(&new_bob, "Bank"), "bank-pw");
    assert_eq!(password(&new_bob, "Wiki"), "wiki-pw");
    assert_eq!(password(&new_bob, "Staging DB"), "staging-pw");
    assert!(
        alice.to_change().unwrap().is_empty(),
        "it's the same person"
    );
    let row = alice
        .users()
        .unwrap()
        .into_iter()
        .find(|row| row.user_id == bob_id)
        .unwrap();
    assert!(row.keys_replaced && row.approved && row.escrow && !row.recovering);

    // What his old keys signed before still checks out, the version in history too; what
    // they sign from now on doesn't, even if a server passes it on.
    let old_keys = AccountKeys::derive(&bob_secret);
    let genuine = alice.profile().items[&database].clone();
    assert!(alice.profile().signed_by_author(&genuine));
    let history = alice.history(database).unwrap();
    assert_eq!(history.len(), 3, "Alice's version and both of Bob's");
    let alice_keys = AccountKeys::derive(&alice_secret);
    let none = GroupKeyring::default();
    let production = alice
        .profile()
        .find_folder(&alice_keys, &none, "Production")
        .unwrap();
    let folder_key = alice
        .profile()
        .folder_key(&alice_keys, &none, production)
        .unwrap();
    let (overview, details) = login("Database", "attackers-pw");
    for (id, version) in [(database, genuine.version + 1), (ItemId::random(), 1)] {
        let forged = EncryptedItem::seal_format_1(
            ItemVersion {
                id,
                folder_id: Some(production),
                owner: None,
                version,
                author: bob_id,
            },
            &folder_key,
            &old_keys,
            &overview,
            &details,
        )
        .unwrap();
        assert!(!alice.profile().signed_by_author(&forged));
    }
    let operations = alice.profile().find_group("Operations").unwrap();
    let (group, latest) = alice.profile().team_group(operations).unwrap();
    let mut entries = group.entries.clone();
    let mut forged = latest.next();
    forged.name = "Pwned".into();
    forged.sign(bob_id, &old_keys);
    entries.push(forged);
    assert!(alice.profile().verify_group(&entries).is_err());

    // He can save again, and everyone checks his new signature.
    let database = new_bob.find_item("Database", None).unwrap();
    new_bob.edit(database, "db-pw-3").unwrap();
    alice.sync().unwrap();
    assert_eq!(password(&alice, "Database"), "db-pw-3");
}

#[test]
fn without_escrow_only_what_was_shared_comes_back_and_a_recovery_can_be_cancelled() {
    use keystead_client::{claim_recovery, finish_recovery, recovery_approved};

    let fixture = Fixture::start();
    let Team {
        mut alice, mut bob, ..
    } = team(&fixture);
    let bob_id = bob.whoami().user_id;
    alice.create_folder("Production").unwrap();
    alice
        .share_folder("Production", bob_id, Role::View)
        .unwrap();
    let (overview, details) = login("Database", "db-pw");
    alice.add(Some("Production"), overview, details).unwrap();
    bob.sync().unwrap();
    let (overview, details) = login("Bank", "bank-pw");
    bob.add(None, overview, details).unwrap();

    // A recovery Bob didn't ask for: he cancels it from his device, and the line is dead.
    let line = alice.start_recovery(bob_id, false).unwrap();
    bob.sync().unwrap();
    bob.cancel_recovery(bob_id).unwrap();
    assert!(recovery_approved(&line).is_err());
    assert!(alice.recovery_request(bob_id).unwrap().is_none());

    // A real one, without escrow: Production comes back, Bank doesn't.
    let line = alice.start_recovery(bob_id, false).unwrap();
    let secret = AccountSecret::generate();
    let signer: Arc<dyn DeviceSigner> = Arc::new(SoftwareDeviceKey::generate());
    let device_id = DeviceId::random();
    let claim = claim_recovery(
        &line,
        &new_device(&fixture, &secret, device_id, signer.clone()),
    )
    .unwrap();
    let approved = alice.approve_recovery(bob_id, &claim.fingerprint).unwrap();
    assert!(!approved.own_logins);
    let mut new_bob = finish_recovery(
        &fixture.profile("new-bob"),
        new_device(&fixture, &secret, device_id, signer),
        &line,
    )
    .unwrap();
    alice.sync().unwrap();
    new_bob.sync().unwrap();
    let names: Vec<String> = new_bob
        .list()
        .unwrap()
        .into_iter()
        .map(|row| row.name)
        .collect();
    assert_eq!(names, ["Database"]);
}

#[test]
fn escrow_brings_back_folders_only_they_could_open_after_every_recovery() {
    use keystead_client::{claim_recovery, finish_recovery};

    let fixture = Fixture::start();
    let Team {
        mut alice, mut bob, ..
    } = team(&fixture);
    let bob_id = bob.whoami().user_id;
    let alice_id = alice.whoami().user_id;

    // Bob keeps Personal and Notes to himself, and shares Team with Alice. Personal is
    // older than his escrow and Notes newer; renaming Personal gives it a new key.
    bob.create_folder("Personal").unwrap();
    let (overview, details) = login("Router", "router-pw");
    bob.add(Some("Personal"), overview, details).unwrap();
    bob.set_escrow(true).unwrap();
    bob.create_folder("Notes").unwrap();
    let (overview, details) = login("Locker", "locker-pw");
    bob.add(Some("Notes"), overview, details).unwrap();
    bob.create_folder("Team").unwrap();
    let (overview, details) = login("Printer", "printer-pw");
    bob.add(Some("Team"), overview, details).unwrap();
    bob.sync().unwrap();
    bob.share_folder("Team", alice_id, Role::Edit).unwrap();
    bob.rename_folder("Personal", "Home").unwrap();
    bob.sync().unwrap();

    // A recovery, and how many folders the new device gave new keys on its first sync.
    let recover = |alice: &mut Vault, profile: &str, escrow: bool| -> (Vault, usize) {
        let line = alice.start_recovery(bob_id, false).unwrap();
        let secret = AccountSecret::generate();
        let signer: Arc<dyn DeviceSigner> = Arc::new(SoftwareDeviceKey::generate());
        let device_id = DeviceId::random();
        let claim = claim_recovery(
            &line,
            &new_device(&fixture, &secret, device_id, signer.clone()),
        )
        .unwrap();
        let approved = alice.approve_recovery(bob_id, &claim.fingerprint).unwrap();
        assert_eq!(approved.own_logins, escrow);
        let mut vault = finish_recovery(
            &fixture.profile(profile),
            new_device(&fixture, &secret, device_id, signer),
            &line,
        )
        .unwrap();
        let rekeyed = vault.sync().unwrap().rekeyed;
        (vault, rekeyed)
    };
    let names = |vault: &Vault| {
        let mut names: Vec<String> = vault
            .list()
            .unwrap()
            .into_iter()
            .map(|row| row.name)
            .collect();
        names.sort();
        names
    };
    let password = |vault: &Vault, name: &str| {
        let id = vault.find_item(name, None).unwrap();
        vault.open_item(id).unwrap().1.password.clone()
    };

    // He loses everything. His own folders are back on the new device at once, under
    // their new name, with new keys, as the lost device had the old ones. Team, which
    // Alice can open, waits for her app to give it back.
    let (mut new_bob, rekeyed) = recover(&mut alice, "new-bob", true);
    assert_eq!(new_bob.folders().unwrap(), ["Home", "Notes"]);
    assert_eq!(rekeyed, 2);
    assert_eq!(names(&new_bob), ["Locker", "Router"]);
    assert_eq!(password(&new_bob, "Router"), "router-pw");
    assert_eq!(password(&new_bob, "Locker"), "locker-pw");
    alice.sync().unwrap();
    new_bob.sync().unwrap();
    assert_eq!(new_bob.folders().unwrap(), ["Home", "Notes", "Team"]);
    assert_eq!(password(&new_bob, "Printer"), "printer-pw");

    // They got new keys, and those went back in escrow, sealed with his new personal key:
    // they come back after another recovery too.
    let (mut newer_bob, _) = recover(&mut alice, "newer-bob", true);
    assert_eq!(newer_bob.folders().unwrap(), ["Home", "Notes"]);
    assert_eq!(password(&newer_bob, "Router"), "router-pw");
    assert!(
        alice.to_change().unwrap().is_empty(),
        "it's the same person"
    );

    // Without escrow they don't.
    alice.sync().unwrap();
    newer_bob.sync().unwrap();
    newer_bob.set_escrow(false).unwrap();
    let (mut last_bob, _) = recover(&mut alice, "last-bob", false);
    assert!(last_bob.folders().unwrap().is_empty());
    alice.sync().unwrap();
    last_bob.sync().unwrap();
    assert_eq!(last_bob.folders().unwrap(), ["Team"]);
}

/// A new device's keys for recovering, sent with the line, and the owner's approval of them.
struct ApprovedDevice {
    line: keystead_client::RecoveryLine,
    secret: AccountSecret,
    signer: Arc<dyn DeviceSigner>,
    device_id: DeviceId,
    own_logins: bool,
}

/// Starts a recovery for `user`, sends a new device's keys, and has the owner approve them.
fn approve_new_device(fixture: &Fixture, owner: &mut Vault, user: UserId) -> ApprovedDevice {
    let line = owner.start_recovery(user, false).unwrap();
    let secret = AccountSecret::generate();
    let signer: Arc<dyn DeviceSigner> = Arc::new(SoftwareDeviceKey::generate());
    let device_id = DeviceId::random();
    let claim = keystead_client::claim_recovery(
        &line,
        &new_device(fixture, &secret, device_id, signer.clone()),
    )
    .unwrap();
    let approved = owner.approve_recovery(user, &claim.fingerprint).unwrap();
    ApprovedDevice {
        line,
        secret,
        signer,
        device_id,
        own_logins: approved.own_logins,
    }
}

/// Signs the approved device in, keeps its profile and syncs.
fn finish(fixture: &Fixture, device: &ApprovedDevice, profile: &str) -> Vault {
    let mut vault = keystead_client::finish_recovery(
        &fixture.profile(profile),
        new_device(
            fixture,
            &device.secret,
            device.device_id,
            device.signer.clone(),
        ),
        &device.line,
    )
    .unwrap();
    vault.sync().unwrap();
    vault
}

fn sorted_names(vault: &Vault) -> Vec<String> {
    let mut names: Vec<String> = vault
        .list()
        .unwrap()
        .into_iter()
        .map(|row| row.name)
        .collect();
    names.sort();
    names
}

#[test]
fn a_recovery_the_new_device_never_finished_can_be_done_again_losing_nothing() {
    let fixture = Fixture::start();
    let Team {
        mut alice, mut bob, ..
    } = team(&fixture);
    let bob_id = bob.whoami().user_id;
    let (overview, details) = login("Bank", "bank-pw");
    bob.add(None, overview, details).unwrap();
    bob.create_folder("Personal").unwrap();
    let (overview, details) = login("Router", "router-pw");
    bob.add(Some("Personal"), overview, details).unwrap();
    bob.set_escrow(true).unwrap();

    // The owner approves a new device that never finishes: Touch ID cancelled, say.
    let lost = approve_new_device(&fixture, &mut alice, bob_id);
    assert!(lost.own_logins);
    // So the owner helps again, and everything still comes back, escrow included.
    let device = approve_new_device(&fixture, &mut alice, bob_id);
    assert!(device.own_logins, "the escrowed key stayed");
    let mut new_bob = finish(&fixture, &device, "new-bob");
    new_bob.sync().unwrap();
    assert_eq!(sorted_names(&new_bob), ["Bank", "Router"]);
    assert_eq!(new_bob.folders().unwrap(), ["Personal"]);
    assert!(new_bob.whoami().escrow);
}

#[test]
fn removing_someone_still_waiting_after_a_recovery_lists_what_they_saw() {
    let fixture = Fixture::start();
    let Team {
        mut alice, mut bob, ..
    } = team(&fixture);
    let bob_id = bob.whoami().user_id;
    alice.create_folder("Production").unwrap();
    alice
        .share_folder("Production", bob_id, Role::View)
        .unwrap();
    let (overview, details) = login("Database", "db-pw");
    alice.add(Some("Production"), overview, details).unwrap();
    bob.sync().unwrap();

    // Bob recovers, and is removed before anyone gives him Production back: he saw it.
    let _device = approve_new_device(&fixture, &mut alice, bob_id);
    alice.remove_user(bob_id).unwrap();
    let rows = alice.to_change().unwrap();
    assert_eq!(rows.len(), 1);
    assert_eq!(
        (rows[0].name.as_str(), rows[0].user_id),
        ("Database", bob_id)
    );
}

#[test]
fn a_recovered_member_gets_a_folder_back_through_the_group_restored_first() {
    let fixture = Fixture::start();
    let Team {
        mut alice,
        bob,
        mut carol,
        ..
    } = team(&fixture);
    let bob_id = bob.whoami().user_id;
    let carol_identity = carol.whoami();
    alice
        .approve(carol_identity.user_id, &carol_identity.fingerprint)
        .unwrap();

    // Shared is shared with two groups Bob is in; Carol is only in the one the server
    // lists second.
    let blue = alice.create_group("Blue", &[bob_id]).unwrap();
    let green = alice.create_group("Green", &[bob_id]).unwrap();
    let second = if blue.to_string() > green.to_string() {
        "Blue"
    } else {
        "Green"
    };
    alice.add_to_group(second, carol_identity.user_id).unwrap();
    alice.create_folder("Shared").unwrap();
    for group in ["Blue", "Green"] {
        alice
            .share_folder_with_group("Shared", group, Role::View)
            .unwrap();
    }
    let (overview, details) = login("Printer", "printer-pw");
    alice.add(Some("Shared"), overview, details).unwrap();
    carol.sync().unwrap();

    // Bob recovers; only Carol's app gives him a group back, the second one.
    let device = approve_new_device(&fixture, &mut alice, bob_id);
    carol.sync().unwrap();
    let new_bob = finish(&fixture, &device, "new-bob");
    assert_eq!(new_bob.folders().unwrap(), ["Shared"]);
    let printer = new_bob.find_item("Printer", None).unwrap();
    assert_eq!(new_bob.open_item(printer).unwrap().1.password, "printer-pw");
}

#[test]
fn escrow_and_approvals_take_the_right_signatures() {
    let fixture = Fixture::start();
    let Team {
        mut alice,
        mut bob,
        alice_secret,
        alice_signer,
        bob_secret,
        bob_signer,
        ..
    } = team(&fixture);
    let bob_id = bob.whoami().user_id;
    let alice_keys = AccountKeys::derive(&alice_secret);
    let bob_keys = AccountKeys::derive(&bob_secret);

    // Bob is approved already: approving him again is refused.
    assert!(alice.approve(bob_id, &bob.whoami().fingerprint).is_err());

    // The server keeps a personal key in escrow only with its owner's own agreement.
    let mut as_bob = Client::new(&fixture.url);
    as_bob
        .sign_in(bob.profile().device_id, bob_signer.as_ref())
        .unwrap();
    let forged = EscrowRequest {
        wrapped_key: bob_keys
            .wrap_personal_key_for(&alice_keys.public(), bob_id)
            .unwrap(),
        consent: escrow_consent(&alice_keys, bob_id, (0, 1)),
        sequence: 1,
    };
    assert!(as_bob.put::<_, ()>("/v1/escrow", &forged).is_err());
    bob.sync().unwrap();
    assert!(!bob.whoami().escrow);

    // Escrow can't change while a recovery is waiting.
    alice.start_recovery(bob_id, false).unwrap();
    bob.sync().unwrap();
    assert!(bob.set_escrow(true).is_err());
    bob.cancel_recovery(bob_id).unwrap();
    bob.set_escrow(true).unwrap();
    assert!(bob.whoami().escrow);

    // Keys after a recovery come only with the recovery's approval, not a plain one.
    let device = approve_new_device(&fixture, &mut alice, bob_id);
    let mut as_alice = Client::new(&fixture.url);
    as_alice
        .sign_in(alice.profile().device_id, alice_signer.as_ref())
        .unwrap();
    let mut entry =
        DirectoryEntry::new(bob_id, "Bob", AccountKeys::derive(&device.secret).public());
    entry.revision = 7;
    entry.approve(&alice_keys);
    let request = ApprovalRequest {
        approval: entry.approval.clone().unwrap(),
    };
    assert!(
        as_alice
            .post::<_, ()>(&format!("/v1/users/{bob_id}/approval"), &request)
            .is_err()
    );

    // Bob had agreed to escrow with his earlier keys, so his new device agrees again,
    // whether or not anything of his own was there to come back.
    let new_bob = finish(&fixture, &device, "new-bob");
    assert!(new_bob.whoami().escrow);
}

#[test]
fn signing_out_their_devices_stops_a_lost_one_cancelling_and_the_kit_still_works() {
    let fixture = Fixture::start();
    let Team {
        mut alice,
        mut bob,
        bob_secret,
        ..
    } = team(&fixture);
    let bob_id = bob.whoami().user_id;

    // The owner signs Bob's devices out as the recovery starts: a lost one can't cancel it.
    let line = alice.start_recovery(bob_id, true).unwrap();
    assert!(bob.sync().is_err());
    assert!(bob.cancel_recovery(bob_id).is_err());
    assert!(!keystead_client::recovery_approved(&line).unwrap());

    // If Bob didn't ask for it, his recovery kit gets him back in, and he can cancel.
    let signer: Arc<dyn DeviceSigner> = Arc::new(SoftwareDeviceKey::generate());
    let owner_fingerprint = alice.whoami().fingerprint;
    let mut back = recover(
        &fixture.profile("bob-again"),
        NewAccount {
            server: &fixture.url,
            secret: &bob_secret,
            device_id: DeviceId::random(),
            device_name: "Bob's other Mac",
            signer,
        },
        Some(&owner_fingerprint),
    )
    .unwrap();
    assert!(back.whoami().recovering);
    back.cancel_recovery(bob_id).unwrap();
    assert!(keystead_client::recovery_approved(&line).is_err());
}

#[test]
fn password_health_lists_weak_reused_and_old_passwords_you_can_change() {
    let fixture = Fixture::start();
    let Team {
        mut alice, mut bob, ..
    } = team(&fixture);
    let bob_id = bob.whoami().user_id;
    alice.create_folder("Production").unwrap();
    alice
        .share_folder("Production", bob_id, Role::View)
        .unwrap();
    let shared = "Hn3$wQ8z!Pc5#rT1vY6b";
    for (name, password) in [
        ("Database", "Xq7#mV2p!Lr9@zK4tW8s"),
        ("Router", "password1"),
        ("Mail", shared),
        ("Billing", shared),
    ] {
        let (overview, details) = login(name, password);
        alice.add(Some("Production"), overview, details).unwrap();
    }
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;
    let summary =
        |health: &keystead_client::PasswordHealth| -> Vec<(String, bool, Vec<String>, bool)> {
            health
                .rows
                .iter()
                .map(|row| {
                    (
                        row.name.clone(),
                        row.weak,
                        row.reused_with.clone(),
                        row.old_since.is_some(),
                    )
                })
                .collect()
        };
    let s = |text: &str| text.to_owned();

    let health = alice.password_health(now).unwrap();
    assert_eq!((health.checked, health.ages_known), (4, true));
    assert_eq!(
        summary(&health),
        [
            (s("Billing"), false, vec![s("Mail")], false),
            (s("Mail"), false, vec![s("Billing")], false),
            (s("Router"), true, vec![], false),
        ]
    );

    // A year on, every one of them is old too.
    let later = alice
        .password_health(now + keystead_client::OLD_AFTER_SECONDS + 60)
        .unwrap();
    let names: Vec<&str> = later.rows.iter().map(|row| row.name.as_str()).collect();
    assert_eq!(names, ["Billing", "Mail", "Router", "Database"]);
    assert!(later.rows.iter().all(|row| row.old_since.is_some()));

    // Bob can only view Production: nothing of it is his to change, but his own login with
    // the same password as two in it shows as reused.
    bob.sync().unwrap();
    let (overview, details) = login("Personal mail", shared);
    bob.add(None, overview, details).unwrap();
    let health = bob.password_health(now).unwrap();
    assert_eq!(health.checked, 1);
    assert_eq!(
        summary(&health),
        [(
            s("Personal mail"),
            false,
            vec![s("Billing"), s("Mail")],
            false
        )]
    );
}

/// Counts what a device key signs: a Mac's asks for Touch ID each time.
struct CountingSigner {
    key: SoftwareDeviceKey,
    signed: AtomicU32,
}

impl DeviceSigner for CountingSigner {
    fn public_key(&self) -> DevicePublicKey {
        self.key.public()
    }

    fn sign(&self, message: &[u8]) -> anyhow::Result<Bytes> {
        self.signed.fetch_add(1, Ordering::Relaxed);
        Ok(self.key.sign(message))
    }
}

#[test]
fn a_session_renews_without_the_device_key() {
    let fixture = Fixture::start();
    let signer = Arc::new(CountingSigner {
        key: SoftwareDeviceKey::generate(),
        signed: AtomicU32::new(0),
    });
    let alice = setup(
        &fixture.profile("alice"),
        NewAccount {
            server: &fixture.url,
            secret: &AccountSecret::generate(),
            device_id: DeviceId::random(),
            device_name: "Test device",
            signer: signer.clone(),
        },
        &fixture.setup_code,
        "Alice",
    )
    .unwrap();
    let mut client = Client::new(&fixture.url);
    let first = client
        .sign_in(alice.profile().device_id, signer.as_ref())
        .unwrap();
    let signed = signer.signed.load(Ordering::Relaxed);

    let renewed = client.renew().unwrap();
    assert_ne!(renewed.token, first.token);
    let devices: keystead_core::api::DeviceList = client.get("/v1/devices", &[]).unwrap();
    assert_eq!(devices.devices.len(), 1);
    assert_eq!(signer.signed.load(Ordering::Relaxed), signed);
}

#[test]
fn folders_and_groups_keep_signed_lists_of_who_is_in_them() {
    let fixture = Fixture::start();
    let Team {
        mut alice,
        mut bob,
        carol,
        ..
    } = team(&fixture);
    let (alice_id, bob_id) = (alice.whoami().user_id, bob.whoami().user_id);
    let carol_identity = carol.whoami();
    let carol_id = carol_identity.user_id;
    alice
        .approve(carol_id, &carol_identity.fingerprint)
        .unwrap();

    // A folder starts with its maker; sharing it and giving it a new key each sign the
    // next entry.
    let folder = alice.create_folder("Production").unwrap();
    let latest = |vault: &Vault| vault.profile().folders[&folder].entries.last().cloned();
    assert_eq!(latest(&alice).unwrap().members, [alice_id]);
    alice
        .share_folder("Production", bob_id, Role::Edit)
        .unwrap();
    alice
        .share_folder("Production", carol_id, Role::View)
        .unwrap();
    bob.sync().unwrap();
    let entry = latest(&bob).unwrap();
    assert_eq!((entry.revision, entry.generation), (3, 0));
    assert_eq!(entry.members, [alice_id, bob_id, carol_id]);
    alice.remove_from_folder("Production", carol_id).unwrap();
    alice.sync().unwrap();
    bob.sync().unwrap();
    let entry = latest(&bob).unwrap();
    assert_eq!((entry.revision, entry.generation), (4, 1));
    assert_eq!(entry.members, [alice_id, bob_id]);

    // A group's entries name its members too.
    alice.create_group("Ops", &[bob_id]).unwrap();
    let members = |vault: &Vault| {
        let (_, latest) = vault
            .profile()
            .team_group(vault.profile().find_group("Ops").unwrap())
            .unwrap();
        latest.members.clone().unwrap()
    };
    assert_eq!(members(&alice), [alice_id, bob_id]);
    alice.add_to_group("Ops", carol_id).unwrap();
    alice.sync().unwrap();
    assert_eq!(members(&alice), [alice_id, bob_id, carol_id]);
    alice.remove_from_group("Ops", carol_id).unwrap();
    bob.sync().unwrap();
    assert_eq!(members(&bob), [alice_id, bob_id]);

    // Someone in a group the folder is shared with can share it on, and it still checks
    // out for everyone, also once the group is gone.
    alice
        .share_folder_with_group("Production", "Ops", Role::Manage)
        .unwrap();
    alice.remove_from_folder("Production", bob_id).unwrap();
    alice.sync().unwrap();
    bob.sync().unwrap();
    bob.share_folder("Production", carol_id, Role::View)
        .unwrap();
    alice.sync().unwrap();
    let summary = alice.delete_group("Ops").unwrap();
    assert!(
        summary.rekey_problems.is_empty(),
        "{:?}",
        summary.rekey_problems
    );
    let summary = alice.sync().unwrap();
    assert!(
        summary.rekey_problems.is_empty(),
        "{:?}",
        summary.rekey_problems
    );
    let mut carol = carol;
    carol.sync().unwrap();
    assert_eq!(latest(&carol).unwrap().members, [alice_id, carol_id]);
    assert!(latest(&carol).unwrap().groups.is_empty());
}

#[test]
fn a_lying_server_cant_get_a_folders_key_handed_to_someone_outside_it() {
    let fixture = Fixture::start();
    let Team {
        mut alice,
        bob,
        mut carol,
        ..
    } = team(&fixture);
    let bob_id = bob.whoami().user_id;
    let carol_identity = carol.whoami();
    let carol_id = carol_identity.user_id;
    // Carol is approved, like anyone on the team, but nobody shared this folder with her.
    alice
        .approve(carol_id, &carol_identity.fingerprint)
        .unwrap();
    let folder = alice.create_folder("Production").unwrap();
    alice
        .share_folder("Production", bob_id, Role::Edit)
        .unwrap();
    let (overview, details) = login("Database", "hunter2");
    alice.add(Some("Production"), overview, details).unwrap();

    // The server lists her as a member who recovered and waits for her copy of the key.
    fixture.lie(&format!(
        "INSERT INTO members (user_id, folder_id, joined_seq, wrapped_key, role, pending)
         SELECT {carol_id}, folder_id, joined_seq, wrapped_key, role, 1 FROM members
         WHERE user_id = {bob_id} AND folder_id = '{folder}'"
    ));
    let summary = alice.sync().unwrap();
    assert_eq!(summary.restored, 0);
    assert!(
        summary
            .rekey_problems
            .iter()
            .any(|problem| problem.contains("aren't among this folder's signed members")),
        "{:?}",
        summary.rekey_problems
    );

    // Then as an ordinary member of a folder that needs a new key.
    fixture.lie(&format!(
        "UPDATE members SET pending = 0 WHERE user_id = {carol_id};
         UPDATE folders SET needs_rekey = 1 WHERE id = '{folder}'"
    ));
    let summary = alice.sync().unwrap();
    assert_eq!(summary.rekeyed, 0);
    assert!(
        summary
            .rekey_problems
            .iter()
            .any(|problem| problem.contains("Don't trust this server")),
        "{:?}",
        summary.rekey_problems
    );
    assert_eq!(alice.profile().folders[&folder].generation, 0);

    // Either way, nothing was made for her.
    let _ = carol.sync();
    assert!(carol.list().unwrap().is_empty());
}

#[test]
fn a_folder_from_before_signed_members_gets_them_from_a_manager() {
    let fixture = Fixture::start();
    let Team {
        mut alice,
        bob,
        alice_secret,
        bob_secret,
        ..
    } = team(&fixture);
    let (alice_id, bob_id) = (alice.whoami().user_id, bob.whoami().user_id);
    let owner_fingerprint = alice.whoami().fingerprint;
    let folder = alice.create_folder("Old").unwrap();
    alice.share_folder("Old", bob_id, Role::Edit).unwrap();
    // As a server that has just been updated holds it: nobody has signed for it.
    fixture.lie("DELETE FROM folder_entries");

    let device = |secret, name| NewAccount {
        server: &fixture.url,
        secret,
        device_id: DeviceId::random(),
        device_name: name,
        signer: Arc::new(SoftwareDeviceKey::generate()),
    };
    // Bob can open it, but until it's signed for, nothing new goes into it: a folder
    // that only its key vouches for could be anyone's.
    let mut bob = recover(
        &fixture.profile("bob-2"),
        device(&bob_secret, "Bob's new Mac"),
        Some(&owner_fingerprint),
    )
    .unwrap();
    bob.sync().unwrap();
    assert!(bob.profile().folders[&folder].entries.is_empty());
    let (overview, details) = login("Database", "hunter2");
    let error = bob
        .add(Some("Old"), overview.clone(), details.clone())
        .err()
        .unwrap();
    assert!(
        format!("{error:#}").contains("nobody has signed for this folder's members yet"),
        "{error:#}"
    );

    // Alice manages it: her next sync signs for who's in it, once.
    let mut alice = recover(
        &fixture.profile("alice-2"),
        device(&alice_secret, "Alice's new Mac"),
        None,
    )
    .unwrap();
    alice.sync().unwrap();
    let entries = alice.profile().folders[&folder].entries.clone();
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].members, [alice_id, bob_id]);
    alice.sync().unwrap();
    assert_eq!(alice.profile().folders[&folder].entries, entries);
    bob.add(Some("Old"), overview, details).unwrap();
    assert_eq!(bob.profile().folders[&folder].entries, entries);
}

#[test]
fn a_lying_server_cant_turn_escrow_on() {
    let fixture = Fixture::start();
    let Team {
        mut alice,
        mut bob,
        bob_secret,
        ..
    } = team(&fixture);
    let bob_id = bob.whoami().user_id;
    let bob_public = AccountKeys::derive(&bob_secret).public();
    let (overview, details) = login("Bank", "bank-pw");
    bob.add(None, overview, details).unwrap();
    let folder = bob.create_folder("Personal").unwrap();
    assert!(!bob.whoami().escrow);

    // Bob never agreed to escrow and never recovered. The server makes it look as if he
    // just had: a personal key of its own choosing as his earlier one, a folder of his
    // "back from escrow" under it, and escrow marked as wanted.
    let servers = AccountKeys::derive(&AccountSecret::generate());
    let earlier_key = servers.wrap_personal_key_for(&bob_public, bob_id).unwrap();
    let from_escrow =
        keystead_core::keys::FolderKey::generate().seal_for_escrow(&servers, folder, 0, bob_id);
    let json = |value: &dyn erased::Json| value.json().replace('\'', "\'\'");
    fixture.lie(&format!(
        "UPDATE users SET escrow_on = 1, recovered_key = '{}' WHERE id = {bob_id};
         UPDATE members SET pending = 1 WHERE user_id = {bob_id} AND folder_id = '{folder}';
         DELETE FROM access WHERE user_id = {bob_id} AND folder_id = '{folder}';
         INSERT INTO folder_escrow (user_id, folder_id, generation, sealed)
             VALUES ({bob_id}, '{folder}', 0, '{}')",
        json(&earlier_key),
        json(&from_escrow),
    ));
    bob.sync().unwrap();
    bob.sync().unwrap();

    // His app doesn't agree to escrow on the server's say: his personal key stays his.
    assert!(!bob.whoami().escrow);
    alice.sync().unwrap();
    let row = alice
        .users()
        .unwrap()
        .into_iter()
        .find(|row| row.user_id == bob_id)
        .unwrap();
    assert!(!row.escrow);
}

/// Anything serde can write, as JSON text, for `Fixture::lie`.
mod erased {
    pub trait Json {
        fn json(&self) -> String;
    }

    impl<T: serde::Serialize> Json for T {
        fn json(&self) -> String {
            serde_json::to_string(self).unwrap()
        }
    }
}

/// A folder too big for one answer: each login has long notes, 12 MB in all.
fn big_folder(alice: &mut Vault, name: &str) -> usize {
    alice.create_folder(name).unwrap();
    let count = 7;
    for index in 0..count {
        let (overview, mut details) = login(&format!("Login {index}"), "pw");
        details.notes = "n".repeat(1_300_000);
        alice.add(Some(name), overview, details).unwrap();
    }
    count
}

#[test]
fn a_folder_of_any_size_reaches_someone_it_is_shared_with_and_a_new_device() {
    use keystead_core::api::{SyncEntry, SyncPage};

    let fixture = Fixture::start();
    let Team {
        mut alice,
        mut bob,
        alice_secret,
        bob_secret,
        ..
    } = team(&fixture);
    let count = big_folder(&mut alice, "Archive");
    let bob_id = bob.whoami().user_id;
    alice.share_folder("Archive", bob_id, Role::View).unwrap();
    let all_there = |vault: &Vault| {
        assert_eq!(vault.list().unwrap().len(), count);
        let last = vault.find_item("Login 6", Some("Archive")).unwrap();
        assert_eq!(vault.open_item(last).unwrap().1.notes.len(), 1_300_000);
    };

    // Shared with Bob, it arrives in parts, and all of it is there.
    bob.sync().unwrap();
    all_there(&bob);

    // A new device of Alice's, who made the folder and then filled it, gets its logins as
    // changes, in pages no bigger than the folder's parts.
    let signer: Arc<dyn DeviceSigner> = Arc::new(SoftwareDeviceKey::generate());
    let mut alice_new = recover(
        &fixture.profile("alice-new"),
        new_device(&fixture, &alice_secret, DeviceId::random(), signer),
        None,
    )
    .unwrap();
    alice_new.sync().unwrap();
    all_there(&alice_new);

    // A new device of Bob's starts from nothing. An app from before 0.17.0 doesn't ask
    // for parts and is sent the folder whole, as a server from before 0.17.0 sends it to
    // anyone: more than those apps could read, and read here.
    let device_id = DeviceId::random();
    let signer: Arc<dyn DeviceSigner> = Arc::new(SoftwareDeviceKey::generate());
    let mut bob_new = recover(
        &fixture.profile("bob-new"),
        new_device(&fixture, &bob_secret, device_id, signer.clone()),
        Some(&alice.whoami().fingerprint),
    )
    .unwrap();
    let mut client = Client::new(&fixture.url);
    client.sign_in(device_id, signer.as_ref()).unwrap();
    let mut cursor = 0;
    let mut whole = 0;
    loop {
        let query = [("cursor", cursor.to_string())];
        let page: SyncPage = client.get("/v1/sync", &query).unwrap();
        assert_eq!(page.resume, None);
        for entry in &page.entries {
            if let SyncEntry::Joined { items, .. } = entry {
                whole = whole.max(items.len());
            }
        }
        cursor = page.cursor;
        if !page.more {
            break;
        }
    }
    assert_eq!(whole, count);
    bob_new.sync().unwrap();
    all_there(&bob_new);
}

/// What each person may do in a folder is signed with who is in it, and apps go by that:
/// a server that says a viewer may edit, or manage, changes nothing for anyone else.
#[test]
fn a_lying_server_cant_raise_someones_role_in_a_folder() {
    let fixture = Fixture::start();
    let Team {
        mut alice,
        mut bob,
        mut carol,
        alice_secret,
        ..
    } = team(&fixture);
    let (alice_id, bob_id) = (alice.whoami().user_id, bob.whoami().user_id);
    let carol_identity = carol.whoami();
    alice
        .approve(carol_identity.user_id, &carol_identity.fingerprint)
        .unwrap();
    let folder = alice.create_folder("Production").unwrap();
    let (overview, details) = login("AWS root", "first");
    let aws = alice.add(Some("Production"), overview, details).unwrap();
    alice
        .share_folder("Production", bob_id, Role::View)
        .unwrap();
    let password = |vault: &Vault| vault.open_item(aws).unwrap().1.password.clone();

    // The folder's entries say who may do what, from the first.
    let entries = alice.profile().folders[&folder].entries.clone();
    assert_eq!(entries.len(), 2);
    assert_eq!(entries[0].member_role(alice_id), Some(Role::Manage));
    assert_eq!(entries[1].member_role(bob_id), Some(Role::View));
    bob.sync().unwrap();
    assert_eq!(bob.profile().folders[&folder].entries, entries);

    // The server says Bob may edit, and takes his change. Alice's app doesn't: her copy
    // stays, and the sync says something was turned away.
    fixture.lie(&format!(
        "UPDATE members SET role = 'edit' WHERE user_id = {bob_id}"
    ));
    bob.sync().unwrap();
    assert!(matches!(
        bob.edit(aws, "changed by a viewer").unwrap(),
        EditOutcome::Saved { .. }
    ));
    let summary = alice.sync().unwrap();
    assert_eq!(summary.rejected, 1);
    assert_eq!(password(&alice), "first");
    // Nor does a new device of hers, which has only the folder's entries to go by: it
    // has no earlier copy, so the login is missing there, not replaced.
    let mut alice_new = recover(
        &fixture.profile("alice-new"),
        new_device(
            &fixture,
            &alice_secret,
            DeviceId::random(),
            Arc::new(SoftwareDeviceKey::generate()),
        ),
        None,
    )
    .unwrap();
    assert_eq!(alice_new.sync().unwrap().rejected, 1);
    assert!(alice_new.list().unwrap().is_empty());

    // The server says Bob manages it. His own app won't sign for a folder whose entries
    // don't make him a manager, and if it did nobody's app would take it.
    fixture.lie(&format!(
        "UPDATE members SET role = 'manage' WHERE user_id = {bob_id}"
    ));
    bob.sync().unwrap();
    let error = bob
        .share_folder("Production", carol_identity.user_id, Role::Edit)
        .err()
        .unwrap();
    assert!(
        format!("{error:#}").contains("signed roles don't make you one of its managers"),
        "{error:#}"
    );

    // Alice makes him an editor, which she signs. Now his changes count, for her and for
    // Carol, who joins afterwards and has seen none of this.
    alice
        .set_folder_role("Production", bob_id, Role::Edit)
        .unwrap();
    let latest = alice.profile().folders[&folder]
        .entries
        .last()
        .cloned()
        .unwrap();
    assert_eq!(latest.member_role(bob_id), Some(Role::Edit));
    assert_eq!(latest.signer, alice_id);
    bob.sync().unwrap();
    assert!(matches!(
        bob.edit(aws, "changed by an editor").unwrap(),
        EditOutcome::Saved { .. }
    ));
    assert_eq!(alice.sync().unwrap().rejected, 0);
    assert_eq!(password(&alice), "changed by an editor");
    alice
        .share_folder("Production", carol_identity.user_id, Role::View)
        .unwrap();
    assert_eq!(carol.sync().unwrap().rejected, 0);
    assert_eq!(password(&carol), "changed by an editor");
}

/// Removing a folder's only manager from the team: the owner, who isn't in the folder,
/// signs someone else in as its manager, and that person gives it a new key.
#[test]
fn the_owner_signs_in_a_new_manager_when_a_folders_only_one_leaves_the_team() {
    let fixture = Fixture::start();
    let Team {
        mut alice,
        mut bob,
        mut carol,
        ..
    } = team(&fixture);
    let (alice_id, bob_id) = (alice.whoami().user_id, bob.whoami().user_id);
    let carol_identity = carol.whoami();
    alice
        .approve(carol_identity.user_id, &carol_identity.fingerprint)
        .unwrap();
    let carol_id = carol_identity.user_id;

    let folder = bob.create_folder("Billing").unwrap();
    let (overview, details) = login("Bank", "pw");
    bob.add(Some("Billing"), overview, details).unwrap();
    bob.share_folder("Billing", carol_id, Role::View).unwrap();
    carol.sync().unwrap();

    alice.remove_user(bob_id).unwrap();
    let summary = carol.sync().unwrap();
    assert_eq!(summary.rekey_problems, Vec::<String>::new());
    assert_eq!(summary.rekeyed, 1);
    let record = &carol.profile().folders[&folder];
    assert_eq!(record.generation, 1);
    let [.., promoted, rekeyed] = &record.entries[..] else {
        panic!("{:?}", record.entries);
    };
    // The owner changed Carol's role and nothing else; Carol dropped Bob with the new key.
    assert_eq!(promoted.signer, alice_id);
    assert_eq!(promoted.members, [bob_id, carol_id]);
    assert_eq!(promoted.member_role(carol_id), Some(Role::Manage));
    assert_eq!(rekeyed.signer, carol_id);
    assert_eq!(rekeyed.members, [carol_id]);
    let members = carol.folder_members("Billing").unwrap();
    assert_eq!(members.len(), 1);
    assert_eq!(members[0].role, Role::Manage);
    // And she can use it as its manager.
    let (overview, details) = login("Card", "pw");
    carol.add(Some("Billing"), overview, details).unwrap();
    carol.share_folder("Billing", alice_id, Role::View).unwrap();
    alice.sync().unwrap();
    assert_eq!(alice.list().unwrap().len(), 2);
}

/// A folder signed for by apps before 0.17.0 has entries without roles. A manager's next
/// sync signs its roles, as the server lists them, changing nothing else.
#[test]
fn a_folder_from_before_signed_roles_gets_them_from_a_manager() {
    use keystead_core::folders::FolderEntry;

    let fixture = Fixture::start();
    let Team {
        mut alice,
        mut bob,
        alice_secret,
        ..
    } = team(&fixture);
    let (alice_id, bob_id) = (alice.whoami().user_id, bob.whoami().user_id);
    let folder = alice.create_folder("Old").unwrap();
    alice.share_folder("Old", bob_id, Role::View).unwrap();
    // As a 0.16.0 app left it: one entry, naming both, without roles.
    let keys = AccountKeys::derive(&alice_secret);
    let key = alice
        .profile()
        .folder_key(&keys, &GroupKeyring::default(), folder)
        .unwrap();
    let mut old = FolderEntry::first(folder, 0, &key, vec![alice_id, bob_id], Vec::new());
    old.sign(alice_id, &keys);
    fixture.lie(&format!(
        "DELETE FROM folder_entries;
         INSERT INTO folder_entries (folder_id, revision, body) VALUES ('{folder}', 1, '{}')",
        serde_json::to_string(&old).unwrap()
    ));
    let fresh = |secret, name: &'static str| NewAccount {
        server: &fixture.url,
        secret,
        device_id: DeviceId::random(),
        device_name: name,
        signer: Arc::new(SoftwareDeviceKey::generate()),
    };
    drop(alice);
    let mut alice = recover(
        &fixture.profile("alice-2"),
        fresh(&alice_secret, "Alice's new Mac"),
        None,
    )
    .unwrap();

    alice.sync().unwrap();
    let entries = alice.profile().folders[&folder].entries.clone();
    assert_eq!(entries.len(), 2);
    assert_eq!(entries[0], old);
    assert_eq!(entries[1].members, old.members);
    assert_eq!(entries[1].member_role(alice_id), Some(Role::Manage));
    assert_eq!(entries[1].member_role(bob_id), Some(Role::View));
    alice.sync().unwrap();
    assert_eq!(alice.profile().folders[&folder].entries, entries);
    // From then on changes carry roles.
    alice.set_folder_role("Old", bob_id, Role::Edit).unwrap();
    let latest = alice.profile().folders[&folder]
        .entries
        .last()
        .cloned()
        .unwrap();
    assert_eq!(
        (latest.revision, latest.member_role(bob_id)),
        (3, Some(Role::Edit))
    );
    let _ = bob.sync();
}

/// In a folder with signed roles a login opens with the folder's key only. Someone outside
/// the folder, with a server that puts their version in a login's place, can make out a
/// copy of their own key to each member, but not one sealed with the folder's key: the
/// login then doesn't open, instead of showing what they wrote.
#[test]
fn a_login_put_in_a_folder_by_someone_outside_it_doesnt_open() {
    use keystead_core::items::{ItemKeys, PersonKey};
    use keystead_core::keys::ItemKey;

    let fixture = Fixture::start();
    let Team {
        mut alice,
        bob,
        alice_secret,
        bob_secret,
        ..
    } = team(&fixture);
    let (alice_id, bob_id) = (alice.whoami().user_id, bob.whoami().user_id);
    let folder = alice.create_folder("Production").unwrap();
    let (overview, details) = login("AWS root", "real");
    let aws = alice.add(Some("Production"), overview, details).unwrap();
    let current = alice.profile().items[&aws].clone();

    // Bob, approved but not in the folder, writes version 2 under a key of his own. He
    // keeps the folder's copy of the real key, which he can't open or replace, and makes
    // out his key to Alice directly.
    let key = ItemKey::generate();
    let alice_public = AccountKeys::derive(&alice_secret).public();
    let keys = ItemKeys {
        folder: current.keys.folder.clone(),
        people: vec![PersonKey {
            user_id: alice_id,
            wrapped_key: alice_public.wrap_item_key(&key, aws).unwrap(),
        }],
        ..ItemKeys::default()
    };
    let at = ItemVersion {
        id: aws,
        folder_id: Some(folder),
        owner: None,
        version: 2,
        author: bob_id,
    };
    let (overview, details) = login("AWS root", "bob's");
    let bob_keys = AccountKeys::derive(&bob_secret);
    let forged = EncryptedItem::seal(at, &key, keys, &bob_keys, &overview, &details).unwrap();
    fixture.lie(&format!(
        "UPDATE feed_counter SET last_seq = last_seq + 1;
         UPDATE items SET version = 2, seq = (SELECT last_seq FROM feed_counter), body = '{}'
         WHERE id = '{aws}'",
        serde_json::to_string(&forged).unwrap()
    ));

    // Her app takes the folder's copy, which holds the real key, and that key doesn't
    // open what Bob wrote. It never tries the copy made out to her.
    alice.sync().unwrap();
    assert_eq!(alice.profile().items[&aws].version, 2);
    assert!(alice.open_item(aws).is_err());
}

/// Puts an older signed version of a login back on the server as its current one, with
/// the history it had then, as a server restored from a backup has it, or one that keeps
/// newer versions back.
fn put_back(fixture: &Fixture, older: &EncryptedItem) {
    fixture.lie(&format!(
        "UPDATE feed_counter SET last_seq = last_seq + 1;
         UPDATE items SET version = {version}, seq = (SELECT last_seq FROM feed_counter),
                body = '{body}'
         WHERE id = '{id}';
         DELETE FROM item_history WHERE item_id = '{id}' AND version >= {version}",
        version = older.version,
        body = serde_json::to_string(older).unwrap(),
        id = older.id
    ));
}

/// Every copy the server hands out is signed, but so is an older one. A device keeps the
/// newest it has seen of a login, in a folder or not, also after losing it, and of each
/// group; and saving over a server that has gone back puts the edit past what anyone saw.
#[test]
fn a_server_cant_hand_back_older_copies_as_current_ones() {
    let fixture = Fixture::start();
    let Team {
        mut alice,
        mut bob,
        carol,
        ..
    } = team(&fixture);
    let bob_id = bob.whoami().user_id;
    let carol_identity = carol.whoami();
    alice
        .approve(carol_identity.user_id, &carol_identity.fingerprint)
        .unwrap();
    let password = |vault: &Vault, item| vault.open_item(item).unwrap().1.password.clone();

    // A login in a folder Bob can edit: version 1, then 2.
    alice.create_folder("Production").unwrap();
    let (overview, details) = login("AWS root", "first");
    let aws = alice.add(Some("Production"), overview, details).unwrap();
    let first = alice.profile().items[&aws].clone();
    alice
        .share_folder("Production", bob_id, Role::Edit)
        .unwrap();
    alice.edit(aws, "second").unwrap();
    bob.sync().unwrap();
    assert_eq!(password(&bob, aws), "second");

    // The server puts version 1 back. Bob keeps version 2, and is told.
    put_back(&fixture, &first);
    let summary = bob.sync().unwrap();
    assert_eq!((summary.older, summary.rejected), (1, 0));
    assert_eq!(password(&bob, aws), "second");

    // Bob changes it: his edit goes on top of the server's copy, as version 3, past what
    // anyone saw, and reaches Alice, who had version 2.
    assert!(matches!(
        bob.edit(aws, "third").unwrap(),
        EditOutcome::Saved { version: 3 }
    ));
    assert_eq!(alice.sync().unwrap().older, 0);
    assert_eq!(password(&alice, aws), "third");

    // Alice's own login, shared with Bob directly, then not: Bob drops it, and remembers
    // how far he had seen it. The server can't hand him an older version as if it were
    // shared with him again.
    let (overview, details) = login("Bank", "pw");
    let bank = alice.add(None, overview, details).unwrap();
    alice.share_item(bank, bob_id, Role::View).unwrap();
    let shared = alice.profile().items[&bank].clone();
    alice.edit(bank, "pw2").unwrap();
    bob.sync().unwrap();
    assert_eq!(password(&bob, bank), "pw2");
    alice.unshare_item(bank, bob_id).unwrap();
    bob.sync().unwrap();
    assert!(bob.open_item(bank).is_err());
    put_back(&fixture, &shared);
    fixture.lie(&format!(
        "INSERT INTO item_reach (user_id, item_id) VALUES ({bob_id}, '{bank}');
         INSERT INTO item_access (user_id, item_id, role) VALUES ({bob_id}, '{bank}', 'view')"
    ));
    assert_eq!(bob.sync().unwrap().older, 1);
    assert!(bob.open_item(bank).is_err());

    // A group's entries, cut back to an earlier revision: one that still has Carol in it,
    // after she was taken out. Bob keeps the newer copy of the group.
    let ops = alice
        .create_group("Ops", &[bob_id, carol_identity.user_id])
        .unwrap();
    alice
        .remove_from_group("Ops", carol_identity.user_id)
        .unwrap();
    bob.sync().unwrap();
    let entries = |vault: &Vault| {
        vault
            .profile()
            .team_groups
            .iter()
            .find(|info| info.entries[0].group_id == ops)
            .map(|info| info.entries.clone())
            .unwrap()
    };
    let held = entries(&bob);
    assert!(!held.last().unwrap().has_member(carol_identity.user_id));
    fixture.lie(&format!(
        "DELETE FROM group_entries WHERE group_id = '{ops}'
           AND revision = (SELECT MAX(revision) FROM group_entries WHERE group_id = '{ops}')"
    ));
    assert_eq!(bob.sync().unwrap().older, 1);
    assert_eq!(entries(&bob), held);

    // Bob, taken out of the folder, remembers how far he had seen it and its logins.
    alice.remove_from_folder("Production", bob_id).unwrap();
    bob.sync().unwrap();
    assert!(bob.profile().folders.is_empty());
    let seen = &bob.profile().seen;
    assert_eq!(seen.items.get(&aws), Some(&3));
    assert!(seen.folders.values().any(|&(_, revision)| revision >= 2));
}

/// After a server goes back, as when restored from a backup, devices follow its change
/// numbers down and say so. Its new changes are numbered from the clock, so they come
/// after anything a device saw before, also on a device that hasn't synced since.
#[test]
fn devices_get_what_changes_on_a_server_that_went_back() {
    let fixture = Fixture::start();
    let Team {
        mut alice, mut bob, ..
    } = team(&fixture);
    let bob_id = bob.whoami().user_id;
    alice.create_folder("Production").unwrap();
    alice
        .share_folder("Production", bob_id, Role::Edit)
        .unwrap();
    let (overview, details) = login("AWS root", "first");
    let aws = alice.add(Some("Production"), overview, details).unwrap();
    bob.sync().unwrap();
    alice.sync().unwrap();
    let before = alice.profile().cursor;

    // Back to an earlier point. Bob's next sync follows it down; then he saves.
    fixture.lie("UPDATE feed_counter SET last_seq = 3");
    let summary = bob.sync().unwrap();
    assert!(summary.server_went_back);
    assert_eq!(bob.profile().cursor, 3);
    bob.edit(aws, "second").unwrap();

    // Alice hasn't synced since. Bob's change comes after her cursor, and reaches her.
    let summary = alice.sync().unwrap();
    assert!(alice.profile().cursor > before);
    assert!(!summary.server_went_back);
    assert_eq!(alice.open_item(aws).unwrap().1.password, "second");
}

/// Turning escrow off is the person's last word on it: their app doesn't take the server
/// showing their earlier agreement again, as a server working with the owner could, to
/// have the keys of folders made since put in escrow. Turning it on again later counts.
/// And the server itself refuses an agreement that doesn't go past the last one, as from
/// someone with a copied session.
#[test]
fn an_agreement_to_escrow_that_was_withdrawn_cant_turn_it_back_on() {
    let fixture = Fixture::start();
    let Team {
        mut alice,
        mut bob,
        alice_secret,
        bob_secret,
        bob_signer,
        ..
    } = team(&fixture);
    let bob_id = bob.whoami().user_id;
    let bob_keys = AccountKeys::derive(&bob_secret);
    let owner = AccountKeys::derive(&alice_secret).public();
    let escrowed = |fixture: &Fixture, folder: keystead_core::ids::FolderId| {
        // Whether the server holds a copy of the folder's key for escrow.
        let path = fixture.root.join("server.sqlite");
        fixture._runtime.block_on(async {
            let options = sqlx::sqlite::SqliteConnectOptions::new().filename(&path);
            let pool = sqlx::SqlitePool::connect_with(options).await.unwrap();
            let count: i64 = sqlx::query_scalar(
                "SELECT COUNT(*) FROM folder_escrow WHERE user_id = ? AND folder_id = ?",
            )
            .bind(bob_id.0)
            .bind(folder.to_string())
            .fetch_one(&pool)
            .await
            .unwrap();
            pool.close().await;
            count > 0
        })
    };

    // On, as the first numbered agreement; a folder of his goes in escrow.
    bob.set_escrow(true).unwrap();
    assert!(bob.whoami().escrow);
    let first = bob.create_folder("Personal").unwrap();
    bob.sync().unwrap();
    assert!(escrowed(&fixture, first));

    // Off. The server then shows the agreement again, as it was.
    bob.set_escrow(false).unwrap();
    assert!(!bob.whoami().escrow);
    let replayed = escrow_consent(&bob_keys, bob_id, (0, 1));
    let wrapped = bob_keys.wrap_personal_key_for(&owner, bob_id).unwrap();
    fixture.lie(&format!(
        "UPDATE users SET escrow_on = 1, escrow_consent = x'{}', escrow = '{}'
         WHERE id = {bob_id}",
        replayed
            .0
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>(),
        serde_json::to_string(&wrapped).unwrap()
    ));
    bob.sync().unwrap();
    // The owner's app is shown it; Bob's own doesn't go by it, and puts nothing more in
    // escrow: not a folder made now.
    alice.sync().unwrap();
    let second = bob.create_folder("Diary").unwrap();
    bob.sync().unwrap();
    bob.sync().unwrap();
    assert!(!bob.whoami().escrow);
    assert!(!escrowed(&fixture, second));

    // The server refuses the old agreement, sent again as from a copied session; and one
    // without a number, as from an app before 0.18.0.
    let mut as_bob = Client::new(&fixture.url);
    as_bob
        .sign_in(bob.profile().device_id, bob_signer.as_ref())
        .unwrap();
    let again = EscrowRequest {
        wrapped_key: wrapped.clone(),
        consent: replayed,
        sequence: 1,
    };
    assert!(as_bob.put::<_, ()>("/v1/escrow", &again).is_err());
    let unnumbered = EscrowRequest {
        wrapped_key: wrapped,
        consent: escrow_consent(&bob_keys, bob_id, (0, 0)),
        sequence: 0,
    };
    assert!(as_bob.put::<_, ()>("/v1/escrow", &unnumbered).is_err());

    // Bob turns it on again: a later agreement, which counts, and the folder goes in.
    bob.set_escrow(true).unwrap();
    assert!(bob.whoami().escrow);
    let latest = bob
        .profile()
        .directory
        .iter()
        .find(|entry| entry.user_id == bob_id)
        .unwrap()
        .escrow_sequence;
    assert_eq!(latest, 2);
    bob.sync().unwrap();
    assert!(escrowed(&fixture, second));
}

/// Someone invited by `owner` joins: with the key on the invite line, or as with a line
/// from before 0.18.0, without it.
fn invited(fixture: &Fixture, owner: &mut Vault, name: &str, with_key: bool) -> UserId {
    let invite = owner.invite(name).unwrap();
    assert!(
        invite.key.is_some(),
        "a 0.18.0 server's invites carry a key"
    );
    let vault = join(
        &fixture.profile(name),
        NewAccount {
            server: &invite.server,
            secret: &AccountSecret::generate(),
            device_id: DeviceId::random(),
            device_name: "Test device",
            signer: Arc::new(SoftwareDeviceKey::generate()),
        },
        &invite.token,
        &invite.owner_fingerprint,
        invite.key.as_deref().filter(|_| with_key),
    )
    .unwrap();
    vault.whoami().user_id
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

#[test]
fn the_owners_app_approves_whoever_joins_with_their_invites_key() {
    let fixture = Fixture::start();
    let mut alice = setup(
        &fixture.profile("alice"),
        NewAccount {
            server: &fixture.url,
            secret: &AccountSecret::generate(),
            device_id: DeviceId::random(),
            device_name: "Test device",
            signer: Arc::new(SoftwareDeviceKey::generate()),
        },
        &fixture.setup_code,
        "Alice",
    )
    .unwrap();
    let row = |alice: &Vault, user: UserId| {
        alice
            .known_users()
            .into_iter()
            .find(|row| row.user_id == user)
            .unwrap()
    };

    // A key cut short is refused before anything reaches the server, so the invite still
    // works afterwards.
    let invite = alice.invite("Sam").unwrap();
    let sam_secret = AccountSecret::generate();
    let account = || NewAccount {
        server: &invite.server,
        secret: &sam_secret,
        device_id: DeviceId::random(),
        device_name: "Test device",
        signer: Arc::new(SoftwareDeviceKey::generate()),
    };
    let key = invite.key.clone().unwrap();
    let cut = join(
        &fixture.profile("sam"),
        account(),
        &invite.token,
        &invite.owner_fingerprint,
        Some(&key[..20]),
    );
    assert!(format!("{:#}", cut.err().unwrap()).contains("cut short"));
    let mut sam_vault = join(
        &fixture.profile("sam"),
        account(),
        &invite.token,
        &invite.owner_fingerprint,
        Some(&key),
    )
    .unwrap();
    let sam = sam_vault.whoami().user_id;

    // Alice's next sync approves Sam, once, and she can share with him at once.
    assert_eq!(alice.sync().unwrap().approved, ["Sam"]);
    assert!(row(&alice, sam).approved && !row(&alice, sam).invite_mismatch);
    assert!(alice.sync().unwrap().approved.is_empty());
    alice.create_folder("Ops").unwrap();
    alice.share_folder("Ops", sam, Role::View).unwrap();

    // Joined without the key: Alice compares fingerprints, as before.
    let una = invited(&fixture, &mut alice, "Una", false);
    // A server that swaps in keys of its own can't make the proof...
    let tom = invited(&fixture, &mut alice, "Tom", true);
    let server_keys = AccountKeys::derive(&AccountSecret::generate()).public();
    fixture.lie(&format!(
        "UPDATE users SET encryption_key = X'{}', signing_key = X'{}' WHERE id = {}",
        hex(&server_keys.encryption.0),
        hex(&server_keys.signing.0),
        tom.0
    ));
    // ...nor move it to another name...
    let vic = invited(&fixture, &mut alice, "Vic", true);
    fixture.lie(&format!(
        "UPDATE users SET name = 'Victor' WHERE id = {}",
        vic.0
    ));
    // ...nor pass one off twice, as two people.
    let wes = invited(&fixture, &mut alice, "Wes", true);
    fixture.lie(&format!(
        "INSERT INTO users (name, encryption_key, signing_key, invite_nonce, invite_proof)
         SELECT name, encryption_key, signing_key, invite_nonce, invite_proof
         FROM users WHERE id = {}",
        wes.0
    ));

    assert!(alice.sync().unwrap().approved.is_empty());
    for (user, mismatch) in [(una, false), (tom, true), (vic, true), (wes, false)] {
        let row = row(&alice, user);
        assert!(!row.approved, "{}", row.name);
        assert_eq!(row.invite_mismatch, mismatch, "{}", row.name);
    }
    // Only the owner's app approves anyone, or can tell a proof from a forged one.
    assert!(sam_vault.sync().unwrap().approved.is_empty());
    assert!(
        sam_vault
            .known_users()
            .iter()
            .all(|row| !row.invite_mismatch && row.approved == [1, sam.0].contains(&row.user_id.0))
    );
}
