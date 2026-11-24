//! The client library against a real server on a local port, with the two kinds of
//! device key in use: a software Ed25519 key (CLI) and a P-256 key like the Mac's Secure
//! Enclave key.

use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicU32, Ordering};

use keystead_client::http::Client;
use keystead_client::{DeviceSigner, EditOutcome, NewAccount, Vault, join, recover, setup};
use keystead_core::api::PutItemRequest;
use keystead_core::encoding::Bytes;
use keystead_core::ids::{DeviceId, ItemId};
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
        .share_folder("Production", bob_identity.user_id)
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
        join(
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
        )
        .unwrap()
    };
    let bob = member("Bob");
    let carol = member("Carol");
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
    let error = alice.share_item(bank, carol_id).unwrap_err();
    assert!(format!("{error:#}").contains("isn't approved"), "{error:#}");
    let me = alice.whoami().user_id;
    assert!(alice.share_item(bank, me).is_err());
    assert_eq!(alice.share_item(bank, bob_id).unwrap(), "Bob");
    assert!(alice.share_item(bank, bob_id).is_err());
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
    let folder_id = alice.profile().find_folder(&keys, "Production").unwrap();
    let folder_key = alice.profile().folder_key(&keys, folder_id).unwrap();
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
            },
        )
        .unwrap();
    alice.sync().unwrap();
    assert_eq!(alice.open_item(old.id).unwrap().1.password, "aws-pass");

    // Sharing it converts it to the new format with a key of its own, in one version.
    alice.share_item(old.id, bob_id).unwrap();
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
}

fn rand_core_rng() -> impl p256::elliptic_curve::rand_core::CryptoRngCore {
    p256::elliptic_curve::rand_core::OsRng
}
