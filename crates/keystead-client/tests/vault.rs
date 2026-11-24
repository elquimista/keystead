//! The client library against a real server on a local port, with the two kinds of
//! device key in use: a software Ed25519 key (CLI) and a P-256 key like the Mac's Secure
//! Enclave key.

use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicU32, Ordering};

use keystead_client::{DeviceSigner, EditOutcome, NewAccount, Vault, join, setup};
use keystead_core::encoding::Bytes;
use keystead_core::ids::DeviceId;
use keystead_core::items::{Details, Overview};
use keystead_core::keys::{AccountSecret, DeviceKeyScheme, DevicePublicKey, SoftwareDeviceKey};
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
            "Production",
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

fn rand_core_rng() -> impl p256::elliptic_curve::rand_core::CryptoRngCore {
    p256::elliptic_curve::rand_core::OsRng
}
