//! The calls the Mac app makes, through the API Swift sees, against a real server on a
//! local port: an owner sets up, invites and approves a member, shares a folder, and both
//! use it. Both devices sign the way the Mac's Secure Enclave key does.

use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicU32, Ordering};

use keystead_ffi::{CoreError, DeviceSigner, PasswordChange, Vault, new_device_id, parse_invite};
use keystead_server::AppState;
use p256::ecdsa::signature::Signer as _;
use p256::elliptic_curve::rand_core::{OsRng, RngCore};

/// ECDSA P-256 with a SEC1 public key and raw r‖s signatures, like `SecureEnclaveSigner`.
struct EnclaveLikeSigner(p256::ecdsa::SigningKey);

impl DeviceSigner for EnclaveLikeSigner {
    fn public_key(&self) -> Vec<u8> {
        self.0
            .verifying_key()
            .to_encoded_point(false)
            .as_bytes()
            .to_vec()
    }

    fn sign(&self, message: Vec<u8>) -> Result<Vec<u8>, CoreError> {
        let signature: p256::ecdsa::Signature = self.0.sign(&message);
        Ok(signature.to_bytes().to_vec())
    }
}

fn signer() -> Arc<dyn DeviceSigner> {
    Arc::new(EnclaveLikeSigner(p256::ecdsa::SigningKey::random(
        &mut OsRng,
    )))
}

fn account_secret() -> Vec<u8> {
    let mut bytes = vec![0; 32];
    OsRng.fill_bytes(&mut bytes);
    bytes
}

struct Server {
    _runtime: tokio::runtime::Runtime,
    url: String,
    setup_code: String,
    root: PathBuf,
}

impl Server {
    fn start() -> Self {
        static NEXT: AtomicU32 = AtomicU32::new(0);
        let root = std::env::temp_dir().join(format!(
            "keystead-ffi-test-{}-{}",
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

    fn profile(&self, who: &str) -> String {
        let directory = self.root.join(who);
        std::fs::create_dir_all(&directory).unwrap();
        directory
            .join("profile.json")
            .to_string_lossy()
            .into_owned()
    }
}

impl Drop for Server {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.root);
    }
}

#[test]
fn an_owner_sets_up_invites_approves_and_shares() {
    let server = Server::start();

    // The setup code as copied from a log: with stray whitespace.
    let owner = Vault::setup(
        server.profile("owner"),
        server.url.clone(),
        format!("  {}\n", server.setup_code),
        "Olivia".into(),
        account_secret(),
        new_device_id(),
        signer(),
    )
    .unwrap();
    assert!(owner.identity().unwrap().is_owner);

    // The member pastes the invite, wrapped onto several lines by a mail client.
    let invitation = owner.invite("Mo".into()).unwrap();
    let pasted = parse_invite(invitation.command.replace(' ', "\n")).unwrap();
    let member_secret = account_secret();
    let member_signer = signer();
    let member = Vault::join(
        server.profile("member"),
        pasted.server,
        pasted.token,
        pasted.owner_fingerprint,
        member_secret.clone(),
        new_device_id(),
        member_signer.clone(),
    )
    .unwrap();
    let them = member.identity().unwrap();
    assert!(!them.is_owner);
    assert!(
        member.invite("Eve".into()).is_err(),
        "only the owner invites"
    );

    let users = owner.users().unwrap();
    assert_eq!(users.len(), 2);
    let waiting = users
        .iter()
        .find(|user| user.user_id == them.user_id)
        .unwrap();
    assert!(!waiting.approved && !waiting.is_owner);
    assert!(users.iter().any(|user| user.is_owner && user.approved));

    // A wrong fingerprint is refused; the right one is accepted however it was typed.
    assert!(
        owner
            .approve(them.user_id, "0000-0000-0000-0000-0000".into())
            .is_err()
    );
    let typed = them.fingerprint.to_uppercase().replace('-', " ");
    assert_eq!(owner.approve(them.user_id, typed).unwrap(), "Mo");
    assert!(owner.users().unwrap().iter().all(|user| user.approved));

    owner.create_folder("Production".into()).unwrap();
    owner
        .add_login(
            "Production".into(),
            "AWS root".into(),
            "root@example.com".into(),
            "https://aws.amazon.com".into(),
            "s3cret".into(),
        )
        .unwrap();
    assert_eq!(
        owner
            .share_folder("Production".into(), them.user_id)
            .unwrap(),
        "Mo"
    );

    // The member unlocks again later, from the saved profile, and sees the shared login.
    drop(member);
    let member = Vault::open(server.profile("member"), member_secret, member_signer).unwrap();
    assert_eq!(member.sync().unwrap().rejected, 0);
    assert_eq!(member.folders().unwrap(), ["Production"]);
    let items = member.items().unwrap();
    assert_eq!(items.len(), 1);
    assert_eq!(items[0].username, "root@example.com");
    assert_eq!(member.password(items[0].id.clone()).unwrap(), "s3cret");

    let change = member
        .change_password(items[0].id.clone(), "rotated".into())
        .unwrap();
    assert!(matches!(change, PasswordChange::Saved { version: 2 }));
    owner.sync().unwrap();
    assert_eq!(owner.password(items[0].id.clone()).unwrap(), "rotated");
}
