//! Two CLI profiles, Alice and Bob, against a real server over HTTP on a local port.

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU32, Ordering};

use keystead_cli::commands::{self, EditOutcome};
use keystead_core::ids::UserId;
use keystead_core::items::{Details, Overview};
use keystead_server::AppState;

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
            "keystead-cli-test-{}-{}",
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

    fn home(&self, who: &str) -> PathBuf {
        self.root.join(who)
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.root);
    }
}

fn login(name: &str, password: &str) -> (Overview, Details) {
    (
        Overview {
            name: name.into(),
            username: "root@example.com".into(),
            ..Overview::default()
        },
        Details {
            password: password.into(),
            notes: String::new(),
        },
    )
}

fn show_password(home: &Path, name: &str) -> String {
    commands::show(home, name, None).unwrap().1.password.clone()
}

#[test]
fn alice_and_bob_share_a_password() {
    let fixture = Fixture::start();
    let alice = fixture.home("alice");
    let bob = fixture.home("bob");

    let owner = commands::setup(&alice, &fixture.url, &fixture.setup_code, "Alice").unwrap();
    assert_eq!(owner.user_id, UserId(1));

    let invite = commands::invite(&alice, "Bob").unwrap();
    let me = commands::join(
        &bob,
        &invite.server,
        &invite.token,
        &invite.owner_fingerprint,
    )
    .unwrap();
    assert_eq!(me.name, "Bob");

    // Until Alice approves Bob, she can't share with him.
    commands::create_folder(&alice, "Production").unwrap();
    assert!(commands::share_folder(&alice, "Production", me.user_id).is_err());

    // A wrong fingerprint is refused; the one Bob reads out works.
    assert!(commands::approve(&alice, me.user_id, "0000-0000-0000-0000-0000").is_err());
    commands::approve(&alice, me.user_id, &me.fingerprint).unwrap();
    let users = commands::users(&bob).unwrap();
    assert!(users.iter().all(|user| user.approved));

    commands::share_folder(&alice, "Production", me.user_id).unwrap();
    let (overview, details) = login("AWS root", "first-secret");
    commands::add(&alice, "Production", overview, details).unwrap();

    // Bob sees it after syncing.
    let rows = commands::list(&bob).unwrap();
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].folder, "Production");
    assert_eq!(rows[0].name, "AWS root");
    assert_eq!(show_password(&bob, "AWS root"), "first-secret");

    // Bob changes it; Alice sees his version.
    let outcome = commands::edit(&bob, "AWS root", None, "bobs-secret").unwrap();
    assert!(matches!(outcome, EditOutcome::Saved { version: 2 }));
    assert_eq!(show_password(&alice, "AWS root"), "bobs-secret");
}

#[test]
fn joining_checks_the_owner_fingerprint() {
    let fixture = Fixture::start();
    let alice = fixture.home("alice");
    commands::setup(&alice, &fixture.url, &fixture.setup_code, "Alice").unwrap();
    let invite = commands::invite(&alice, "Bob").unwrap();

    let error = commands::join(
        &fixture.home("bob"),
        &invite.server,
        &invite.token,
        "0000-0000-0000-0000-0000",
    )
    .unwrap_err();
    assert!(
        error.to_string().contains("Don't trust this server"),
        "{error}"
    );
    assert!(!fixture.home("bob").join("profile.json").exists());
    assert!(!fixture.home("bob").join("device.json").exists());
}

#[test]
fn a_recovery_kit_restores_an_account_on_another_machine() {
    let fixture = Fixture::start();
    let old = fixture.home("alice-old");
    commands::setup(&old, &fixture.url, &fixture.setup_code, "Alice").unwrap();
    commands::create_folder(&old, "Production").unwrap();
    let (overview, details) = login("AWS root", "s3cret");
    commands::add(&old, "Production", overview, details).unwrap();

    let (words, me) = commands::recovery_kit(&old).unwrap();
    assert_eq!(words.split(' ').count(), 24);

    // Typed in from paper: numbered, over several lines.
    let typed: String = words
        .split(' ')
        .enumerate()
        .map(|(index, word)| format!("{}. {word}\n", index + 1))
        .collect();
    let new = fixture.home("alice-new");
    let recovered = commands::recover(&new, &fixture.url, &me.owner_fingerprint, &typed).unwrap();
    assert_eq!(recovered.fingerprint, me.fingerprint);
    assert!(recovered.is_owner);
    assert_eq!(show_password(&new, "AWS root"), "s3cret");

    let devices = commands::devices(&new).unwrap();
    assert_eq!(devices.len(), 2);
    let old_device = devices.iter().find(|device| !device.current).unwrap();
    commands::remove_device(&new, old_device.id).unwrap();
    assert!(
        commands::sync(&old).is_err(),
        "the removed device is locked out"
    );
}
