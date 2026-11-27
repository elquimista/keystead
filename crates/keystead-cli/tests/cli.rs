//! Two CLI profiles, Alice and Bob, against a real server over HTTP on a local port.

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU32, Ordering};

use keystead_cli::commands::{self, EditOutcome, Role};
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
        // Throwaway accounts stay out of the login Keychain.
        keystead_cli::device::keep_keys_in_files();
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
            otp: String::new(),
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
        None,
    )
    .unwrap();
    assert_eq!(me.name, "Bob");

    // Until Alice approves Bob, she can't share with him.
    commands::create_folder(&alice, "Production").unwrap();
    assert!(commands::share_folder(&alice, "Production", me.user_id, Role::Edit).is_err());

    // A wrong fingerprint is refused; the one Bob reads out works.
    assert!(commands::approve(&alice, me.user_id, "0000-0000-0000-0000-0000").is_err());
    commands::approve(&alice, me.user_id, &me.fingerprint).unwrap();
    let users = commands::users(&bob).unwrap();
    assert!(users.iter().all(|user| user.approved));

    commands::share_folder(&alice, "Production", me.user_id, Role::Edit).unwrap();
    let (overview, details) = login("AWS root", "first-secret");
    commands::add(&alice, Some("Production"), overview, details).unwrap();

    // Bob sees it after syncing.
    let rows = commands::list(&bob).unwrap();
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].folder.as_deref(), Some("Production"));
    assert_eq!(rows[0].name, "AWS root");
    assert_eq!(show_password(&bob, "AWS root"), "first-secret");

    // Bob changes it; Alice sees his version.
    let outcome = commands::edit(&bob, "AWS root", None, "bobs-secret").unwrap();
    assert!(matches!(outcome, EditOutcome::Saved { version: 2 }));
    assert_eq!(show_password(&alice, "AWS root"), "bobs-secret");

    // A login of Alice's own reaches Bob only once she shares it.
    let (overview, details) = login("Bank", "own-secret");
    commands::add(&alice, None, overview, details).unwrap();
    assert_eq!(commands::list(&bob).unwrap().len(), 1);
    assert_eq!(
        commands::share(&alice, "Bank", None, me.user_id, Role::Edit).unwrap(),
        "Bob"
    );
    let rows = commands::list(&bob).unwrap();
    let bank = rows.iter().find(|row| row.name == "Bank").unwrap();
    assert_eq!(bank.folder, None);
    assert_eq!(bank.owner.as_deref(), Some("Alice"));
    assert_eq!(show_password(&bob, "Bank"), "own-secret");

    // Bob edits a few fields; the password stays unless asked for.
    commands::update(
        &bob,
        "Bank",
        None,
        commands::Changes {
            username: Some("bob@example.com".into()),
            notes: Some("Branch 12".into()),
            ..commands::Changes::default()
        },
    )
    .unwrap();
    let (overview, details) = commands::show(&alice, "Bank", None).unwrap();
    assert_eq!(overview.username, "bob@example.com");
    assert_eq!(details.notes, "Branch 12");
    assert_eq!(details.password, "own-secret");

    // Alice deletes it; it's gone for Bob too.
    commands::remove(&alice, "Bank", None).unwrap();
    assert!(
        commands::list(&bob)
            .unwrap()
            .iter()
            .all(|row| row.name != "Bank")
    );
    assert!(commands::show(&bob, "Bank", None).is_err());
}

#[test]
fn the_owner_lists_invites_and_takes_one_back() {
    let fixture = Fixture::start();
    let alice = fixture.home("alice");
    commands::setup(&alice, &fixture.url, &fixture.setup_code, "Alice").unwrap();
    assert_eq!(commands::pending_invites(&alice).unwrap(), Some(Vec::new()));

    let for_bob = commands::invite(&alice, "Bob").unwrap();
    let for_carol = commands::invite(&alice, "Carol").unwrap();
    let waiting = commands::pending_invites(&alice).unwrap().unwrap();
    let names: Vec<&str> = waiting.iter().map(|invite| invite.name.as_str()).collect();
    assert_eq!(names, ["Bob", "Carol"]);
    // An invite works for seven days, and its line says until when.
    assert_eq!(waiting[0].expires_at - waiting[0].created_at, 7 * 86_400);
    assert_eq!(for_bob.expires_at, Some(waiting[0].expires_at));

    // Bob's invite is taken back: his line stops working, and Carol's still does.
    commands::revoke_invite(&alice, waiting[0].id).unwrap();
    let error = commands::join(
        &fixture.home("bob"),
        &for_bob.server,
        &for_bob.token,
        &for_bob.owner_fingerprint,
        None,
    )
    .unwrap_err();
    assert!(error.to_string().contains("revoked"), "{error}");
    assert!(!fixture.home("bob").join("profile.json").exists());
    let carol = fixture.home("carol");
    commands::join(
        &carol,
        &for_carol.server,
        &for_carol.token,
        &for_carol.owner_fingerprint,
        None,
    )
    .unwrap();
    assert_eq!(commands::pending_invites(&alice).unwrap(), Some(Vec::new()));

    // Neither can be taken back now, and only the owner sees or takes back invites.
    for invite in &waiting {
        let error = commands::revoke_invite(&alice, invite.id).unwrap_err();
        assert!(error.to_string().contains("isn't waiting"), "{error}");
    }
    assert!(commands::pending_invites(&carol).is_err());
    assert!(commands::revoke_invite(&carol, waiting[0].id).is_err());
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
        None,
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
    commands::add(&old, Some("Production"), overview, details).unwrap();

    let (words, me) = commands::recovery_kit(&old).unwrap();
    assert_eq!(words.split(' ').count(), 24);

    // Typed in from paper, one word per line.
    let typed = words.replace(' ', "\n");
    let new = fixture.home("alice-new");
    // The owner can leave out the owner's fingerprint: it's their own.
    let recovered = commands::recover(&new, &fixture.url, None, &typed).unwrap();
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

    // Signing out forgets this machine, here and on the server.
    assert_eq!(commands::sign_out(&new).unwrap(), None);
    assert!(!new.join("profile.json").exists());
    assert!(!new.join("device.json").exists());
    assert!(commands::whoami(&new).is_err());
    let again = fixture.home("alice-again");
    commands::recover(&again, &fixture.url, Some(&me.owner_fingerprint), &words).unwrap();
    assert_eq!(commands::devices(&again).unwrap().len(), 1);
}

#[test]
fn with_the_invites_key_the_owners_next_sync_approves_them() {
    let fixture = Fixture::start();
    let alice = fixture.home("alice");
    let bob = fixture.home("bob");
    commands::setup(&alice, &fixture.url, &fixture.setup_code, "Alice").unwrap();
    let invite = commands::invite(&alice, "Bob").unwrap();
    let me = commands::join(
        &bob,
        &invite.server,
        &invite.token,
        &invite.owner_fingerprint,
        invite.key.as_deref(),
    )
    .unwrap();
    // Listing people fetches them, and approves whoever proved their keys.
    let users = commands::users(&alice).unwrap();
    let bob_row = users
        .iter()
        .find(|user| user.user_id == me.user_id)
        .unwrap();
    assert!(bob_row.approved);
    commands::create_folder(&alice, "Production").unwrap();
    commands::share_folder(&alice, "Production", me.user_id, Role::View).unwrap();
}
