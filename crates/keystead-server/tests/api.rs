//! End-to-end tests of the API, with real keys and real encryption on the client side.

use std::path::PathBuf;
use std::sync::atomic::{AtomicU32, Ordering};

use axum::Router;
use axum::body::Body;
use axum::http::{Method, Request, StatusCode, header};
use keystead_core::api::{
    AcceptInviteRequest, AddMemberRequest, ApprovalRequest, Challenge, ChallengeRequest, Conflict,
    CreateFolderRequest, DeviceList, Directory, Enrolled, Invite, InviteRequest, PutItemRequest,
    RecoverRequest, RecoveryChallenge, RecoveryChallengeRequest, Session, SetupRequest,
    SignInRequest, SyncEntry, SyncPage,
};
use keystead_core::directory::DirectoryEntry;
use keystead_core::ids::{DeviceId, FolderId, ItemId, UserId};
use keystead_core::items::{Details, EncryptedItem, FolderInfo, ItemVersion, Overview};
use keystead_core::keys::{
    AccountKeys, AccountPublicKeys, AccountSecret, FolderKey, SoftwareDeviceKey, recovery_message,
    sign_in_message,
};
use keystead_server::{AppState, router};
use serde::Serialize;
use serde::de::DeserializeOwned;
use serde_json::Value;
use tower::ServiceExt;

struct Server {
    router: Router,
    path: PathBuf,
    setup_code: String,
}

impl Server {
    async fn new() -> Self {
        static NEXT: AtomicU32 = AtomicU32::new(0);
        let path = std::env::temp_dir().join(format!(
            "keystead-server-test-{}-{}.sqlite",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        let state = AppState::open(&path).await.unwrap();
        let setup_code = state.pending_setup_code().await.unwrap().unwrap();
        Self {
            router: router(state),
            path,
            setup_code,
        }
    }

    async fn call(
        &self,
        method: Method,
        uri: &str,
        token: Option<&str>,
        body: Option<Value>,
    ) -> (StatusCode, Value) {
        let mut request = Request::builder().method(method).uri(uri);
        if let Some(token) = token {
            request = request.header(header::AUTHORIZATION, format!("Bearer {token}"));
        }
        let body = match body {
            Some(value) => {
                request = request.header(header::CONTENT_TYPE, "application/json");
                Body::from(value.to_string())
            }
            None => Body::empty(),
        };
        let response = self
            .router
            .clone()
            .oneshot(request.body(body).unwrap())
            .await
            .unwrap();
        let status = response.status();
        let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let value = if bytes.is_empty() {
            Value::Null
        } else {
            serde_json::from_slice(&bytes)
                .unwrap_or_else(|_| Value::String(String::from_utf8_lossy(&bytes).into()))
        };
        (status, value)
    }
}

impl Drop for Server {
    fn drop(&mut self) {
        for suffix in ["", "-wal", "-shm"] {
            let _ = std::fs::remove_file(format!("{}{suffix}", self.path.display()));
        }
    }
}

fn json<T: Serialize>(value: &T) -> Option<Value> {
    Some(serde_json::to_value(value).unwrap())
}

fn decode<T: DeserializeOwned>(value: Value) -> T {
    serde_json::from_value(value).unwrap()
}

/// A person with an account and one CLI-style device.
struct Person {
    name: String,
    keys: AccountKeys,
    device: SoftwareDeviceKey,
    device_id: DeviceId,
    user_id: UserId,
    token: String,
}

impl Person {
    fn new(name: &str) -> Self {
        Self::with_secret(name, &AccountSecret::generate())
    }

    /// The same account as another `Person` with this secret, on a new device.
    fn with_secret(name: &str, secret: &AccountSecret) -> Self {
        Self {
            name: name.into(),
            keys: AccountKeys::derive(secret),
            device: SoftwareDeviceKey::generate(),
            device_id: DeviceId::random(),
            user_id: UserId(0),
            token: String::new(),
        }
    }

    fn entry(&self) -> DirectoryEntry {
        DirectoryEntry {
            user_id: self.user_id,
            name: self.name.clone(),
            keys: self.keys.public(),
            approval: None,
        }
    }

    fn token(&self) -> Option<&str> {
        Some(&self.token)
    }

    async fn sign_in(&mut self, server: &Server) {
        let (status, body) = server
            .call(
                Method::POST,
                "/v1/sign-in/challenge",
                None,
                json(&ChallengeRequest {
                    device_id: self.device_id,
                }),
            )
            .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        let challenge: Challenge = decode(body);
        let signature = self.device.sign(&sign_in_message(
            self.device_id,
            challenge.challenge.as_slice(),
        ));
        let (status, body) = server
            .call(
                Method::POST,
                "/v1/sign-in",
                None,
                json(&SignInRequest {
                    device_id: self.device_id,
                    challenge: challenge.challenge,
                    signature,
                }),
            )
            .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        let session: Session = decode(body);
        self.token = session.token;
        self.user_id = session.user_id;
    }

    async fn sync(&self, server: &Server, cursor: i64, limit: i64) -> SyncPage {
        let (status, body) = server
            .call(
                Method::GET,
                &format!("/v1/sync?cursor={cursor}&limit={limit}"),
                self.token(),
                None,
            )
            .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        decode(body)
    }

    async fn put(
        &self,
        server: &Server,
        item: &EncryptedItem,
        base_version: Option<u64>,
    ) -> (StatusCode, Value) {
        server
            .call(
                Method::PUT,
                &format!("/v1/items/{}", item.id),
                self.token(),
                json(&PutItemRequest {
                    base_version,
                    item: item.clone(),
                }),
            )
            .await
    }
}

async fn set_up_owner(server: &Server) -> Person {
    set_up(server, Person::new("Alice")).await
}

async fn set_up(server: &Server, mut alice: Person) -> Person {
    alice.user_id = UserId(1);
    let mut entry = alice.entry();
    entry.approve(&alice.keys);
    let request = SetupRequest {
        setup_code: server.setup_code.clone(),
        name: alice.name.clone(),
        keys: alice.keys.public(),
        device_id: alice.device_id,
        device_key: alice.device.public(),
        device_name: "Alice's Mac".into(),
        approval: entry.approval.unwrap(),
    };
    let (status, body) = server
        .call(Method::POST, "/v1/setup", None, json(&request))
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    alice.sign_in(server).await;
    alice
}

async fn invite(server: &Server, owner: &Person, name: &str) -> Person {
    let (status, body) = server
        .call(
            Method::POST,
            "/v1/invites",
            owner.token(),
            json(&InviteRequest { name: name.into() }),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let invite: Invite = decode(body);
    let mut person = Person::new(name);
    let (status, body) = server
        .call(
            Method::POST,
            "/v1/invites/accept",
            None,
            json(&AcceptInviteRequest {
                token: invite.token,
                keys: person.keys.public(),
                device_id: person.device_id,
                device_key: person.device.public(),
                device_name: format!("{name}'s Mac"),
            }),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    person.sign_in(server).await;
    person
}

async fn approve(server: &Server, owner: &Person, person: &Person) {
    let mut entry = person.entry();
    entry.approve(&owner.keys);
    let (status, body) = server
        .call(
            Method::POST,
            &format!("/v1/users/{}/approval", person.user_id),
            owner.token(),
            json(&ApprovalRequest {
                approval: entry.approval.unwrap(),
            }),
        )
        .await;
    assert_eq!(status, StatusCode::NO_CONTENT, "{body}");
}

async fn create_folder(server: &Server, owner: &Person, name: &str) -> (FolderId, FolderKey) {
    let folder_id = FolderId::random();
    let key = FolderKey::generate();
    let request = CreateFolderRequest {
        folder_id,
        info: FolderInfo { name: name.into() }
            .seal(folder_id, &key)
            .unwrap(),
        wrapped_key: owner
            .keys
            .public()
            .wrap_folder_key(&key, folder_id)
            .unwrap(),
    };
    let (status, body) = server
        .call(Method::POST, "/v1/folders", owner.token(), json(&request))
        .await;
    assert_eq!(status, StatusCode::CREATED, "{body}");
    (folder_id, key)
}

fn login(name: &str, password: &str) -> (Overview, Details) {
    (
        Overview {
            name: name.into(),
            username: "ops@example.com".into(),
            ..Overview::default()
        },
        Details {
            password: password.into(),
            notes: String::new(),
        },
    )
}

fn seal(
    author: &Person,
    key: &FolderKey,
    at: ItemVersion,
    name: &str,
    password: &str,
) -> EncryptedItem {
    let (overview, details) = login(name, password);
    EncryptedItem::seal(at, key, &author.keys, &overview, &details).unwrap()
}

/// Keys of approved directory entries, checked against the pinned owner keys.
fn trusted_keys(
    directory: &Directory,
    owner: &AccountPublicKeys,
    user: UserId,
) -> AccountPublicKeys {
    let entry = directory
        .entries
        .iter()
        .find(|entry| entry.user_id == user)
        .expect("user is in the directory");
    entry.verify(owner).expect("entry is approved by the owner");
    entry.keys.clone()
}

#[tokio::test]
async fn invite_share_sync_and_conflict_end_to_end() {
    let server = Server::new().await;
    let alice = set_up_owner(&server).await;
    let bob = invite(&server, &alice, "Bob").await;
    approve(&server, &alice, &bob).await;

    // Bob pinned Alice's keys when he joined; he trusts directory entries she signed.
    let (status, body) = server
        .call(Method::GET, "/v1/directory", bob.token(), None)
        .await;
    assert_eq!(status, StatusCode::OK);
    let directory: Directory = decode(body);
    let owner = alice.keys.public();
    let bob_keys = trusted_keys(&directory, &owner, bob.user_id);
    let alice_keys = trusted_keys(&directory, &owner, alice.user_id);

    // Alice creates a folder, shares it with Bob and saves a password in it.
    let (folder_id, key) = create_folder(&server, &alice, "Production").await;
    let (status, body) = server
        .call(
            Method::POST,
            &format!("/v1/folders/{folder_id}/members"),
            alice.token(),
            json(&AddMemberRequest {
                user_id: bob.user_id,
                wrapped_key: bob_keys.wrap_folder_key(&key, folder_id).unwrap(),
            }),
        )
        .await;
    assert_eq!(status, StatusCode::NO_CONTENT, "{body}");

    let at = ItemVersion {
        id: ItemId::random(),
        folder_id,
        version: 1,
        author: alice.user_id,
    };
    let item = seal(&alice, &key, at, "AWS root", "first-secret");
    let (status, body) = alice.put(&server, &item, None).await;
    assert_eq!(status, StatusCode::OK, "{body}");

    // Bob syncs: the join carries the folder key and the item.
    let page = bob.sync(&server, 0, 100).await;
    assert!(!page.more);
    let Some(SyncEntry::Joined {
        folder_id: joined,
        info,
        wrapped_key,
        items,
        ..
    }) = page.entries.into_iter().next()
    else {
        panic!("expected a join entry first");
    };
    assert_eq!(joined, folder_id);
    let bob_folder_key = bob.keys.unwrap_folder_key(&wrapped_key, folder_id).unwrap();
    assert_eq!(
        FolderInfo::open(&info, folder_id, &bob_folder_key)
            .unwrap()
            .name,
        "Production"
    );
    assert_eq!(items.len(), 1);
    items[0].verify(&alice_keys).unwrap();
    assert_eq!(
        items[0].open_overview(&bob_folder_key).unwrap().name,
        "AWS root"
    );
    assert_eq!(
        items[0].open_details(&bob_folder_key).unwrap().password,
        "first-secret"
    );
    let bob_cursor = page.cursor;

    // Bob saves version 2; Alice's edit, also based on version 1, is a conflict.
    let bob_edit = seal(
        &bob,
        &bob_folder_key,
        ItemVersion {
            version: 2,
            author: bob.user_id,
            ..at
        },
        "AWS root",
        "bobs-secret",
    );
    let (status, body) = bob.put(&server, &bob_edit, Some(1)).await;
    assert_eq!(status, StatusCode::OK, "{body}");

    let alice_edit = seal(
        &alice,
        &key,
        ItemVersion { version: 2, ..at },
        "AWS root",
        "alices-secret",
    );
    let (status, body) = alice.put(&server, &alice_edit, Some(1)).await;
    assert_eq!(status, StatusCode::CONFLICT);
    let conflict: Conflict = decode(body);
    assert_eq!(conflict.current.version, 2);
    assert_eq!(conflict.current.author, bob.user_id);
    conflict.current.verify(&bob_keys).unwrap();

    // Alice keeps her copy by saving on top of Bob's version.
    let alice_edit = seal(
        &alice,
        &key,
        ItemVersion { version: 3, ..at },
        "AWS root",
        "alices-secret",
    );
    let (status, body) = alice.put(&server, &alice_edit, Some(2)).await;
    assert_eq!(status, StatusCode::OK, "{body}");

    // Bob's next sync brings only the latest version.
    let page = bob.sync(&server, bob_cursor, 100).await;
    let versions: Vec<u64> = page
        .entries
        .iter()
        .map(|entry| match entry {
            SyncEntry::Item { item, .. } => item.version,
            other => panic!("unexpected entry {other:?}"),
        })
        .collect();
    assert_eq!(versions, [3]);
    let follow_up = bob.sync(&server, page.cursor, 100).await;
    assert!(follow_up.entries.is_empty());
}

#[tokio::test]
async fn access_rules_are_enforced() {
    let server = Server::new().await;

    let (status, _) = server.call(Method::GET, "/v1/directory", None, None).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);

    // A wrong setup code is refused, and setup works only once.
    let mut mallory = Person::new("Mallory");
    mallory.user_id = UserId(1);
    let mut entry = mallory.entry();
    entry.approve(&mallory.keys);
    let mut request = SetupRequest {
        setup_code: "WRONG-CODE-0000".into(),
        name: "Mallory".into(),
        keys: mallory.keys.public(),
        device_id: mallory.device_id,
        device_key: mallory.device.public(),
        device_name: String::new(),
        approval: entry.approval.unwrap(),
    };
    let (status, _) = server
        .call(Method::POST, "/v1/setup", None, json(&request))
        .await;
    assert_eq!(status, StatusCode::FORBIDDEN);

    let alice = set_up_owner(&server).await;
    request.setup_code = server.setup_code.clone();
    let (status, _) = server
        .call(Method::POST, "/v1/setup", None, json(&request))
        .await;
    assert_eq!(status, StatusCode::CONFLICT);

    // Only the owner invites, and an invite works once.
    let bob = invite(&server, &alice, "Bob").await;
    let (status, _) = server
        .call(
            Method::POST,
            "/v1/invites",
            bob.token(),
            json(&InviteRequest { name: "Eve".into() }),
        )
        .await;
    assert_eq!(status, StatusCode::FORBIDDEN);

    // Only the owner approves, even with a correctly signed entry.
    let mut self_approved = bob.entry();
    self_approved.approve(&bob.keys);
    let (status, _) = server
        .call(
            Method::POST,
            &format!("/v1/users/{}/approval", bob.user_id),
            bob.token(),
            json(&ApprovalRequest {
                approval: self_approved.approval.unwrap(),
            }),
        )
        .await;
    assert_eq!(status, StatusCode::FORBIDDEN);

    // A challenge can't be replayed.
    let (_, body) = server
        .call(
            Method::POST,
            "/v1/sign-in/challenge",
            None,
            json(&ChallengeRequest {
                device_id: bob.device_id,
            }),
        )
        .await;
    let challenge: Challenge = decode(body);
    let sign_in = SignInRequest {
        device_id: bob.device_id,
        signature: bob.device.sign(&sign_in_message(
            bob.device_id,
            challenge.challenge.as_slice(),
        )),
        challenge: challenge.challenge,
    };
    let (status, _) = server
        .call(Method::POST, "/v1/sign-in", None, json(&sign_in))
        .await;
    assert_eq!(status, StatusCode::OK);
    let (status, _) = server
        .call(Method::POST, "/v1/sign-in", None, json(&sign_in))
        .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);

    // Bob isn't approved yet, so nobody can share a folder with him.
    let (folder_id, key) = create_folder(&server, &alice, "Finance").await;
    let (status, _) = server
        .call(
            Method::POST,
            &format!("/v1/folders/{folder_id}/members"),
            alice.token(),
            json(&AddMemberRequest {
                user_id: bob.user_id,
                wrapped_key: bob.keys.public().wrap_folder_key(&key, folder_id).unwrap(),
            }),
        )
        .await;
    assert_eq!(status, StatusCode::FORBIDDEN);

    // Writes need membership, the caller as author, and a valid signature.
    let at = ItemVersion {
        id: ItemId::random(),
        folder_id,
        version: 1,
        author: bob.user_id,
    };
    let (status, _) = bob
        .put(&server, &seal(&bob, &key, at, "x", "y"), None)
        .await;
    assert_eq!(status, StatusCode::FORBIDDEN);

    let as_alice = ItemVersion {
        author: alice.user_id,
        ..at
    };
    let (status, _) = alice
        .put(&server, &seal(&bob, &key, as_alice, "x", "y"), None)
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "signed by the wrong key");

    let (status, _) = alice
        .put(&server, &seal(&bob, &key, at, "x", "y"), None)
        .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "someone else as author");

    let mut tampered = seal(&alice, &key, as_alice, "x", "y");
    tampered.details.ciphertext.0[0] ^= 1;
    let (status, _) = alice.put(&server, &tampered, None).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);

    let (status, _) = alice
        .put(
            &server,
            &seal(
                &alice,
                &key,
                ItemVersion {
                    version: 2,
                    ..as_alice
                },
                "x",
                "y",
            ),
            None,
        )
        .await;
    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "a new item starts at version 1"
    );
}

#[tokio::test]
async fn the_feed_pages_in_order() {
    let server = Server::new().await;
    let alice = set_up_owner(&server).await;
    let (folder_id, key) = create_folder(&server, &alice, "Engineering").await;
    let mut cursor = alice.sync(&server, 0, 100).await.cursor;

    for n in 0..30 {
        let at = ItemVersion {
            id: ItemId::random(),
            folder_id,
            version: 1,
            author: alice.user_id,
        };
        let (status, _) = alice
            .put(
                &server,
                &seal(&alice, &key, at, &format!("item {n}"), "pw"),
                None,
            )
            .await;
        assert_eq!(status, StatusCode::OK);
    }

    let mut seen = Vec::new();
    let mut pages = 0;
    loop {
        let page = alice.sync(&server, cursor, 10).await;
        pages += 1;
        seen.extend(page.entries.iter().map(SyncEntry::seq));
        cursor = page.cursor;
        if !page.more {
            break;
        }
    }
    assert_eq!(seen.len(), 30);
    assert!(seen.windows(2).all(|pair| pair[0] < pair[1]));
    assert_eq!(pages, 3);
}

/// Asks for a recovery challenge for `keys`, as a new device would.
async fn recovery_challenge(server: &Server, keys: AccountPublicKeys) -> (StatusCode, Value) {
    server
        .call(
            Method::POST,
            "/v1/recover/challenge",
            None,
            json(&RecoveryChallengeRequest { keys }),
        )
        .await
}

/// Recovers `person`'s account onto their (new) device, signing with `signer`'s keys.
async fn recover(server: &Server, person: &Person, signer: &AccountKeys) -> (StatusCode, Value) {
    let (status, body) = recovery_challenge(server, person.keys.public()).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let challenge: RecoveryChallenge = decode(body);
    assert_eq!(challenge.owner.user_id, UserId(1));
    let device_key = person.device.public();
    let signature = signer.sign(&recovery_message(
        challenge.challenge.as_slice(),
        person.device_id,
        &device_key,
    ));
    server
        .call(
            Method::POST,
            "/v1/recover",
            None,
            json(&RecoverRequest {
                challenge: challenge.challenge,
                device_id: person.device_id,
                device_key,
                device_name: "Alice's new Mac".into(),
                signature,
            }),
        )
        .await
}

async fn devices(server: &Server, person: &Person) -> (StatusCode, Value) {
    server
        .call(Method::GET, "/v1/devices", person.token(), None)
        .await
}

#[tokio::test]
async fn recovery_adds_a_device_and_the_lost_one_can_be_removed() {
    let server = Server::new().await;
    let secret = AccountSecret::generate();
    let old_mac = set_up(&server, Person::with_secret("Alice", &secret)).await;
    let mut bob = invite(&server, &old_mac, "Bob").await;

    // Keys nobody on the server has: no challenge.
    let (status, _) = recovery_challenge(&server, Person::new("Eve").keys.public()).await;
    assert_eq!(status, StatusCode::FORBIDDEN);

    // Someone without Alice's secret can't sign for her account, even with a challenge.
    let mut new_mac = Person::with_secret("Alice", &secret);
    let (status, _) = recover(&server, &new_mac, &bob.keys).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);

    // With the secret from her recovery kit, she can.
    let (status, body) = recover(&server, &new_mac, &new_mac.keys).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(decode::<Enrolled>(body).user_id, UserId(1));
    new_mac.sign_in(&server).await;
    assert_eq!(new_mac.user_id, UserId(1));

    let (status, body) = devices(&server, &new_mac).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let list: DeviceList = decode(body);
    assert_eq!(list.devices.len(), 2);
    let current = list.devices.iter().find(|device| device.current).unwrap();
    assert_eq!(current.device_id, new_mac.device_id);
    assert_eq!(current.name, "Alice's new Mac");
    assert!(current.added_at.is_some());
    assert!(
        list.devices
            .iter()
            .any(|device| device.name == "Alice's Mac")
    );

    // She can't remove the device she's using, or someone else's.
    let remove = |device: DeviceId| format!("/v1/devices/{device}");
    let (status, _) = server
        .call(
            Method::DELETE,
            &remove(new_mac.device_id),
            new_mac.token(),
            None,
        )
        .await;
    assert_eq!(status, StatusCode::CONFLICT);
    let (status, _) = server
        .call(
            Method::DELETE,
            &remove(bob.device_id),
            new_mac.token(),
            None,
        )
        .await;
    assert_eq!(status, StatusCode::NOT_FOUND);

    // Removing the lost Mac ends its session and stops it signing in again.
    let (status, _) = server
        .call(
            Method::DELETE,
            &remove(old_mac.device_id),
            new_mac.token(),
            None,
        )
        .await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    let (status, _) = devices(&server, &old_mac).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    let (status, _) = server
        .call(
            Method::POST,
            "/v1/sign-in/challenge",
            None,
            json(&ChallengeRequest {
                device_id: old_mac.device_id,
            }),
        )
        .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);

    // Bob's own session is untouched, and he sees only his own device.
    bob.sign_in(&server).await;
    let (status, body) = devices(&server, &bob).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(decode::<DeviceList>(body).devices.len(), 1);
}

#[tokio::test]
async fn a_recovery_challenge_works_once() {
    let server = Server::new().await;
    let secret = AccountSecret::generate();
    set_up(&server, Person::with_secret("Alice", &secret)).await;
    let new_mac = Person::with_secret("Alice", &secret);
    let (status, body) = recovery_challenge(&server, new_mac.keys.public()).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let challenge: RecoveryChallenge = decode(body);
    assert_eq!(challenge.owner.keys, new_mac.keys.public());
    let device_key = new_mac.device.public();
    let request = RecoverRequest {
        signature: new_mac.keys.sign(&recovery_message(
            challenge.challenge.as_slice(),
            new_mac.device_id,
            &device_key,
        )),
        challenge: challenge.challenge,
        device_id: new_mac.device_id,
        device_key,
        device_name: String::new(),
    };
    let (status, _) = server
        .call(Method::POST, "/v1/recover", None, json(&request))
        .await;
    assert_eq!(status, StatusCode::OK);
    let (status, _) = server
        .call(Method::POST, "/v1/recover", None, json(&request))
        .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
}

/// A database from Keystead 0.1.0 opens with its data intact and gains the new columns.
#[tokio::test]
async fn a_database_from_0_1_0_is_upgraded() {
    let path = std::env::temp_dir().join(format!(
        "keystead-server-migrate-{}.sqlite",
        std::process::id()
    ));
    let _ = std::fs::remove_file(&path);
    {
        let options = sqlx::sqlite::SqliteConnectOptions::new()
            .filename(&path)
            .create_if_missing(true);
        let pool = sqlx::SqlitePool::connect_with(options).await.unwrap();
        sqlx::raw_sql(include_str!("../src/schema.sql"))
            .execute(&pool)
            .await
            .unwrap();
        sqlx::query(
            "INSERT INTO users (id, name, encryption_key, signing_key, is_owner)
             VALUES (1, 'Alice', zeroblob(32), zeroblob(32), 1)",
        )
        .execute(&pool)
        .await
        .unwrap();
        sqlx::query("INSERT INTO devices (id, user_id, public_key) VALUES ('d1', 1, '{}')")
            .execute(&pool)
            .await
            .unwrap();
        pool.close().await;
    }
    for _ in 0..2 {
        // Opening twice runs each migration once.
        let state = AppState::open(&path).await.unwrap();
        assert_eq!(state.pending_setup_code().await.unwrap(), None);
    }
    let pool = sqlx::SqlitePool::connect(&format!("sqlite://{}", path.display()))
        .await
        .unwrap();
    let row: (String, String, Option<i64>) =
        sqlx::query_as("SELECT id, name, added_at FROM devices")
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(row, ("d1".to_owned(), String::new(), None));
    let version: i64 = sqlx::query_scalar("PRAGMA user_version")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(version, 1);
    pool.close().await;
    let _ = std::fs::remove_file(&path);
}
