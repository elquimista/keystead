//! End-to-end tests of the API, with real keys and real encryption on the client side.

use std::path::PathBuf;
use std::sync::atomic::{AtomicU32, Ordering};

use axum::Router;
use axum::body::Body;
use axum::http::{Method, Request, StatusCode, header};
use keystead_core::api::{
    AcceptInviteRequest, AddFolderGroupRequest, AddGroupMemberRequest, AddMemberRequest,
    ApprovalRequest, Challenge, ChallengeRequest, Conflict, CreateFolderRequest,
    CreateGroupRequest, DeviceList, Directory, Enrolled, FolderRole, GroupFolderKey,
    GroupMemberKey, GroupRekeyRequest, GroupShare, Groups, Invite, InviteRequest, ItemRole, Member,
    MemberKey, Members, PutItemRequest, RecoverRequest, RecoveryChallenge,
    RecoveryChallengeRequest, RekeyRequest, Role, RoleRequest, Session, SetupRequest,
    SignInRequest, SyncEntry, SyncPage, UpdateGroupRequest, ViaGroup,
};
use keystead_core::api::{FolderEntryRequest, Health, Invites, Removal, RemoveUserRequest};
use keystead_core::directory::DirectoryEntry;
use keystead_core::folders::FolderEntry;
use keystead_core::groups::{GroupEntry, GroupKeyring, verify_entries};
use keystead_core::ids::{DeviceId, FolderId, GroupId, ItemId, UserId};
use keystead_core::items::{
    Details, EncryptedItem, FolderInfo, GroupKeyCopy, ItemKeys, ItemVersion, Overview, PersonKey,
};
use keystead_core::keys::{
    AccountKeys, AccountPublicKeys, AccountSecret, FolderKey, GroupKeys, GroupSecret, ItemKey,
    SoftwareDeviceKey, recovery_message, sign_in_message,
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

    /// Changes the database directly, for what would otherwise take days to come about.
    async fn sql(&self, sql: &str) {
        let options = sqlx::sqlite::SqliteConnectOptions::new().filename(&self.path);
        let pool = sqlx::SqlitePool::connect_with(options).await.unwrap();
        sqlx::raw_sql(sql).execute(&pool).await.unwrap();
        pool.close().await;
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
        DirectoryEntry::new(self.user_id, &self.name, self.keys.public())
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
        self.put_with_roles(server, item, base_version, Vec::new())
            .await
    }

    /// Saves a version that gives these people, new to it, these roles.
    async fn put_with_roles(
        &self,
        server: &Server,
        item: &EncryptedItem,
        base_version: Option<u64>,
        roles: Vec<Member>,
    ) -> (StatusCode, Value) {
        server
            .call(
                Method::PUT,
                &format!("/v1/items/{}", item.id),
                self.token(),
                json(&PutItemRequest {
                    base_version,
                    item: item.clone(),
                    roles,
                    group_roles: Vec::new(),
                    password_changed: false,
                }),
            )
            .await
    }

    /// Calls the API as this person.
    async fn call(
        &self,
        server: &Server,
        method: Method,
        uri: &str,
        body: Option<Value>,
    ) -> (StatusCode, Value) {
        server.call(method, uri, self.token(), body).await
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
        entry: None,
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
            otp: String::new(),
        },
    )
}

/// A version of an item in a folder, with a fresh item key sealed for the folder.
fn seal(
    author: &Person,
    folder_key: &FolderKey,
    at: ItemVersion,
    name: &str,
    password: &str,
) -> EncryptedItem {
    let key = ItemKey::generate();
    let keys = ItemKeys {
        folder: Some(key.seal_for_folder(at.id, at.folder_id.unwrap(), folder_key)),
        ..ItemKeys::default()
    };
    seal_with(author, &key, at, keys, name, password)
}

fn seal_with(
    author: &Person,
    key: &ItemKey,
    at: ItemVersion,
    keys: ItemKeys,
    name: &str,
    password: &str,
) -> EncryptedItem {
    let (overview, details) = login(name, password);
    EncryptedItem::seal(at, key, keys, &author.keys, &overview, &details).unwrap()
}

/// The item key copy for `person`.
fn copy_for(person: &Person, key: &ItemKey, item: ItemId) -> PersonKey {
    PersonKey {
        user_id: person.user_id,
        wrapped_key: person.keys.public().wrap_item_key(key, item).unwrap(),
    }
}

/// Opens an item as `person`, with the folder key if they're in its folder.
fn open_password(person: &Person, item: &EncryptedItem, folder_key: Option<&FolderKey>) -> String {
    let key = item
        .unlock(folder_key, &person.keys, person.user_id)
        .unwrap();
    item.open_details(&key).unwrap().password.clone()
}

/// The item entries in a sync page, as (item id, version).
fn item_entries(page: &SyncPage) -> Vec<(ItemId, u64)> {
    page.entries
        .iter()
        .filter_map(|entry| match entry {
            SyncEntry::Item { item, .. } => Some((item.id, item.version)),
            _ => None,
        })
        .collect()
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
                entry: None,
                user_id: bob.user_id,
                wrapped_key: bob_keys.wrap_folder_key(&key, folder_id).unwrap(),
                role: Role::Edit,
                generation: 0,
            }),
        )
        .await;
    assert_eq!(status, StatusCode::NO_CONTENT, "{body}");

    let at = ItemVersion {
        id: ItemId::random(),
        folder_id: Some(folder_id),
        owner: None,
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
    let item_key = items[0]
        .unlock(Some(&bob_folder_key), &bob.keys, bob.user_id)
        .unwrap();
    assert_eq!(items[0].open_overview(&item_key).unwrap().name, "AWS root");
    assert_eq!(
        open_password(&bob, &items[0], Some(&bob_folder_key)),
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
                entry: None,
                user_id: bob.user_id,
                wrapped_key: bob.keys.public().wrap_folder_key(&key, folder_id).unwrap(),
                role: Role::Edit,
                generation: 0,
            }),
        )
        .await;
    assert_eq!(status, StatusCode::FORBIDDEN);

    // Writes need membership, the caller as author, and a valid signature.
    let at = ItemVersion {
        id: ItemId::random(),
        folder_id: Some(folder_id),
        owner: None,
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
            folder_id: Some(folder_id),
            owner: None,
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

/// Alice's own item outside any folder, version 1, and its key.
async fn private_item(server: &Server, alice: &Person, name: &str) -> (EncryptedItem, ItemKey) {
    let key = ItemKey::generate();
    let at = ItemVersion {
        id: ItemId::random(),
        folder_id: None,
        owner: Some(alice.user_id),
        version: 1,
        author: alice.user_id,
    };
    let keys = ItemKeys {
        owner: Some(key.seal_for_owner(at.id, alice.user_id, &alice.keys)),
        ..ItemKeys::default()
    };
    let item = seal_with(alice, &key, at, keys, name, "own-secret");
    let (status, body) = alice.put(server, &item, None).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    (item, key)
}

/// The next version of `item` by `author`, with `keys`.
fn next(
    author: &Person,
    key: &ItemKey,
    item: &EncryptedItem,
    keys: ItemKeys,
    password: &str,
) -> EncryptedItem {
    let at = ItemVersion {
        id: item.id,
        folder_id: item.folder_id,
        owner: item.owner,
        version: item.version + 1,
        author: author.user_id,
    };
    seal_with(author, key, at, keys, "Bank", password)
}

#[tokio::test]
async fn an_item_outside_folders_reaches_only_its_owner_and_who_it_is_shared_with() {
    let server = Server::new().await;
    let alice = set_up_owner(&server).await;
    let bob = invite(&server, &alice, "Bob").await;
    approve(&server, &alice, &bob).await;
    let carol = invite(&server, &alice, "Carol").await;

    let (status, body) = server.call(Method::GET, "/v1/health", None, None).await;
    assert_eq!(
        (status, &body["item_format"]),
        (StatusCode::OK, &Value::from(4)),
        "{body}"
    );

    let (item, key) = private_item(&server, &alice, "Bank").await;
    let bob_cursor = bob.sync(&server, 0, 100).await.cursor;
    assert!(bob.sync(&server, 0, 100).await.entries.is_empty());
    assert_eq!(
        item_entries(&alice.sync(&server, 0, 100).await),
        [(item.id, 1)]
    );
    assert_eq!(open_password(&alice, &item, None), "own-secret");

    // Nobody else can save it, or start one as someone else's.
    let mut bobs = next(&bob, &key, &item, item.keys.clone(), "taken");
    let (status, _) = bob.put(&server, &bobs, Some(1)).await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    bobs.id = ItemId::random();
    bobs.version = 1;
    let bobs = seal_with(
        &bob,
        &key,
        ItemVersion {
            id: ItemId::random(),
            folder_id: None,
            owner: Some(alice.user_id),
            version: 1,
            author: bob.user_id,
        },
        ItemKeys {
            owner: Some(key.seal_for_owner(bobs.id, alice.user_id, &bob.keys)),
            ..ItemKeys::default()
        },
        "x",
        "y",
    );
    let (status, _) = bob.put(&server, &bobs, None).await;
    assert_eq!(status, StatusCode::FORBIDDEN);

    // Only approved people can be given a copy, and each gets one.
    let mut with_carol = item.keys.clone();
    with_carol.people.push(copy_for(&carol, &key, item.id));
    let (status, _) = alice
        .put(
            &server,
            &next(&alice, &key, &item, with_carol, "own-secret"),
            Some(1),
        )
        .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    let mut twice = item.keys.clone();
    twice.people.push(copy_for(&bob, &key, item.id));
    twice.people.push(copy_for(&bob, &key, item.id));
    let (status, _) = alice
        .put(
            &server,
            &next(&alice, &key, &item, twice, "own-secret"),
            Some(1),
        )
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);

    // Alice shares it with Bob: a new version with his copy. Bob's feed brings it.
    let mut with_bob = item.keys.clone();
    with_bob.people.push(copy_for(&bob, &key, item.id));
    let shared = next(&alice, &key, &item, with_bob, "own-secret");
    let editor = vec![Member {
        user_id: bob.user_id,
        role: Role::Edit,
    }];
    let (status, body) = alice
        .put_with_roles(&server, &shared, Some(1), editor)
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let page = bob.sync(&server, bob_cursor, 100).await;
    assert_eq!(item_entries(&page), [(item.id, 2)]);
    assert_eq!(open_password(&bob, &shared, None), "own-secret");

    // Bob can now save it, keeping everyone's copies.
    let edited = next(&bob, &key, &shared, shared.keys.clone(), "bobs-secret");
    let (status, body) = bob.put(&server, &edited, Some(2)).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(
        item_entries(&alice.sync(&server, 0, 100).await),
        [(item.id, 3)]
    );

    // As an editor, Bob can't change who has it, and the item can't move.
    let (status, body) = bob
        .put(
            &server,
            &next(&bob, &key, &edited, item.keys.clone(), "x"),
            Some(3),
        )
        .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
    let mut moved = next(&bob, &key, &edited, edited.keys.clone(), "x");
    moved.owner = Some(bob.user_id);
    let (status, _) = bob.put(&server, &moved, Some(3)).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);

    // Alice, its owner, takes Bob's copy away: his feed says to drop it.
    let bob_cursor = bob.sync(&server, 0, 100).await.cursor;
    let unshared = next(&alice, &key, &edited, item.keys.clone(), "rotated");
    let (status, body) = alice.put(&server, &unshared, Some(3)).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let page = bob.sync(&server, bob_cursor, 100).await;
    assert!(
        page.entries.iter().any(
            |entry| matches!(entry, SyncEntry::LeftItem { item_id, .. } if *item_id == item.id)
        ),
        "{:?}",
        page.entries
    );
    assert!(item_entries(&page).is_empty());
}

#[tokio::test]
async fn an_item_in_a_folder_can_be_shared_with_someone_outside_it() {
    let server = Server::new().await;
    let alice = set_up_owner(&server).await;
    let bob = invite(&server, &alice, "Bob").await;
    approve(&server, &alice, &bob).await;
    let (folder_id, folder_key) = create_folder(&server, &alice, "Production").await;

    let key = ItemKey::generate();
    let at = ItemVersion {
        id: ItemId::random(),
        folder_id: Some(folder_id),
        owner: None,
        version: 1,
        author: alice.user_id,
    };
    let mut keys = ItemKeys {
        folder: Some(key.seal_for_folder(at.id, folder_id, &folder_key)),
        ..ItemKeys::default()
    };
    let item = seal_with(&alice, &key, at, keys.clone(), "Bank", "pw");
    let (status, _) = alice.put(&server, &item, None).await;
    assert_eq!(status, StatusCode::OK);
    let (other, _) = private_item(&server, &alice, "Other").await;

    keys.people.push(copy_for(&bob, &key, item.id));
    let shared = next(&alice, &key, &item, keys, "pw");
    let (status, body) = alice.put(&server, &shared, Some(1)).await;
    assert_eq!(status, StatusCode::OK, "{body}");

    // Bob gets that one item, not the folder or anything else in it.
    let page = bob.sync(&server, 0, 100).await;
    assert_eq!(item_entries(&page), [(item.id, 2)]);
    assert_eq!(page.entries.len(), 1);
    assert_eq!(open_password(&bob, &shared, None), "pw");
    assert_ne!(other.id, item.id);

    // Once he's in the folder too, each change still reaches him once.
    let (status, _) = server
        .call(
            Method::POST,
            &format!("/v1/folders/{folder_id}/members"),
            alice.token(),
            json(&AddMemberRequest {
                entry: None,
                user_id: bob.user_id,
                wrapped_key: bob
                    .keys
                    .public()
                    .wrap_folder_key(&folder_key, folder_id)
                    .unwrap(),
                role: Role::Edit,
                generation: 0,
            }),
        )
        .await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    let edited = next(&alice, &key, &shared, shared.keys.clone(), "pw2");
    let (status, _) = alice.put(&server, &edited, Some(2)).await;
    assert_eq!(status, StatusCode::OK);
    let page = bob.sync(&server, page.cursor, 100).await;
    let joined: Vec<(ItemId, u64)> = page
        .entries
        .iter()
        .flat_map(|entry| match entry {
            SyncEntry::Joined { items, .. } => items.iter().map(|i| (i.id, i.version)).collect(),
            _ => Vec::new(),
        })
        .collect();
    assert_eq!(joined, [(item.id, 3)]);
    assert!(item_entries(&page).is_empty());
}

#[tokio::test]
async fn format_1_items_become_format_2_when_saved() {
    let server = Server::new().await;
    let alice = set_up_owner(&server).await;
    let (folder_id, folder_key) = create_folder(&server, &alice, "Production").await;
    let at = ItemVersion {
        id: ItemId::random(),
        folder_id: Some(folder_id),
        owner: None,
        version: 1,
        author: alice.user_id,
    };
    let (overview, details) = login("Old", "pw");
    let old =
        EncryptedItem::seal_format_1(at, &folder_key, &alice.keys, &overview, &details).unwrap();
    let (status, body) = alice.put(&server, &old, None).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(open_password(&alice, &old, Some(&folder_key)), "pw");

    let converted = seal(
        &alice,
        &folder_key,
        ItemVersion { version: 2, ..at },
        "Old",
        "pw",
    );
    let (status, body) = alice.put(&server, &converted, Some(1)).await;
    assert_eq!(status, StatusCode::OK, "{body}");

    let back = EncryptedItem::seal_format_1(
        ItemVersion { version: 3, ..at },
        &folder_key,
        &alice.keys,
        &overview,
        &details,
    )
    .unwrap();
    let (status, _) = alice.put(&server, &back, Some(2)).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
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

    // Signing out removes the device making the request: its session ends at once.
    let (status, _) = server
        .call(Method::POST, "/v1/sign-out", new_mac.token(), None)
        .await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    let (status, _) = devices(&server, &new_mac).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    let (status, _) = server
        .call(
            Method::POST,
            "/v1/sign-in/challenge",
            None,
            json(&ChallengeRequest {
                device_id: new_mac.device_id,
            }),
        )
        .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    let (status, _) = server.call(Method::POST, "/v1/sign-out", None, None).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
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
        sqlx::raw_sql(
            "INSERT INTO folders (id, info) VALUES ('f1', '{}');
             INSERT INTO members (user_id, folder_id, joined_seq, wrapped_key)
                 VALUES (1, 'f1', 4, '{}');
             INSERT INTO items (id, folder_id, version, seq, body) VALUES ('i1', 'f1', 1, 5, '{}');",
        )
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
    // Items survive the table rebuild, and new ones can be outside folders.
    let item: (String, Option<String>, i64) =
        sqlx::query_as("SELECT id, folder_id, seq FROM items")
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(item, ("i1".to_owned(), Some("f1".to_owned()), 5));
    // Members can open their folders, and since when is kept.
    let access: (i64, String, i64) =
        sqlx::query_as("SELECT user_id, folder_id, joined_seq FROM access")
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(access, (1, "f1".to_owned(), 4));
    sqlx::raw_sql(
        "INSERT INTO items (id, folder_id, version, seq, body) VALUES ('i2', NULL, 1, 6, '{}');
         INSERT INTO item_access (user_id, item_id) VALUES (1, 'i2');",
    )
    .execute(&pool)
    .await
    .unwrap();
    let version: i64 = sqlx::query_scalar("PRAGMA user_version")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(version, 16);
    pool.close().await;
    let _ = std::fs::remove_file(&path);
}

/// `by` adds `person` to a folder with `role`, wrapping the folder key of `generation`.
async fn add_to_folder(
    server: &Server,
    by: &Person,
    folder: (FolderId, &FolderKey),
    person: &Person,
    role: Role,
    generation: u32,
) -> (StatusCode, Value) {
    let (folder_id, key) = folder;
    by.call(
        server,
        Method::POST,
        &format!("/v1/folders/{folder_id}/members"),
        json(&AddMemberRequest {
            entry: None,
            user_id: person.user_id,
            wrapped_key: person
                .keys
                .public()
                .wrap_folder_key(key, folder_id)
                .unwrap(),
            role,
            generation,
        }),
    )
    .await
}

async fn folder_members(server: &Server, by: &Person, folder_id: FolderId) -> Vec<(UserId, Role)> {
    let (status, body) = by
        .call(
            server,
            Method::GET,
            &format!("/v1/folders/{folder_id}/members"),
            None,
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    decode::<Members>(body)
        .members
        .into_iter()
        .map(|member| (member.user_id, member.role))
        .collect()
}

/// Alice owns the server; Bob and Carol are approved members.
async fn team(server: &Server) -> (Person, Person, Person) {
    let alice = set_up_owner(server).await;
    let bob = invite(server, &alice, "Bob").await;
    approve(server, &alice, &bob).await;
    let carol = invite(server, &alice, "Carol").await;
    approve(server, &alice, &carol).await;
    (alice, bob, carol)
}

fn new_item(
    author: &Person,
    folder_id: FolderId,
    folder_key: &FolderKey,
    name: &str,
) -> EncryptedItem {
    let at = ItemVersion {
        id: ItemId::random(),
        folder_id: Some(folder_id),
        owner: None,
        version: 1,
        author: author.user_id,
    };
    seal(author, folder_key, at, name, "pw")
}

#[tokio::test]
async fn roles_limit_what_people_can_do_in_a_folder() {
    let server = Server::new().await;
    let (alice, bob, carol) = team(&server).await;
    let (folder_id, key) = create_folder(&server, &alice, "Production").await;
    let folder = (folder_id, &key);
    let (status, body) = add_to_folder(&server, &alice, folder, &bob, Role::View, 0).await;
    assert_eq!(status, StatusCode::NO_CONTENT, "{body}");
    let (status, _) = add_to_folder(&server, &alice, folder, &carol, Role::Edit, 0).await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    assert_eq!(
        folder_members(&server, &bob, folder_id).await,
        [
            (alice.user_id, Role::Manage),
            (bob.user_id, Role::View),
            (carol.user_id, Role::Edit)
        ]
    );

    // A viewer can't add logins; an editor can, but can't share the folder.
    let (status, _) = bob
        .put(&server, &new_item(&bob, folder_id, &key, "x"), None)
        .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    let (status, body) = carol
        .put(
            &server,
            &new_item(&carol, folder_id, &key, "Database"),
            None,
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let dave = invite(&server, &alice, "Dave").await;
    approve(&server, &alice, &dave).await;
    let (status, _) = add_to_folder(&server, &carol, folder, &dave, Role::View, 0).await;
    assert_eq!(status, StatusCode::FORBIDDEN);

    // Bob's sync says what he may do there.
    let page = bob.sync(&server, 0, 100).await;
    let roles = page.roles.expect("the last page carries roles");
    assert_eq!(roles.folders[0].role, Role::View);

    // Alice makes Bob an editor; now he can add logins.
    let role = |role| json(&RoleRequest { role, entry: None });
    let path = format!("/v1/folders/{folder_id}/members/{}", bob.user_id);
    let (status, _) = alice
        .call(&server, Method::PUT, &path, role(Role::Edit))
        .await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    let (status, _) = bob
        .put(&server, &new_item(&bob, folder_id, &key, "Bob's"), None)
        .await;
    assert_eq!(status, StatusCode::OK);

    // Only managers change roles, and the last manager can't step down or leave.
    let (status, _) = carol
        .call(&server, Method::PUT, &path, role(Role::Manage))
        .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    let alice_path = format!("/v1/folders/{folder_id}/members/{}", alice.user_id);
    let (status, _) = alice
        .call(&server, Method::PUT, &alice_path, role(Role::Edit))
        .await;
    assert_eq!(status, StatusCode::CONFLICT);
    let (status, _) = alice.call(&server, Method::DELETE, &alice_path, None).await;
    assert_eq!(status, StatusCode::CONFLICT);
}

#[tokio::test]
async fn removing_someone_from_a_folder_ends_their_access_and_changes_its_key() {
    let server = Server::new().await;
    let (alice, bob, carol) = team(&server).await;
    let (folder_id, key) = create_folder(&server, &alice, "Production").await;
    let folder = (folder_id, &key);
    add_to_folder(&server, &alice, folder, &bob, Role::Edit, 0).await;
    add_to_folder(&server, &alice, folder, &carol, Role::View, 0).await;
    let item = new_item(&alice, folder_id, &key, "AWS root");
    alice.put(&server, &item, None).await;
    let bob_cursor = bob.sync(&server, 0, 100).await.cursor;
    let carol_cursor = carol.sync(&server, 0, 100).await.cursor;

    // Bob can't remove anyone but himself; Alice removes him.
    let bob_path = format!("/v1/folders/{folder_id}/members/{}", bob.user_id);
    let carol_path = format!("/v1/folders/{folder_id}/members/{}", carol.user_id);
    let (status, _) = bob.call(&server, Method::DELETE, &carol_path, None).await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    let (status, _) = alice.call(&server, Method::DELETE, &bob_path, None).await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    let page = bob.sync(&server, bob_cursor, 100).await;
    assert!(
        matches!(page.entries[..], [SyncEntry::Left { .. }]),
        "{:?}",
        page.entries
    );
    let edit = seal(
        &bob,
        &key,
        ItemVersion {
            version: 2,
            author: bob.user_id,
            ..ItemVersion {
                id: item.id,
                folder_id: Some(folder_id),
                owner: None,
                version: 1,
                author: bob.user_id,
            }
        },
        "AWS root",
        "x",
    );
    let (status, _) = bob.put(&server, &edit, Some(1)).await;
    assert_eq!(status, StatusCode::FORBIDDEN);

    // The folder now needs a new key, and Alice's sync says so.
    let page = alice.sync(&server, 0, 100).await;
    assert_eq!(page.rekey_needed, [folder_id]);

    // A new key must go to exactly the remaining members, at the next generation.
    let new_key = FolderKey::generate();
    let wrapped = |people: &[&Person]| -> Vec<MemberKey> {
        people
            .iter()
            .map(|person| MemberKey {
                user_id: person.user_id,
                wrapped_key: person
                    .keys
                    .public()
                    .wrap_folder_key(&new_key, folder_id)
                    .unwrap(),
            })
            .collect()
    };
    let rekey = |generation, people: &[&Person]| {
        json(&RekeyRequest {
            entry: None,
            generation,
            wrapped_keys: wrapped(people),
            group_keys: Vec::new(),
            previous: new_key.seal_previous(&key, folder_id, generation),
            info: FolderInfo {
                name: "Production".into(),
            }
            .seal(folder_id, &new_key)
            .unwrap(),
        })
    };
    let path = format!("/v1/folders/{folder_id}/rekey");
    let (status, _) = alice
        .call(
            &server,
            Method::POST,
            &path,
            rekey(1, &[&alice, &bob, &carol]),
        )
        .await;
    assert_eq!(status, StatusCode::CONFLICT, "Bob is no longer a member");
    let (status, _) = alice
        .call(&server, Method::POST, &path, rekey(2, &[&alice, &carol]))
        .await;
    assert_eq!(
        status,
        StatusCode::CONFLICT,
        "the generation must be the next one"
    );
    let (status, _) = carol
        .call(&server, Method::POST, &path, rekey(1, &[&alice, &carol]))
        .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "only managers");
    let (status, body) = alice
        .call(&server, Method::POST, &path, rekey(1, &[&alice, &carol]))
        .await;
    assert_eq!(status, StatusCode::NO_CONTENT, "{body}");
    assert!(alice.sync(&server, 0, 100).await.rekey_needed.is_empty());

    // Carol gets the new key, and through the chain still opens the old one.
    let page = carol.sync(&server, carol_cursor, 100).await;
    let Some(SyncEntry::Rekeyed {
        wrapped_key,
        generation,
        chain,
        info,
        ..
    }) = page
        .entries
        .into_iter()
        .find(|entry| matches!(entry, SyncEntry::Rekeyed { .. }))
    else {
        panic!("expected a new key");
    };
    assert_eq!(generation, 1);
    let carols_key = carol
        .keys
        .unwrap_folder_key(&wrapped_key, folder_id)
        .unwrap();
    assert_eq!(
        FolderInfo::open(&info, folder_id, &carols_key)
            .unwrap()
            .name,
        "Production"
    );
    let old = carols_key
        .open_previous(&chain[0].previous, folder_id, 1)
        .unwrap();
    assert_eq!(open_password(&carol, &item, Some(&old)), "pw");

    // Adding someone now needs the new key's generation; a new member gets the chain.
    let (status, _) = add_to_folder(&server, &alice, folder, &bob, Role::View, 0).await;
    assert_eq!(status, StatusCode::CONFLICT);
    let (status, _) =
        add_to_folder(&server, &alice, (folder_id, &new_key), &bob, Role::View, 1).await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    let page = bob.sync(&server, 0, 100).await;
    let joined_chain = page.entries.iter().find_map(|entry| match entry {
        SyncEntry::Joined {
            chain, generation, ..
        } => Some((chain.len(), *generation)),
        _ => None,
    });
    assert_eq!(joined_chain, Some((1, 1)));

    // Anyone can leave a folder on their own.
    let (status, _) = carol.call(&server, Method::DELETE, &carol_path, None).await;
    assert_eq!(status, StatusCode::NO_CONTENT);
}

#[tokio::test]
async fn the_owner_can_remove_someone_from_the_team() {
    let server = Server::new().await;
    let (alice, bob, carol) = team(&server).await;
    // Bob made a folder and shared it with Carol as a viewer; Alice isn't in it.
    let (folder_id, key) = create_folder(&server, &bob, "Bob's team").await;
    add_to_folder(&server, &bob, (folder_id, &key), &carol, Role::View, 0).await;
    // Alice shared one of her own logins with Bob.
    let (item, item_key) = private_item(&server, &alice, "Bank").await;
    let mut keys = item.keys.clone();
    keys.people.push(copy_for(&bob, &item_key, item.id));
    let shared = next(&alice, &item_key, &item, keys, "own-secret");
    alice.put(&server, &shared, Some(1)).await;

    // Only the owner removes people, and not herself.
    let path = |person: &Person| format!("/v1/users/{}", person.user_id);
    let (status, _) = carol.call(&server, Method::DELETE, &path(&bob), None).await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    let (status, _) = alice
        .call(&server, Method::DELETE, &path(&alice), None)
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    let carol_cursor = carol.sync(&server, 0, 100).await.cursor;
    let (status, body) = alice.call(&server, Method::DELETE, &path(&bob), None).await;
    assert_eq!(status, StatusCode::NO_CONTENT, "{body}");

    // Bob's devices stop working, and his account can't be recovered.
    let (status, _) = devices(&server, &bob).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    let (status, _) = recovery_challenge(&server, bob.keys.public()).await;
    assert_eq!(status, StatusCode::FORBIDDEN);

    // He's still in the directory, marked removed, so his past signatures verify.
    let (_, body) = alice
        .call(&server, Method::GET, "/v1/directory", None)
        .await;
    let directory: Directory = decode(body);
    let entry = directory
        .entries
        .iter()
        .find(|entry| entry.user_id == bob.user_id)
        .unwrap();
    assert!(entry.removed && entry.approval.is_some());

    // Carol now manages Bob's folder, which needs a new key; the login is Alice's alone.
    assert_eq!(
        folder_members(&server, &carol, folder_id).await,
        [(carol.user_id, Role::Manage)]
    );
    assert_eq!(
        carol.sync(&server, carol_cursor, 100).await.rekey_needed,
        [folder_id]
    );
    let (_, body) = alice
        .call(
            &server,
            Method::GET,
            &format!("/v1/items/{}/people", item.id),
            None,
        )
        .await;
    let people: Vec<UserId> = decode::<Members>(body)
        .members
        .iter()
        .map(|m| m.user_id)
        .collect();
    assert_eq!(people, [alice.user_id]);

    // Nobody can share with him again, but anyone who can save may drop his old copy.
    let (status, _) = add_to_folder(&server, &carol, (folder_id, &key), &bob, Role::View, 0).await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    let dropped = next(&alice, &item_key, &shared, item.keys.clone(), "own-secret");
    let (status, body) = alice.put(&server, &dropped, Some(2)).await;
    assert_eq!(status, StatusCode::OK, "{body}");
}

/// A group's secret wrapped for `person`.
fn group_copy(
    person: &Person,
    secret: &GroupSecret,
    group: GroupId,
    generation: u32,
) -> GroupMemberKey {
    GroupMemberKey {
        user_id: person.user_id,
        wrapped_secret: person
            .keys
            .public()
            .wrap_group_secret(secret, group, generation)
            .unwrap(),
    }
}

/// The group keys `person` gets from a sync page, after checking each group's entries.
fn keyring_from(page: &SyncPage, person: &Person, people: &[&Person]) -> GroupKeyring {
    let keys_of = |user: UserId| {
        people
            .iter()
            .find(|someone| someone.user_id == user)
            .map(|someone| someone.keys.public())
    };
    let mut keyring = GroupKeyring::default();
    for entry in &page.entries {
        if let SyncEntry::Group {
            group_id,
            entries,
            generation,
            wrapped_secret,
            chain,
            ..
        } = entry
        {
            let latest = verify_entries(entries, UserId(1), keys_of).unwrap();
            assert_eq!(latest.generation, *generation);
            let secret = person
                .keys
                .unwrap_group_secret(wrapped_secret, *group_id, *generation)
                .unwrap();
            keyring.add(latest, secret, chain).unwrap();
        }
    }
    keyring
}

fn has(page: &SyncPage, matches: impl Fn(&SyncEntry) -> bool) -> bool {
    page.entries.iter().any(matches)
}

#[tokio::test]
async fn groups_share_folders_and_logins_and_lose_access_when_someone_leaves() {
    let server = Server::new().await;
    let (alice, bob, carol) = team(&server).await;
    let people = [&alice, &bob, &carol];

    // Only the owner makes groups.
    let group_id = GroupId::random();
    let secret = GroupSecret::generate();
    let group_keys = GroupKeys::derive(&secret);
    let mut first = GroupEntry::first(group_id, "Ops", &group_keys, vec![alice.user_id]);
    let members = vec![
        group_copy(&alice, &secret, group_id, 1),
        group_copy(&bob, &secret, group_id, 1),
    ];
    first.sign(bob.user_id, &bob.keys);
    let request = CreateGroupRequest {
        entry: first.clone(),
        members: members.clone(),
    };
    let (status, _) = server
        .call(Method::POST, "/v1/groups", bob.token(), json(&request))
        .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    first.sign(alice.user_id, &alice.keys);
    let request = CreateGroupRequest {
        entry: first.clone(),
        members,
    };
    let (status, body) = server
        .call(Method::POST, "/v1/groups", alice.token(), json(&request))
        .await;
    assert_eq!(status, StatusCode::CREATED, "{body}");

    // A folder shared with the group reaches its members, with the group's role.
    let (folder_id, folder_key) = create_folder(&server, &alice, "Production").await;
    let item = new_item(&alice, folder_id, &folder_key, "Database");
    let (status, body) = alice.put(&server, &item, None).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let share = AddFolderGroupRequest {
        entry: None,
        group_id,
        wrapped_key: group_keys
            .public()
            .wrap_folder_key(&folder_key, folder_id)
            .unwrap(),
        group_generation: 1,
        role: Role::Edit,
        generation: 0,
    };
    let path = format!("/v1/folders/{folder_id}/groups");
    let (status, body) = server
        .call(Method::POST, &path, alice.token(), json(&share))
        .await;
    assert_eq!(status, StatusCode::NO_CONTENT, "{body}");

    let page = bob.sync(&server, 0, 100).await;
    let keyring = keyring_from(&page, &bob, &people);
    let (wrapped, via, items) = page
        .entries
        .iter()
        .find_map(|entry| match entry {
            SyncEntry::Joined {
                folder_id: id,
                wrapped_key,
                via_group,
                items,
                ..
            } if *id == folder_id => Some((wrapped_key, *via_group, items)),
            _ => None,
        })
        .expect("Bob joined the folder");
    assert_eq!(
        via,
        Some(ViaGroup {
            group_id,
            generation: 1
        })
    );
    let bobs_key = keyring
        .get(group_id, 1)
        .unwrap()
        .unwrap_folder_key(wrapped, folder_id)
        .unwrap();
    assert_eq!(open_password(&bob, &items[0], Some(&bobs_key)), "pw");
    assert_eq!(
        page.roles.unwrap().folders,
        [FolderRole {
            folder_id,
            role: Role::Edit
        }]
    );
    let bob_cursor = page.cursor;

    // So does a login shared with the group: format 3, opened with the group's key.
    let (login, login_key) = private_item(&server, &alice, "Pager").await;
    let mut keys = login.keys.clone();
    keys.groups.push(GroupKeyCopy {
        group_id,
        generation: 1,
        wrapped_key: group_keys
            .public()
            .wrap_item_key(&login_key, login.id)
            .unwrap(),
    });
    let shared = next(&alice, &login_key, &login, keys, "own-secret");
    assert_eq!(shared.format, 3);
    let put = PutItemRequest {
        base_version: Some(1),
        item: shared.clone(),
        roles: Vec::new(),
        group_roles: vec![GroupShare {
            group_id,
            role: Role::View,
        }],
        password_changed: false,
    };
    let (status, _) = server
        .call(
            Method::PUT,
            &format!("/v1/items/{}", shared.id),
            bob.token(),
            json(&PutItemRequest {
                item: next(&bob, &login_key, &login, shared.keys.clone(), "x"),
                ..put.clone()
            }),
        )
        .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    let (status, body) = server
        .call(
            Method::PUT,
            &format!("/v1/items/{}", shared.id),
            alice.token(),
            json(&put),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let page = bob.sync(&server, bob_cursor, 100).await;
    let copies: Vec<_> = item_entries(&page)
        .into_iter()
        .filter(|(id, _)| *id == shared.id)
        .collect();
    assert_eq!(copies, [(shared.id, 2)]);
    let key = shared
        .unlock_with(None, &bob.keys, bob.user_id, &keyring)
        .unwrap();
    assert_eq!(shared.open_details(&key).unwrap().password, "own-secret");
    assert!(page.roles.unwrap().items.contains(&ItemRole {
        item_id: shared.id,
        role: Role::View
    }));
    let bob_cursor = page.cursor;

    // Only managers add people. Carol, added later, gets what the group already had.
    let carol_before = carol.sync(&server, 0, 100).await.cursor;
    let add = AddGroupMemberRequest {
        entry: None,
        user_id: carol.user_id,
        generation: 1,
        wrapped_secret: carol
            .keys
            .public()
            .wrap_group_secret(&secret, group_id, 1)
            .unwrap(),
    };
    let path = format!("/v1/groups/{group_id}/members");
    let (status, _) = server
        .call(Method::POST, &path, bob.token(), json(&add))
        .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    let (status, body) = server
        .call(Method::POST, &path, alice.token(), json(&add))
        .await;
    assert_eq!(status, StatusCode::NO_CONTENT, "{body}");
    let page = carol.sync(&server, carol_before, 100).await;
    assert!(has(
        &page,
        |entry| matches!(entry, SyncEntry::Group { group_id: id, .. } if *id == group_id)
    ));
    assert!(has(
        &page,
        |entry| matches!(entry, SyncEntry::Joined { folder_id: id, .. } if *id == folder_id)
    ));
    let copies: Vec<_> = item_entries(&page)
        .into_iter()
        .filter(|(id, _)| *id == shared.id)
        .collect();
    assert_eq!(copies, [(shared.id, 2)]);
    let carol_cursor = page.cursor;

    // Only the owner and managers rename a group or change its managers.
    let mut renamed = first.next();
    renamed.name = "Operations".into();
    renamed.managers.push(carol.user_id);
    renamed.sign(carol.user_id, &carol.keys);
    let path = format!("/v1/groups/{group_id}");
    let (status, _) = server
        .call(
            Method::PUT,
            &path,
            carol.token(),
            json(&UpdateGroupRequest {
                entry: renamed.clone(),
            }),
        )
        .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    renamed.sign(alice.user_id, &alice.keys);
    let (status, body) = server
        .call(
            Method::PUT,
            &path,
            alice.token(),
            json(&UpdateGroupRequest {
                entry: renamed.clone(),
            }),
        )
        .await;
    assert_eq!(status, StatusCode::NO_CONTENT, "{body}");

    // Bob can't remove others; Alice removes him, and everything the group gave him goes.
    let path = format!("/v1/groups/{group_id}/members/{}", carol.user_id);
    let (status, _) = server.call(Method::DELETE, &path, bob.token(), None).await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    let path = format!("/v1/groups/{group_id}/members/{}", bob.user_id);
    let (status, body) = server
        .call(Method::DELETE, &path, alice.token(), None)
        .await;
    assert_eq!(status, StatusCode::NO_CONTENT, "{body}");
    let page = bob.sync(&server, bob_cursor, 100).await;
    assert!(has(
        &page,
        |entry| matches!(entry, SyncEntry::LeftGroup { group_id: id, .. } if *id == group_id)
    ));
    assert!(has(
        &page,
        |entry| matches!(entry, SyncEntry::Left { folder_id: id, .. } if *id == folder_id)
    ));
    assert!(has(
        &page,
        |entry| matches!(entry, SyncEntry::LeftItem { item_id, .. } if *item_id == shared.id)
    ));
    let (status, _) = server
        .call(
            Method::GET,
            &format!("/v1/folders/{folder_id}/members"),
            bob.token(),
            None,
        )
        .await;
    assert_eq!(status, StatusCode::FORBIDDEN);

    // The group needs a new key first; the folder's waits for it.
    let page = alice.sync(&server, 0, 1000).await;
    assert_eq!(page.group_rekey_needed, [group_id]);
    assert!(page.rekey_needed.is_empty());
    let new_folder_key = FolderKey::generate();
    let folder_rekey = |group_generation: u32, keys: &GroupKeys| RekeyRequest {
        entry: None,
        generation: 1,
        wrapped_keys: vec![MemberKey {
            user_id: alice.user_id,
            wrapped_key: alice
                .keys
                .public()
                .wrap_folder_key(&new_folder_key, folder_id)
                .unwrap(),
        }],
        group_keys: vec![GroupFolderKey {
            group_id,
            group_generation,
            wrapped_key: keys
                .public()
                .wrap_folder_key(&new_folder_key, folder_id)
                .unwrap(),
        }],
        previous: new_folder_key.seal_previous(&folder_key, folder_id, 1),
        info: FolderInfo {
            name: "Production".into(),
        }
        .seal(folder_id, &new_folder_key)
        .unwrap(),
    };
    let path = format!("/v1/folders/{folder_id}/rekey");
    let (status, _) = server
        .call(
            Method::POST,
            &path,
            alice.token(),
            json(&folder_rekey(1, &group_keys)),
        )
        .await;
    assert_eq!(status, StatusCode::CONFLICT);

    let new_secret = GroupSecret::generate();
    let new_group_keys = GroupKeys::derive(&new_secret);
    let mut rekeyed = renamed.next_generation(&new_group_keys);
    rekeyed.managers.retain(|&manager| manager != bob.user_id);
    rekeyed.sign(alice.user_id, &alice.keys);
    let rekey = GroupRekeyRequest {
        entry: rekeyed,
        members: vec![
            group_copy(&alice, &new_secret, group_id, 2),
            group_copy(&carol, &new_secret, group_id, 2),
        ],
        previous: new_group_keys.seal_previous(&secret, group_id, 2),
    };
    let group_path = format!("/v1/groups/{group_id}/rekey");
    let mut with_bob = rekey.clone();
    with_bob
        .members
        .push(group_copy(&bob, &new_secret, group_id, 2));
    let (status, _) = server
        .call(Method::POST, &group_path, alice.token(), json(&with_bob))
        .await;
    assert_eq!(status, StatusCode::CONFLICT);
    let (status, body) = server
        .call(Method::POST, &group_path, alice.token(), json(&rekey))
        .await;
    assert_eq!(status, StatusCode::NO_CONTENT, "{body}");
    let page = alice.sync(&server, 0, 1000).await;
    assert!(page.group_rekey_needed.is_empty());
    assert_eq!(page.rekey_needed, [folder_id]);

    // The folder's new key goes to the group's new key, not the old one Bob still knows.
    let (status, _) = server
        .call(
            Method::POST,
            &path,
            alice.token(),
            json(&folder_rekey(1, &group_keys)),
        )
        .await;
    assert_eq!(status, StatusCode::CONFLICT);
    let (status, body) = server
        .call(
            Method::POST,
            &path,
            alice.token(),
            json(&folder_rekey(2, &new_group_keys)),
        )
        .await;
    assert_eq!(status, StatusCode::NO_CONTENT, "{body}");

    // Carol gets the group's new key, then the folder's, and still opens the login shared
    // with the group's first key, through its chain.
    let page = carol.sync(&server, carol_cursor, 100).await;
    let keyring = keyring_from(&page, &carol, &people);
    let (info, wrapped, via) = page
        .entries
        .iter()
        .find_map(|entry| match entry {
            SyncEntry::Rekeyed {
                folder_id: id,
                info,
                wrapped_key,
                via_group,
                ..
            } if *id == folder_id => Some((info, wrapped_key, *via_group)),
            _ => None,
        })
        .expect("the folder's new key");
    assert_eq!(
        via,
        Some(ViaGroup {
            group_id,
            generation: 2
        })
    );
    let opened = keyring
        .get(group_id, 2)
        .unwrap()
        .unwrap_folder_key(wrapped, folder_id)
        .unwrap();
    assert_eq!(
        FolderInfo::open(info, folder_id, &opened).unwrap().name,
        "Production"
    );
    let key = shared
        .unlock_with(None, &carol.keys, carol.user_id, &keyring)
        .unwrap();
    assert_eq!(shared.open_details(&key).unwrap().password, "own-secret");

    // Anyone can list the groups, and their entries check out.
    let (status, body) = server
        .call(Method::GET, "/v1/groups", bob.token(), None)
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let groups: Groups = decode(body);
    let info = &groups.groups[0];
    let keys_of = |user: UserId| {
        people
            .iter()
            .find(|someone| someone.user_id == user)
            .map(|someone| someone.keys.public())
    };
    let latest = verify_entries(&info.entries, alice.user_id, keys_of).unwrap();
    assert_eq!((latest.name.as_str(), latest.generation), ("Operations", 2));
    assert_eq!(info.members, [alice.user_id, carol.user_id]);
    assert!(!info.needs_rekey);
}

#[tokio::test]
async fn a_session_renews_without_the_device_key() {
    let server = Server::new().await;
    let alice = set_up_owner(&server).await;

    // A fresh session for the same person and device, asked for with the current one.
    let (status, body) = alice
        .call(&server, Method::POST, "/v1/sign-in/renew", None)
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let renewed: Session = decode(body);
    assert_ne!(renewed.token, alice.token);
    assert_eq!(renewed.user_id, alice.user_id);
    assert_eq!(renewed.expires_in_seconds, 15 * 60);
    let (status, body) = server
        .call(Method::GET, "/v1/devices", Some(&renewed.token), None)
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(decode::<DeviceList>(body).devices.len(), 1);
    // The old session still ends when it would have.
    let (status, _) = devices(&server, &alice).await;
    assert_eq!(status, StatusCode::OK);

    // Only a session renews.
    let (status, _) = server
        .call(Method::POST, "/v1/sign-in/renew", None, None)
        .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    let (status, _) = server
        .call(
            Method::POST,
            "/v1/sign-in/renew",
            Some("not-a-session"),
            None,
        )
        .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);

    // Signing out ends every session of the device, renewed or not.
    let (status, _) = server
        .call(Method::POST, "/v1/sign-out", Some(&renewed.token), None)
        .await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    for token in [&alice.token, &renewed.token] {
        let (status, _) = server
            .call(Method::POST, "/v1/sign-in/renew", Some(token), None)
            .await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
    }
}

#[tokio::test]
async fn an_id_already_taken_shows_the_login_only_to_people_who_can_open_it() {
    let server = Server::new().await;
    let (_alice, bob, carol) = team(&server).await;
    let (folder_id, key) = create_folder(&server, &bob, "Bob's").await;
    // Carol is in the folder for a while, then removed; nobody gives it a new key yet.
    let (status, _) = add_to_folder(&server, &bob, (folder_id, &key), &carol, Role::View, 0).await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    let item = new_item(&bob, folder_id, &key, "Bank");
    let (status, _) = bob.put(&server, &item, None).await;
    assert_eq!(status, StatusCode::OK);
    let (status, _) = bob
        .call(
            &server,
            Method::DELETE,
            &format!("/v1/folders/{folder_id}/members/{}", carol.user_id),
            None,
        )
        .await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    // Bob changes the password because Carol left; the folder still has its old key.
    let at = ItemVersion {
        id: item.id,
        folder_id: Some(folder_id),
        owner: None,
        version: 2,
        author: bob.user_id,
    };
    let changed = seal(&bob, &key, at, "Bank", "new-password-after-removal");
    let (status, body) = bob.put(&server, &changed, Some(1)).await;
    assert_eq!(status, StatusCode::OK, "{body}");

    // Carol kept the login's id. Starting a login of her own under it is refused, and the
    // answer doesn't carry Bob's.
    let item_key = ItemKey::generate();
    let at = ItemVersion {
        id: item.id,
        folder_id: None,
        owner: Some(carol.user_id),
        version: 1,
        author: carol.user_id,
    };
    let keys = ItemKeys {
        owner: Some(item_key.seal_for_owner(at.id, carol.user_id, &carol.keys)),
        ..ItemKeys::default()
    };
    let hers = seal_with(&carol, &item_key, at, keys, "x", "x");
    let (status, body) = carol.put(&server, &hers, None).await;
    assert_eq!(status, StatusCode::CONFLICT, "{body}");
    assert!(body.get("current").is_none(), "{body}");
    assert!(body["error"].is_string(), "{body}");

    // Bob can open it, so the same mistake from him still gets the current version back.
    let (status, body) = bob.put(&server, &item, None).await;
    assert_eq!(status, StatusCode::CONFLICT, "{body}");
    let conflict: Conflict = decode(body);
    assert_eq!(conflict.current, changed);
}

#[tokio::test]
async fn a_recovery_challenge_from_before_a_removal_adds_no_device() {
    let server = Server::new().await;
    let alice = set_up_owner(&server).await;
    // Bob, with his account secret kept, as his recovery kit keeps it.
    let secret = AccountSecret::generate();
    let (_, body) = server
        .call(
            Method::POST,
            "/v1/invites",
            alice.token(),
            json(&InviteRequest { name: "Bob".into() }),
        )
        .await;
    let invite: Invite = decode(body);
    let mut bob = Person::with_secret("Bob", &secret);
    let (status, body) = server
        .call(
            Method::POST,
            "/v1/invites/accept",
            None,
            json(&AcceptInviteRequest {
                token: invite.token,
                keys: bob.keys.public(),
                device_id: bob.device_id,
                device_key: bob.device.public(),
                device_name: "Bob's Mac".into(),
            }),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let enrolled: Enrolled = decode(body);
    bob.user_id = enrolled.user_id;
    bob.sign_in(&server).await;
    approve(&server, &alice, &bob).await;

    // Two challenges for a new device, asked for while he's still on the team.
    let spare = Person::with_secret("Bob", &secret);
    let mut challenges = Vec::new();
    for _ in 0..2 {
        let (status, body) = recovery_challenge(&server, spare.keys.public()).await;
        assert_eq!(status, StatusCode::OK, "{body}");
        challenges.push(decode::<RecoveryChallenge>(body));
    }
    let (status, _) = alice
        .call(
            &server,
            Method::DELETE,
            &format!("/v1/users/{}", bob.user_id),
            None,
        )
        .await;
    assert_eq!(status, StatusCode::NO_CONTENT);

    // Neither works afterwards: removing him forgot them, and a removed account takes no
    // new device.
    for challenge in challenges {
        let device_key = spare.device.public();
        let signature = spare.keys.sign(&recovery_message(
            challenge.challenge.as_slice(),
            spare.device_id,
            &device_key,
        ));
        let (status, body) = server
            .call(
                Method::POST,
                "/v1/recover",
                None,
                json(&RecoverRequest {
                    challenge: challenge.challenge,
                    device_id: spare.device_id,
                    device_key,
                    device_name: "after removal".into(),
                    signature,
                }),
            )
            .await;
        assert_eq!(status, StatusCode::UNAUTHORIZED, "{body}");
    }
    let (status, _) = recovery_challenge(&server, spare.keys.public()).await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    // Removing him again finds nothing left to remove.
    let (status, _) = alice
        .call(
            &server,
            Method::DELETE,
            &format!("/v1/users/{}", bob.user_id),
            None,
        )
        .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn someone_the_owner_has_not_approved_cannot_share() {
    let server = Server::new().await;
    let alice = set_up_owner(&server).await;
    let bob = invite(&server, &alice, "Bob").await;
    approve(&server, &alice, &bob).await;
    // Mallory used an invite; the owner hasn't approved her.
    let mallory = invite(&server, &alice, "Mallory").await;

    // She keeps logins and folders of her own.
    let (own, own_key) = private_item(&server, &mallory, "Hers").await;
    let (folder_id, key) = create_folder(&server, &mallory, "Shared - Finance").await;
    let in_folder = new_item(&mallory, folder_id, &key, "In her folder");
    let (status, body) = mallory.put(&server, &in_folder, None).await;
    assert_eq!(status, StatusCode::OK, "{body}");

    // But she can't put the folder in Bob's app, or share a login with him.
    let (status, body) =
        add_to_folder(&server, &mallory, (folder_id, &key), &bob, Role::Edit, 0).await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
    let keys = ItemKeys {
        people: vec![copy_for(&bob, &own_key, own.id)],
        ..own.keys.clone()
    };
    let shared = next(&mallory, &own_key, &own, keys, "own-secret");
    let (status, body) = mallory.put(&server, &shared, Some(1)).await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
    assert!(bob.sync(&server, 0, 100).await.entries.is_empty());

    // Nor does she see how the team is organised.
    let (status, body) = mallory.call(&server, Method::GET, "/v1/groups", None).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert!(decode::<Groups>(body).groups.is_empty());

    // Once approved, she shares like anyone.
    approve(&server, &alice, &mallory).await;
    let (status, body) =
        add_to_folder(&server, &mallory, (folder_id, &key), &bob, Role::Edit, 0).await;
    assert_eq!(status, StatusCode::NO_CONTENT, "{body}");
    let (status, body) = mallory.put(&server, &shared, Some(1)).await;
    assert_eq!(status, StatusCode::OK, "{body}");
}

#[tokio::test]
async fn a_group_that_manages_keeps_viewers_as_viewers_when_a_manager_is_removed() {
    let server = Server::new().await;
    let (alice, bob, carol) = team(&server).await;
    // Bob's folder: Carol views it, and the Ops group (Alice) manages it.
    let (folder_id, key) = create_folder(&server, &bob, "Bob's team").await;
    let (status, _) = add_to_folder(&server, &bob, (folder_id, &key), &carol, Role::View, 0).await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    let group_id = GroupId::random();
    let secret = GroupSecret::generate();
    let group_keys = GroupKeys::derive(&secret);
    let mut first = GroupEntry::first(group_id, "Ops", &group_keys, vec![alice.user_id]);
    first.sign(alice.user_id, &alice.keys);
    let request = CreateGroupRequest {
        entry: first,
        members: vec![group_copy(&alice, &secret, group_id, 1)],
    };
    let (status, body) = server
        .call(Method::POST, "/v1/groups", alice.token(), json(&request))
        .await;
    assert_eq!(status, StatusCode::CREATED, "{body}");
    let share = AddFolderGroupRequest {
        entry: None,
        group_id,
        wrapped_key: group_keys
            .public()
            .wrap_folder_key(&key, folder_id)
            .unwrap(),
        group_generation: 1,
        role: Role::Manage,
        generation: 0,
    };
    let (status, body) = server
        .call(
            Method::POST,
            &format!("/v1/folders/{folder_id}/groups"),
            bob.token(),
            json(&share),
        )
        .await;
    assert_eq!(status, StatusCode::NO_CONTENT, "{body}");

    // Bob, its only manager in person, is removed from the team. The group still manages
    // the folder, so Carol isn't made a manager to fill the gap.
    let (status, _) = alice
        .call(
            &server,
            Method::DELETE,
            &format!("/v1/users/{}", bob.user_id),
            None,
        )
        .await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    assert_eq!(
        folder_members(&server, &alice, folder_id).await,
        [(carol.user_id, Role::View)]
    );
}

/// Shares a folder as `add_to_folder` does, with the folder's next signed entry.
async fn add_with_entry(
    server: &Server,
    by: &Person,
    folder: (FolderId, &FolderKey),
    person: &Person,
    entry: Option<&FolderEntry>,
) -> (StatusCode, Value) {
    let (folder_id, key) = folder;
    by.call(
        server,
        Method::POST,
        &format!("/v1/folders/{folder_id}/members"),
        json(&AddMemberRequest {
            entry: entry.cloned(),
            user_id: person.user_id,
            wrapped_key: person
                .keys
                .public()
                .wrap_folder_key(key, folder_id)
                .unwrap(),
            role: Role::Edit,
            generation: 0,
        }),
    )
    .await
}

#[tokio::test]
async fn a_folders_members_are_signed_once_it_has_a_first_entry() {
    let server = Server::new().await;
    let (alice, bob, carol) = team(&server).await;
    let (_, body) = server.call(Method::GET, "/v1/health", None, None).await;
    assert_eq!(decode::<Health>(body).membership, 2);

    // A folder as apps before 0.15.0 make and share it: no entries.
    let (folder_id, key) = create_folder(&server, &alice, "Old").await;
    let (status, _) = add_with_entry(&server, &alice, (folder_id, &key), &bob, None).await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    let first_by = |who: &Person, members: Vec<UserId>| {
        let mut entry = FolderEntry::first(folder_id, 0, &key, members, Vec::new());
        entry.sign(who.user_id, &who.keys);
        entry
    };
    let path = format!("/v1/folders/{folder_id}/entries");
    let put = |who: &Person, entry: &FolderEntry| {
        let request = json(&FolderEntryRequest {
            entry: entry.clone(),
        });
        let (path, token) = (path.clone(), who.token().map(str::to_owned));
        let server = &server;
        async move {
            server
                .call(Method::PUT, &path, token.as_deref(), request)
                .await
                .0
        }
    };
    // An entry can't come with a change before the folder has a first one.
    let everyone = vec![alice.user_id, bob.user_id];
    let early = first_by(&alice, vec![alice.user_id, bob.user_id, carol.user_id]);
    let (status, _) =
        add_with_entry(&server, &alice, (folder_id, &key), &carol, Some(&early)).await;
    assert_eq!(status, StatusCode::CONFLICT);
    // Its first entry is a manager's, naming exactly who's in it now.
    assert_eq!(
        put(&alice, &first_by(&alice, vec![alice.user_id])).await,
        StatusCode::CONFLICT
    );
    assert_eq!(
        put(&bob, &first_by(&bob, everyone.clone())).await,
        StatusCode::FORBIDDEN
    );
    let first = first_by(&alice, everyone.clone());
    assert_eq!(put(&alice, &first).await, StatusCode::NO_CONTENT);
    assert_eq!(put(&alice, &first).await, StatusCode::CONFLICT);

    // From then on a change comes with the next entry, saying just that change.
    let (status, _) = add_with_entry(&server, &alice, (folder_id, &key), &carol, None).await;
    assert_eq!(status, StatusCode::CONFLICT);
    let next_by = |who: &Person, change: &dyn Fn(&mut FolderEntry)| {
        let mut entry = first.next();
        change(&mut entry);
        entry.sign(who.user_id, &who.keys);
        entry
    };
    let unchanged = next_by(&alice, &|_| {});
    let (status, _) =
        add_with_entry(&server, &alice, (folder_id, &key), &carol, Some(&unchanged)).await;
    assert_eq!(status, StatusCode::CONFLICT);
    let signed_by_bob = next_by(&bob, &|entry| entry.members.push(carol.user_id));
    let (status, _) = add_with_entry(
        &server,
        &alice,
        (folder_id, &key),
        &carol,
        Some(&signed_by_bob),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    let second = next_by(&alice, &|entry| entry.members.push(carol.user_id));
    let (status, body) =
        add_with_entry(&server, &alice, (folder_id, &key), &carol, Some(&second)).await;
    assert_eq!(status, StatusCode::NO_CONTENT, "{body}");

    // Everyone in the folder gets the entries with it.
    let (status, body) = bob
        .call(
            &server,
            Method::GET,
            &format!("/v1/folders/{folder_id}/members"),
            None,
        )
        .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        decode::<Members>(body).entries,
        [first.clone(), second.clone()]
    );
    let page = carol.sync(&server, 0, 100).await;
    assert!(page.entries.iter().any(|entry| matches!(
        entry,
        SyncEntry::Joined { entries, .. } if *entries == [first.clone(), second.clone()]
    )));
}

#[tokio::test]
async fn a_groups_members_are_signed_once_an_entry_names_them() {
    let server = Server::new().await;
    let (alice, bob, carol) = team(&server).await;
    // A group as apps before 0.15.0 make it: its entry doesn't name its members.
    let group_id = GroupId::random();
    let secret = GroupSecret::generate();
    let group_keys = GroupKeys::derive(&secret);
    let mut first = GroupEntry::first(group_id, "Ops", &group_keys, vec![alice.user_id]);
    first.sign(alice.user_id, &alice.keys);
    let request = CreateGroupRequest {
        entry: first.clone(),
        members: vec![group_copy(&alice, &secret, group_id, 1)],
    };
    let (status, body) = server
        .call(Method::POST, "/v1/groups", alice.token(), json(&request))
        .await;
    assert_eq!(status, StatusCode::CREATED, "{body}");
    let add = |person: &Person, entry: Option<&GroupEntry>| {
        let request = json(&AddGroupMemberRequest {
            entry: entry.cloned(),
            user_id: person.user_id,
            generation: 1,
            wrapped_secret: person
                .keys
                .public()
                .wrap_group_secret(&secret, group_id, 1)
                .unwrap(),
        });
        let (path, token) = (
            format!("/v1/groups/{group_id}/members"),
            alice.token().map(str::to_owned),
        );
        let server = &server;
        async move {
            server
                .call(Method::POST, &path, token.as_deref(), request)
                .await
                .0
        }
    };
    assert_eq!(add(&bob, None).await, StatusCode::NO_CONTENT);

    // The first entry to name them names exactly who's in it now.
    let update = |entry: &GroupEntry| {
        let request = json(&UpdateGroupRequest {
            entry: entry.clone(),
        });
        let (path, token) = (
            format!("/v1/groups/{group_id}"),
            alice.token().map(str::to_owned),
        );
        let server = &server;
        async move {
            server
                .call(Method::PUT, &path, token.as_deref(), request)
                .await
                .0
        }
    };
    let by_alice = |mut entry: GroupEntry| {
        entry.sign(alice.user_id, &alice.keys);
        entry
    };
    let short = by_alice(first.next().with_members(vec![alice.user_id]));
    assert_eq!(update(&short).await, StatusCode::CONFLICT);
    let named = by_alice(first.next().with_members(vec![alice.user_id, bob.user_id]));
    assert_eq!(update(&named).await, StatusCode::NO_CONTENT);

    // From then on someone new comes with the next entry, naming them too.
    assert_eq!(add(&carol, None).await, StatusCode::CONFLICT);
    let same = by_alice(named.next());
    assert_eq!(add(&carol, Some(&same)).await, StatusCode::CONFLICT);
    let with_carol =
        by_alice(
            named
                .next()
                .with_members(vec![alice.user_id, bob.user_id, carol.user_id]),
        );
    assert_eq!(add(&carol, Some(&with_carol)).await, StatusCode::NO_CONTENT);
    // A change that isn't to its members keeps them, and can't stop naming them.
    let mut renamed = with_carol.next();
    renamed.name = "Operations".into();
    renamed.members = None;
    assert_eq!(
        update(&by_alice(renamed.clone())).await,
        StatusCode::CONFLICT
    );
    renamed.members = with_carol.members.clone();
    assert_eq!(update(&by_alice(renamed)).await, StatusCode::NO_CONTENT);
}

#[tokio::test]
async fn invites_run_out_and_can_be_taken_back() {
    let server = Server::new().await;
    let alice = set_up_owner(&server).await;
    let bob = invite(&server, &alice, "Bob").await;
    let make = |name: &str| {
        let request = json(&InviteRequest { name: name.into() });
        let (token, server) = (alice.token().map(str::to_owned), &server);
        async move {
            let (status, body) = server
                .call(Method::POST, "/v1/invites", token.as_deref(), request)
                .await;
            assert_eq!(status, StatusCode::OK, "{body}");
            decode::<Invite>(body)
        }
    };
    let accept = |token: String| {
        let person = Person::new("Someone");
        let request = json(&AcceptInviteRequest {
            token,
            keys: person.keys.public(),
            device_id: person.device_id,
            device_key: person.device.public(),
            device_name: "Their Mac".into(),
        });
        let server = &server;
        async move {
            server
                .call(Method::POST, "/v1/invites/accept", None, request)
                .await
                .0
        }
    };
    let list = |who: &Person| {
        let (token, server) = (who.token().map(str::to_owned), &server);
        async move {
            server
                .call(Method::GET, "/v1/invites", token.as_deref(), None)
                .await
        }
    };

    // Only the owner sees them; one that was used isn't waiting any more.
    let carol = make("Carol").await;
    let dan = make("Dan").await;
    assert!(carol.expires_at.is_some());
    assert_eq!(list(&bob).await.0, StatusCode::FORBIDDEN);
    let (status, body) = list(&alice).await;
    assert_eq!(status, StatusCode::OK);
    let waiting = decode::<Invites>(body).invites;
    let names: Vec<&str> = waiting.iter().map(|invite| invite.name.as_str()).collect();
    assert_eq!(names, ["Carol", "Dan"]);
    assert_eq!(waiting[0].expires_at, carol.expires_at.unwrap());
    assert_eq!(
        waiting[0].expires_at - waiting[0].created_at,
        7 * 24 * 60 * 60
    );

    // Taken back: its line stops working. Only the owner can, and only once.
    let path = format!("/v1/invites/{}", waiting[0].id);
    let (status, _) = bob.call(&server, Method::DELETE, &path, None).await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    let (status, _) = alice.call(&server, Method::DELETE, &path, None).await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    let (status, _) = alice.call(&server, Method::DELETE, &path, None).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    assert_eq!(accept(carol.token).await, StatusCode::FORBIDDEN);

    // More than seven days old: it doesn't work, and isn't listed.
    server
        .sql("UPDATE invites SET expires_at = CAST(strftime('%s', 'now') AS INTEGER) - 1 WHERE used = 0")
        .await;
    assert_eq!(accept(dan.token).await, StatusCode::FORBIDDEN);
    assert!(decode::<Invites>(list(&alice).await.1).invites.is_empty());

    // A new one works, once, and gets a number no other invite had.
    let erin = make("Erin").await;
    let listed = decode::<Invites>(list(&alice).await.1).invites;
    assert_eq!(listed.len(), 1);
    assert!(listed[0].id > waiting[1].id);
    assert_eq!(accept(erin.token.clone()).await, StatusCode::OK);
    assert_eq!(accept(erin.token).await, StatusCode::FORBIDDEN);
    assert!(decode::<Invites>(list(&alice).await.1).invites.is_empty());
    // A used invite is a person now; it can't be taken back as an invite.
    let path = format!("/v1/invites/{}", listed[0].id);
    let (status, _) = alice.call(&server, Method::DELETE, &path, None).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
}

/// One device signing in or renewing over and over, or asking for challenges it never
/// answers, leaves the server holding a few of each for it, not one per request.
#[tokio::test]
async fn a_device_keeps_only_its_newest_sessions_and_challenges() {
    let server = Server::new().await;
    let mut alice = set_up_owner(&server).await;
    let works = async |token: &str| {
        let (status, _) = server
            .call(Method::GET, "/v1/devices", Some(token), None)
            .await;
        status == StatusCode::OK
    };

    // Eight sessions at a time: the ninth ends the oldest.
    let mut tokens = vec![alice.token.clone()];
    for _ in 0..8 {
        alice.sign_in(&server).await;
        tokens.push(alice.token.clone());
    }
    assert!(!works(&tokens[0]).await);
    for token in &tokens[1..] {
        assert!(works(token).await);
    }
    // Renewing counts the same, so a session renewed in a loop pushes out only its
    // own device's older ones.
    let mut bob = invite(&server, &alice, "Bob").await;
    bob.sign_in(&server).await;
    for _ in 0..20 {
        let (status, body) = alice
            .call(&server, Method::POST, "/v1/sign-in/renew", None)
            .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        alice.token = decode::<Session>(body).token;
    }
    assert!(!works(&tokens[8]).await);
    assert!(works(&alice.token).await);
    assert!(works(&bob.token).await);

    // Four challenges wait for a device: a fifth drops the first, which then signs
    // nobody in.
    let mut challenges = Vec::new();
    for _ in 0..5 {
        let (status, body) = server
            .call(
                Method::POST,
                "/v1/sign-in/challenge",
                None,
                json(&ChallengeRequest {
                    device_id: alice.device_id,
                }),
            )
            .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        challenges.push(decode::<Challenge>(body).challenge);
    }
    let answer = async |challenge: &keystead_core::encoding::Bytes| {
        let signature = alice
            .device
            .sign(&sign_in_message(alice.device_id, challenge.as_slice()));
        let request = SignInRequest {
            device_id: alice.device_id,
            challenge: challenge.clone(),
            signature,
        };
        server
            .call(Method::POST, "/v1/sign-in", None, json(&request))
            .await
            .0
    };
    assert_eq!(answer(&challenges[0]).await, StatusCode::UNAUTHORIZED);
    assert_eq!(answer(&challenges[4]).await, StatusCode::OK);

    // The same for the challenges of a recovery kit, which anyone who knows an account's
    // public keys can ask for.
    let mut recoveries = Vec::new();
    for _ in 0..5 {
        let (status, body) = recovery_challenge(&server, alice.keys.public()).await;
        assert_eq!(status, StatusCode::OK, "{body}");
        recoveries.push(decode::<RecoveryChallenge>(body).challenge);
    }
    // Only its device key and id are used: the account's own keys sign.
    let new_device = Person::new("Alice");
    let answer = async |challenge: &keystead_core::encoding::Bytes| {
        let device_key = new_device.device.public();
        let signature = alice.keys.sign(&recovery_message(
            challenge.as_slice(),
            new_device.device_id,
            &device_key,
        ));
        let request = RecoverRequest {
            challenge: challenge.clone(),
            device_id: new_device.device_id,
            device_key,
            device_name: "Alice's new Mac".into(),
            signature,
        };
        server
            .call(Method::POST, "/v1/recover", None, json(&request))
            .await
            .0
    };
    assert_eq!(answer(&recoveries[0]).await, StatusCode::UNAUTHORIZED);
    assert_eq!(answer(&recoveries[4]).await, StatusCode::OK);
}

/// A setup code works for a day. After that, a server nobody claimed makes a new one
/// when it's restarted, and the old one is no use to whoever finds it in a log.
#[tokio::test]
async fn the_setup_code_runs_out_and_a_restart_makes_a_new_one() {
    let mut server = Server::new().await;
    let mut alice = Person::new("Alice");
    alice.user_id = UserId(1);
    let mut entry = alice.entry();
    entry.approve(&alice.keys);
    let request = |code: &str| {
        json(&SetupRequest {
            setup_code: code.to_owned(),
            name: "Alice".into(),
            keys: alice.keys.public(),
            device_id: alice.device_id,
            device_key: alice.device.public(),
            device_name: "Alice's Mac".into(),
            approval: entry.approval.clone().unwrap(),
        })
    };

    // A code from before codes ran out gets a day from the first start that knows of it.
    server
        .sql("DELETE FROM settings WHERE name = 'setup_code_expires'")
        .await;
    let (status, body) = server
        .call(Method::POST, "/v1/setup", None, request(&server.setup_code))
        .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
    let state = AppState::open(&server.path).await.unwrap();
    assert_eq!(
        state.pending_setup_code().await.unwrap().as_deref(),
        Some(server.setup_code.as_str())
    );
    assert!(state.setup_code_works_until().await.unwrap().is_some());

    // A day later it's refused, and only for someone who has it does the server say why.
    server
        .sql(
            "UPDATE settings SET value = CAST(strftime('%s', 'now') AS INTEGER) - 1
             WHERE name = 'setup_code_expires'",
        )
        .await;
    assert_eq!(state.pending_setup_code().await.unwrap(), None);
    let (status, body) = server
        .call(Method::POST, "/v1/setup", None, request(&server.setup_code))
        .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert!(body.to_string().contains("run out"), "{body}");
    let (status, body) = server
        .call(Method::POST, "/v1/setup", None, request("WRONG-CODE-0000"))
        .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert!(body.to_string().contains("wrong setup code"), "{body}");

    // The restart makes a new code, and that one claims the server.
    let state = AppState::open(&server.path).await.unwrap();
    let old = std::mem::replace(
        &mut server.setup_code,
        state.pending_setup_code().await.unwrap().unwrap(),
    );
    assert_ne!(old, server.setup_code);
    server.router = router(state);
    let (status, _) = server
        .call(Method::POST, "/v1/setup", None, request(&old))
        .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    let (status, body) = server
        .call(Method::POST, "/v1/setup", None, request(&server.setup_code))
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let (status, _) = server
        .call(Method::POST, "/v1/setup", None, request(&server.setup_code))
        .await;
    assert_eq!(status, StatusCode::CONFLICT);
}

/// A page of the feed for an app that takes big folders in parts, and its size as sent.
async fn sync_in_parts(
    server: &Server,
    person: &Person,
    cursor: i64,
    resume: Option<&str>,
) -> (SyncPage, usize) {
    let resume = resume.map(|resume| format!("&resume={resume}"));
    let uri = format!(
        "/v1/sync?cursor={cursor}&parts=true{}",
        resume.unwrap_or_default()
    );
    let (status, body) = server.call(Method::GET, &uri, person.token(), None).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let size = body.to_string().len();
    (decode(body), size)
}

/// No answer to a sync is bigger than a few megabytes, however much there is to send: a
/// folder someone just joined comes in parts, and changes in pages cut by size.
#[tokio::test]
async fn a_big_folder_arrives_in_parts_and_pages_stay_small() {
    const SMALL: usize = 7 * 1024 * 1024;
    let server = Server::new().await;
    let (alice, bob, carol) = team(&server).await;
    let (folder_id, key) = create_folder(&server, &alice, "Archive").await;
    // Twelve logins of about 800 KB each as stored: more than apps before 0.17.0 can
    // read in one answer.
    let long = "p".repeat(600_000);
    let mut items = Vec::new();
    for n in 0..12 {
        let at = ItemVersion {
            id: ItemId::random(),
            folder_id: Some(folder_id),
            owner: None,
            version: 1,
            author: alice.user_id,
        };
        let item = seal(&alice, &key, at, &format!("item {n}"), &long);
        let (status, body) = alice.put(&server, &item, None).await;
        assert_eq!(status, StatusCode::OK, "{body}");
        items.push(item);
    }
    for person in [&bob, &carol] {
        let (status, body) =
            add_to_folder(&server, &alice, (folder_id, &key), person, Role::View, 0).await;
        assert_eq!(status, StatusCode::NO_CONTENT, "{body}");
    }
    let second_version = |item: &EncryptedItem| {
        let at = ItemVersion {
            id: item.id,
            folder_id: Some(folder_id),
            owner: None,
            version: 2,
            author: alice.user_id,
        };
        seal(&alice, &key, at, "changed", "pw")
    };

    // The first part is the join, with the folder's key and the first of its logins.
    // The cursor stays, and `resume` says where the next part starts.
    let (first, size) = sync_in_parts(&server, &bob, 0, None).await;
    assert!(size < SMALL, "{size}");
    assert_eq!((first.cursor, first.more), (0, true));
    let [SyncEntry::Joined { items: sent, .. }] = &first.entries[..] else {
        panic!("{:?}", first.entries);
    };
    let mut got: Vec<(ItemId, u64)> = sent.iter().map(|item| (item.id, item.version)).collect();
    assert!((1..12).contains(&got.len()), "{}", got.len());
    assert_eq!(got[0].0, items[0].id);

    // Meanwhile a login already sent changes, and so does one still to come. Neither
    // change is in a part: both follow the join, like any change.
    for item in [&items[0], &items[11]] {
        let (status, body) = alice.put(&server, &second_version(item), Some(1)).await;
        assert_eq!(status, StatusCode::OK, "{body}");
    }
    let mut page = first;
    let mut parts = 1;
    while let Some(resume) = page.resume.clone() {
        let cursor = page.cursor;
        (page, _) = sync_in_parts(&server, &bob, cursor, Some(&resume)).await;
        parts += 1;
        assert!(page.more);
        assert!(
            page.entries
                .iter()
                .all(|entry| matches!(entry, SyncEntry::Item { .. }))
        );
        got.extend(item_entries(&page));
    }
    assert!(parts >= 3, "{parts}");
    assert!(page.cursor > 0);
    assert_eq!(got.len(), 11);
    assert!(got.iter().all(|(_, version)| *version == 1));
    loop {
        let size;
        (page, size) = sync_in_parts(&server, &bob, page.cursor, None).await;
        assert!(size < SMALL, "{size}");
        assert_eq!(page.resume, None);
        got.extend(item_entries(&page));
        if !page.more {
            break;
        }
    }
    let mut expected: Vec<(ItemId, u64)> = items.iter().map(|item| (item.id, 1)).collect();
    expected[11].1 = 2;
    expected.push((items[0].id, 2));
    got.sort();
    expected.sort();
    assert_eq!(got, expected);

    // Someone removed from the folder halfway gets no more of it, only that they left.
    // A `resume` that isn't of this join starts the folder from its beginning.
    let (first, _) = sync_in_parts(&server, &carol, 0, Some("999.5")).await;
    assert!(matches!(first.entries[..], [SyncEntry::Joined { .. }]));
    let resume = first.resume.clone().unwrap();
    let (status, body) = alice
        .call(
            &server,
            Method::DELETE,
            &format!("/v1/folders/{folder_id}/members/{}", carol.user_id.0),
            None,
        )
        .await;
    assert_eq!(status, StatusCode::NO_CONTENT, "{body}");
    let mut cursor = first.cursor;
    let mut resume = Some(resume);
    let mut left = false;
    loop {
        let (page, _) = sync_in_parts(&server, &carol, cursor, resume.as_deref()).await;
        assert!(item_entries(&page).is_empty());
        left |= has(&page, |entry| matches!(entry, SyncEntry::Left { .. }));
        cursor = page.cursor;
        resume = page.resume;
        if !page.more {
            break;
        }
    }
    assert!(left);

    // An app from before 0.17.0 doesn't ask for parts, and gets the folder as it was when
    // Bob joined in one answer, then the two changes since.
    let whole = bob.sync(&server, 0, 500).await;
    assert_eq!((whole.resume.as_ref(), whole.more), (None, true));
    assert!(has(&whole, |entry| matches!(
        entry,
        SyncEntry::Joined { items, .. } if items.len() == 10
    )));
    let after = bob.sync(&server, whole.cursor, 500).await;
    assert_eq!(item_entries(&after).len(), 2);
    assert!(!after.more);

    // Alice made the folder and then filled it, so a new device of hers gets the logins
    // as changes: in pages cut by size, with or without asking for parts.
    let mut cursor = 0;
    let mut pages = 0;
    let mut seen = Vec::new();
    loop {
        let (status, body) = alice
            .call(
                &server,
                Method::GET,
                &format!("/v1/sync?cursor={cursor}"),
                None,
            )
            .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert!(body.to_string().len() < SMALL);
        let page: SyncPage = decode(body);
        pages += 1;
        seen.extend(item_entries(&page));
        cursor = page.cursor;
        if !page.more {
            break;
        }
    }
    assert!(pages >= 3, "{pages}");
    assert_eq!(seen.len(), 12);
}

/// Once a folder's entry says what each of its members may do, every change to the folder
/// comes with the next one, saying the same as the server's own lists, and only someone
/// the entries make a manager signs it.
#[tokio::test]
async fn a_folders_roles_are_signed_once_an_entry_has_them() {
    let server = Server::new().await;
    let (alice, bob, carol) = team(&server).await;
    let dan = invite(&server, &alice, "Dan").await;
    approve(&server, &alice, &dan).await;

    // Bob makes a folder as 0.17.0 apps do: its first entry names him its manager.
    let folder_id = FolderId::random();
    let key = FolderKey::generate();
    let mut first = FolderEntry::first(folder_id, 0, &key, vec![bob.user_id], Vec::new())
        .with_roles(|_| Role::Manage, |_| Role::Manage);
    first.sign(bob.user_id, &bob.keys);
    let request = CreateFolderRequest {
        entry: Some(first.clone()),
        folder_id,
        info: FolderInfo {
            name: "Billing".into(),
        }
        .seal(folder_id, &key)
        .unwrap(),
        wrapped_key: bob.keys.public().wrap_folder_key(&key, folder_id).unwrap(),
    };
    let (status, body) = bob
        .call(&server, Method::POST, "/v1/folders", json(&request))
        .await;
    assert_eq!(status, StatusCode::CREATED, "{body}");
    let members_path = format!("/v1/folders/{folder_id}/members");
    let add = async |entry: Option<FolderEntry>, person: &Person, role: Role| {
        let request = AddMemberRequest {
            entry,
            user_id: person.user_id,
            wrapped_key: person
                .keys
                .public()
                .wrap_folder_key(&key, folder_id)
                .unwrap(),
            role,
            generation: 0,
        };
        bob.call(&server, Method::POST, &members_path, json(&request))
            .await
    };
    let signed = |by: &Person, after: &FolderEntry, change: &dyn Fn(&mut FolderEntry)| {
        let mut entry = after.next();
        change(&mut entry);
        entry.sign(by.user_id, &by.keys);
        entry
    };

    // Sharing it takes the next entry, with the role it's shared at: not none, not one
    // without roles as apps before 0.17.0 would send, and not one that says otherwise.
    let (status, _) = add(None, &carol, Role::View).await;
    assert_eq!(status, StatusCode::CONFLICT);
    let mut without = first.next();
    without.roles = None;
    without.members.push(carol.user_id);
    without.sign(bob.user_id, &bob.keys);
    let (status, body) = add(Some(without), &carol, Role::View).await;
    assert_eq!(status, StatusCode::CONFLICT);
    assert!(body.to_string().contains("update Keystead"), "{body}");
    let wrong = signed(&bob, &first, &|entry| {
        entry.put_member(carol.user_id, Role::Manage);
    });
    let (status, _) = add(Some(wrong), &carol, Role::View).await;
    assert_eq!(status, StatusCode::CONFLICT);
    let second = signed(&bob, &first, &|entry| {
        entry.put_member(carol.user_id, Role::View);
    });
    let (status, body) = add(Some(second.clone()), &carol, Role::View).await;
    assert_eq!(status, StatusCode::NO_CONTENT, "{body}");
    let third = signed(&bob, &second, &|entry| {
        entry.put_member(dan.user_id, Role::View);
    });
    let (status, body) = add(Some(third.clone()), &dan, Role::View).await;
    assert_eq!(status, StatusCode::NO_CONTENT, "{body}");

    // Carol only views the folder. A login in it shared with her directly to edit stays
    // out of her reach: everyone's app would refuse what she saved there.
    let at = ItemVersion {
        id: ItemId::random(),
        folder_id: Some(folder_id),
        owner: None,
        version: 1,
        author: bob.user_id,
    };
    let item_key = ItemKey::generate();
    let copies = || ItemKeys {
        folder: Some(item_key.seal_for_folder(at.id, folder_id, &key)),
        people: vec![copy_for(&carol, &item_key, at.id)],
        ..ItemKeys::default()
    };
    let shared = seal_with(&bob, &item_key, at, copies(), "Bank", "pw");
    let to_edit = vec![Member {
        user_id: carol.user_id,
        role: Role::Edit,
    }];
    let (status, body) = bob.put_with_roles(&server, &shared, None, to_edit).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let by_carol = ItemVersion {
        version: 2,
        author: carol.user_id,
        ..at
    };
    let changed = seal_with(&carol, &item_key, by_carol, copies(), "Bank", "hers");
    let (status, _) = carol.put(&server, &changed, Some(1)).await;
    assert_eq!(status, StatusCode::FORBIDDEN);

    // So does changing a role.
    let role_path = format!("{members_path}/{}", dan.user_id.0);
    let set = async |entry: Option<FolderEntry>, role: Role| {
        bob.call(
            &server,
            Method::PUT,
            &role_path,
            json(&RoleRequest { role, entry }),
        )
        .await
    };
    let (status, _) = set(None, Role::Edit).await;
    assert_eq!(status, StatusCode::CONFLICT);
    let fourth = signed(&bob, &third, &|entry| {
        entry.put_member(dan.user_id, Role::Edit);
    });
    let (status, body) = set(Some(fourth.clone()), Role::Edit).await;
    assert_eq!(status, StatusCode::NO_CONTENT, "{body}");

    // Bob is its only manager. The owner can't remove him from the team without signing
    // someone else in as one: the server's own choice wouldn't count with anyone's app.
    let removal_path = format!("/v1/users/{}/removal", bob.user_id.0);
    let (status, _) = carol.call(&server, Method::GET, &removal_path, None).await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    let (status, body) = alice.call(&server, Method::GET, &removal_path, None).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let removal: Removal = decode(body);
    let [waiting] = &removal.folders[..] else {
        panic!("{:?}", removal.folders);
    };
    assert_eq!(waiting.folder_id, folder_id);
    assert_eq!(waiting.promote, carol.user_id);
    assert_eq!(waiting.entries.last(), Some(&fourth));
    let (status, body) = alice
        .call(
            &server,
            Method::DELETE,
            &format!("/v1/users/{}", bob.user_id.0),
            None,
        )
        .await;
    assert_eq!(status, StatusCode::CONFLICT, "{body}");
    // The owner signs a change of roles and nothing else, and only a rise to manager.
    let lowered = signed(&alice, &fourth, &|entry| {
        entry.put_member(carol.user_id, Role::Manage);
        entry.put_member(dan.user_id, Role::View);
    });
    let remove = async |entry: &FolderEntry| {
        let request = RemoveUserRequest {
            promotions: vec![entry.clone()],
        };
        alice
            .call(&server, Method::POST, &removal_path, json(&request))
            .await
    };
    let (status, _) = remove(&lowered).await;
    assert_eq!(status, StatusCode::CONFLICT);
    let by_carol = signed(&carol, &fourth, &|entry| {
        entry.put_member(carol.user_id, Role::Manage);
    });
    let (status, _) = remove(&by_carol).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    let fifth = signed(&alice, &fourth, &|entry| {
        entry.put_member(carol.user_id, Role::Manage);
    });
    let (status, body) = remove(&fifth).await;
    assert_eq!(status, StatusCode::NO_CONTENT, "{body}");

    // Carol manages it now, by the server's list and by the entries, and gives it a new
    // key without Bob.
    let (status, body) = carol.call(&server, Method::GET, &members_path, None).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let members: Members = decode(body);
    assert_eq!(members.entries.last(), Some(&fifth));
    let roles: Vec<(UserId, Role)> = members
        .members
        .iter()
        .map(|member| (member.user_id, member.role))
        .collect();
    assert_eq!(
        roles,
        [(carol.user_id, Role::Manage), (dan.user_id, Role::Edit)]
    );
    let new_key = FolderKey::generate();
    let mut sixth = fifth.next_generation(&new_key);
    sixth.drop_member(bob.user_id);
    sixth.sign(carol.user_id, &carol.keys);
    let rekey = RekeyRequest {
        entry: Some(sixth),
        generation: 1,
        info: FolderInfo {
            name: "Billing".into(),
        }
        .seal(folder_id, &new_key)
        .unwrap(),
        previous: new_key.seal_previous(&key, folder_id, 1),
        wrapped_keys: [&carol, &dan]
            .iter()
            .map(|person| MemberKey {
                user_id: person.user_id,
                wrapped_key: person
                    .keys
                    .public()
                    .wrap_folder_key(&new_key, folder_id)
                    .unwrap(),
            })
            .collect(),
        group_keys: Vec::new(),
    };
    let (status, body) = carol
        .call(
            &server,
            Method::POST,
            &format!("/v1/folders/{folder_id}/rekey"),
            json(&rekey),
        )
        .await;
    assert_eq!(status, StatusCode::NO_CONTENT, "{body}");

    // A folder signed for before 0.17.0 has entries without roles. Its roles are the
    // server's to change until a manager signs them, which changes nothing else.
    let (old_id, old_key) = create_folder(&server, &alice, "Old").await;
    let entries_path = format!("/v1/folders/{old_id}/entries");
    let put = async |who: &Person, entry: &FolderEntry| {
        let request = FolderEntryRequest {
            entry: entry.clone(),
        };
        who.call(&server, Method::PUT, &entries_path, json(&request))
            .await
            .0
    };
    let mut old = FolderEntry::first(old_id, 0, &old_key, vec![alice.user_id], Vec::new());
    old.sign(alice.user_id, &alice.keys);
    assert_eq!(put(&alice, &old).await, StatusCode::NO_CONTENT);
    let mut again = old.next();
    again.sign(alice.user_id, &alice.keys);
    assert_eq!(put(&alice, &again).await, StatusCode::CONFLICT);
    let mut wrong = old.next().with_roles(|_| Role::Edit, |_| Role::Manage);
    wrong.sign(alice.user_id, &alice.keys);
    assert_ne!(put(&alice, &wrong).await, StatusCode::NO_CONTENT);
    let mut with = old.next().with_roles(|_| Role::Manage, |_| Role::Manage);
    with.sign(alice.user_id, &alice.keys);
    assert_eq!(put(&alice, &with).await, StatusCode::NO_CONTENT);
    assert_eq!(put(&alice, &with).await, StatusCode::CONFLICT);
}

/// A saved version may skip ahead of the one after its base, within a bound: a device
/// that saw newer versions than a server restored from a backup has saves past them. And
/// a cursor past the newest change, after the server went back, gets the newest one.
#[tokio::test]
async fn versions_may_skip_ahead_and_the_cursor_follows_a_server_that_went_back() {
    let server = Server::new().await;
    let alice = set_up_owner(&server).await;
    let (folder_id, key) = create_folder(&server, &alice, "Production").await;
    let item = new_item(&alice, folder_id, &key, "AWS root");
    let (status, body) = alice.put(&server, &item, None).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let at = |version| ItemVersion {
        id: item.id,
        folder_id: Some(folder_id),
        owner: None,
        version,
        author: alice.user_id,
    };

    // On top of version 1: version 5 is taken, one too far past isn't, and an earlier
    // one never was.
    let too_far = seal(&alice, &key, at(1_000_003), "AWS root", "pw");
    let (status, _) = alice.put(&server, &too_far, Some(1)).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    let fifth = seal(&alice, &key, at(5), "AWS root", "pw");
    let (status, body) = alice.put(&server, &fifth, Some(1)).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let same = seal(&alice, &key, at(5), "AWS root", "pw");
    let (status, _) = alice.put(&server, &same, Some(5)).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    // A base that isn't the current version is still a conflict.
    let stale = seal(&alice, &key, at(9), "AWS root", "pw");
    let (status, _) = alice.put(&server, &stale, Some(1)).await;
    assert_eq!(status, StatusCode::CONFLICT);

    // A cursor past the newest change number gets the newest one back, lower.
    let newest = alice.sync(&server, 0, 100).await.cursor;
    let page = alice.sync(&server, newest + 50, 100).await;
    assert_eq!((page.cursor, page.more), (newest, false));
    assert!(page.entries.is_empty());
}
