//! Folders, items, roles and the change feed.
//!
//! The server can't open anything, but it decides who receives what and who may change
//! it. An item goes to the members of its folder, its owner, and everyone it's shared with
//! directly, each with a role: view, edit or manage. Folders and items can also be shared
//! with groups, which gives each of their members the group's role. Who holds a key copy
//! comes from the item itself, which its author signed; roles are the server's to enforce.
//!
//! Who can open what, whichever way, is kept in two tables derived from the rest: `access`
//! (folders, and since when) and `item_reach` (items reached without their folder).
//! [`reconcile`] brings them up to date after every change, and logs each join and leave
//! for the feed.

use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::str::FromStr;

use axum::Json;
use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use keystead_core::api::{
    AddFolderGroupRequest, AddMemberRequest, CreateFolderRequest, DeletedItem, DeletedItems,
    EscrowedFolder, Exposure, Exposures, FolderEntryRequest, FolderEscrowRequest, FolderMember,
    FolderRole, GroupMember, GroupShare, ItemHistory, ItemRole, KeyLink, Member, Members,
    PasswordAge, PasswordAges, PutItemRequest, PutItemsRequest, RekeyRequest, Restore,
    RestoreFolderKeyRequest, Role, RoleRequest, Roles, SavedItems, SavedVersion, SyncEntry,
    SyncPage, ViaGroup,
};
use keystead_core::folders::{FolderEntry, verify_folder_step};
use keystead_core::ids::{FolderId, GroupId, ItemId, UserId};
use keystead_core::items::{EncryptedItem, ITEM_FORMAT, Sealed};
use keystead_core::keys::WrappedKey;
use serde::Deserialize;
use sqlx::AssertSqlSafe;
use sqlx::SqliteConnection;

use crate::accounts::Auth;
use crate::groups::{group_key_state, group_member_ids, group_state, parse_group};
use crate::{ApiError, AppState, content_tag, next_seq, user_entry};

const DEFAULT_PAGE: i64 = 500;
/// How far a saved version may skip ahead of the one after its base (0.17.0 and later).
/// A device that saw newer versions than a server restored from a backup has saves its
/// edit past them, so every app takes it; the bound keeps anyone from pushing a login's
/// version so high that nobody can save after them.
const MAX_VERSION_SKIP: u64 = 1_000_000;
const MAX_PAGE: i64 = 1_000;
/// How much of items a sync page holds, in bytes of their stored form. A page takes one
/// entry whatever its size, and an item is at most 2 MB, so an answer stays well under
/// the 10 MB that apps before 0.17.0 can read. The one exception is a folder bigger than
/// this as someone joined it, for those same apps (see `folder_part`).
const PAGE_BYTES: usize = 4 * 1024 * 1024;

/// One ordered stream: the latest version of each item in the user's folders, then of
/// each item they reach directly (owned, or shared with them or a group of theirs) outside
/// those folders, plus the user's own joins and leaves of folders, items and groups, new
/// folder keys, and changes to their groups. Folders joined after the cursor are left out
/// here; their items ride on the join entry instead. An item reached directly after its
/// latest version (through a group just joined) rides on its own join entry.
const FEED_QUERY: &str = "
    SELECT i.seq AS seq, 'item' AS kind, i.body AS body, NULL AS target, NULL AS joined
    FROM items i JOIN access a ON a.folder_id = i.folder_id
    WHERE a.user_id = ?1 AND i.seq > ?2 AND a.joined_seq <= ?2
    UNION ALL
    SELECT i.seq, 'item', i.body, NULL, NULL
    FROM item_reach r JOIN items i ON i.id = r.item_id
    WHERE r.user_id = ?1 AND i.seq > ?2
      AND NOT EXISTS (SELECT 1 FROM access a WHERE a.user_id = ?1 AND a.folder_id = i.folder_id)
    UNION ALL
    SELECT seq, 'membership', NULL, folder_id, joined
    FROM membership_log WHERE user_id = ?1 AND seq > ?2
    UNION ALL
    SELECT seq, 'rekey', NULL, folder_id, NULL
    FROM rekey_log WHERE user_id = ?1 AND seq > ?2
    UNION ALL
    SELECT seq, CASE WHEN moved THEN 'moved_item' ELSE 'left_item' END, NULL, item_id, NULL
    FROM item_leave_log WHERE user_id = ?1 AND seq > ?2
    UNION ALL
    SELECT seq, 'joined_item', NULL, item_id, NULL
    FROM item_join_log WHERE user_id = ?1 AND seq > ?2
    UNION ALL
    SELECT seq, 'group', NULL, group_id, joined
    FROM group_log WHERE user_id = ?1 AND seq > ?2
    ORDER BY seq
    LIMIT ?3
";

type FeedRow = (i64, String, Option<String>, Option<String>, Option<bool>);

// MARK: - Folders

/// `POST /v1/folders`: creates a folder with the caller as its first member and manager.
pub(crate) async fn create_folder(
    State(state): State<AppState>,
    auth: Auth,
    Json(request): Json<CreateFolderRequest>,
) -> Result<StatusCode, ApiError> {
    let mut tx = state.writer.begin().await?;
    require_approved_to_save(&mut tx, auth.user_id).await?;
    let exists: bool = sqlx::query_scalar("SELECT EXISTS (SELECT 1 FROM folders WHERE id = ?)")
        .bind(request.folder_id.to_string())
        .fetch_one(&mut *tx)
        .await?;
    if exists {
        return Err(ApiError::Conflict("folder id already exists".into()));
    }
    sqlx::query("INSERT INTO folders (id, info) VALUES (?, ?)")
        .bind(request.folder_id.to_string())
        .bind(serde_json::to_string(&request.info)?)
        .execute(&mut *tx)
        .await?;
    join(
        &mut tx,
        auth.user_id,
        request.folder_id,
        &request.wrapped_key,
        Role::Manage,
    )
    .await?;
    if let Some(entry) = &request.entry {
        let change = Membership {
            generation: 0,
            members: HashSet::from([auth.user_id]),
            groups: HashSet::new(),
            roles: false,
        };
        add_folder_entry(&mut tx, request.folder_id, auth.user_id, entry, &change).await?;
    }
    tx.commit().await?;
    Ok(StatusCode::CREATED)
}

/// `POST /v1/folders/{folder_id}/members`: a manager adds an approved user, with a copy of
/// the folder's current key.
pub(crate) async fn add_member(
    State(state): State<AppState>,
    auth: Auth,
    Path(folder_id): Path<FolderId>,
    Json(request): Json<AddMemberRequest>,
) -> Result<StatusCode, ApiError> {
    let mut tx = state.writer.begin().await?;
    require(
        folder_role(&mut tx, auth.user_id, folder_id).await?,
        Role::Manage,
        "share this folder",
    )?;
    require_approved_to_share(&mut tx, auth.user_id).await?;
    require_shareable(&mut tx, request.user_id).await?;
    if direct_role(&mut tx, request.user_id, folder_id)
        .await?
        .is_some()
    {
        return Err(ApiError::Conflict("already a member".into()));
    }
    if request.generation != generation(&mut tx, folder_id).await? {
        return Err(ApiError::Conflict(
            "the folder's key changed; sync and try again".into(),
        ));
    }
    let before = signed_membership(&mut tx, folder_id).await?;
    join(
        &mut tx,
        request.user_id,
        folder_id,
        &request.wrapped_key,
        request.role,
    )
    .await?;
    if let Some(mut change) = entry_needed(before, request.entry.as_ref())? {
        change.members.insert(request.user_id);
        let entry = request.entry.as_ref().expect("checked by entry_needed");
        add_folder_entry(&mut tx, folder_id, auth.user_id, entry, &change).await?;
    }
    tx.commit().await?;
    Ok(StatusCode::NO_CONTENT)
}

/// `GET /v1/folders/{folder_id}/members`: everyone in the folder and the groups it's
/// shared with, and their roles, for anyone who can open it.
pub(crate) async fn members(
    State(state): State<AppState>,
    auth: Auth,
    Path(folder_id): Path<FolderId>,
) -> Result<Json<Members>, ApiError> {
    let mut conn = state.readers.acquire().await?;
    require(
        folder_role(&mut conn, auth.user_id, folder_id).await?,
        Role::View,
        "see this folder",
    )?;
    Ok(Json(Members {
        members: folder_members(&mut conn, folder_id).await?,
        groups: folder_groups(&mut conn, folder_id).await?,
        entries: folder_entries(&mut conn, folder_id).await?,
    }))
}

/// `PUT /v1/folders/{folder_id}/members/{user_id}`: a manager changes someone's role.
pub(crate) async fn set_member_role(
    State(state): State<AppState>,
    auth: Auth,
    Path((folder_id, user_id)): Path<(FolderId, i64)>,
    Json(request): Json<RoleRequest>,
) -> Result<StatusCode, ApiError> {
    let user = UserId(user_id);
    let mut tx = state.writer.begin().await?;
    require(
        folder_role(&mut tx, auth.user_id, folder_id).await?,
        Role::Manage,
        "change roles in this folder",
    )?;
    let current = direct_role(&mut tx, user, folder_id)
        .await?
        .ok_or(ApiError::NotFound)?;
    if current == Role::Manage && request.role != Role::Manage {
        require_another_manager(&mut tx, folder_id, Some(user), None).await?;
    }
    sqlx::query("UPDATE members SET role = ? WHERE user_id = ? AND folder_id = ?")
        .bind(request.role.name())
        .bind(user.0)
        .bind(folder_id.to_string())
        .execute(&mut *tx)
        .await?;
    add_role_entry(&mut tx, folder_id, auth.user_id, request.entry.as_ref()).await?;
    tx.commit().await?;
    Ok(StatusCode::NO_CONTENT)
}

/// `DELETE /v1/folders/{folder_id}/members/{user_id}`: a manager removes someone, or a
/// member leaves. Their access ends at once, unless a group still gives it; the folder
/// then needs a new key, which a manager's app makes with `rekey`.
pub(crate) async fn remove_member(
    State(state): State<AppState>,
    auth: Auth,
    Path((folder_id, user_id)): Path<(FolderId, i64)>,
) -> Result<StatusCode, ApiError> {
    let user = UserId(user_id);
    let mut tx = state.writer.begin().await?;
    let mine = folder_role(&mut tx, auth.user_id, folder_id).await?;
    if user != auth.user_id {
        require(mine, Role::Manage, "remove people from this folder")?;
    }
    let theirs = direct_role(&mut tx, user, folder_id)
        .await?
        .ok_or(ApiError::NotFound)?;
    if theirs == Role::Manage {
        require_another_manager(&mut tx, folder_id, Some(user), None).await?;
    }
    leave(&mut tx, user, folder_id).await?;
    tx.commit().await?;
    Ok(StatusCode::NO_CONTENT)
}

/// `POST /v1/folders/{folder_id}/rekey`: a manager gives the folder a new key, wrapped for
/// exactly its current members and groups, with the old key sealed under the new one. A
/// group that lost someone gets its own new key first, so the folder's can't reach them.
pub(crate) async fn rekey(
    State(state): State<AppState>,
    auth: Auth,
    Path(folder_id): Path<FolderId>,
    Json(request): Json<RekeyRequest>,
) -> Result<StatusCode, ApiError> {
    let mut tx = state.writer.begin().await?;
    require(
        folder_role(&mut tx, auth.user_id, folder_id).await?,
        Role::Manage,
        "change this folder's key",
    )?;
    let current = generation(&mut tx, folder_id).await?;
    if request.generation != current + 1 {
        return Err(ApiError::Conflict(format!(
            "the folder's key is at generation {current}; sync and try again"
        )));
    }
    let members: HashSet<UserId> = folder_members(&mut tx, folder_id)
        .await?
        .into_iter()
        .map(|member| member.user_id)
        .collect();
    let wrapped: HashSet<UserId> = request.wrapped_keys.iter().map(|key| key.user_id).collect();
    if wrapped != members || wrapped.len() != request.wrapped_keys.len() {
        return Err(ApiError::Conflict(
            "the folder's members changed; sync and try again".into(),
        ));
    }
    let groups: HashSet<GroupId> = folder_groups(&mut tx, folder_id)
        .await?
        .into_iter()
        .map(|share| share.group_id)
        .collect();
    let wrapped: HashSet<GroupId> = request.group_keys.iter().map(|key| key.group_id).collect();
    if wrapped != groups || wrapped.len() != request.group_keys.len() {
        return Err(ApiError::Conflict(
            "the groups this folder is shared with changed; sync and try again".into(),
        ));
    }
    for key in &request.group_keys {
        let (generation, needs_rekey) = group_key_state(&mut tx, key.group_id).await?;
        if needs_rekey {
            return Err(ApiError::Conflict(
                "a group this folder is shared with needs a new key first".into(),
            ));
        }
        if key.group_generation != generation {
            return Err(ApiError::Conflict(
                "a group's key changed; sync and try again".into(),
            ));
        }
    }
    if let Some(mut change) = entry_needed(
        signed_membership(&mut tx, folder_id).await?,
        request.entry.as_ref(),
    )? {
        // The new key is for exactly who's in the folder now.
        change.generation = request.generation;
        change.members = members;
        change.groups = groups;
        let entry = request.entry.as_ref().expect("checked by entry_needed");
        add_folder_entry(&mut tx, folder_id, auth.user_id, entry, &change).await?;
    }
    sqlx::query("INSERT INTO folder_keys (folder_id, generation, previous) VALUES (?, ?, ?)")
        .bind(folder_id.to_string())
        .bind(request.generation)
        .bind(serde_json::to_string(&request.previous)?)
        .execute(&mut *tx)
        .await?;
    sqlx::query("UPDATE folders SET generation = ?, info = ?, needs_rekey = 0 WHERE id = ?")
        .bind(request.generation)
        .bind(serde_json::to_string(&request.info)?)
        .bind(folder_id.to_string())
        .execute(&mut *tx)
        .await?;
    for key in &request.wrapped_keys {
        sqlx::query("UPDATE members SET wrapped_key = ? WHERE user_id = ? AND folder_id = ?")
            .bind(serde_json::to_string(&key.wrapped_key)?)
            .bind(key.user_id.0)
            .bind(folder_id.to_string())
            .execute(&mut *tx)
            .await?;
    }
    for key in &request.group_keys {
        sqlx::query(
            "UPDATE folder_groups SET wrapped_key = ?, group_generation = ?
             WHERE folder_id = ? AND group_id = ?",
        )
        .bind(serde_json::to_string(&key.wrapped_key)?)
        .bind(key.group_generation)
        .bind(folder_id.to_string())
        .bind(key.group_id.to_string())
        .execute(&mut *tx)
        .await?;
    }
    // Members who recovered got a copy for their new keys with everyone else.
    let restored: Vec<i64> = sqlx::query_scalar(
        "UPDATE members SET pending = 0 WHERE folder_id = ? AND pending = 1 RETURNING user_id",
    )
    .bind(folder_id.to_string())
    .fetch_all(&mut *tx)
    .await?;
    for user in restored {
        reconcile(&mut tx, UserId(user)).await?;
    }
    // Everyone who can open the folder, whichever way, hears about the new key.
    let users: Vec<i64> =
        sqlx::query_scalar("SELECT user_id FROM access WHERE folder_id = ? ORDER BY user_id")
            .bind(folder_id.to_string())
            .fetch_all(&mut *tx)
            .await?;
    for user in users {
        let seq = next_seq(&mut tx).await?;
        sqlx::query("INSERT INTO rekey_log (seq, user_id, folder_id) VALUES (?, ?, ?)")
            .bind(seq)
            .bind(user)
            .bind(folder_id.to_string())
            .execute(&mut *tx)
            .await?;
    }
    tx.commit().await?;
    Ok(StatusCode::NO_CONTENT)
}

/// `PUT /v1/folders/{folder_id}/members/{user_id}/key`: anyone who can open the folder
/// gives a member who recovered a copy of its current key for their new keys, so they
/// have it back without waiting for a manager. Only for members waiting for one. A member
/// gives it to themselves only from the copy of its current key they put in escrow, for a
/// folder nobody else could open.
pub(crate) async fn restore_folder_key(
    State(state): State<AppState>,
    auth: Auth,
    Path((folder_id, user_id)): Path<(FolderId, i64)>,
    Json(request): Json<RestoreFolderKeyRequest>,
) -> Result<StatusCode, ApiError> {
    let user = UserId(user_id);
    let mut tx = state.writer.begin().await?;
    if user == auth.user_id {
        let escrowed: bool = sqlx::query_scalar(
            "SELECT EXISTS (SELECT 1 FROM folder_escrow
                            WHERE user_id = ? AND folder_id = ? AND generation = ?)",
        )
        .bind(user.0)
        .bind(folder_id.to_string())
        .bind(request.generation)
        .fetch_one(&mut *tx)
        .await?;
        if !escrowed {
            return Err(ApiError::Forbidden(
                "only someone who can open this folder can give it back to you".into(),
            ));
        }
    } else {
        require(
            folder_role(&mut tx, auth.user_id, folder_id).await?,
            Role::View,
            "give someone this folder's key",
        )?;
    }
    let waiting: bool = sqlx::query_scalar(
        "SELECT EXISTS (SELECT 1 FROM members WHERE user_id = ? AND folder_id = ? AND pending)",
    )
    .bind(user.0)
    .bind(folder_id.to_string())
    .fetch_one(&mut *tx)
    .await?;
    if !waiting {
        return Err(ApiError::Conflict(
            "they aren't waiting for this folder's key".into(),
        ));
    }
    if request.generation != generation(&mut tx, folder_id).await? {
        return Err(ApiError::Conflict(
            "the folder's key changed; sync and try again".into(),
        ));
    }
    sqlx::query(
        "UPDATE members SET wrapped_key = ?, pending = 0 WHERE user_id = ? AND folder_id = ?",
    )
    .bind(serde_json::to_string(&request.wrapped_key)?)
    .bind(user.0)
    .bind(folder_id.to_string())
    .execute(&mut *tx)
    .await?;
    // The copy in escrow was sealed with their earlier personal key; a new one follows.
    sqlx::query("DELETE FROM folder_escrow WHERE user_id = ? AND folder_id = ?")
        .bind(user.0)
        .bind(folder_id.to_string())
        .execute(&mut *tx)
        .await?;
    reconcile(&mut tx, user).await?;
    tx.commit().await?;
    Ok(StatusCode::NO_CONTENT)
}

/// `PUT /v1/folders/{folder_id}/escrow`: a member with escrow on keeps a copy of the
/// folder's current key, sealed with their personal key, for a folder nobody else can
/// open, so it can come back after a recovery. Conflict if nobody needs it now.
pub(crate) async fn put_folder_escrow(
    State(state): State<AppState>,
    auth: Auth,
    Path(folder_id): Path<FolderId>,
    Json(request): Json<FolderEscrowRequest>,
) -> Result<StatusCode, ApiError> {
    let mut tx = state.writer.begin().await?;
    crate::accounts::refuse_while_recovering(&mut tx, auth.user_id).await?;
    let escrow_on: bool = sqlx::query_scalar("SELECT escrow_on FROM users WHERE id = ?")
        .bind(auth.user_id.0)
        .fetch_one(&mut *tx)
        .await?;
    if !escrow_on {
        return Err(ApiError::Conflict("your escrow is off".into()));
    }
    let member: bool = sqlx::query_scalar(
        "SELECT EXISTS (SELECT 1 FROM members WHERE user_id = ? AND folder_id = ? AND NOT pending)",
    )
    .bind(auth.user_id.0)
    .bind(folder_id.to_string())
    .fetch_one(&mut *tx)
    .await?;
    if !member {
        return Err(ApiError::Forbidden(
            "you aren't in this folder yourself".into(),
        ));
    }
    let shared: bool = sqlx::query_scalar(
        "SELECT EXISTS (SELECT 1 FROM access WHERE folder_id = ? AND user_id != ?)",
    )
    .bind(folder_id.to_string())
    .bind(auth.user_id.0)
    .fetch_one(&mut *tx)
    .await?;
    if shared {
        return Err(ApiError::Conflict(
            "someone else can open this folder, and can give it back to you".into(),
        ));
    }
    if request.generation != generation(&mut tx, folder_id).await? {
        return Err(ApiError::Conflict(
            "the folder's key changed; sync and try again".into(),
        ));
    }
    sqlx::query(
        "INSERT INTO folder_escrow (user_id, folder_id, generation, sealed) VALUES (?, ?, ?, ?)
         ON CONFLICT (user_id, folder_id)
         DO UPDATE SET generation = excluded.generation, sealed = excluded.sealed",
    )
    .bind(auth.user_id.0)
    .bind(folder_id.to_string())
    .bind(request.generation)
    .bind(serde_json::to_string(&request.sealed)?)
    .execute(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(StatusCode::NO_CONTENT)
}

/// After someone recovered with new keys: every copy wrapped for their old keys waits
/// until someone makes them one for the new keys, and what the old keys opened gets new
/// keys too, in case they turn up on the lost device. Logins they own stay theirs, for
/// their personal key, if it was in escrow. Until then they can't open any of it; nothing
/// goes on passwords to change, as it's the same person.
pub(crate) async fn recovered(conn: &mut SqliteConnection, user: UserId) -> Result<(), ApiError> {
    sqlx::query(
        "UPDATE folders SET needs_rekey = 1 WHERE id IN (SELECT folder_id FROM access WHERE user_id = ?)",
    )
    .bind(user.0)
    .execute(&mut *conn)
    .await?;
    sqlx::query(
        "UPDATE team_groups SET needs_rekey = 1
         WHERE id IN (SELECT group_id FROM group_members WHERE user_id = ?)",
    )
    .bind(user.0)
    .execute(&mut *conn)
    .await?;
    for table in ["members", "group_members"] {
        sqlx::query(AssertSqlSafe(format!(
            "UPDATE {table} SET pending = 1 WHERE user_id = ?"
        )))
        .bind(user.0)
        .execute(&mut *conn)
        .await?;
    }
    sqlx::query(
        "UPDATE item_access SET pending = 1
         WHERE user_id = ?1
           AND item_id NOT IN (SELECT id FROM items WHERE json_extract(body, '$.owner') = ?1)",
    )
    .bind(user.0)
    .execute(&mut *conn)
    .await?;
    reconcile_with(conn, user, false).await
}

#[derive(Deserialize)]
pub(crate) struct DeleteFolderParams {
    /// How many logins in it the caller agreed to delete with it.
    #[serde(default)]
    logins: i64,
}

/// `DELETE /v1/folders/{folder_id}?logins=N`: a manager deletes a folder for everyone,
/// with the logins in it and their history, for good. `logins` is how many the caller
/// agreed to delete; if the folder has another number now, nothing happens. Everyone who
/// could open the folder or a login in it loses it as if removed, but nothing goes on
/// passwords to change: the logins are gone, and what was there for them goes too.
/// Folders inside it by name are folders of their own and stay.
pub(crate) async fn delete_folder(
    State(state): State<AppState>,
    auth: Auth,
    Path(folder_id): Path<FolderId>,
    Query(params): Query<DeleteFolderParams>,
) -> Result<StatusCode, ApiError> {
    let mut tx = state.writer.begin().await?;
    require(
        folder_role(&mut tx, auth.user_id, folder_id).await?,
        Role::Manage,
        "delete this folder",
    )?;
    let folder = folder_id.to_string();
    let live: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM items
         WHERE folder_id = ? AND NOT COALESCE(json_extract(body, '$.deleted'), 0)",
    )
    .bind(&folder)
    .fetch_one(&mut *tx)
    .await?;
    if live != params.logins {
        return Err(ApiError::Conflict(format!(
            "the folder has {live} logins now, not {}; sync and try again",
            params.logins
        )));
    }
    // Everyone who can open the folder, or a login in it without the folder.
    let affected: Vec<i64> = sqlx::query_scalar(
        "SELECT user_id FROM access WHERE folder_id = ?1
         UNION
         SELECT r.user_id FROM item_reach r JOIN items i ON i.id = r.item_id
         WHERE i.folder_id = ?1",
    )
    .bind(&folder)
    .fetch_all(&mut *tx)
    .await?;
    for table in ["item_access", "item_groups", "item_history", "exposures"] {
        sqlx::query(AssertSqlSafe(format!(
            "DELETE FROM {table} WHERE item_id IN (SELECT id FROM items WHERE folder_id = ?)"
        )))
        .bind(&folder)
        .execute(&mut *tx)
        .await?;
    }
    for table in [
        "items",
        "members",
        "folder_groups",
        "folder_keys",
        "folder_entries",
    ] {
        sqlx::query(AssertSqlSafe(format!(
            "DELETE FROM {table} WHERE folder_id = ?"
        )))
        .bind(&folder)
        .execute(&mut *tx)
        .await?;
    }
    sqlx::query("DELETE FROM folders WHERE id = ?")
        .bind(&folder)
        .execute(&mut *tx)
        .await?;
    // Their feeds drop the folder first, then the logins they had without it.
    for user in affected {
        reconcile(&mut tx, UserId(user)).await?;
    }
    tx.commit().await?;
    Ok(StatusCode::NO_CONTENT)
}

/// `POST /v1/folders/{folder_id}/groups`: a manager shares the folder with a group, with
/// the folder's current key wrapped for the group's current key.
pub(crate) async fn add_folder_group(
    State(state): State<AppState>,
    auth: Auth,
    Path(folder_id): Path<FolderId>,
    Json(request): Json<AddFolderGroupRequest>,
) -> Result<StatusCode, ApiError> {
    let mut tx = state.writer.begin().await?;
    require(
        folder_role(&mut tx, auth.user_id, folder_id).await?,
        Role::Manage,
        "share this folder",
    )?;
    require_approved_to_share(&mut tx, auth.user_id).await?;
    let (group_generation, _) = group_key_state(&mut tx, request.group_id).await?;
    if request.group_generation != group_generation {
        return Err(ApiError::Conflict(
            "the group's key changed; sync and try again".into(),
        ));
    }
    if request.generation != generation(&mut tx, folder_id).await? {
        return Err(ApiError::Conflict(
            "the folder's key changed; sync and try again".into(),
        ));
    }
    if folder_group_role(&mut tx, folder_id, request.group_id)
        .await?
        .is_some()
    {
        return Err(ApiError::Conflict(
            "the folder is already shared with this group".into(),
        ));
    }
    sqlx::query(
        "INSERT INTO folder_groups (folder_id, group_id, role, group_generation, wrapped_key)
         VALUES (?, ?, ?, ?, ?)",
    )
    .bind(folder_id.to_string())
    .bind(request.group_id.to_string())
    .bind(request.role.name())
    .bind(request.group_generation)
    .bind(serde_json::to_string(&request.wrapped_key)?)
    .execute(&mut *tx)
    .await?;
    if let Some(mut change) = entry_needed(
        signed_membership(&mut tx, folder_id).await?,
        request.entry.as_ref(),
    )? {
        change.groups.insert(request.group_id);
        let entry = request.entry.as_ref().expect("checked by entry_needed");
        add_folder_entry(&mut tx, folder_id, auth.user_id, entry, &change).await?;
    }
    for member in group_member_ids(&mut tx, request.group_id).await? {
        reconcile(&mut tx, member).await?;
    }
    tx.commit().await?;
    Ok(StatusCode::NO_CONTENT)
}

/// `PUT /v1/folders/{folder_id}/entries` (managers): the first signed entry of a folder
/// that has none, one made before 0.15.0. It names exactly who the folder is shared with
/// now, for its current key; from then on every change to them comes with the next entry.
pub(crate) async fn put_first_folder_entry(
    State(state): State<AppState>,
    auth: Auth,
    Path(folder_id): Path<FolderId>,
    Json(request): Json<FolderEntryRequest>,
) -> Result<StatusCode, ApiError> {
    let mut tx = state.writer.begin().await?;
    require(
        folder_role(&mut tx, auth.user_id, folder_id).await?,
        Role::Manage,
        "sign for this folder's members",
    )?;
    let change = match signed_membership(&mut tx, folder_id).await? {
        // Signed for before 0.17.0: its first entry with roles names the same as the
        // last without.
        Some(signed) if !signed.roles && request.entry.roles.is_some() => signed,
        Some(_) => {
            return Err(ApiError::Conflict(
                "this folder's members are signed already; sync and try again".into(),
            ));
        }
        None => Membership {
            generation: generation(&mut tx, folder_id).await?,
            members: folder_members(&mut tx, folder_id)
                .await?
                .into_iter()
                .map(|member| member.user_id)
                .collect(),
            groups: folder_groups(&mut tx, folder_id)
                .await?
                .into_iter()
                .map(|share| share.group_id)
                .collect(),
            roles: false,
        },
    };
    add_folder_entry(&mut tx, folder_id, auth.user_id, &request.entry, &change).await?;
    tx.commit().await?;
    Ok(StatusCode::NO_CONTENT)
}

/// After a role changed in a folder: its next entry, which says so. A folder whose roles
/// are signed needs one; one whose members aren't signed yet can't have one.
pub(crate) async fn add_role_entry(
    conn: &mut SqliteConnection,
    folder_id: FolderId,
    signer: UserId,
    entry: Option<&FolderEntry>,
) -> Result<(), ApiError> {
    match (signed_membership(conn, folder_id).await?, entry) {
        (Some(signed), Some(entry)) => {
            add_folder_entry(conn, folder_id, signer, entry, &signed).await
        }
        (Some(signed), None) if signed.roles => Err(ApiError::Conflict(
            "this folder's roles are signed, and this change isn't; update Keystead".into(),
        )),
        (None, Some(_)) => Err(ApiError::Conflict(
            "nobody has signed for this folder's members yet; sync and try again".into(),
        )),
        (_, None) => Ok(()),
    }
}

/// Who a folder's next entry must name, and for which key.
struct Membership {
    generation: u32,
    members: HashSet<UserId>,
    groups: HashSet<GroupId>,
    /// Whether the latest entry has roles: then the next one must.
    roles: bool,
}

/// A folder's entries, oldest first; none for a folder from before 0.15.0 that nobody has
/// signed for yet.
pub(crate) async fn folder_entries(
    conn: &mut SqliteConnection,
    folder_id: FolderId,
) -> Result<Vec<FolderEntry>, ApiError> {
    let bodies: Vec<String> =
        sqlx::query_scalar("SELECT body FROM folder_entries WHERE folder_id = ? ORDER BY revision")
            .bind(folder_id.to_string())
            .fetch_all(conn)
            .await?;
    bodies
        .iter()
        .map(|body| Ok(serde_json::from_str(body)?))
        .collect()
}

/// Whether a folder's roles are signed: its latest entry has them.
pub(crate) async fn signed_roles(
    conn: &mut SqliteConnection,
    folder_id: FolderId,
) -> Result<bool, ApiError> {
    Ok(signed_membership(conn, folder_id)
        .await?
        .is_some_and(|signed| signed.roles))
}

/// What a folder's latest entry says, if it has entries.
async fn signed_membership(
    conn: &mut SqliteConnection,
    folder_id: FolderId,
) -> Result<Option<Membership>, ApiError> {
    Ok(folder_entries(conn, folder_id)
        .await?
        .pop()
        .map(|latest| Membership {
            generation: latest.generation,
            roles: latest.roles.is_some(),
            members: latest.members.into_iter().collect(),
            groups: latest.groups.into_iter().collect(),
        }))
}

/// Whether a change to who a folder is shared with needs its next entry: it does once
/// the folder has entries, and can't have one before (its first comes on its own, naming
/// everyone). Returns what the latest entry says, to build on.
fn entry_needed(
    signed: Option<Membership>,
    entry: Option<&FolderEntry>,
) -> Result<Option<Membership>, ApiError> {
    match (signed, entry) {
        (Some(signed), Some(_)) => Ok(Some(signed)),
        (None, None) => Ok(None),
        (Some(_), None) => Err(ApiError::Conflict(
            "this folder's members are signed, and this change isn't; update Keystead".into(),
        )),
        (None, Some(_)) => Err(ApiError::Conflict(
            "nobody has signed for this folder's members yet; sync and try again".into(),
        )),
    }
}

/// Checks a folder's next entry and stores it. It must be the caller's own, follow the
/// latest one, and say exactly `expected`. The server keeps who's in a folder either way;
/// it checks entries so that what clients verify matches what it stores.
async fn add_folder_entry(
    conn: &mut SqliteConnection,
    folder_id: FolderId,
    signer: UserId,
    entry: &FolderEntry,
    expected: &Membership,
) -> Result<(), ApiError> {
    let bad = |message: &str| Err(ApiError::BadRequest(message.into()));
    let entries = folder_entries(conn, folder_id).await?;
    let latest = entries.last();
    let revision = latest.map_or(1, |latest| latest.revision + 1);
    if entry.revision != revision {
        return Err(ApiError::Conflict(format!(
            "the folder's members are at revision {}; sync and try again",
            revision - 1
        )));
    }
    if entry.folder_id != folder_id || entry.signer != signer {
        return bad("you can only send entries you signed, for this folder");
    }
    let members: HashSet<UserId> = entry.members.iter().copied().collect();
    let groups: HashSet<GroupId> = entry.groups.iter().copied().collect();
    if entry.generation != expected.generation
        || members != expected.members
        || groups != expected.groups
    {
        return Err(ApiError::Conflict(
            "the folder's members or key changed; sync and try again".into(),
        ));
    }
    // Roles, once signed, come with every entry, and say what the server's lists say:
    // for whoever is still on them. Someone who left stays named until the folder's next
    // key, with the role they had.
    if expected.roles && entry.roles.is_none() {
        return Err(ApiError::Conflict(
            "this folder's roles are signed, and this change isn't; update Keystead".into(),
        ));
    }
    if entry.roles.is_some() {
        let before = |role: Option<Role>| role.or(Some(Role::before_roles()));
        let listed = folder_members(conn, folder_id).await?;
        let members = entry.members.iter().all(|&user| {
            let now = listed.iter().find(|member| member.user_id == user);
            let expected = match now {
                Some(member) => Some(member.role),
                None => before(latest.and_then(|latest| latest.member_role(user))),
            };
            entry.member_role(user) == expected
        });
        let listed = folder_groups(conn, folder_id).await?;
        let groups = entry.groups.iter().all(|&group| {
            let now = listed.iter().find(|share| share.group_id == group);
            let expected = match now {
                Some(share) => Some(share.role),
                None => before(latest.and_then(|latest| latest.group_role(group))),
            };
            entry.group_role(group) == expected
        });
        if !members || !groups {
            return Err(ApiError::Conflict(
                "the folder's roles changed; sync and try again".into(),
            ));
        }
    }
    // As clients check it: the caller's place in the folder or one of its groups, the
    // order of the change, and their signature. Earlier entries were checked as they came.
    let named = latest.map_or(&entry.groups, |latest| &latest.groups);
    let mut in_groups = HashSet::new();
    for &group in named {
        if group_member_ids(conn, group).await?.contains(&signer) {
            in_groups.insert(group);
        }
    }
    verify_folder_step(latest, entry, |group, user| {
        user == signer && in_groups.contains(&group)
    })
    .map_err(|error| ApiError::BadRequest(error.to_string()))?;
    let keys = user_entry(conn, signer)
        .await?
        .ok_or(ApiError::Unauthorized)?
        .keys;
    entry
        .verify(&keys)
        .map_err(|_| ApiError::BadRequest("folder entry signature does not verify".into()))?;
    sqlx::query("INSERT INTO folder_entries (folder_id, revision, body) VALUES (?, ?, ?)")
        .bind(folder_id.to_string())
        .bind(entry.revision)
        .bind(serde_json::to_string(entry)?)
        .execute(conn)
        .await?;
    Ok(())
}

/// `PUT /v1/folders/{folder_id}/groups/{group_id}`: a manager changes a group's role.
pub(crate) async fn set_folder_group_role(
    State(state): State<AppState>,
    auth: Auth,
    Path((folder_id, group_id)): Path<(FolderId, GroupId)>,
    Json(request): Json<RoleRequest>,
) -> Result<StatusCode, ApiError> {
    let mut tx = state.writer.begin().await?;
    require(
        folder_role(&mut tx, auth.user_id, folder_id).await?,
        Role::Manage,
        "change roles in this folder",
    )?;
    let current = folder_group_role(&mut tx, folder_id, group_id)
        .await?
        .ok_or(ApiError::NotFound)?;
    if current == Role::Manage && request.role != Role::Manage {
        require_another_manager(&mut tx, folder_id, None, Some(group_id)).await?;
    }
    sqlx::query("UPDATE folder_groups SET role = ? WHERE folder_id = ? AND group_id = ?")
        .bind(request.role.name())
        .bind(folder_id.to_string())
        .bind(group_id.to_string())
        .execute(&mut *tx)
        .await?;
    add_role_entry(&mut tx, folder_id, auth.user_id, request.entry.as_ref()).await?;
    tx.commit().await?;
    Ok(StatusCode::NO_CONTENT)
}

/// `DELETE /v1/folders/{folder_id}/groups/{group_id}`: a manager stops sharing the folder
/// with a group. Its members lose access at once, unless they have it another way, and the
/// folder then needs a new key.
pub(crate) async fn remove_folder_group(
    State(state): State<AppState>,
    auth: Auth,
    Path((folder_id, group_id)): Path<(FolderId, GroupId)>,
) -> Result<StatusCode, ApiError> {
    let mut tx = state.writer.begin().await?;
    require(
        folder_role(&mut tx, auth.user_id, folder_id).await?,
        Role::Manage,
        "remove groups from this folder",
    )?;
    let current = folder_group_role(&mut tx, folder_id, group_id)
        .await?
        .ok_or(ApiError::NotFound)?;
    if current == Role::Manage {
        require_another_manager(&mut tx, folder_id, None, Some(group_id)).await?;
    }
    sqlx::query("DELETE FROM folder_groups WHERE folder_id = ? AND group_id = ?")
        .bind(folder_id.to_string())
        .bind(group_id.to_string())
        .execute(&mut *tx)
        .await?;
    for member in group_member_ids(&mut tx, group_id).await? {
        reconcile(&mut tx, member).await?;
        resend_keys(&mut tx, member, &[folder_id.to_string()]).await?;
    }
    tx.commit().await?;
    Ok(StatusCode::NO_CONTENT)
}

// MARK: - Items

/// `PUT /v1/items/{item_id}`: saves a new version if it builds on the latest one. Editors
/// can change an item; managers can also share it with more people or groups, or take a
/// copy away.
pub(crate) async fn put_item(
    State(state): State<AppState>,
    auth: Auth,
    Path(item_id): Path<ItemId>,
    Json(request): Json<PutItemRequest>,
) -> Result<Json<EncryptedItem>, ApiError> {
    if request.item.id != item_id {
        return Err(ApiError::BadRequest(
            "item id doesn't match the path".into(),
        ));
    }
    let mut tx = state.writer.begin().await?;
    let item = save_item(&mut tx, auth.user_id, request).await?;
    tx.commit().await?;
    Ok(Json(item))
}

/// The most versions `POST /v1/items` saves in one go.
const MAX_BATCH: usize = 500;

/// `POST /v1/items` (0.19.0 and later): saves several versions in one transaction, each as
/// `PUT /v1/items/{item_id}` would, and all of them or none: the first that can't be saved
/// stops the lot. For imports, which otherwise take a request and a write per login.
pub(crate) async fn put_items(
    State(state): State<AppState>,
    auth: Auth,
    Json(request): Json<PutItemsRequest>,
) -> Result<Json<SavedItems>, ApiError> {
    if request.items.len() > MAX_BATCH {
        return Err(ApiError::BadRequest(format!(
            "save at most {MAX_BATCH} logins at once"
        )));
    }
    let mut tx = state.writer.begin().await?;
    let mut items = Vec::with_capacity(request.items.len());
    for request in request.items {
        items.push(save_item(&mut tx, auth.user_id, request).await?);
    }
    tx.commit().await?;
    Ok(Json(SavedItems { items }))
}

/// Saves one version for `caller`, within a transaction the caller commits: everything
/// `PUT /v1/items/{item_id}` checks and does.
async fn save_item(
    tx: &mut SqliteConnection,
    caller: UserId,
    request: PutItemRequest,
) -> Result<EncryptedItem, ApiError> {
    let item = request.item;
    let item_id = item.id;
    if item.author != caller {
        return Err(ApiError::Forbidden(
            "you can only save versions you authored".into(),
        ));
    }
    check_shape(&item)?;
    require_approved_to_save(&mut *tx, caller).await?;

    // A courtesy check: clients verify signatures themselves, but rejecting bad ones here
    // keeps garbage out of everyone's feed.
    let author = user_entry(&mut *tx, caller)
        .await?
        .ok_or(ApiError::Unauthorized)?;
    item.verify(&author.keys)
        .map_err(|_| ApiError::BadRequest("item signature does not verify".into()))?;

    let current: Option<String> = sqlx::query_scalar("SELECT body FROM items WHERE id = ?")
        .bind(item_id.to_string())
        .fetch_optional(&mut *tx)
        .await?;
    let current: Option<EncryptedItem> = current
        .map(|body| serde_json::from_str(&body))
        .transpose()?;
    let (role, expected_version) = match (request.base_version, &current) {
        (None, None) => {
            let role = match item.folder_id {
                Some(folder_id) => folder_role(&mut *tx, caller, folder_id).await?,
                None if item.owner == Some(caller) => Some(Role::Manage),
                None => {
                    return Err(ApiError::Forbidden(
                        "an item outside folders starts out as its author's own".into(),
                    ));
                }
            };
            (require(role, Role::Edit, "add logins here")?, 1)
        }
        // The id is taken. Only someone who can open that login gets it back: anyone
        // else, such as a person who lost access and kept its id, learns nothing more.
        (None, Some(current)) => {
            return Err(if item_role(&mut *tx, caller, current).await?.is_some() {
                ApiError::ItemConflict(Box::new(current.clone()))
            } else {
                ApiError::Conflict("a login with that id already exists".into())
            });
        }
        (Some(_), None) => return Err(ApiError::NotFound),
        (Some(base), Some(current)) => {
            let role = require(
                item_role(&mut *tx, caller, current).await?,
                Role::Edit,
                "change this login",
            )?;
            // Moving: from where the mover can change it, to a folder where they can add
            // logins, or out of folders as their own. A login in no folder stays its
            // owner's to move.
            if current.folder_id != item.folder_id || current.owner != item.owner {
                if current.owner.is_some_and(|owner| owner != caller) {
                    return Err(ApiError::Forbidden(
                        "only its owner can move a login that's in no folder".into(),
                    ));
                }
                match (item.folder_id, item.owner) {
                    (Some(folder_id), _) => {
                        require(
                            folder_role(&mut *tx, caller, folder_id).await?,
                            Role::Edit,
                            "move logins into that folder",
                        )?;
                    }
                    (None, Some(owner)) if owner == caller => {}
                    _ => {
                        return Err(ApiError::BadRequest(
                            "a login moved out of folders becomes the mover's own".into(),
                        ));
                    }
                }
            }
            // Format 3 goes back to 2 when its last group is removed, but nothing goes
            // back to format 1.
            if item.format < current.format.min(2) {
                return Err(ApiError::BadRequest(
                    "an item can't go back to an older format".into(),
                ));
            }
            // A live version on top of a deletion brings the item back (`deleted`).
            if current.version != base || (current.deleted && item.deleted) {
                return Err(ApiError::ItemConflict(Box::new(current.clone())));
            }
            (role, base + 1)
        }
    };
    // A new login starts at 1; a version after another may skip ahead.
    let skip = if request.base_version.is_some() {
        MAX_VERSION_SKIP
    } else {
        0
    };
    if item.version < expected_version || item.version > expected_version + skip {
        return Err(ApiError::BadRequest(format!(
            "expected version {expected_version}"
        )));
    }

    // Who gains or loses a key copy. Only managers change that, except that anyone who
    // can save may drop people the owner removed from the team.
    let before: HashSet<UserId> = current
        .iter()
        .flat_map(|current| current.keys.people.iter().map(|person| person.user_id))
        .collect();
    let after: HashSet<UserId> = item.keys.people.iter().map(|p| p.user_id).collect();
    let added: Vec<UserId> = after.difference(&before).copied().collect();
    let mut dropped_active = false;
    // Someone it was shared with who becomes its owner, by moving it, isn't dropped.
    let dropped: Vec<UserId> = before
        .difference(&after)
        .copied()
        .filter(|&user| Some(user) != item.owner)
        .collect();
    for &user in &dropped {
        let removed = user_entry(&mut *tx, user)
            .await?
            .is_none_or(|entry| entry.removed);
        dropped_active |= !removed;
    }
    let groups_before: HashSet<GroupId> = current
        .iter()
        .flat_map(|current| current.keys.groups.iter().map(|copy| copy.group_id))
        .collect();
    let groups_after: HashSet<GroupId> = item.keys.groups.iter().map(|c| c.group_id).collect();
    // Dropping the copy of a group that was deleted is anyone's to do, like dropping
    // people removed from the team; other changes to groups take a manager.
    let mut groups_changed = groups_after.difference(&groups_before).next().is_some();
    for group in groups_before.difference(&groups_after) {
        let exists: bool =
            sqlx::query_scalar("SELECT EXISTS (SELECT 1 FROM team_groups WHERE id = ?)")
                .bind(group.to_string())
                .fetch_one(&mut *tx)
                .await?;
        groups_changed |= exists;
    }
    if (!added.is_empty() || dropped_active || groups_changed) && role != Role::Manage {
        return Err(ApiError::Forbidden(
            "you need manage access to change who this login is shared with".into(),
        ));
    }
    if !added.is_empty() || groups_after.difference(&groups_before).next().is_some() {
        require_approved_to_share(&mut *tx, caller).await?;
    }
    for &user in &added {
        require_shareable(&mut *tx, user).await?;
    }
    // Copies for a group are for one of its generations: the current one when the group
    // is new to the item, and never one that doesn't exist yet.
    for copy in &item.keys.groups {
        let (generation, _) = group_key_state(&mut *tx, copy.group_id)
            .await
            .map_err(|_| ApiError::BadRequest(format!("no group {}", copy.group_id)))?;
        let new = !groups_before.contains(&copy.group_id);
        if copy.generation > generation || (new && copy.generation != generation) {
            return Err(ApiError::Conflict(
                "a group's key changed; sync and try again".into(),
            ));
        }
    }

    // The version being replaced joins the item's history, which keeps the last
    // `HISTORY_KEPT`. A deleted item's history stays `DELETED_KEPT_DAYS`, so it can be
    // brought back; `AppState::tidy` forgets it after that.
    if let Some(current) = current.as_ref().filter(|current| !current.deleted) {
        sqlx::query(
            "INSERT INTO item_history (item_id, version, saved_at, body)
             SELECT id, version, saved_at, body FROM items WHERE id = ?",
        )
        .bind(item_id.to_string())
        .execute(&mut *tx)
        .await?;
        sqlx::query("DELETE FROM item_history WHERE item_id = ? AND version <= ?")
            .bind(item_id.to_string())
            .bind(current.version as i64 - HISTORY_KEPT)
            .execute(&mut *tx)
            .await?;
    }

    let seq = next_seq(&mut *tx).await?;
    sqlx::query(
        "INSERT INTO items (id, folder_id, version, seq, body, saved_at, password_saved_at)
         VALUES (?1, ?2, ?3, ?4, ?5, CAST(strftime('%s', 'now') AS INTEGER),
                 CAST(strftime('%s', 'now') AS INTEGER))
         ON CONFLICT (id) DO UPDATE SET folder_id = excluded.folder_id, version = excluded.version,
                                        seq = excluded.seq, body = excluded.body, saved_at = excluded.saved_at,
                                        password_saved_at = CASE WHEN ?6 THEN excluded.saved_at
                                                                 ELSE items.password_saved_at END",
    )
    .bind(item_id.to_string())
    .bind(item.folder_id.map(|folder_id| folder_id.to_string()))
    .bind(item.version as i64)
    .bind(seq)
    .bind(serde_json::to_string(&item)?)
    .bind(request.password_changed)
    .execute(&mut *tx)
    .await?;

    // Direct access, with roles: kept for people who had it, as asked for newcomers.
    let roles: Vec<(i64, String)> =
        sqlx::query_as("SELECT user_id, role FROM item_access WHERE item_id = ?")
            .bind(item_id.to_string())
            .fetch_all(&mut *tx)
            .await?;
    let mut roles: HashMap<UserId, Role> = roles
        .into_iter()
        .map(|(user, role)| Ok((UserId(user), parse_role(&role)?)))
        .collect::<Result<_, ApiError>>()?;
    for member in &request.roles {
        if added.contains(&member.user_id) {
            roles.insert(member.user_id, member.role);
        }
    }
    sqlx::query("DELETE FROM item_access WHERE item_id = ?")
        .bind(item_id.to_string())
        .execute(&mut *tx)
        .await?;
    let direct = item
        .owner
        .map(|owner| (owner, Role::Manage))
        .into_iter()
        .chain(item.keys.people.iter().map(|person| {
            let role = roles
                .get(&person.user_id)
                .copied()
                .unwrap_or_else(Role::before_roles);
            (person.user_id, role)
        }));
    for (user, role) in direct {
        sqlx::query("INSERT INTO item_access (user_id, item_id, role) VALUES (?, ?, ?)")
            .bind(user.0)
            .bind(item_id.to_string())
            .bind(role.name())
            .execute(&mut *tx)
            .await?;
    }

    // Groups the same way; a group shared with before roles existed can't happen.
    let group_roles: Vec<(String, String)> =
        sqlx::query_as("SELECT group_id, role FROM item_groups WHERE item_id = ?")
            .bind(item_id.to_string())
            .fetch_all(&mut *tx)
            .await?;
    let mut group_roles: HashMap<GroupId, Role> = group_roles
        .into_iter()
        .map(|(group, role)| Ok((parse_group(&group)?, parse_role(&role)?)))
        .collect::<Result<_, ApiError>>()?;
    for share in &request.group_roles {
        if !groups_before.contains(&share.group_id) {
            group_roles.insert(share.group_id, share.role);
        }
    }
    sqlx::query("DELETE FROM item_groups WHERE item_id = ?")
        .bind(item_id.to_string())
        .execute(&mut *tx)
        .await?;
    for group in &groups_after {
        let role = group_roles.get(group).copied().unwrap_or(Role::View);
        sqlx::query("INSERT INTO item_groups (item_id, group_id, role) VALUES (?, ?, ?)")
            .bind(item_id.to_string())
            .bind(group.to_string())
            .bind(role.name())
            .execute(&mut *tx)
            .await?;
    }

    // Nobody who lost access earlier knows a new password. (A deleted item keeps its
    // exposures, for if it's brought back; the listing leaves it out meanwhile.)
    if request.password_changed {
        sqlx::query("DELETE FROM exposures WHERE item_id = ?")
            .bind(item_id.to_string())
            .execute(&mut *tx)
            .await?;
    }

    // Who reaches this item directly may have changed, and nothing else: a save changes no
    // folder's members, no group, and no other item.
    reconcile_item(&mut *tx, &item_id.to_string()).await?;
    // Moved out of a folder: its members who can't reach it now lose it, as if removed,
    // and their devices are told it moved.
    if let Some(old_folder) = current
        .as_ref()
        .and_then(|current| current.folder_id)
        .filter(|&folder_id| Some(folder_id) != item.folder_id)
    {
        let members: Vec<i64> =
            sqlx::query_scalar("SELECT user_id FROM access WHERE folder_id = ?")
                .bind(old_folder.to_string())
                .fetch_all(&mut *tx)
                .await?;
        for member in members {
            let reaches: bool = sqlx::query_scalar(
                "SELECT EXISTS (SELECT 1 FROM access WHERE user_id = ?1 AND folder_id = ?2)
                     OR EXISTS (SELECT 1 FROM item_reach WHERE user_id = ?1 AND item_id = ?3)",
            )
            .bind(member)
            .bind(item.folder_id.map(|folder_id| folder_id.to_string()))
            .bind(item_id.to_string())
            .fetch_one(&mut *tx)
            .await?;
            if reaches {
                continue;
            }
            let seq = next_seq(&mut *tx).await?;
            sqlx::query(
                "INSERT INTO item_leave_log (seq, user_id, item_id, moved) VALUES (?, ?, ?, 1)",
            )
            .bind(seq)
            .bind(member)
            .bind(item_id.to_string())
            .execute(&mut *tx)
            .await?;
            sqlx::query(AssertSqlSafe(format!(
                "{EXPOSE} VALUES (?1, ?2, CAST(strftime('%s', 'now') AS INTEGER)) {EXPOSE_AGAIN}"
            )))
            .bind(item_id.to_string())
            .bind(member)
            .execute(&mut *tx)
            .await?;
        }
    }
    Ok(item)
}

/// `GET /v1/items/{item_id}/people`: who has the item directly (its owner, and everyone
/// and every group it's shared with) and their roles, for anyone who can open it.
/// How many earlier versions of each item the server keeps.
const HISTORY_KEPT: i64 = 10;
/// How long a deleted item can be brought back.
const DELETED_KEPT_DAYS: i64 = 30;

/// Forgets the history (and passwords to change) of items deleted more than
/// `DELETED_KEPT_DAYS` ago; their deletion markers stay, for everyone's devices. Run by
/// `AppState::tidy` every hour, so saves don't wait on it; the index `items_deleted`
/// makes it look only at deleted items.
pub(crate) async fn purge_deleted(conn: &mut SqliteConnection) -> Result<(), sqlx::Error> {
    let expired = format!(
        "SELECT id FROM items WHERE COALESCE(json_extract(body, '$.deleted'), 0)
         AND saved_at < CAST(strftime('%s', 'now') AS INTEGER) - {}",
        DELETED_KEPT_DAYS * 86_400
    );
    for table in ["item_history", "exposures"] {
        sqlx::query(AssertSqlSafe(format!(
            "DELETE FROM {table} WHERE item_id IN ({expired})"
        )))
        .execute(&mut *conn)
        .await?;
    }
    Ok(())
}

/// `GET /v1/deleted`: items deleted in the last `DELETED_KEPT_DAYS` that the caller can
/// change, each with its deletion marker and its last version before it, newest first.
/// Read only, from a reader: older ones, whose history waits for the next
/// `AppState::tidy`, are left out here.
pub(crate) async fn deleted_items(
    State(state): State<AppState>,
    auth: Auth,
) -> Result<Json<DeletedItems>, ApiError> {
    let mut conn = state.readers.acquire().await?;
    let rows: Vec<(i64, String, String)> = sqlx::query_as(AssertSqlSafe(format!(
        "SELECT i.saved_at, i.body, h.body FROM items i
         JOIN item_history h ON h.item_id = i.id
         WHERE COALESCE(json_extract(i.body, '$.deleted'), 0)
           AND i.saved_at >= CAST(strftime('%s', 'now') AS INTEGER) - {}
           AND h.version = (SELECT MAX(version) FROM item_history WHERE item_id = i.id)
         ORDER BY i.saved_at DESC",
        DELETED_KEPT_DAYS * 86_400
    )))
    .fetch_all(&mut *conn)
    .await?;
    let mut items = Vec::new();
    for (deleted_at, deleted, last) in rows {
        let deleted: EncryptedItem = serde_json::from_str(&deleted)?;
        if item_role(&mut conn, auth.user_id, &deleted).await? >= Some(Role::Edit) {
            items.push(DeletedItem {
                deleted_at,
                deleted,
                last: serde_json::from_str(&last)?,
            });
        }
    }
    Ok(Json(DeletedItems { items }))
}

/// `DELETE /v1/deleted/{item_id}`: forgets a deleted item's history now, so it can't be
/// brought back (editors and managers).
pub(crate) async fn purge_item(
    State(state): State<AppState>,
    auth: Auth,
    Path(item_id): Path<ItemId>,
) -> Result<StatusCode, ApiError> {
    let mut tx = state.writer.begin().await?;
    let item = stored_item(&mut tx, item_id).await?;
    if !item.deleted {
        return Err(ApiError::BadRequest(
            "only a deleted login can be deleted for good".into(),
        ));
    }
    require(
        item_role(&mut tx, auth.user_id, &item).await?,
        Role::Edit,
        "delete this for good",
    )?;
    for table in ["item_history", "exposures"] {
        sqlx::query(AssertSqlSafe(format!(
            "DELETE FROM {table} WHERE item_id = ?"
        )))
        .bind(item_id.to_string())
        .execute(&mut *tx)
        .await?;
    }
    tx.commit().await?;
    Ok(StatusCode::NO_CONTENT)
}

/// `GET /v1/items/{item_id}/history`: the item's current version and the earlier ones the
/// server keeps, newest first, for anyone who can change it (edit or manage). Viewers can
/// open only the current version.
pub(crate) async fn item_history(
    State(state): State<AppState>,
    auth: Auth,
    Path(item_id): Path<ItemId>,
) -> Result<Json<ItemHistory>, ApiError> {
    let mut conn = state.readers.acquire().await?;
    let item = stored_item(&mut conn, item_id).await?;
    if item.deleted {
        return Err(ApiError::NotFound);
    }
    require(
        item_role(&mut conn, auth.user_id, &item).await?,
        Role::Edit,
        "see this login's history",
    )?;
    let rows: Vec<(Option<i64>, String)> = sqlx::query_as(
        "SELECT saved_at, body FROM items WHERE id = ?1
         UNION ALL
         SELECT saved_at, body FROM item_history WHERE item_id = ?1",
    )
    .bind(item_id.to_string())
    .fetch_all(&mut *conn)
    .await?;
    let mut versions = rows
        .into_iter()
        .map(|(saved_at, body)| {
            Ok(SavedVersion {
                saved_at,
                item: serde_json::from_str(&body)?,
            })
        })
        .collect::<Result<Vec<_>, ApiError>>()?;
    versions.sort_by_key(|saved| std::cmp::Reverse(saved.item.version));
    Ok(Json(ItemHistory { versions }))
}

pub(crate) async fn item_people(
    State(state): State<AppState>,
    auth: Auth,
    Path(item_id): Path<ItemId>,
) -> Result<Json<Members>, ApiError> {
    let mut conn = state.readers.acquire().await?;
    let item = stored_item(&mut conn, item_id).await?;
    require(
        item_role(&mut conn, auth.user_id, &item).await?,
        Role::View,
        "see this login",
    )?;
    let rows: Vec<(i64, String)> =
        sqlx::query_as("SELECT user_id, role FROM item_access WHERE item_id = ? ORDER BY user_id")
            .bind(item_id.to_string())
            .fetch_all(&mut *conn)
            .await?;
    let members = rows
        .into_iter()
        .map(|(user, role)| {
            Ok(Member {
                user_id: UserId(user),
                role: parse_role(&role)?,
            })
        })
        .collect::<Result<_, ApiError>>()?;
    let rows: Vec<(String, String)> = sqlx::query_as(
        "SELECT group_id, role FROM item_groups WHERE item_id = ? ORDER BY group_id",
    )
    .bind(item_id.to_string())
    .fetch_all(&mut *conn)
    .await?;
    let groups = rows
        .into_iter()
        .map(|(group, role)| {
            Ok(GroupShare {
                group_id: parse_group(&group)?,
                role: parse_role(&role)?,
            })
        })
        .collect::<Result<_, ApiError>>()?;
    Ok(Json(Members {
        members,
        groups,
        entries: Vec::new(),
    }))
}

/// `PUT /v1/items/{item_id}/people/{user_id}`: a manager changes the role of someone the
/// item is shared with directly. Its owner always manages it.
pub(crate) async fn set_item_role(
    State(state): State<AppState>,
    auth: Auth,
    Path((item_id, user_id)): Path<(ItemId, i64)>,
    Json(request): Json<RoleRequest>,
) -> Result<StatusCode, ApiError> {
    let user = UserId(user_id);
    let mut tx = state.writer.begin().await?;
    let item = stored_item(&mut tx, item_id).await?;
    require(
        item_role(&mut tx, auth.user_id, &item).await?,
        Role::Manage,
        "change roles on this login",
    )?;
    if item.owner == Some(user) {
        return Err(ApiError::BadRequest(
            "a login's owner always manages it".into(),
        ));
    }
    let updated = sqlx::query("UPDATE item_access SET role = ? WHERE user_id = ? AND item_id = ?")
        .bind(request.role.name())
        .bind(user.0)
        .bind(item_id.to_string())
        .execute(&mut *tx)
        .await?
        .rows_affected();
    if updated == 0 {
        return Err(ApiError::NotFound);
    }
    tx.commit().await?;
    Ok(StatusCode::NO_CONTENT)
}

/// `PUT /v1/items/{item_id}/groups/{group_id}`: a manager changes the role of a group the
/// item is shared with.
pub(crate) async fn set_item_group_role(
    State(state): State<AppState>,
    auth: Auth,
    Path((item_id, group_id)): Path<(ItemId, GroupId)>,
    Json(request): Json<RoleRequest>,
) -> Result<StatusCode, ApiError> {
    let mut tx = state.writer.begin().await?;
    let item = stored_item(&mut tx, item_id).await?;
    require(
        item_role(&mut tx, auth.user_id, &item).await?,
        Role::Manage,
        "change roles on this login",
    )?;
    let updated = sqlx::query("UPDATE item_groups SET role = ? WHERE item_id = ? AND group_id = ?")
        .bind(request.role.name())
        .bind(item_id.to_string())
        .bind(group_id.to_string())
        .execute(&mut *tx)
        .await?
        .rows_affected();
    if updated == 0 {
        return Err(ApiError::NotFound);
    }
    tx.commit().await?;
    Ok(StatusCode::NO_CONTENT)
}

/// Checks what the server can see of an item: its format, that it has a folder or an
/// owner and the matching key copy, and that nobody and no group is listed twice.
fn check_shape(item: &EncryptedItem) -> Result<(), ApiError> {
    if item.format == 0 || item.format > ITEM_FORMAT {
        return Err(ApiError::BadRequest(format!(
            "this server stores item formats up to {ITEM_FORMAT}, not {}",
            item.format
        )));
    }
    item.check_shape()
        .map_err(|reason| ApiError::BadRequest(reason.into()))
}

// MARK: - Sync

#[derive(Deserialize)]
pub(crate) struct SyncParams {
    #[serde(default)]
    cursor: i64,
    limit: Option<i64>,
    /// The client takes a folder too big for a page in parts (0.17.0 and later).
    #[serde(default)]
    parts: bool,
    /// Where the last part ended, from that page's `resume`.
    resume: Option<String>,
    /// The `roles_tag` of the caller's roles as the client has them (0.19.0 and later):
    /// the last page leaves the roles out if they're still the same.
    roles_tag: Option<String>,
}

/// `GET /v1/sync`: feed entries after the cursor, all read from one snapshot.
pub(crate) async fn sync(
    State(state): State<AppState>,
    auth: Auth,
    Query(params): Query<SyncParams>,
) -> Result<Json<SyncPage>, ApiError> {
    let limit = params.limit.unwrap_or(DEFAULT_PAGE).clamp(1, MAX_PAGE);
    let cursor = params.cursor.max(0);
    let user = auth.user_id.0;

    let mut tx = state.readers.begin().await?;
    let rows: Vec<FeedRow> = sqlx::query_as(FEED_QUERY)
        .bind(user)
        .bind(cursor)
        .bind(limit + 1)
        .fetch_all(&mut *tx)
        .await?;
    let high_water: i64 = sqlx::query_scalar("SELECT last_seq FROM feed_counter WHERE id = 1")
        .fetch_one(&mut *tx)
        .await?;

    let mut more = rows.len() as i64 > limit;
    let mut rows: Vec<FeedRow> = rows.into_iter().take(limit as usize).collect();

    // The page ends before the entry that would take it over `PAGE_BYTES`. A join counts
    // as the folder's items, which come with it.
    let mut bytes = 0;
    let mut fits = 0;
    let mut in_parts = None;
    for (seq, kind, body, target, was_join) in &rows {
        let size = match (kind.as_str(), body, target) {
            ("item", Some(body), _) => body.len(),
            ("membership", _, Some(folder_id)) if *was_join == Some(true) => {
                let size = joined_bytes(&mut tx, auth.user_id, folder_id, *seq).await?;
                if fits == 0 && size > PAGE_BYTES {
                    in_parts = Some((*seq, parse_folder(folder_id)?));
                    break;
                }
                size
            }
            _ => 0,
        };
        if fits > 0 && bytes + size > PAGE_BYTES {
            break;
        }
        bytes += size;
        fits += 1;
    }
    if let Some((seq, folder_id)) = in_parts {
        // Too big for a page: it comes first on one, alone.
        let resume = params.resume.as_deref().filter(|_| params.parts);
        let part = (auth.user_id, folder_id, seq, cursor, resume);
        let (entries, next_cursor, resume) = folder_part(&mut tx, part, params.parts).await?;
        let page = SyncPage {
            entries,
            cursor: next_cursor,
            more: true,
            resume,
            ..page_without_entries(&mut tx, auth.user_id, true, None).await?
        };
        tx.commit().await?;
        return Ok(Json(page));
    }
    more |= fits < rows.len();
    rows.truncate(fits);
    // Caught up: the newest change number, also when the cursor asked with is past it.
    // That happens only if the server went back, as when restored from a backup; the
    // client then follows the lower number and gets what changes from there.
    let next_cursor = match (more, rows.last()) {
        (true, Some(last)) => last.0,
        _ => high_water,
    };

    // Current access that began inside this page, with what its join entries carry.
    let joins: Vec<(String, i64)> = sqlx::query_as(
        "SELECT folder_id, joined_seq FROM access
         WHERE user_id = ? AND joined_seq > ? AND joined_seq <= ?",
    )
    .bind(user)
    .bind(cursor)
    .bind(next_cursor)
    .fetch_all(&mut *tx)
    .await?;
    let mut joined = HashMap::new();
    for (folder_id, joined_seq) in joins {
        let folder_id = parse_folder(&folder_id)?;
        let Some(key) = current_key(&mut tx, auth.user_id, folder_id).await? else {
            continue;
        };
        let items: Vec<String> =
            sqlx::query_scalar("SELECT body FROM items WHERE folder_id = ? AND seq <= ?")
                .bind(folder_id.to_string())
                .bind(next_cursor)
                .fetch_all(&mut *tx)
                .await?;
        let items = items
            .iter()
            .map(|body| serde_json::from_str(body))
            .collect::<Result<Vec<EncryptedItem>, _>>()?;
        joined.insert(
            joined_seq,
            SyncEntry::Joined {
                seq: joined_seq,
                folder_id,
                info: key.info,
                wrapped_key: key.wrapped_key,
                generation: key.generation,
                chain: key.chain,
                via_group: key.via_group,
                items,
                entries: key.entries,
            },
        );
    }

    let mut entries = Vec::with_capacity(rows.len());
    for (seq, kind, body, target, was_join) in rows {
        match (kind.as_str(), body, target) {
            ("item", Some(body), _) => entries.push(SyncEntry::Item {
                seq,
                item: serde_json::from_str(&body)?,
            }),
            // A join that is no longer current is skipped: a later leave follows it.
            ("membership", _, Some(_)) if was_join == Some(true) => {
                entries.extend(joined.remove(&seq));
            }
            ("membership", _, Some(folder_id)) => entries.push(SyncEntry::Left {
                seq,
                folder_id: parse_folder(&folder_id)?,
            }),
            // Built from the folder as it is now: several new keys in a row arrive as the
            // latest, and none for a folder the user has since left.
            ("rekey", _, Some(folder_id)) => {
                let folder_id = parse_folder(&folder_id)?;
                if let Some(key) = current_key(&mut tx, auth.user_id, folder_id).await? {
                    entries.push(SyncEntry::Rekeyed {
                        seq,
                        folder_id,
                        info: key.info,
                        wrapped_key: key.wrapped_key,
                        generation: key.generation,
                        chain: key.chain,
                        via_group: key.via_group,
                        entries: key.entries,
                    });
                }
            }
            ("left_item" | "moved_item", _, Some(item_id)) => entries.push(SyncEntry::LeftItem {
                seq,
                item_id: parse_item(&item_id)?,
                moved: kind == "moved_item",
            }),
            // Reached through a group joined after the item's latest version, which the
            // item rows would never send again. Later versions arrive as item rows.
            ("joined_item", _, Some(item_id)) => {
                let row: Option<(String, i64)> = sqlx::query_as(
                    "SELECT i.body, i.seq FROM item_reach r JOIN items i ON i.id = r.item_id
                     WHERE r.user_id = ?1 AND r.item_id = ?2
                       AND NOT EXISTS (SELECT 1 FROM access a
                                       WHERE a.user_id = ?1 AND a.folder_id = i.folder_id)",
                )
                .bind(user)
                .bind(&item_id)
                .fetch_optional(&mut *tx)
                .await?;
                if let Some((body, item_seq)) = row
                    && item_seq <= cursor
                {
                    entries.push(SyncEntry::Item {
                        seq,
                        item: serde_json::from_str(&body)?,
                    });
                }
            }
            // Built from the group as it is now, like a new folder key.
            ("group", _, Some(group_id)) if was_join == Some(true) => {
                let group_id = parse_group(&group_id)?;
                entries.extend(group_state(&mut tx, auth.user_id, group_id, seq).await?);
            }
            ("group", _, Some(group_id)) => entries.push(SyncEntry::LeftGroup {
                seq,
                group_id: parse_group(&group_id)?,
            }),
            _ => {}
        }
    }

    let page = SyncPage {
        entries,
        cursor: next_cursor,
        more,
        ..page_without_entries(&mut tx, auth.user_id, more, params.roles_tag.as_deref()).await?
    };
    tx.commit().await?;
    Ok(Json(page))
}

/// What a sync page carries besides its entries: what this user should do, and on the
/// last page their roles, unless `roles_tag` says the client has them.
async fn page_without_entries(
    conn: &mut SqliteConnection,
    user: UserId,
    more: bool,
    roles_tag: Option<&str>,
) -> Result<SyncPage, ApiError> {
    // Folders wait for the groups they're shared with to get their new keys first.
    let rekey_needed: Vec<String> = sqlx::query_scalar(
        "SELECT a.folder_id FROM access a JOIN folders f ON f.id = a.folder_id
         WHERE a.user_id = ? AND f.needs_rekey = 1
           AND NOT EXISTS (SELECT 1 FROM folder_groups fg JOIN team_groups g ON g.id = fg.group_id
                           WHERE fg.folder_id = f.id AND g.needs_rekey = 1)
         ORDER BY a.folder_id",
    )
    .bind(user.0)
    .fetch_all(&mut *conn)
    .await?;
    let mut folders = Vec::new();
    for folder_id in rekey_needed {
        let folder_id = parse_folder(&folder_id)?;
        if folder_role(&mut *conn, user, folder_id).await? == Some(Role::Manage) {
            folders.push(folder_id);
        }
    }
    let group_rekey_needed = crate::groups::rekey_needed(&mut *conn, user).await?;
    let restore = restore_needed(&mut *conn, user).await?;
    let (recovered_key, escrow_needed): (Option<String>, bool) = sqlx::query_as(
        "SELECT recovered_key, escrow_on AND (escrow IS NULL OR escrow_revision < revision)
         FROM users WHERE id = ?",
    )
    .bind(user.0)
    .fetch_one(&mut *conn)
    .await?;
    // Folders only this user can open, with no copy of their current key in escrow.
    let escrow_folders: Vec<String> = sqlx::query_scalar(
        "SELECT m.folder_id FROM members m
         JOIN users u ON u.id = m.user_id
         JOIN folders f ON f.id = m.folder_id
         WHERE m.user_id = ?1 AND NOT m.pending AND u.escrow_on
           AND NOT EXISTS (SELECT 1 FROM access a
                           WHERE a.folder_id = m.folder_id AND a.user_id != ?1)
           AND NOT EXISTS (SELECT 1 FROM folder_escrow e
                           WHERE e.user_id = ?1 AND e.folder_id = m.folder_id
                             AND e.generation = f.generation)
         ORDER BY m.folder_id",
    )
    .bind(user.0)
    .fetch_all(&mut *conn)
    .await?;
    // On the last page, the caller's roles and their tag; the roles only if the client
    // doesn't have them already.
    let (roles, roles_tag) = if more {
        (None, None)
    } else {
        let roles = user_roles(&mut *conn, user).await?;
        let tag = content_tag(&serde_json::to_vec(&roles)?);
        let had = roles_tag == Some(tag.as_str());
        ((!had).then_some(roles), Some(tag))
    };
    Ok(SyncPage {
        entries: Vec::new(),
        cursor: 0,
        more,
        resume: None,
        rekey_needed: folders,
        roles,
        roles_tag,
        group_rekey_needed,
        restore,
        recovered_key: recovered_key
            .as_deref()
            .map(serde_json::from_str)
            .transpose()?,
        escrow_needed,
        escrow_folders: escrow_folders
            .iter()
            .map(|folder_id| parse_folder(folder_id))
            .collect::<Result<_, _>>()?,
    })
}

/// The most bytes of items a join entry at `seq` would carry: all the folder's, if that
/// join is how `user` has the folder now, and nothing for a join since undone, which is
/// skipped.
async fn joined_bytes(
    conn: &mut SqliteConnection,
    user: UserId,
    folder_id: &str,
    seq: i64,
) -> Result<usize, ApiError> {
    let bytes: i64 = sqlx::query_scalar(
        "SELECT COALESCE(SUM(LENGTH(CAST(body AS BLOB))), 0) FROM items
         WHERE folder_id = ?2
           AND EXISTS (SELECT 1 FROM access
                       WHERE user_id = ?1 AND folder_id = ?2 AND joined_seq = ?3)",
    )
    .bind(user.0)
    .bind(folder_id)
    .bind(seq)
    .fetch_one(conn)
    .await?;
    Ok(bytes as usize)
}

/// A folder too big for a page, on a page of its own: the join with its items from
/// before the join, oldest change first. The cursor ends at the join, so what changed in
/// the folder since comes after it like any change, in pages.
///
/// A client that takes it in parts (`in_parts`) gets the join with the first of those
/// items, then more of them as item entries. Until the last part the cursor stays where
/// it was and `resume` says where this part ended, so a client that stops halfway starts
/// the folder again. Any other client gets them all at once, as apps before 0.17.0
/// expect; that answer is as big as the folder was when they joined.
async fn folder_part(
    conn: &mut SqliteConnection,
    (user, folder_id, join_seq, cursor, resume): (UserId, FolderId, i64, i64, Option<&str>),
    in_parts: bool,
) -> Result<(Vec<SyncEntry>, i64, Option<String>), ApiError> {
    // A `resume` from another join, or none, starts this one from its first item.
    let after = resume
        .and_then(|resume| resume.split_once('.'))
        .filter(|(join, _)| join.parse() == Ok(join_seq))
        .and_then(|(_, item_seq)| item_seq.parse::<i64>().ok())
        .filter(|item_seq| *item_seq > 0);
    let rows: Vec<(i64, String)> = sqlx::query_as(
        "SELECT seq, body FROM items WHERE folder_id = ? AND seq > ? AND seq <= ?
         ORDER BY seq LIMIT ?",
    )
    .bind(folder_id.to_string())
    .bind(after.unwrap_or(0))
    .bind(join_seq)
    .bind(if in_parts { MAX_PAGE + 1 } else { -1 })
    .fetch_all(&mut *conn)
    .await?;
    let most = if in_parts {
        MAX_PAGE as usize
    } else {
        rows.len()
    };
    let mut bytes = 0;
    let mut items = Vec::new();
    for (seq, body) in rows.iter().take(most) {
        if in_parts && !items.is_empty() && bytes + body.len() > PAGE_BYTES {
            break;
        }
        bytes += body.len();
        items.push((*seq, serde_json::from_str::<EncryptedItem>(body)?));
    }
    let position = match items.last() {
        Some((last, _)) if items.len() < rows.len() => Some(format!("{join_seq}.{last}")),
        _ => None,
    };
    let entries = match after {
        Some(_) => items
            .into_iter()
            .map(|(seq, item)| SyncEntry::Item { seq, item })
            .collect(),
        None => match current_key(conn, user, folder_id).await? {
            Some(key) => vec![SyncEntry::Joined {
                seq: join_seq,
                folder_id,
                info: key.info,
                wrapped_key: key.wrapped_key,
                generation: key.generation,
                chain: key.chain,
                via_group: key.via_group,
                items: items.into_iter().map(|(_, item)| item).collect(),
                entries: key.entries,
            }],
            // Its copy of the key is still to come, after a recovery: skipped, as on a
            // page of its own.
            None => return Ok((Vec::new(), join_seq, None)),
        },
    };
    match position {
        Some(position) => Ok((entries, cursor, Some(position))),
        None => Ok((entries, join_seq, None)),
    }
}

/// Copies people who recovered are waiting for, that `user` can make them: of the key of
/// a folder `user` can open, of the secret of a group `user` is in, and of logins `user`
/// can change, by saving them again. And after `user` recovered, the folders only they
/// could open, from the copies of their keys they put in escrow.
async fn restore_needed(conn: &mut SqliteConnection, user: UserId) -> Result<Restore, ApiError> {
    let folders: Vec<(String, i64)> = sqlx::query_as(
        "SELECT m.folder_id, m.user_id FROM members m
         JOIN access a ON a.folder_id = m.folder_id AND a.user_id = ?1
         WHERE m.pending ORDER BY m.folder_id, m.user_id",
    )
    .bind(user.0)
    .fetch_all(&mut *conn)
    .await?;
    let groups: Vec<(String, i64)> = sqlx::query_as(
        "SELECT p.group_id, p.user_id FROM group_members p
         JOIN group_members me ON me.group_id = p.group_id AND me.user_id = ?1 AND NOT me.pending
         WHERE p.pending ORDER BY p.group_id, p.user_id",
    )
    .bind(user.0)
    .fetch_all(&mut *conn)
    .await?;
    let waiting: Vec<String> = sqlx::query_scalar(
        "SELECT DISTINCT item_id FROM item_access WHERE pending AND user_id != ? ORDER BY item_id",
    )
    .bind(user.0)
    .fetch_all(&mut *conn)
    .await?;
    let mut items = Vec::new();
    for item_id in waiting {
        let item = stored_item(conn, parse_item(&item_id)?).await?;
        if !item.deleted && item_role(conn, user, &item).await? >= Some(Role::Edit) {
            items.push(item.id);
        }
    }
    let escrowed: Vec<(String, u32, String)> = sqlx::query_as(
        "SELECT e.folder_id, e.generation, e.sealed FROM folder_escrow e
         JOIN members m ON m.user_id = e.user_id AND m.folder_id = e.folder_id
         JOIN folders f ON f.id = e.folder_id
         WHERE e.user_id = ? AND m.pending AND e.generation = f.generation
         ORDER BY e.folder_id",
    )
    .bind(user.0)
    .fetch_all(&mut *conn)
    .await?;
    Ok(Restore {
        escrowed: escrowed
            .into_iter()
            .map(|(folder_id, generation, sealed)| {
                Ok(EscrowedFolder {
                    folder_id: parse_folder(&folder_id)?,
                    generation,
                    sealed: serde_json::from_str(&sealed)?,
                })
            })
            .collect::<Result<_, ApiError>>()?,
        folders: folders
            .into_iter()
            .map(|(folder_id, user_id)| {
                Ok(FolderMember {
                    folder_id: parse_folder(&folder_id)?,
                    user_id: UserId(user_id),
                })
            })
            .collect::<Result<_, ApiError>>()?,
        groups: groups
            .into_iter()
            .map(|(group_id, user_id)| {
                Ok(GroupMember {
                    group_id: parse_group(&group_id)?,
                    user_id: UserId(user_id),
                })
            })
            .collect::<Result<_, ApiError>>()?,
        items,
    })
}

// MARK: - Helpers

/// What `require` lets through, or why not.
fn require(role: Option<Role>, needed: Role, action: &str) -> Result<Role, ApiError> {
    match role {
        None => Err(ApiError::Forbidden("you don't have access to this".into())),
        Some(role) if role < needed => Err(ApiError::Forbidden(format!(
            "you need {} access to {action}",
            needed.name()
        ))),
        Some(role) => Ok(role),
    }
}

pub(crate) fn parse_role(name: &str) -> Result<Role, ApiError> {
    Role::from_name(name).ok_or_else(|| ApiError::Internal(format!("bad stored role {name}")))
}

/// The highest of some roles, as stored.
fn highest(roles: Vec<String>) -> Result<Option<Role>, ApiError> {
    roles
        .iter()
        .map(|role| parse_role(role))
        .try_fold(None, |best, role| Ok(best.max(Some(role?))))
}

/// `user`'s role in a folder, if they can open it: the highest of their own and those of
/// the groups they're in that it's shared with.
pub(crate) async fn folder_role(
    conn: &mut SqliteConnection,
    user: UserId,
    folder_id: FolderId,
) -> Result<Option<Role>, ApiError> {
    let roles: Vec<String> = sqlx::query_scalar(
        "SELECT role FROM members WHERE user_id = ?1 AND folder_id = ?2 AND NOT pending
         UNION ALL
         SELECT fg.role FROM folder_groups fg JOIN group_members gm ON gm.group_id = fg.group_id
         WHERE gm.user_id = ?1 AND fg.folder_id = ?2 AND NOT gm.pending",
    )
    .bind(user.0)
    .bind(folder_id.to_string())
    .fetch_all(conn)
    .await?;
    highest(roles)
}

/// `user`'s own role in a folder, not counting groups.
async fn direct_role(
    conn: &mut SqliteConnection,
    user: UserId,
    folder_id: FolderId,
) -> Result<Option<Role>, ApiError> {
    let role: Option<String> =
        sqlx::query_scalar("SELECT role FROM members WHERE user_id = ? AND folder_id = ?")
            .bind(user.0)
            .bind(folder_id.to_string())
            .fetch_optional(conn)
            .await?;
    role.as_deref().map(parse_role).transpose()
}

async fn folder_group_role(
    conn: &mut SqliteConnection,
    folder_id: FolderId,
    group_id: GroupId,
) -> Result<Option<Role>, ApiError> {
    let role: Option<String> =
        sqlx::query_scalar("SELECT role FROM folder_groups WHERE folder_id = ? AND group_id = ?")
            .bind(folder_id.to_string())
            .bind(group_id.to_string())
            .fetch_optional(conn)
            .await?;
    role.as_deref().map(parse_role).transpose()
}

/// What `user` may do with a stored item: the highest of their role in its folder, their
/// direct role (its owner always manages it), and the roles of their groups it's shared
/// with. In a folder with signed roles, someone its entries never made more than a viewer
/// stays one, whatever is shared with them directly: everyone's app would refuse what
/// they saved.
async fn item_role(
    conn: &mut SqliteConnection,
    user: UserId,
    item: &EncryptedItem,
) -> Result<Option<Role>, ApiError> {
    let in_folder = match item.folder_id {
        Some(folder_id) => folder_role(conn, user, folder_id).await?,
        None => None,
    };
    let direct: Vec<String> = sqlx::query_scalar(
        "SELECT role FROM item_access WHERE user_id = ?1 AND item_id = ?2 AND NOT pending
         UNION ALL
         SELECT ig.role FROM item_groups ig JOIN group_members gm ON gm.group_id = ig.group_id
         WHERE gm.user_id = ?1 AND ig.item_id = ?2 AND NOT gm.pending",
    )
    .bind(user.0)
    .bind(item.id.to_string())
    .fetch_all(&mut *conn)
    .await?;
    let role = in_folder.max(highest(direct)?);
    if let (Some(folder_id), true) = (item.folder_id, role > Some(Role::View)) {
        let entries = folder_entries(conn, folder_id).await?;
        let signed = entries.last().is_some_and(|latest| latest.roles.is_some());
        // By the entries that name them; through a group, by the group's role now.
        let most = entries
            .iter()
            .filter(|entry| entry.members.contains(&user))
            .map(|entry| entry.member_role(user).unwrap_or_else(Role::before_roles))
            .max()
            .max(in_folder);
        if signed && most == Some(Role::View) {
            return Ok(most);
        }
    }
    Ok(role)
}

async fn stored_item(
    conn: &mut SqliteConnection,
    item_id: ItemId,
) -> Result<EncryptedItem, ApiError> {
    let body: String = sqlx::query_scalar("SELECT body FROM items WHERE id = ?")
        .bind(item_id.to_string())
        .fetch_optional(conn)
        .await?
        .ok_or(ApiError::NotFound)?;
    Ok(serde_json::from_str(&body)?)
}

/// Approved, and not removed from the team.
pub(crate) async fn require_shareable(
    conn: &mut SqliteConnection,
    user: UserId,
) -> Result<(), ApiError> {
    match user_entry(conn, user).await? {
        Some(entry) if entry.approval.is_some() && !entry.removed => Ok(()),
        _ => Err(ApiError::Forbidden(format!(
            "user {user} is not approved, or was removed"
        ))),
    }
}

/// Whether the owner approved this account and hasn't removed it.
pub(crate) async fn is_approved(
    conn: &mut SqliteConnection,
    user: UserId,
) -> Result<bool, ApiError> {
    Ok(sqlx::query_scalar(
        "SELECT approval IS NOT NULL AND removed_at IS NULL FROM users WHERE id = ?",
    )
    .bind(user.0)
    .fetch_optional(&mut *conn)
    .await?
    .unwrap_or(false))
}

/// Only an account the owner approved saves anything on the team's server: logins (new,
/// changed or deleted) and folders. An invite alone can leak, and whoever has it shouldn't
/// be able to store things there; with an invite's key, the owner's app approves an honest
/// joiner within a minute or so of its next sync.
pub(crate) async fn require_approved_to_save(
    conn: &mut SqliteConnection,
    user: UserId,
) -> Result<(), ApiError> {
    if is_approved(conn, user).await? {
        Ok(())
    } else {
        Err(ApiError::Forbidden(
            "the owner hasn't approved you yet, so you can't save anything; once they have, \
             try again"
                .into(),
        ))
    }
}

/// Only an account the owner approved gives anyone else access: it can't put a folder or
/// a login in a teammate's app for them to save into.
pub(crate) async fn require_approved_to_share(
    conn: &mut SqliteConnection,
    user: UserId,
) -> Result<(), ApiError> {
    if is_approved(conn, user).await? {
        Ok(())
    } else {
        Err(ApiError::Forbidden(
            "the owner hasn't approved you yet, so you can't share".into(),
        ))
    }
}

/// A folder must keep a manager, a person or a group: someone has to be able to share it
/// and change its key.
pub(crate) async fn require_another_manager(
    conn: &mut SqliteConnection,
    folder_id: FolderId,
    leaving: Option<UserId>,
    leaving_group: Option<GroupId>,
) -> Result<(), ApiError> {
    let others: i64 = sqlx::query_scalar(
        "SELECT (SELECT COUNT(*) FROM members
                 WHERE folder_id = ?1 AND role = 'manage' AND user_id != ?2 AND NOT pending)
              + (SELECT COUNT(*) FROM folder_groups
                 WHERE folder_id = ?1 AND role = 'manage' AND group_id != ?3)",
    )
    .bind(folder_id.to_string())
    .bind(leaving.map_or(0, |user| user.0))
    .bind(
        leaving_group
            .map(|group| group.to_string())
            .unwrap_or_default(),
    )
    .fetch_one(conn)
    .await?;
    if others == 0 {
        return Err(ApiError::Conflict(
            "a folder needs at least one manager; make someone else a manager first".into(),
        ));
    }
    Ok(())
}

pub(crate) async fn folder_members(
    conn: &mut SqliteConnection,
    folder_id: FolderId,
) -> Result<Vec<Member>, ApiError> {
    let rows: Vec<(i64, String)> =
        sqlx::query_as("SELECT user_id, role FROM members WHERE folder_id = ? ORDER BY joined_seq")
            .bind(folder_id.to_string())
            .fetch_all(conn)
            .await?;
    rows.into_iter()
        .map(|(user, role)| {
            Ok(Member {
                user_id: UserId(user),
                role: parse_role(&role)?,
            })
        })
        .collect()
}

async fn folder_groups(
    conn: &mut SqliteConnection,
    folder_id: FolderId,
) -> Result<Vec<GroupShare>, ApiError> {
    let rows: Vec<(String, String)> = sqlx::query_as(
        "SELECT group_id, role FROM folder_groups WHERE folder_id = ? ORDER BY group_id",
    )
    .bind(folder_id.to_string())
    .fetch_all(conn)
    .await?;
    rows.into_iter()
        .map(|(group, role)| {
            Ok(GroupShare {
                group_id: parse_group(&group)?,
                role: parse_role(&role)?,
            })
        })
        .collect()
}

async fn generation(conn: &mut SqliteConnection, folder_id: FolderId) -> Result<u32, ApiError> {
    sqlx::query_scalar("SELECT generation FROM folders WHERE id = ?")
        .bind(folder_id.to_string())
        .fetch_optional(conn)
        .await?
        .ok_or(ApiError::NotFound)
}

/// A folder's current key as one member holds it: wrapped for them, or for a group
/// they're in.
struct MemberFolderKey {
    info: Sealed,
    wrapped_key: WrappedKey,
    generation: u32,
    chain: Vec<KeyLink>,
    via_group: Option<ViaGroup>,
    entries: Vec<FolderEntry>,
}

async fn current_key(
    conn: &mut SqliteConnection,
    user: UserId,
    folder_id: FolderId,
) -> Result<Option<MemberFolderKey>, ApiError> {
    // Only copies made for their current keys: not ones waiting after a recovery.
    let direct: Option<String> = sqlx::query_scalar(
        "SELECT wrapped_key FROM members WHERE user_id = ? AND folder_id = ? AND NOT pending",
    )
    .bind(user.0)
    .bind(folder_id.to_string())
    .fetch_optional(&mut *conn)
    .await?;
    let (wrapped_key, via_group) = match direct {
        Some(wrapped_key) => (wrapped_key, None),
        None => {
            let row: Option<(String, String, u32)> = sqlx::query_as(
                "SELECT fg.wrapped_key, fg.group_id, fg.group_generation
                 FROM folder_groups fg JOIN group_members gm ON gm.group_id = fg.group_id
                 WHERE gm.user_id = ? AND fg.folder_id = ? AND NOT gm.pending
                 ORDER BY fg.group_id LIMIT 1",
            )
            .bind(user.0)
            .bind(folder_id.to_string())
            .fetch_optional(&mut *conn)
            .await?;
            let Some((wrapped_key, group_id, generation)) = row else {
                return Ok(None);
            };
            let via = ViaGroup {
                group_id: parse_group(&group_id)?,
                generation,
            };
            (wrapped_key, Some(via))
        }
    };
    let (info, generation): (String, u32) =
        sqlx::query_as("SELECT info, generation FROM folders WHERE id = ?")
            .bind(folder_id.to_string())
            .fetch_one(&mut *conn)
            .await?;
    let links: Vec<(u32, String)> = sqlx::query_as(
        "SELECT generation, previous FROM folder_keys WHERE folder_id = ? ORDER BY generation",
    )
    .bind(folder_id.to_string())
    .fetch_all(&mut *conn)
    .await?;
    let chain = links
        .into_iter()
        .map(|(generation, previous)| {
            Ok(KeyLink {
                generation,
                previous: serde_json::from_str(&previous)?,
            })
        })
        .collect::<Result<_, ApiError>>()?;
    Ok(Some(MemberFolderKey {
        info: serde_json::from_str(&info)?,
        wrapped_key: serde_json::from_str(&wrapped_key)?,
        generation,
        chain,
        via_group,
        entries: folder_entries(conn, folder_id).await?,
    }))
}

/// `user`'s role in every folder they can open and on every item they reach directly, the
/// highest of the ways they reach each.
async fn user_roles(conn: &mut SqliteConnection, user: UserId) -> Result<Roles, ApiError> {
    let highest_by = |rows: Vec<(String, String)>| -> Result<BTreeMap<String, Role>, ApiError> {
        let mut best = BTreeMap::new();
        for (id, role) in rows {
            let role = parse_role(&role)?;
            let entry = best.entry(id).or_insert(role);
            *entry = (*entry).max(role);
        }
        Ok(best)
    };
    let folders: Vec<(String, String)> = sqlx::query_as(
        "SELECT folder_id, role FROM members WHERE user_id = ?1 AND NOT pending
         UNION ALL
         SELECT fg.folder_id, fg.role FROM folder_groups fg
         JOIN group_members gm ON gm.group_id = fg.group_id
         WHERE gm.user_id = ?1 AND NOT gm.pending",
    )
    .bind(user.0)
    .fetch_all(&mut *conn)
    .await?;
    let items: Vec<(String, String)> = sqlx::query_as(
        "SELECT item_id, role FROM item_access WHERE user_id = ?1 AND NOT pending
         UNION ALL
         SELECT ig.item_id, ig.role FROM item_groups ig
         JOIN group_members gm ON gm.group_id = ig.group_id
         WHERE gm.user_id = ?1 AND NOT gm.pending",
    )
    .bind(user.0)
    .fetch_all(&mut *conn)
    .await?;
    Ok(Roles {
        folders: highest_by(folders)?
            .into_iter()
            .map(|(folder_id, role)| {
                Ok(FolderRole {
                    folder_id: parse_folder(&folder_id)?,
                    role,
                })
            })
            .collect::<Result<_, ApiError>>()?,
        items: highest_by(items)?
            .into_iter()
            .map(|(item_id, role)| {
                Ok(ItemRole {
                    item_id: parse_item(&item_id)?,
                    role,
                })
            })
            .collect::<Result<_, ApiError>>()?,
    })
}

/// Makes `user` a member of a folder themselves.
async fn join(
    conn: &mut SqliteConnection,
    user: UserId,
    folder_id: FolderId,
    wrapped_key: &WrappedKey,
    role: Role,
) -> Result<(), ApiError> {
    let seq = next_seq(conn).await?;
    sqlx::query(
        "INSERT INTO members (user_id, folder_id, joined_seq, wrapped_key, role)
         VALUES (?, ?, ?, ?, ?)",
    )
    .bind(user.0)
    .bind(folder_id.to_string())
    .bind(seq)
    .bind(serde_json::to_string(wrapped_key)?)
    .bind(role.name())
    .execute(&mut *conn)
    .await?;
    reconcile(conn, user).await
}

/// Takes `user` out of a folder they're in themselves. Unless a group still gives it,
/// their access ends at once, their feed tells their devices to drop it, and the folder is
/// marked for a new key if anyone can still open it.
pub(crate) async fn leave(
    conn: &mut SqliteConnection,
    user: UserId,
    folder_id: FolderId,
) -> Result<(), ApiError> {
    let pending: Option<bool> = sqlx::query_scalar(
        "DELETE FROM members WHERE user_id = ? AND folder_id = ? RETURNING pending",
    )
    .bind(user.0)
    .bind(folder_id.to_string())
    .fetch_optional(&mut *conn)
    .await?;
    if pending == Some(true) {
        expose_folder(conn, user, &folder_id.to_string()).await?;
    }
    reconcile(conn, user).await
}

/// Puts what a folder holds on passwords to change for `user`, who lost it while waiting
/// for a copy after a recovery: they could see it all before. Those who can still open it
/// are left out when the list is read.
pub(crate) async fn expose_folder(
    conn: &mut SqliteConnection,
    user: UserId,
    folder_id: &str,
) -> Result<(), ApiError> {
    sqlx::query(AssertSqlSafe(format!(
        "{EXPOSE} SELECT id, ?1, CAST(strftime('%s', 'now') AS INTEGER) FROM items
         WHERE folder_id = ?2 AND NOT COALESCE(json_extract(body, '$.deleted'), 0)
         {EXPOSE_AGAIN}"
    )))
    .bind(user.0)
    .bind(folder_id)
    .execute(&mut *conn)
    .await?;
    Ok(())
}

/// Like [`expose_folder`], for one item.
pub(crate) async fn expose_item(
    conn: &mut SqliteConnection,
    user: UserId,
    item_id: &str,
) -> Result<(), ApiError> {
    sqlx::query(AssertSqlSafe(format!(
        "{EXPOSE} SELECT id, ?1, CAST(strftime('%s', 'now') AS INTEGER) FROM items
         WHERE id = ?2 AND NOT COALESCE(json_extract(body, '$.deleted'), 0)
         {EXPOSE_AGAIN}"
    )))
    .bind(user.0)
    .bind(item_id)
    .execute(&mut *conn)
    .await?;
    Ok(())
}

/// Takes away `user`'s own direct access to an item; unless a group still gives it, their
/// devices drop it.
pub(crate) async fn leave_item(
    conn: &mut SqliteConnection,
    user: UserId,
    item_id: &str,
) -> Result<(), ApiError> {
    let pending: Option<bool> = sqlx::query_scalar(
        "DELETE FROM item_access WHERE user_id = ? AND item_id = ? RETURNING pending",
    )
    .bind(user.0)
    .bind(item_id)
    .fetch_optional(&mut *conn)
    .await?;
    if pending == Some(true) {
        expose_item(conn, user, item_id).await?;
    }
    reconcile(conn, user).await
}

/// Sends `user` the current key of each of these folders they can still open, after the
/// way they reached it (a group) went away: the copy their devices hold may be the one
/// wrapped for that group.
pub(crate) async fn resend_keys(
    conn: &mut SqliteConnection,
    user: UserId,
    folders: &[String],
) -> Result<(), ApiError> {
    for folder_id in folders {
        let still: bool = sqlx::query_scalar(
            "SELECT EXISTS (SELECT 1 FROM access WHERE user_id = ? AND folder_id = ?)",
        )
        .bind(user.0)
        .bind(folder_id)
        .fetch_one(&mut *conn)
        .await?;
        if still {
            let seq = next_seq(conn).await?;
            sqlx::query("INSERT INTO rekey_log (seq, user_id, folder_id) VALUES (?, ?, ?)")
                .bind(seq)
                .bind(user.0)
                .bind(folder_id)
                .execute(&mut *conn)
                .await?;
        }
    }
    Ok(())
}

/// Brings what `user` can open up to date after anything that may have changed it: the
/// folders they can open and the items they reach directly, themselves or through their
/// groups. Each folder or item gained or lost goes in their feed as a join or a leave, and
/// a folder they lost is marked for a new key if anyone can still open it.
pub(crate) async fn reconcile(conn: &mut SqliteConnection, user: UserId) -> Result<(), ApiError> {
    reconcile_with(conn, user, true).await
}

/// Like [`reconcile`]; with `expose` false, nothing lost goes on passwords to change.
/// Copies waiting for someone who recovered give no access until they're made again.
async fn reconcile_with(
    conn: &mut SqliteConnection,
    user: UserId,
    expose: bool,
) -> Result<(), ApiError> {
    let reachable: BTreeSet<String> = sqlx::query_scalar(
        "SELECT folder_id FROM members WHERE user_id = ?1 AND NOT pending
         UNION
         SELECT fg.folder_id FROM folder_groups fg
         JOIN group_members gm ON gm.group_id = fg.group_id
         WHERE gm.user_id = ?1 AND NOT gm.pending",
    )
    .bind(user.0)
    .fetch_all(&mut *conn)
    .await?
    .into_iter()
    .collect();
    let held: BTreeSet<String> =
        sqlx::query_scalar("SELECT folder_id FROM access WHERE user_id = ?")
            .bind(user.0)
            .fetch_all(&mut *conn)
            .await?
            .into_iter()
            .collect();
    for folder_id in reachable.difference(&held) {
        let seq = next_seq(conn).await?;
        sqlx::query("INSERT INTO access (user_id, folder_id, joined_seq) VALUES (?, ?, ?)")
            .bind(user.0)
            .bind(folder_id)
            .bind(seq)
            .execute(&mut *conn)
            .await?;
        // Whoever had it in escrow no longer needs to: this user can give it back.
        sqlx::query("DELETE FROM folder_escrow WHERE folder_id = ? AND user_id != ?")
            .bind(folder_id)
            .bind(user.0)
            .execute(&mut *conn)
            .await?;
        sqlx::query(
            "INSERT INTO membership_log (seq, user_id, folder_id, joined) VALUES (?, ?, ?, 1)",
        )
        .bind(seq)
        .bind(user.0)
        .bind(folder_id)
        .execute(&mut *conn)
        .await?;
    }
    for folder_id in held.difference(&reachable) {
        sqlx::query("DELETE FROM access WHERE user_id = ? AND folder_id = ?")
            .bind(user.0)
            .bind(folder_id)
            .execute(&mut *conn)
            .await?;
        let seq = next_seq(conn).await?;
        sqlx::query(
            "INSERT INTO membership_log (seq, user_id, folder_id, joined) VALUES (?, ?, ?, 0)",
        )
        .bind(seq)
        .bind(user.0)
        .bind(folder_id)
        .execute(&mut *conn)
        .await?;
        sqlx::query(
            "UPDATE folders SET needs_rekey = 1
             WHERE id = ?1 AND EXISTS (SELECT 1 FROM access WHERE folder_id = ?1)",
        )
        .bind(folder_id)
        .execute(&mut *conn)
        .await?;
        // They could see every password in it.
        if expose {
            sqlx::query(AssertSqlSafe(format!(
                "{EXPOSE} SELECT id, ?1, CAST(strftime('%s', 'now') AS INTEGER) FROM items
                 WHERE folder_id = ?2 AND NOT COALESCE(json_extract(body, '$.deleted'), 0)
                 {EXPOSE_AGAIN}"
            )))
            .bind(user.0)
            .bind(folder_id)
            .execute(&mut *conn)
            .await?;
        }
    }

    let reachable: BTreeSet<String> = sqlx::query_scalar(
        "SELECT item_id FROM item_access WHERE user_id = ?1 AND NOT pending
         UNION
         SELECT ig.item_id FROM item_groups ig
         JOIN group_members gm ON gm.group_id = ig.group_id
         WHERE gm.user_id = ?1 AND NOT gm.pending",
    )
    .bind(user.0)
    .fetch_all(&mut *conn)
    .await?
    .into_iter()
    .collect();
    let held: BTreeSet<String> =
        sqlx::query_scalar("SELECT item_id FROM item_reach WHERE user_id = ?")
            .bind(user.0)
            .fetch_all(&mut *conn)
            .await?
            .into_iter()
            .collect();
    for item_id in reachable.difference(&held) {
        reach_item(conn, user.0, item_id).await?;
    }
    for item_id in held.difference(&reachable) {
        lose_item(conn, user.0, item_id, expose).await?;
    }
    Ok(())
}

/// Like [`reconcile`], for one item and everyone: who reaches it directly, themselves or
/// through a group, against who did. After a save, which changes that and nothing else, so
/// it costs what the item's people and groups do, not everything each of them reaches.
async fn reconcile_item(conn: &mut SqliteConnection, item_id: &str) -> Result<(), ApiError> {
    let reachable: BTreeSet<i64> = sqlx::query_scalar(
        "SELECT user_id FROM item_access WHERE item_id = ?1 AND NOT pending
         UNION
         SELECT gm.user_id FROM item_groups ig
         JOIN group_members gm ON gm.group_id = ig.group_id
         WHERE ig.item_id = ?1 AND NOT gm.pending",
    )
    .bind(item_id)
    .fetch_all(&mut *conn)
    .await?
    .into_iter()
    .collect();
    let held: BTreeSet<i64> =
        sqlx::query_scalar("SELECT user_id FROM item_reach WHERE item_id = ?")
            .bind(item_id)
            .fetch_all(&mut *conn)
            .await?
            .into_iter()
            .collect();
    for &user in reachable.difference(&held) {
        reach_item(conn, user, item_id).await?;
    }
    for &user in held.difference(&reachable) {
        lose_item(conn, user, item_id, true).await?;
    }
    Ok(())
}

/// `user` now reaches the item directly: it goes in their feed as a join.
async fn reach_item(conn: &mut SqliteConnection, user: i64, item_id: &str) -> Result<(), ApiError> {
    sqlx::query("INSERT INTO item_reach (user_id, item_id) VALUES (?, ?)")
        .bind(user)
        .bind(item_id)
        .execute(&mut *conn)
        .await?;
    let seq = next_seq(conn).await?;
    sqlx::query("INSERT INTO item_join_log (seq, user_id, item_id) VALUES (?, ?, ?)")
        .bind(seq)
        .bind(user)
        .bind(item_id)
        .execute(&mut *conn)
        .await?;
    Ok(())
}

/// `user` no longer reaches the item directly: it goes in their feed as a leave, and, with
/// `expose`, its password on passwords to change, as they may still know it.
async fn lose_item(
    conn: &mut SqliteConnection,
    user: i64,
    item_id: &str,
    expose: bool,
) -> Result<(), ApiError> {
    sqlx::query("DELETE FROM item_reach WHERE user_id = ? AND item_id = ?")
        .bind(user)
        .bind(item_id)
        .execute(&mut *conn)
        .await?;
    let seq = next_seq(conn).await?;
    sqlx::query("INSERT INTO item_leave_log (seq, user_id, item_id) VALUES (?, ?, ?)")
        .bind(seq)
        .bind(user)
        .bind(item_id)
        .execute(&mut *conn)
        .await?;
    if expose {
        sqlx::query(AssertSqlSafe(format!(
            "{EXPOSE} SELECT id, ?1, CAST(strftime('%s', 'now') AS INTEGER) FROM items
             WHERE id = ?2 AND NOT COALESCE(json_extract(body, '$.deleted'), 0)
             {EXPOSE_AGAIN}"
        )))
        .bind(user)
        .bind(item_id)
        .execute(&mut *conn)
        .await?;
    }
    Ok(())
}

/// `GET /v1/password-ages`: when the password of each live item the caller can open was
/// last set, as apps said when saving, for password health. Unknown for items last saved
/// before 0.7.0.
pub(crate) async fn password_ages(
    State(state): State<AppState>,
    auth: Auth,
) -> Result<Json<PasswordAges>, ApiError> {
    let rows: Vec<(String, Option<i64>)> = sqlx::query_as(
        "SELECT i.id, i.password_saved_at FROM items i
         WHERE NOT COALESCE(json_extract(i.body, '$.deleted'), 0)
           AND (EXISTS (SELECT 1 FROM access a WHERE a.user_id = ?1 AND a.folder_id = i.folder_id)
                OR EXISTS (SELECT 1 FROM item_reach r WHERE r.user_id = ?1 AND r.item_id = i.id)
                OR (i.folder_id IS NULL AND json_extract(i.body, '$.owner') = ?1))
         ORDER BY i.id",
    )
    .bind(auth.user_id.0)
    .fetch_all(&state.readers)
    .await?;
    Ok(Json(PasswordAges {
        items: rows
            .into_iter()
            .map(|(item_id, since)| {
                Ok(PasswordAge {
                    item_id: parse_item(&item_id)?,
                    since,
                })
            })
            .collect::<Result<_, ApiError>>()?,
    }))
}

/// Records that someone lost access to items while their passwords stayed the same; the
/// `SELECT` gives item id, user id and the time.
const EXPOSE: &str = "INSERT INTO exposures (item_id, user_id, since)";
/// Losing access again moves the time on.
const EXPOSE_AGAIN: &str = "ON CONFLICT (item_id, user_id) DO UPDATE SET since = excluded.since";

/// `GET /v1/exposures`: who may still know the passwords of the items the caller can
/// change, because they lost access since those passwords were set. People who can open
/// the item again (and aren't removed from the team) are left out.
pub(crate) async fn exposures(
    State(state): State<AppState>,
    auth: Auth,
) -> Result<Json<Exposures>, ApiError> {
    let mut conn = state.readers.acquire().await?;
    let rows: Vec<(String, i64, i64, String)> = sqlx::query_as(
        "SELECT e.item_id, e.user_id, e.since, i.body FROM exposures e
         JOIN items i ON i.id = e.item_id
         WHERE (i.folder_id IN (SELECT folder_id FROM access WHERE user_id = ?1)
                OR e.item_id IN (SELECT item_id FROM item_reach WHERE user_id = ?1))
           AND NOT EXISTS (
               SELECT 1 FROM users u
               WHERE u.id = e.user_id AND u.removed_at IS NULL
                 AND (i.folder_id IN (SELECT folder_id FROM access WHERE user_id = u.id)
                      OR e.item_id IN (SELECT item_id FROM item_reach WHERE user_id = u.id)))
         ORDER BY e.since DESC, e.item_id, e.user_id",
    )
    .bind(auth.user_id.0)
    .fetch_all(&mut *conn)
    .await?;
    let mut can_change: HashMap<String, bool> = HashMap::new();
    let mut exposures = Vec::new();
    for (item_id, user_id, since, body) in rows {
        let allowed = match can_change.get(&item_id) {
            Some(&allowed) => allowed,
            None => {
                let item: EncryptedItem = serde_json::from_str(&body)?;
                let role = item_role(&mut conn, auth.user_id, &item).await?;
                let allowed = role >= Some(Role::Edit) && !item.deleted;
                can_change.insert(item_id.clone(), allowed);
                allowed
            }
        };
        if allowed {
            exposures.push(Exposure {
                item_id: parse_item(&item_id)?,
                user_id: UserId(user_id),
                since,
            });
        }
    }
    Ok(Json(Exposures { exposures }))
}

/// `DELETE /v1/items/{item_id}/exposures/{user_id}`: someone who can change the item
/// decides the password doesn't need changing after all.
pub(crate) async fn dismiss_exposure(
    State(state): State<AppState>,
    auth: Auth,
    Path((item_id, user_id)): Path<(ItemId, i64)>,
) -> Result<StatusCode, ApiError> {
    let mut tx = state.writer.begin().await?;
    let item = stored_item(&mut tx, item_id).await?;
    require(
        item_role(&mut tx, auth.user_id, &item).await?,
        Role::Edit,
        "dismiss this",
    )?;
    sqlx::query("DELETE FROM exposures WHERE item_id = ? AND user_id = ?")
        .bind(item_id.to_string())
        .bind(user_id)
        .execute(&mut *tx)
        .await?;
    tx.commit().await?;
    Ok(StatusCode::NO_CONTENT)
}

pub(crate) fn parse_folder(text: &str) -> Result<FolderId, ApiError> {
    FolderId::from_str(text).map_err(|_| ApiError::Internal(format!("bad stored folder id {text}")))
}

fn parse_item(text: &str) -> Result<ItemId, ApiError> {
    ItemId::from_str(text).map_err(|_| ApiError::Internal(format!("bad stored item id {text}")))
}
