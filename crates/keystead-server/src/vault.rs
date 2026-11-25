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
    EscrowedFolder, Exposure, Exposures, FolderEscrowRequest, FolderMember, FolderRole,
    GroupMember, GroupShare, ItemHistory, ItemRole, KeyLink, Member, Members, PasswordAge,
    PasswordAges, PutItemRequest, RekeyRequest, Restore, RestoreFolderKeyRequest, Role,
    RoleRequest, Roles, SavedVersion, SyncEntry, SyncPage, ViaGroup,
};
use keystead_core::ids::{FolderId, GroupId, ItemId, UserId};
use keystead_core::items::{EncryptedItem, ITEM_FORMAT, Sealed};
use keystead_core::keys::WrappedKey;
use serde::Deserialize;
use sqlx::SqliteConnection;

use crate::accounts::Auth;
use crate::groups::{group_key_state, group_member_ids, group_state, parse_group};
use crate::{ApiError, AppState, next_seq, user_entry};

const DEFAULT_PAGE: i64 = 500;
const MAX_PAGE: i64 = 1_000;

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
    join(
        &mut tx,
        request.user_id,
        folder_id,
        &request.wrapped_key,
        request.role,
    )
    .await?;
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
        sqlx::query(&format!("UPDATE {table} SET pending = 1 WHERE user_id = ?"))
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
        sqlx::query(&format!(
            "DELETE FROM {table} WHERE item_id IN (SELECT id FROM items WHERE folder_id = ?)"
        ))
        .bind(&folder)
        .execute(&mut *tx)
        .await?;
    }
    for table in ["items", "members", "folder_groups", "folder_keys"] {
        sqlx::query(&format!("DELETE FROM {table} WHERE folder_id = ?"))
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
    for member in group_member_ids(&mut tx, request.group_id).await? {
        reconcile(&mut tx, member).await?;
    }
    tx.commit().await?;
    Ok(StatusCode::NO_CONTENT)
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
    let item = request.item;
    if item.id != item_id {
        return Err(ApiError::BadRequest(
            "item id doesn't match the path".into(),
        ));
    }
    if item.author != auth.user_id {
        return Err(ApiError::Forbidden(
            "you can only save versions you authored".into(),
        ));
    }
    check_shape(&item)?;

    let mut tx = state.writer.begin().await?;
    // A courtesy check: clients verify signatures themselves, but rejecting bad ones here
    // keeps garbage out of everyone's feed.
    let author = user_entry(&mut tx, auth.user_id)
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
                Some(folder_id) => folder_role(&mut tx, auth.user_id, folder_id).await?,
                None if item.owner == Some(auth.user_id) => Some(Role::Manage),
                None => {
                    return Err(ApiError::Forbidden(
                        "an item outside folders starts out as its author's own".into(),
                    ));
                }
            };
            (require(role, Role::Edit, "add logins here")?, 1)
        }
        (None, Some(current)) => return Err(ApiError::ItemConflict(Box::new(current.clone()))),
        (Some(_), None) => return Err(ApiError::NotFound),
        (Some(base), Some(current)) => {
            let role = require(
                item_role(&mut tx, auth.user_id, current).await?,
                Role::Edit,
                "change this login",
            )?;
            // Moving: from where the mover can change it, to a folder where they can add
            // logins, or out of folders as their own. A login in no folder stays its
            // owner's to move.
            if current.folder_id != item.folder_id || current.owner != item.owner {
                if current.owner.is_some_and(|owner| owner != auth.user_id) {
                    return Err(ApiError::Forbidden(
                        "only its owner can move a login that's in no folder".into(),
                    ));
                }
                match (item.folder_id, item.owner) {
                    (Some(folder_id), _) => {
                        require(
                            folder_role(&mut tx, auth.user_id, folder_id).await?,
                            Role::Edit,
                            "move logins into that folder",
                        )?;
                    }
                    (None, Some(owner)) if owner == auth.user_id => {}
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
    if item.version != expected_version {
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
        let removed = user_entry(&mut tx, user)
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
    for &user in &added {
        require_shareable(&mut tx, user).await?;
    }
    // Copies for a group are for one of its generations: the current one when the group
    // is new to the item, and never one that doesn't exist yet.
    for copy in &item.keys.groups {
        let (generation, _) = group_key_state(&mut tx, copy.group_id)
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
    // brought back.
    purge_deleted(&mut tx).await?;
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

    let seq = next_seq(&mut tx).await?;
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

    // Everyone whose reach may have changed: people and members of groups, before and after.
    let mut affected: BTreeSet<UserId> = before.union(&after).copied().collect();
    affected.extend(item.owner);
    affected.extend(current.as_ref().and_then(|current| current.owner));
    for group in groups_before.union(&groups_after) {
        affected.extend(group_member_ids(&mut tx, *group).await?);
    }
    for user in affected {
        reconcile(&mut tx, user).await?;
    }
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
            let seq = next_seq(&mut tx).await?;
            sqlx::query(
                "INSERT INTO item_leave_log (seq, user_id, item_id, moved) VALUES (?, ?, ?, 1)",
            )
            .bind(seq)
            .bind(member)
            .bind(item_id.to_string())
            .execute(&mut *tx)
            .await?;
            sqlx::query(&format!(
                "{EXPOSE} VALUES (?1, ?2, CAST(strftime('%s', 'now') AS INTEGER)) {EXPOSE_AGAIN}"
            ))
            .bind(item_id.to_string())
            .bind(member)
            .execute(&mut *tx)
            .await?;
        }
    }
    tx.commit().await?;
    Ok(Json(item))
}

/// `GET /v1/items/{item_id}/people`: who has the item directly (its owner, and everyone
/// and every group it's shared with) and their roles, for anyone who can open it.
/// How many earlier versions of each item the server keeps.
const HISTORY_KEPT: i64 = 10;
/// How long a deleted item can be brought back.
const DELETED_KEPT_DAYS: i64 = 30;

/// Forgets the history (and passwords to change) of items deleted more than
/// `DELETED_KEPT_DAYS` ago; their deletion markers stay, for everyone's devices.
pub(crate) async fn purge_deleted(conn: &mut SqliteConnection) -> Result<(), ApiError> {
    let expired = format!(
        "SELECT id FROM items WHERE COALESCE(json_extract(body, '$.deleted'), 0)
         AND saved_at < CAST(strftime('%s', 'now') AS INTEGER) - {}",
        DELETED_KEPT_DAYS * 86_400
    );
    for table in ["item_history", "exposures"] {
        sqlx::query(&format!("DELETE FROM {table} WHERE item_id IN ({expired})"))
            .execute(&mut *conn)
            .await?;
    }
    Ok(())
}

/// `GET /v1/deleted`: items deleted in the last `DELETED_KEPT_DAYS` that the caller can
/// change, each with its deletion marker and its last version before it, newest first.
pub(crate) async fn deleted_items(
    State(state): State<AppState>,
    auth: Auth,
) -> Result<Json<DeletedItems>, ApiError> {
    let mut tx = state.writer.begin().await?;
    purge_deleted(&mut tx).await?;
    let rows: Vec<(i64, String, String)> = sqlx::query_as(
        "SELECT i.saved_at, i.body, h.body FROM items i
         JOIN item_history h ON h.item_id = i.id
         WHERE COALESCE(json_extract(i.body, '$.deleted'), 0) AND i.saved_at IS NOT NULL
           AND h.version = (SELECT MAX(version) FROM item_history WHERE item_id = i.id)
         ORDER BY i.saved_at DESC",
    )
    .fetch_all(&mut *tx)
    .await?;
    let mut items = Vec::new();
    for (deleted_at, deleted, last) in rows {
        let deleted: EncryptedItem = serde_json::from_str(&deleted)?;
        if item_role(&mut tx, auth.user_id, &deleted).await? >= Some(Role::Edit) {
            items.push(DeletedItem {
                deleted_at,
                deleted,
                last: serde_json::from_str(&last)?,
            });
        }
    }
    tx.commit().await?;
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
        sqlx::query(&format!("DELETE FROM {table} WHERE item_id = ?"))
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
    Ok(Json(Members { members, groups }))
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
    let bad = |message: &str| Err(ApiError::BadRequest(message.into()));
    match item.format {
        1 => {
            if item.folder_id.is_none() || item.owner.is_some() || !item.keys.is_empty() {
                return bad("a format 1 item is in a folder and has no key copies");
            }
        }
        2..=4 => {
            let keys = &item.keys;
            // Format 4 (a one-time code in the details) may have group copies or not.
            if item.format < 4 && (item.format == 3) == keys.groups.is_empty() {
                return bad("format 3 items, and only they, have copies for groups");
            }
            let mut groups = HashSet::new();
            if !keys.groups.iter().all(|copy| groups.insert(copy.group_id)) {
                return bad("each group gets one copy of an item's key");
            }
            let in_folder = item.folder_id.is_some();
            let owned = item.owner.is_some();
            if in_folder == owned
                || keys.folder.is_some() != in_folder
                || keys.owner.is_some() != owned
            {
                return bad("an item has either a folder or an owner, with its key copy");
            }
            let mut seen = Vec::new();
            for person in &keys.people {
                if Some(person.user_id) == item.owner || seen.contains(&person.user_id) {
                    return bad("each person gets one copy of an item's key");
                }
                seen.push(person.user_id);
            }
        }
        other => {
            return Err(ApiError::BadRequest(format!(
                "this server stores item formats up to {ITEM_FORMAT}, not {other}"
            )));
        }
    }
    Ok(())
}

// MARK: - Sync

#[derive(Deserialize)]
pub(crate) struct SyncParams {
    #[serde(default)]
    cursor: i64,
    limit: Option<i64>,
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

    let more = rows.len() as i64 > limit;
    let rows: Vec<FeedRow> = rows.into_iter().take(limit as usize).collect();
    let next_cursor = match (more, rows.last()) {
        (true, Some(last)) => last.0,
        _ => high_water.max(cursor),
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

    // Folders wait for the groups they're shared with to get their new keys first.
    let rekey_needed: Vec<String> = sqlx::query_scalar(
        "SELECT a.folder_id FROM access a JOIN folders f ON f.id = a.folder_id
         WHERE a.user_id = ? AND f.needs_rekey = 1
           AND NOT EXISTS (SELECT 1 FROM folder_groups fg JOIN team_groups g ON g.id = fg.group_id
                           WHERE fg.folder_id = f.id AND g.needs_rekey = 1)
         ORDER BY a.folder_id",
    )
    .bind(user)
    .fetch_all(&mut *tx)
    .await?;
    let mut folders = Vec::new();
    for folder_id in rekey_needed {
        let folder_id = parse_folder(&folder_id)?;
        if folder_role(&mut tx, auth.user_id, folder_id).await? == Some(Role::Manage) {
            folders.push(folder_id);
        }
    }
    let group_rekey_needed = crate::groups::rekey_needed(&mut tx, auth.user_id).await?;
    let restore = restore_needed(&mut tx, auth.user_id).await?;
    let (recovered_key, escrow_needed): (Option<String>, bool) = sqlx::query_as(
        "SELECT recovered_key, escrow_on AND (escrow IS NULL OR escrow_revision < revision)
         FROM users WHERE id = ?",
    )
    .bind(user)
    .fetch_one(&mut *tx)
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
    .bind(user)
    .fetch_all(&mut *tx)
    .await?;
    let roles = if more {
        None
    } else {
        Some(user_roles(&mut tx, auth.user_id).await?)
    };
    tx.commit().await?;

    Ok(Json(SyncPage {
        entries,
        cursor: next_cursor,
        more,
        rekey_needed: folders,
        roles,
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
    }))
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
/// with.
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
    Ok(in_folder.max(highest(direct)?))
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
    sqlx::query(&format!(
        "{EXPOSE} SELECT id, ?1, CAST(strftime('%s', 'now') AS INTEGER) FROM items
         WHERE folder_id = ?2 AND NOT COALESCE(json_extract(body, '$.deleted'), 0)
         {EXPOSE_AGAIN}"
    ))
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
    sqlx::query(&format!(
        "{EXPOSE} SELECT id, ?1, CAST(strftime('%s', 'now') AS INTEGER) FROM items
         WHERE id = ?2 AND NOT COALESCE(json_extract(body, '$.deleted'), 0)
         {EXPOSE_AGAIN}"
    ))
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
            sqlx::query(&format!(
                "{EXPOSE} SELECT id, ?1, CAST(strftime('%s', 'now') AS INTEGER) FROM items
                 WHERE folder_id = ?2 AND NOT COALESCE(json_extract(body, '$.deleted'), 0)
                 {EXPOSE_AGAIN}"
            ))
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
        sqlx::query("INSERT INTO item_reach (user_id, item_id) VALUES (?, ?)")
            .bind(user.0)
            .bind(item_id)
            .execute(&mut *conn)
            .await?;
        let seq = next_seq(conn).await?;
        sqlx::query("INSERT INTO item_join_log (seq, user_id, item_id) VALUES (?, ?, ?)")
            .bind(seq)
            .bind(user.0)
            .bind(item_id)
            .execute(&mut *conn)
            .await?;
    }
    for item_id in held.difference(&reachable) {
        sqlx::query("DELETE FROM item_reach WHERE user_id = ? AND item_id = ?")
            .bind(user.0)
            .bind(item_id)
            .execute(&mut *conn)
            .await?;
        let seq = next_seq(conn).await?;
        sqlx::query("INSERT INTO item_leave_log (seq, user_id, item_id) VALUES (?, ?, ?)")
            .bind(seq)
            .bind(user.0)
            .bind(item_id)
            .execute(&mut *conn)
            .await?;
        if expose {
            sqlx::query(&format!(
                "{EXPOSE} SELECT id, ?1, CAST(strftime('%s', 'now') AS INTEGER) FROM items
                 WHERE id = ?2 AND NOT COALESCE(json_extract(body, '$.deleted'), 0)
                 {EXPOSE_AGAIN}"
            ))
            .bind(user.0)
            .bind(item_id)
            .execute(&mut *conn)
            .await?;
        }
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
