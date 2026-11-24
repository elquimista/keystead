//! Folders, items, roles and the change feed.
//!
//! The server can't open anything, but it decides who receives what and who may change
//! it. An item goes to the members of its folder, its owner, and everyone it's shared with
//! directly, each with a role: view, edit or manage. Who holds a key copy comes from the
//! item itself, which its author signed; roles are the server's to enforce.

use std::collections::{HashMap, HashSet};
use std::str::FromStr;

use axum::Json;
use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use keystead_core::api::{
    AddMemberRequest, CreateFolderRequest, FolderRole, ItemRole, KeyLink, Member, Members,
    PutItemRequest, RekeyRequest, Role, RoleRequest, Roles, SyncEntry, SyncPage,
};
use keystead_core::ids::{FolderId, ItemId, UserId};
use keystead_core::items::{EncryptedItem, ITEM_FORMAT, Sealed};
use keystead_core::keys::WrappedKey;
use serde::Deserialize;
use sqlx::SqliteConnection;

use crate::accounts::Auth;
use crate::{ApiError, AppState, next_seq, user_entry};

const DEFAULT_PAGE: i64 = 500;
const MAX_PAGE: i64 = 1_000;

/// One ordered stream: the latest version of each item in the user's folders, then of
/// each item they reach directly (owned or shared with them) outside those folders, plus
/// the user's own joins and leaves, new folder keys, and logins they lost direct access
/// to. Folders joined after the cursor are left out here; their items ride on the join
/// entry instead. An item reached directly always arrives on its own: whatever gave the
/// access saved a new version, with a new change number.
const FEED_QUERY: &str = "
    SELECT i.seq AS seq, 'item' AS kind, i.body AS body, NULL AS target, NULL AS joined
    FROM items i JOIN members m ON m.folder_id = i.folder_id
    WHERE m.user_id = ?1 AND i.seq > ?2 AND m.joined_seq <= ?2
    UNION ALL
    SELECT i.seq, 'item', i.body, NULL, NULL
    FROM item_access a JOIN items i ON i.id = a.item_id
    WHERE a.user_id = ?1 AND i.seq > ?2
      AND NOT EXISTS (SELECT 1 FROM members m WHERE m.user_id = ?1 AND m.folder_id = i.folder_id)
    UNION ALL
    SELECT seq, 'membership', NULL, folder_id, joined
    FROM membership_log WHERE user_id = ?1 AND seq > ?2
    UNION ALL
    SELECT seq, 'rekey', NULL, folder_id, NULL
    FROM rekey_log WHERE user_id = ?1 AND seq > ?2
    UNION ALL
    SELECT seq, 'left_item', NULL, item_id, NULL
    FROM item_leave_log WHERE user_id = ?1 AND seq > ?2
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
    if folder_role(&mut tx, request.user_id, folder_id)
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

/// `GET /v1/folders/{folder_id}/members`: everyone in the folder and their roles, for its
/// members.
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
    let current = folder_role(&mut tx, user, folder_id)
        .await?
        .ok_or(ApiError::NotFound)?;
    if current == Role::Manage && request.role != Role::Manage {
        require_another_manager(&mut tx, folder_id, user).await?;
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
/// member leaves. Their access ends at once; the folder then needs a new key, which a
/// manager's app makes with `rekey`.
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
    let theirs = folder_role(&mut tx, user, folder_id)
        .await?
        .ok_or(ApiError::NotFound)?;
    if theirs == Role::Manage {
        require_another_manager(&mut tx, folder_id, user).await?;
    }
    leave(&mut tx, user, folder_id).await?;
    tx.commit().await?;
    Ok(StatusCode::NO_CONTENT)
}

/// `POST /v1/folders/{folder_id}/rekey`: a manager gives the folder a new key, wrapped for
/// exactly its current members, with the old key sealed under the new one.
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
        let seq = next_seq(&mut tx).await?;
        sqlx::query("INSERT INTO rekey_log (seq, user_id, folder_id) VALUES (?, ?, ?)")
            .bind(seq)
            .bind(key.user_id.0)
            .bind(folder_id.to_string())
            .execute(&mut *tx)
            .await?;
    }
    tx.commit().await?;
    Ok(StatusCode::NO_CONTENT)
}

// MARK: - Items

/// `PUT /v1/items/{item_id}`: saves a new version if it builds on the latest one. Editors
/// can change an item; managers can also share it with more people or take someone's
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
            if current.folder_id != item.folder_id || current.owner != item.owner {
                return Err(ApiError::BadRequest(
                    "items can't move between folders or owners".into(),
                ));
            }
            if item.format < current.format {
                return Err(ApiError::BadRequest(
                    "an item can't go back to an older format".into(),
                ));
            }
            if current.deleted || current.version != base {
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
    let dropped: Vec<UserId> = before.difference(&after).copied().collect();
    for &user in &dropped {
        let removed = user_entry(&mut tx, user)
            .await?
            .is_none_or(|entry| entry.removed);
        dropped_active |= !removed;
    }
    if (!added.is_empty() || dropped_active) && role != Role::Manage {
        return Err(ApiError::Forbidden(
            "you need manage access to change who this login is shared with".into(),
        ));
    }
    for &user in &added {
        require_shareable(&mut tx, user).await?;
    }

    let seq = next_seq(&mut tx).await?;
    sqlx::query(
        "INSERT INTO items (id, folder_id, version, seq, body) VALUES (?, ?, ?, ?, ?)
         ON CONFLICT (id) DO UPDATE SET version = excluded.version, seq = excluded.seq,
                                        body = excluded.body",
    )
    .bind(item_id.to_string())
    .bind(item.folder_id.map(|folder_id| folder_id.to_string()))
    .bind(item.version as i64)
    .bind(seq)
    .bind(serde_json::to_string(&item)?)
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
    for user in dropped {
        let seq = next_seq(&mut tx).await?;
        sqlx::query("INSERT INTO item_leave_log (seq, user_id, item_id) VALUES (?, ?, ?)")
            .bind(seq)
            .bind(user.0)
            .bind(item_id.to_string())
            .execute(&mut *tx)
            .await?;
    }
    tx.commit().await?;
    Ok(Json(item))
}

/// `GET /v1/items/{item_id}/people`: who has the item directly (its owner and everyone
/// it's shared with) and their roles, for anyone who can open it.
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
    Ok(Json(Members { members }))
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

/// Checks what the server can see of an item: its format, that it has a folder or an
/// owner and the matching key copy, and that nobody is listed twice.
fn check_shape(item: &EncryptedItem) -> Result<(), ApiError> {
    let bad = |message: &str| Err(ApiError::BadRequest(message.into()));
    match item.format {
        1 => {
            if item.folder_id.is_none() || item.owner.is_some() || !item.keys.is_empty() {
                return bad("a format 1 item is in a folder and has no key copies");
            }
        }
        2 => {
            let keys = &item.keys;
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

    // Current memberships that began inside this page, with what their join entries carry.
    let joins: Vec<(String, i64)> = sqlx::query_as(
        "SELECT folder_id, joined_seq FROM members
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
                    });
                }
            }
            ("left_item", _, Some(item_id)) => entries.push(SyncEntry::LeftItem {
                seq,
                item_id: ItemId::from_str(&item_id)
                    .map_err(|_| ApiError::Internal(format!("bad stored item id {item_id}")))?,
            }),
            _ => {}
        }
    }

    let rekey_needed: Vec<String> = sqlx::query_scalar(
        "SELECT m.folder_id FROM members m JOIN folders f ON f.id = m.folder_id
         WHERE m.user_id = ? AND m.role = 'manage' AND f.needs_rekey = 1",
    )
    .bind(user)
    .fetch_all(&mut *tx)
    .await?;
    let rekey_needed = rekey_needed
        .iter()
        .map(|folder_id| parse_folder(folder_id))
        .collect::<Result<_, _>>()?;
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
        rekey_needed,
        roles,
    }))
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

/// `user`'s role in a folder, if they're in it.
async fn folder_role(
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

/// What `user` may do with a stored item: the higher of their role in its folder and their
/// direct role (its owner always manages it).
async fn item_role(
    conn: &mut SqliteConnection,
    user: UserId,
    item: &EncryptedItem,
) -> Result<Option<Role>, ApiError> {
    let in_folder = match item.folder_id {
        Some(folder_id) => folder_role(conn, user, folder_id).await?,
        None => None,
    };
    let direct: Option<String> =
        sqlx::query_scalar("SELECT role FROM item_access WHERE user_id = ? AND item_id = ?")
            .bind(user.0)
            .bind(item.id.to_string())
            .fetch_optional(&mut *conn)
            .await?;
    let direct = direct.as_deref().map(parse_role).transpose()?;
    Ok(in_folder.max(direct))
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
async fn require_shareable(conn: &mut SqliteConnection, user: UserId) -> Result<(), ApiError> {
    match user_entry(conn, user).await? {
        Some(entry) if entry.approval.is_some() && !entry.removed => Ok(()),
        _ => Err(ApiError::Forbidden(format!(
            "user {user} is not approved, or was removed"
        ))),
    }
}

/// A folder must keep a manager: someone has to be able to share it and change its key.
async fn require_another_manager(
    conn: &mut SqliteConnection,
    folder_id: FolderId,
    leaving: UserId,
) -> Result<(), ApiError> {
    let others: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM members WHERE folder_id = ? AND role = 'manage' AND user_id != ?",
    )
    .bind(folder_id.to_string())
    .bind(leaving.0)
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

async fn generation(conn: &mut SqliteConnection, folder_id: FolderId) -> Result<u32, ApiError> {
    sqlx::query_scalar("SELECT generation FROM folders WHERE id = ?")
        .bind(folder_id.to_string())
        .fetch_optional(conn)
        .await?
        .ok_or(ApiError::NotFound)
}

/// A folder's current key as one member holds it.
struct MemberFolderKey {
    info: Sealed,
    wrapped_key: WrappedKey,
    generation: u32,
    chain: Vec<KeyLink>,
}

async fn current_key(
    conn: &mut SqliteConnection,
    user: UserId,
    folder_id: FolderId,
) -> Result<Option<MemberFolderKey>, ApiError> {
    let row: Option<(String, String, u32)> = sqlx::query_as(
        "SELECT m.wrapped_key, f.info, f.generation
         FROM members m JOIN folders f ON f.id = m.folder_id
         WHERE m.user_id = ? AND m.folder_id = ?",
    )
    .bind(user.0)
    .bind(folder_id.to_string())
    .fetch_optional(&mut *conn)
    .await?;
    let Some((wrapped_key, info, generation)) = row else {
        return Ok(None);
    };
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
    }))
}

async fn user_roles(conn: &mut SqliteConnection, user: UserId) -> Result<Roles, ApiError> {
    let folders: Vec<(String, String)> =
        sqlx::query_as("SELECT folder_id, role FROM members WHERE user_id = ?")
            .bind(user.0)
            .fetch_all(&mut *conn)
            .await?;
    let items: Vec<(String, String)> =
        sqlx::query_as("SELECT item_id, role FROM item_access WHERE user_id = ?")
            .bind(user.0)
            .fetch_all(&mut *conn)
            .await?;
    Ok(Roles {
        folders: folders
            .into_iter()
            .map(|(folder_id, role)| {
                Ok(FolderRole {
                    folder_id: parse_folder(&folder_id)?,
                    role: parse_role(&role)?,
                })
            })
            .collect::<Result<_, ApiError>>()?,
        items: items
            .into_iter()
            .map(|(item_id, role)| {
                Ok(ItemRole {
                    item_id: ItemId::from_str(&item_id)
                        .map_err(|_| ApiError::Internal(format!("bad stored item id {item_id}")))?,
                    role: parse_role(&role)?,
                })
            })
            .collect::<Result<_, ApiError>>()?,
    })
}

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
    sqlx::query("INSERT INTO membership_log (seq, user_id, folder_id, joined) VALUES (?, ?, ?, 1)")
        .bind(seq)
        .bind(user.0)
        .bind(folder_id.to_string())
        .execute(&mut *conn)
        .await?;
    Ok(())
}

/// Takes `user` out of a folder: their access ends at once, their feed tells their devices
/// to drop it, and the folder is marked for a new key if anyone's still in it.
pub(crate) async fn leave(
    conn: &mut SqliteConnection,
    user: UserId,
    folder_id: FolderId,
) -> Result<(), ApiError> {
    sqlx::query("DELETE FROM members WHERE user_id = ? AND folder_id = ?")
        .bind(user.0)
        .bind(folder_id.to_string())
        .execute(&mut *conn)
        .await?;
    let seq = next_seq(conn).await?;
    sqlx::query("INSERT INTO membership_log (seq, user_id, folder_id, joined) VALUES (?, ?, ?, 0)")
        .bind(seq)
        .bind(user.0)
        .bind(folder_id.to_string())
        .execute(&mut *conn)
        .await?;
    sqlx::query(
        "UPDATE folders SET needs_rekey = 1
         WHERE id = ? AND EXISTS (SELECT 1 FROM members WHERE folder_id = ?)",
    )
    .bind(folder_id.to_string())
    .bind(folder_id.to_string())
    .execute(&mut *conn)
    .await?;
    Ok(())
}

/// Takes away `user`'s direct access to an item, and tells their devices to drop it.
pub(crate) async fn leave_item(
    conn: &mut SqliteConnection,
    user: UserId,
    item_id: &str,
) -> Result<(), ApiError> {
    sqlx::query("DELETE FROM item_access WHERE user_id = ? AND item_id = ?")
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
    Ok(())
}

pub(crate) fn parse_folder(text: &str) -> Result<FolderId, ApiError> {
    FolderId::from_str(text).map_err(|_| ApiError::Internal(format!("bad stored folder id {text}")))
}
