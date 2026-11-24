//! Folders, items and the change feed.
//!
//! The server can't open anything, but it decides who receives what: an item goes to the
//! members of its folder, its owner, and everyone it's shared with directly. Those come
//! from the item's own key copies, which its author signed.

use std::collections::HashMap;
use std::str::FromStr;

use axum::Json;
use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use keystead_core::api::{
    AddMemberRequest, CreateFolderRequest, PutItemRequest, SyncEntry, SyncPage,
};
use keystead_core::ids::{FolderId, ItemId, UserId};
use keystead_core::items::{EncryptedItem, ITEM_FORMAT};
use keystead_core::keys::WrappedKey;
use serde::Deserialize;
use sqlx::SqliteConnection;

use crate::accounts::Auth;
use crate::{ApiError, AppState, is_member, next_seq, user_entry};

const DEFAULT_PAGE: i64 = 500;
const MAX_PAGE: i64 = 1_000;

/// One ordered stream: the latest version of each item in the user's folders, then of
/// each item they reach directly (owned or shared with them) outside those folders, plus
/// the user's own joins and leaves. Folders joined after the cursor are left out here;
/// their items ride on the join entry instead. An item reached directly always arrives
/// on its own: whatever gave the access saved a new version, with a new change number.
const FEED_QUERY: &str = "
    SELECT i.seq AS seq, i.body AS body, NULL AS folder_id, NULL AS joined
    FROM items i JOIN members m ON m.folder_id = i.folder_id
    WHERE m.user_id = ?1 AND i.seq > ?2 AND m.joined_seq <= ?2
    UNION ALL
    SELECT i.seq, i.body, NULL, NULL
    FROM item_access a JOIN items i ON i.id = a.item_id
    WHERE a.user_id = ?1 AND i.seq > ?2
      AND NOT EXISTS (SELECT 1 FROM members m WHERE m.user_id = ?1 AND m.folder_id = i.folder_id)
    UNION ALL
    SELECT seq, NULL, folder_id, joined
    FROM membership_log
    WHERE user_id = ?1 AND seq > ?2
    ORDER BY seq
    LIMIT ?3
";

type FeedRow = (i64, Option<String>, Option<String>, Option<bool>);

/// `POST /v1/folders`: creates a folder with the caller as its first member.
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
    )
    .await?;
    tx.commit().await?;
    Ok(StatusCode::CREATED)
}

/// `POST /v1/folders/{folder_id}/members`: any member can add an approved user.
pub(crate) async fn add_member(
    State(state): State<AppState>,
    auth: Auth,
    Path(folder_id): Path<FolderId>,
    Json(request): Json<AddMemberRequest>,
) -> Result<StatusCode, ApiError> {
    let mut tx = state.writer.begin().await?;
    if !is_member(&mut tx, auth.user_id, folder_id).await? {
        return Err(ApiError::Forbidden("not a member of this folder".into()));
    }
    let target = user_entry(&mut tx, request.user_id)
        .await?
        .ok_or(ApiError::NotFound)?;
    if target.approval.is_none() {
        return Err(ApiError::Forbidden("that user is not approved yet".into()));
    }
    if is_member(&mut tx, request.user_id, folder_id).await? {
        return Err(ApiError::Conflict("already a member".into()));
    }
    join(&mut tx, request.user_id, folder_id, &request.wrapped_key).await?;
    tx.commit().await?;
    Ok(StatusCode::NO_CONTENT)
}

/// `PUT /v1/items/{item_id}`: saves a new version if it builds on the latest one. Anyone
/// who can open an item can save it, including to share it with more people; for now
/// nobody can be removed.
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
    let expected_version = match (request.base_version, &current) {
        (None, None) => {
            match item.folder_id {
                Some(folder_id) => {
                    if !is_member(&mut tx, auth.user_id, folder_id).await? {
                        return Err(ApiError::Forbidden("not a member of this folder".into()));
                    }
                }
                None => {
                    if item.owner != Some(auth.user_id) {
                        return Err(ApiError::Forbidden(
                            "an item outside folders starts out as its author's own".into(),
                        ));
                    }
                }
            }
            1
        }
        (None, Some(current)) => return Err(ApiError::ItemConflict(Box::new(current.clone()))),
        (Some(_), None) => return Err(ApiError::NotFound),
        (Some(base), Some(current)) => {
            if !can_open(&mut tx, auth.user_id, current).await? {
                return Err(ApiError::Forbidden(
                    "you don't have access to this item".into(),
                ));
            }
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
            if current
                .keys
                .people
                .iter()
                .any(|person| !item.reaches_directly(person.user_id))
            {
                return Err(ApiError::BadRequest(
                    "removing someone's access to an item isn't possible yet".into(),
                ));
            }
            base + 1
        }
    };
    if item.version != expected_version {
        return Err(ApiError::BadRequest(format!(
            "expected version {expected_version}"
        )));
    }
    for person in &item.keys.people {
        let already = current
            .as_ref()
            .is_some_and(|current| current.reaches_directly(person.user_id));
        if already {
            continue;
        }
        let entry = user_entry(&mut tx, person.user_id).await?;
        if entry.is_none_or(|entry| entry.approval.is_none()) {
            return Err(ApiError::Forbidden(format!(
                "user {} is not approved yet",
                person.user_id
            )));
        }
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
    sqlx::query("DELETE FROM item_access WHERE item_id = ?")
        .bind(item_id.to_string())
        .execute(&mut *tx)
        .await?;
    let direct = item
        .owner
        .into_iter()
        .chain(item.keys.people.iter().map(|person| person.user_id));
    for user in direct {
        sqlx::query("INSERT INTO item_access (user_id, item_id) VALUES (?, ?)")
            .bind(user.0)
            .bind(item_id.to_string())
            .execute(&mut *tx)
            .await?;
    }
    tx.commit().await?;
    Ok(Json(item))
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

/// Whether `user` can open the stored item: through its folder, or directly.
async fn can_open(
    conn: &mut SqliteConnection,
    user: UserId,
    item: &EncryptedItem,
) -> Result<bool, sqlx::Error> {
    if let Some(folder_id) = item.folder_id {
        if is_member(conn, user, folder_id).await? {
            return Ok(true);
        }
    }
    Ok(item.reaches_directly(user))
}

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
    let joins: Vec<(String, i64, String, String)> = sqlx::query_as(
        "SELECT m.folder_id, m.joined_seq, m.wrapped_key, f.info
         FROM members m JOIN folders f ON f.id = m.folder_id
         WHERE m.user_id = ? AND m.joined_seq > ? AND m.joined_seq <= ?",
    )
    .bind(user)
    .bind(cursor)
    .bind(next_cursor)
    .fetch_all(&mut *tx)
    .await?;
    let mut joined = HashMap::new();
    for (folder_id, joined_seq, wrapped_key, info) in joins {
        let items: Vec<String> =
            sqlx::query_scalar("SELECT body FROM items WHERE folder_id = ? AND seq <= ?")
                .bind(&folder_id)
                .bind(next_cursor)
                .fetch_all(&mut *tx)
                .await?;
        let items = items
            .iter()
            .map(|body| serde_json::from_str(body))
            .collect::<Result<Vec<EncryptedItem>, _>>()?;
        let wrapped_key: WrappedKey = serde_json::from_str(&wrapped_key)?;
        joined.insert(
            joined_seq,
            SyncEntry::Joined {
                seq: joined_seq,
                folder_id: parse_folder(&folder_id)?,
                info: serde_json::from_str(&info)?,
                wrapped_key,
                items,
            },
        );
    }
    tx.commit().await?;

    let mut entries = Vec::with_capacity(rows.len());
    for (seq, body, folder_id, was_join) in rows {
        match (body, folder_id, was_join) {
            (Some(body), _, _) => entries.push(SyncEntry::Item {
                seq,
                item: serde_json::from_str(&body)?,
            }),
            // A join that is no longer current is skipped: a later leave follows it.
            (None, Some(_), Some(true)) => entries.extend(joined.remove(&seq)),
            (None, Some(folder_id), _) => entries.push(SyncEntry::Left {
                seq,
                folder_id: parse_folder(&folder_id)?,
            }),
            (None, None, _) => {}
        }
    }
    Ok(Json(SyncPage {
        entries,
        cursor: next_cursor,
        more,
    }))
}

async fn join(
    conn: &mut SqliteConnection,
    user: UserId,
    folder_id: FolderId,
    wrapped_key: &WrappedKey,
) -> Result<(), ApiError> {
    let seq = next_seq(conn).await?;
    sqlx::query(
        "INSERT INTO members (user_id, folder_id, joined_seq, wrapped_key) VALUES (?, ?, ?, ?)",
    )
    .bind(user.0)
    .bind(folder_id.to_string())
    .bind(seq)
    .bind(serde_json::to_string(wrapped_key)?)
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

fn parse_folder(text: &str) -> Result<FolderId, ApiError> {
    FolderId::from_str(text).map_err(|_| ApiError::Internal(format!("bad stored folder id {text}")))
}
