//! Folders, items and the change feed.

use std::collections::HashMap;
use std::str::FromStr;

use axum::Json;
use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use keystead_core::api::{
    AddMemberRequest, CreateFolderRequest, PutItemRequest, SyncEntry, SyncPage,
};
use keystead_core::ids::{FolderId, ItemId, UserId};
use keystead_core::items::EncryptedItem;
use keystead_core::keys::WrappedKey;
use serde::Deserialize;
use sqlx::SqliteConnection;

use crate::accounts::Auth;
use crate::{ApiError, AppState, is_member, next_seq, user_entry};

const DEFAULT_PAGE: i64 = 500;
const MAX_PAGE: i64 = 1_000;

/// One ordered stream: the latest version of each item in the user's folders, plus the
/// user's own joins and leaves. Folders joined after the cursor are left out here;
/// their items ride on the join entry instead.
const FEED_QUERY: &str = "
    SELECT i.seq AS seq, i.body AS body, NULL AS folder_id, NULL AS joined
    FROM items i JOIN members m ON m.folder_id = i.folder_id
    WHERE m.user_id = ?1 AND i.seq > ?2 AND m.joined_seq <= ?2
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

/// `PUT /v1/items/{item_id}`: saves a new version if it builds on the latest one.
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

    let mut tx = state.writer.begin().await?;
    if !is_member(&mut tx, auth.user_id, item.folder_id).await? {
        return Err(ApiError::Forbidden("not a member of this folder".into()));
    }
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
    let expected_version = match (request.base_version, current) {
        (None, None) => 1,
        (None, Some(current)) => return Err(ApiError::ItemConflict(Box::new(current))),
        (Some(_), None) => return Err(ApiError::NotFound),
        (Some(base), Some(current)) => {
            if current.folder_id != item.folder_id {
                return Err(ApiError::BadRequest(
                    "items can't move between folders".into(),
                ));
            }
            if current.deleted || current.version != base {
                return Err(ApiError::ItemConflict(Box::new(current)));
            }
            base + 1
        }
    };
    if item.version != expected_version {
        return Err(ApiError::BadRequest(format!(
            "expected version {expected_version}"
        )));
    }

    let seq = next_seq(&mut tx).await?;
    sqlx::query(
        "INSERT INTO items (id, folder_id, version, seq, body) VALUES (?, ?, ?, ?, ?)
         ON CONFLICT (id) DO UPDATE SET version = excluded.version, seq = excluded.seq,
                                        body = excluded.body",
    )
    .bind(item_id.to_string())
    .bind(item.folder_id.to_string())
    .bind(item.version as i64)
    .bind(seq)
    .bind(serde_json::to_string(&item)?)
    .execute(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(Json(item))
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
