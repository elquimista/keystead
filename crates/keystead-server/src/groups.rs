//! Groups: people shared with as one.
//!
//! The server keeps each group's signed entries, its members with the group's secret
//! wrapped for each, and the chain of older secrets; it can't open any of them. It only
//! accepts entries from the owner or a manager who is in the group, as apps check too.
//! Managers who aren't in the group anymore lose that power here at once, and from the
//! entries at the group's next change.

use std::collections::HashSet;
use std::str::FromStr;

use axum::Json;
use axum::extract::{Path, State};
use axum::http::StatusCode;
use keystead_core::api::{
    AddGroupMemberRequest, CreateGroupRequest, GroupInfo, GroupMemberKey, GroupRekeyRequest,
    Groups, KeyLink, SyncEntry, UpdateGroupRequest,
};
use keystead_core::groups::GroupEntry;
use keystead_core::ids::{GroupId, UserId};
use sqlx::SqliteConnection;

use crate::accounts::{Auth, check_name};
use crate::vault::{
    parse_folder, reconcile, require_another_manager, require_shareable, resend_keys,
};
use crate::{ApiError, AppState, next_seq, user_entry};

/// `POST /v1/groups` (owner): makes a group with its first members, the owner among them.
pub(crate) async fn create_group(
    State(state): State<AppState>,
    auth: Auth,
    Json(request): Json<CreateGroupRequest>,
) -> Result<StatusCode, ApiError> {
    let entry = request.entry;
    let group_id = entry.group_id;
    let mut tx = state.writer.begin().await?;
    if !is_owner(&mut tx, auth.user_id).await? {
        return Err(ApiError::Forbidden("only the owner can make groups".into()));
    }
    if entry.revision != 1 || entry.generation != 1 {
        return Err(ApiError::BadRequest(
            "a new group starts at revision 1 and generation 1".into(),
        ));
    }
    let exists: bool = sqlx::query_scalar("SELECT EXISTS (SELECT 1 FROM team_groups WHERE id = ?)")
        .bind(group_id.to_string())
        .fetch_one(&mut *tx)
        .await?;
    if exists {
        return Err(ApiError::Conflict("group id already exists".into()));
    }
    let members = member_set(&request.members)?;
    if !members.contains(&auth.user_id) {
        return Err(ApiError::BadRequest(
            "whoever makes a group is its first member".into(),
        ));
    }
    check_entry(&mut tx, &entry, None, auth.user_id, &members).await?;
    for &user in &members {
        require_shareable(&mut tx, user).await?;
    }

    sqlx::query("INSERT INTO team_groups (id, generation, needs_rekey) VALUES (?, 1, 0)")
        .bind(group_id.to_string())
        .execute(&mut *tx)
        .await?;
    insert_entry(&mut tx, &entry).await?;
    for member in &request.members {
        add(&mut tx, group_id, member).await?;
    }
    tx.commit().await?;
    Ok(StatusCode::CREATED)
}

/// `GET /v1/groups`: every group, its entries and its members, for anyone on the team.
pub(crate) async fn groups(
    State(state): State<AppState>,
    _auth: Auth,
) -> Result<Json<Groups>, ApiError> {
    let mut conn = state.readers.acquire().await?;
    let rows: Vec<(String, bool)> =
        sqlx::query_as("SELECT id, needs_rekey FROM team_groups ORDER BY rowid")
            .fetch_all(&mut *conn)
            .await?;
    let mut groups = Vec::with_capacity(rows.len());
    for (group_id, needs_rekey) in rows {
        let group_id = parse_group(&group_id)?;
        groups.push(GroupInfo {
            entries: entries(&mut conn, group_id).await?,
            members: group_member_ids(&mut conn, group_id).await?,
            needs_rekey,
        });
    }
    Ok(Json(Groups { groups }))
}

/// `POST /v1/groups/{group_id}/members`: a manager in the group adds someone, with the
/// group's current secret wrapped for them. They get everything shared with the group.
pub(crate) async fn add_group_member(
    State(state): State<AppState>,
    auth: Auth,
    Path(group_id): Path<GroupId>,
    Json(request): Json<AddGroupMemberRequest>,
) -> Result<StatusCode, ApiError> {
    let mut tx = state.writer.begin().await?;
    let latest = latest_entry(&mut tx, group_id).await?;
    let members = group_member_ids(&mut tx, group_id).await?;
    if !members.contains(&auth.user_id) || !can_manage(&mut tx, auth.user_id, &latest).await? {
        return Err(ApiError::Forbidden(
            "only the group's managers in it can add people".into(),
        ));
    }
    if members.contains(&request.user_id) {
        return Err(ApiError::Conflict("already in the group".into()));
    }
    require_shareable(&mut tx, request.user_id).await?;
    let (generation, _) = group_key_state(&mut tx, group_id).await?;
    if request.generation != generation {
        return Err(ApiError::Conflict(
            "the group's key changed; sync and try again".into(),
        ));
    }
    let member = GroupMemberKey {
        user_id: request.user_id,
        wrapped_secret: request.wrapped_secret,
    };
    add(&mut tx, group_id, &member).await?;
    tx.commit().await?;
    Ok(StatusCode::NO_CONTENT)
}

/// `DELETE /v1/groups/{group_id}/members/{user_id}`: the owner or a manager removes
/// someone, or a member leaves. Their access through the group ends at once, and the group
/// needs a new key, which a manager's app makes with `rekey`.
pub(crate) async fn remove_group_member(
    State(state): State<AppState>,
    auth: Auth,
    Path((group_id, user_id)): Path<(GroupId, i64)>,
) -> Result<StatusCode, ApiError> {
    let user = UserId(user_id);
    let mut tx = state.writer.begin().await?;
    let latest = latest_entry(&mut tx, group_id).await?;
    let members = group_member_ids(&mut tx, group_id).await?;
    if !members.contains(&user) {
        return Err(ApiError::NotFound);
    }
    let allowed = user == auth.user_id
        || is_owner(&mut tx, auth.user_id).await?
        || (latest.is_manager(auth.user_id) && members.contains(&auth.user_id));
    if !allowed {
        return Err(ApiError::Forbidden(
            "only the owner and the group's managers can remove people".into(),
        ));
    }
    // Someone left in the group has to be able to give it its new key.
    let mut rest = Vec::new();
    for &member in members.iter().filter(|&&member| member != user) {
        if latest.is_manager(member) || is_owner(&mut tx, member).await? {
            rest.push(member);
        }
    }
    if rest.is_empty() && members.len() > 1 {
        return Err(ApiError::Conflict(
            "a group needs a manager in it; make someone else a manager first".into(),
        ));
    }
    leave_group(&mut tx, user, group_id).await?;
    tx.commit().await?;
    Ok(StatusCode::NO_CONTENT)
}

/// `PUT /v1/groups/{group_id}`: the owner or a manager in the group renames it or changes
/// its managers, with the next revision of its entry and the same key.
pub(crate) async fn update_group(
    State(state): State<AppState>,
    auth: Auth,
    Path(group_id): Path<GroupId>,
    Json(request): Json<UpdateGroupRequest>,
) -> Result<StatusCode, ApiError> {
    let entry = request.entry;
    let mut tx = state.writer.begin().await?;
    let latest = latest_entry(&mut tx, group_id).await?;
    let members = group_member_ids(&mut tx, group_id).await?;
    let manager = latest.is_manager(auth.user_id) && members.contains(&auth.user_id);
    if !manager && !is_owner(&mut tx, auth.user_id).await? {
        return Err(ApiError::Forbidden(
            "only the owner and the group's managers can change it".into(),
        ));
    }
    if entry.group_id != group_id
        || entry.generation != latest.generation
        || entry.encryption != latest.encryption
    {
        return Err(ApiError::BadRequest(
            "changing a group keeps its key; a new key goes through rekey".into(),
        ));
    }
    let members: HashSet<UserId> = members.into_iter().collect();
    check_entry(&mut tx, &entry, Some(&latest), auth.user_id, &members).await?;
    insert_entry(&mut tx, &entry).await?;
    for member in members {
        log(&mut tx, member, group_id, true).await?;
    }
    tx.commit().await?;
    Ok(StatusCode::NO_CONTENT)
}

/// `DELETE /v1/groups/{group_id}`: the owner or a manager in the group deletes it. Its
/// members lose whatever only the group gave them, as if each had left it: their devices
/// forget it, folders shared with it get new keys, and what they could see goes on the
/// passwords to change. Refused while it's the only manager of a folder.
pub(crate) async fn delete_group(
    State(state): State<AppState>,
    auth: Auth,
    Path(group_id): Path<GroupId>,
) -> Result<StatusCode, ApiError> {
    let mut tx = state.writer.begin().await?;
    let latest = latest_entry(&mut tx, group_id).await?;
    let members = group_member_ids(&mut tx, group_id).await?;
    let manager = latest.is_manager(auth.user_id) && members.contains(&auth.user_id);
    if !manager && !is_owner(&mut tx, auth.user_id).await? {
        return Err(ApiError::Forbidden(
            "only the owner and the group's managers can delete it".into(),
        ));
    }
    let folders: Vec<(String, String)> =
        sqlx::query_as("SELECT folder_id, role FROM folder_groups WHERE group_id = ?")
            .bind(group_id.to_string())
            .fetch_all(&mut *tx)
            .await?;
    for (folder_id, role) in &folders {
        if role == "manage" {
            require_another_manager(&mut tx, parse_folder(folder_id)?, None, Some(group_id))
                .await
                .map_err(|_| {
                    ApiError::Conflict(
                        "this group is the only manager of a folder shared with it; make \
                         someone else a manager of that folder first"
                            .into(),
                    )
                })?;
        }
    }
    for table in [
        "folder_groups",
        "item_groups",
        "group_members",
        "group_keys",
        "group_entries",
    ] {
        sqlx::query(&format!("DELETE FROM {table} WHERE group_id = ?"))
            .bind(group_id.to_string())
            .execute(&mut *tx)
            .await?;
    }
    sqlx::query("DELETE FROM team_groups WHERE id = ?")
        .bind(group_id.to_string())
        .execute(&mut *tx)
        .await?;
    let folders: Vec<String> = folders
        .into_iter()
        .map(|(folder_id, _)| folder_id)
        .collect();
    for member in members {
        log(&mut tx, member, group_id, false).await?;
        reconcile(&mut tx, member).await?;
        resend_keys(&mut tx, member, &folders).await?;
    }
    tx.commit().await?;
    Ok(StatusCode::NO_CONTENT)
}

/// `POST /v1/groups/{group_id}/rekey`: a manager in the group gives it a new secret after
/// someone left, wrapped for exactly its current members, with the old one sealed under it.
pub(crate) async fn rekey_group(
    State(state): State<AppState>,
    auth: Auth,
    Path(group_id): Path<GroupId>,
    Json(request): Json<GroupRekeyRequest>,
) -> Result<StatusCode, ApiError> {
    let entry = request.entry;
    let mut tx = state.writer.begin().await?;
    let latest = latest_entry(&mut tx, group_id).await?;
    let members: HashSet<UserId> = group_member_ids(&mut tx, group_id)
        .await?
        .into_iter()
        .collect();
    if !members.contains(&auth.user_id) || !can_manage(&mut tx, auth.user_id, &latest).await? {
        return Err(ApiError::Forbidden(
            "only the group's managers in it can change its key".into(),
        ));
    }
    if entry.group_id != group_id || entry.generation != latest.generation + 1 {
        return Err(ApiError::Conflict(format!(
            "the group's key is at generation {}; sync and try again",
            latest.generation
        )));
    }
    if member_set(&request.members)? != members {
        return Err(ApiError::Conflict(
            "the group's members changed; sync and try again".into(),
        ));
    }
    check_entry(&mut tx, &entry, Some(&latest), auth.user_id, &members).await?;

    sqlx::query("INSERT INTO group_keys (group_id, generation, previous) VALUES (?, ?, ?)")
        .bind(group_id.to_string())
        .bind(entry.generation)
        .bind(serde_json::to_string(&request.previous)?)
        .execute(&mut *tx)
        .await?;
    sqlx::query("UPDATE team_groups SET generation = ?, needs_rekey = 0 WHERE id = ?")
        .bind(entry.generation)
        .bind(group_id.to_string())
        .execute(&mut *tx)
        .await?;
    insert_entry(&mut tx, &entry).await?;
    for member in &request.members {
        sqlx::query(
            "UPDATE group_members SET wrapped_secret = ? WHERE group_id = ? AND user_id = ?",
        )
        .bind(serde_json::to_string(&member.wrapped_secret)?)
        .bind(group_id.to_string())
        .bind(member.user_id.0)
        .execute(&mut *tx)
        .await?;
        log(&mut tx, member.user_id, group_id, true).await?;
    }
    tx.commit().await?;
    Ok(StatusCode::NO_CONTENT)
}

// MARK: - Helpers

/// Checks a new revision as apps will: its number, who signed it and that the signature
/// verifies, its name, and that its managers are all in the group.
async fn check_entry(
    conn: &mut SqliteConnection,
    entry: &GroupEntry,
    previous: Option<&GroupEntry>,
    signer: UserId,
    members: &HashSet<UserId>,
) -> Result<(), ApiError> {
    check_name(&entry.name)?;
    let expected = previous.map_or(1, |previous| previous.revision + 1);
    if entry.revision != expected {
        return Err(ApiError::Conflict(format!(
            "the group is at revision {}; sync and try again",
            expected - 1
        )));
    }
    if entry.signer != signer {
        return Err(ApiError::BadRequest(
            "you can only send entries you signed".into(),
        ));
    }
    if !entry.managers.is_sorted_by(|a, b| a < b) {
        return Err(ApiError::BadRequest("managers must be sorted".into()));
    }
    if !entry
        .managers
        .iter()
        .all(|manager| members.contains(manager))
    {
        return Err(ApiError::BadRequest(
            "a group's managers must be in it".into(),
        ));
    }
    let keys = user_entry(conn, signer)
        .await?
        .ok_or(ApiError::Unauthorized)?
        .keys;
    entry
        .verify(&keys)
        .map_err(|_| ApiError::BadRequest("group entry signature does not verify".into()))
}

fn member_set(members: &[GroupMemberKey]) -> Result<HashSet<UserId>, ApiError> {
    let set: HashSet<UserId> = members.iter().map(|member| member.user_id).collect();
    if set.len() != members.len() {
        return Err(ApiError::BadRequest(
            "each member gets one copy of the group's secret".into(),
        ));
    }
    Ok(set)
}

async fn insert_entry(conn: &mut SqliteConnection, entry: &GroupEntry) -> Result<(), ApiError> {
    sqlx::query("INSERT INTO group_entries (group_id, revision, body) VALUES (?, ?, ?)")
        .bind(entry.group_id.to_string())
        .bind(entry.revision)
        .bind(serde_json::to_string(entry)?)
        .execute(conn)
        .await?;
    Ok(())
}

/// Puts someone in a group: their copy of its secret, a join in their feed before anything
/// it opens, then what the group gives them.
async fn add(
    conn: &mut SqliteConnection,
    group_id: GroupId,
    member: &GroupMemberKey,
) -> Result<(), ApiError> {
    sqlx::query("INSERT INTO group_members (user_id, group_id, wrapped_secret) VALUES (?, ?, ?)")
        .bind(member.user_id.0)
        .bind(group_id.to_string())
        .bind(serde_json::to_string(&member.wrapped_secret)?)
        .execute(&mut *conn)
        .await?;
    log(conn, member.user_id, group_id, true).await?;
    reconcile(conn, member.user_id).await
}

/// Takes `user` out of a group: its keys leave their devices, so does whatever only the
/// group gave them, and the group is marked for a new key if anyone's still in it.
pub(crate) async fn leave_group(
    conn: &mut SqliteConnection,
    user: UserId,
    group_id: GroupId,
) -> Result<(), ApiError> {
    sqlx::query("DELETE FROM group_members WHERE user_id = ? AND group_id = ?")
        .bind(user.0)
        .bind(group_id.to_string())
        .execute(&mut *conn)
        .await?;
    log(conn, user, group_id, false).await?;
    sqlx::query(
        "UPDATE team_groups SET needs_rekey = 1
         WHERE id = ?1 AND EXISTS (SELECT 1 FROM group_members WHERE group_id = ?1)",
    )
    .bind(group_id.to_string())
    .execute(&mut *conn)
    .await?;
    reconcile(conn, user).await?;
    let folders: Vec<String> =
        sqlx::query_scalar("SELECT folder_id FROM folder_groups WHERE group_id = ?")
            .bind(group_id.to_string())
            .fetch_all(&mut *conn)
            .await?;
    resend_keys(conn, user, &folders).await
}

/// A join (or a change, to someone already in it) or a leave, for `user`'s feed.
async fn log(
    conn: &mut SqliteConnection,
    user: UserId,
    group_id: GroupId,
    joined: bool,
) -> Result<(), ApiError> {
    let seq = next_seq(conn).await?;
    sqlx::query("INSERT INTO group_log (seq, user_id, group_id, joined) VALUES (?, ?, ?, ?)")
        .bind(seq)
        .bind(user.0)
        .bind(group_id.to_string())
        .bind(joined)
        .execute(conn)
        .await?;
    Ok(())
}

/// The owner manages every group; managers only one they're in.
async fn can_manage(
    conn: &mut SqliteConnection,
    user: UserId,
    latest: &GroupEntry,
) -> Result<bool, ApiError> {
    Ok(latest.is_manager(user) || is_owner(conn, user).await?)
}

pub(crate) async fn is_owner(conn: &mut SqliteConnection, user: UserId) -> Result<bool, ApiError> {
    Ok(
        sqlx::query_scalar("SELECT is_owner FROM users WHERE id = ?")
            .bind(user.0)
            .fetch_optional(conn)
            .await?
            .unwrap_or(false),
    )
}

async fn entries(
    conn: &mut SqliteConnection,
    group_id: GroupId,
) -> Result<Vec<GroupEntry>, ApiError> {
    let bodies: Vec<String> =
        sqlx::query_scalar("SELECT body FROM group_entries WHERE group_id = ? ORDER BY revision")
            .bind(group_id.to_string())
            .fetch_all(conn)
            .await?;
    bodies
        .iter()
        .map(|body| Ok(serde_json::from_str(body)?))
        .collect()
}

async fn latest_entry(
    conn: &mut SqliteConnection,
    group_id: GroupId,
) -> Result<GroupEntry, ApiError> {
    let body: String = sqlx::query_scalar(
        "SELECT body FROM group_entries WHERE group_id = ? ORDER BY revision DESC LIMIT 1",
    )
    .bind(group_id.to_string())
    .fetch_optional(conn)
    .await?
    .ok_or(ApiError::NotFound)?;
    Ok(serde_json::from_str(&body)?)
}

pub(crate) async fn group_member_ids(
    conn: &mut SqliteConnection,
    group_id: GroupId,
) -> Result<Vec<UserId>, ApiError> {
    let users: Vec<i64> =
        sqlx::query_scalar("SELECT user_id FROM group_members WHERE group_id = ? ORDER BY user_id")
            .bind(group_id.to_string())
            .fetch_all(conn)
            .await?;
    Ok(users.into_iter().map(UserId).collect())
}

/// A group's current key generation, and whether it's waiting for a new one.
pub(crate) async fn group_key_state(
    conn: &mut SqliteConnection,
    group_id: GroupId,
) -> Result<(u32, bool), ApiError> {
    sqlx::query_as("SELECT generation, needs_rekey FROM team_groups WHERE id = ?")
        .bind(group_id.to_string())
        .fetch_optional(conn)
        .await?
        .ok_or(ApiError::NotFound)
}

/// A group as one member holds it, for their feed; `None` once they've left it.
pub(crate) async fn group_state(
    conn: &mut SqliteConnection,
    user: UserId,
    group_id: GroupId,
    seq: i64,
) -> Result<Option<SyncEntry>, ApiError> {
    let wrapped: Option<String> = sqlx::query_scalar(
        "SELECT wrapped_secret FROM group_members WHERE user_id = ? AND group_id = ?",
    )
    .bind(user.0)
    .bind(group_id.to_string())
    .fetch_optional(&mut *conn)
    .await?;
    let Some(wrapped) = wrapped else {
        return Ok(None);
    };
    let (generation, _) = group_key_state(conn, group_id).await?;
    let links: Vec<(u32, String)> = sqlx::query_as(
        "SELECT generation, previous FROM group_keys WHERE group_id = ? ORDER BY generation",
    )
    .bind(group_id.to_string())
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
    Ok(Some(SyncEntry::Group {
        seq,
        group_id,
        entries: entries(conn, group_id).await?,
        generation,
        wrapped_secret: serde_json::from_str(&wrapped)?,
        chain,
    }))
}

/// Groups waiting for a new key that `user` can give them: they're in it, and the owner
/// or one of its managers.
pub(crate) async fn rekey_needed(
    conn: &mut SqliteConnection,
    user: UserId,
) -> Result<Vec<GroupId>, ApiError> {
    let waiting: Vec<String> = sqlx::query_scalar(
        "SELECT g.id FROM team_groups g JOIN group_members gm ON gm.group_id = g.id
         WHERE gm.user_id = ? AND g.needs_rekey = 1 ORDER BY g.id",
    )
    .bind(user.0)
    .fetch_all(&mut *conn)
    .await?;
    let mut groups = Vec::new();
    for group_id in waiting {
        let group_id = parse_group(&group_id)?;
        let latest = latest_entry(conn, group_id).await?;
        if can_manage(conn, user, &latest).await? {
            groups.push(group_id);
        }
    }
    Ok(groups)
}

pub(crate) fn parse_group(text: &str) -> Result<GroupId, ApiError> {
    GroupId::from_str(text).map_err(|_| ApiError::Internal(format!("bad stored group id {text}")))
}
