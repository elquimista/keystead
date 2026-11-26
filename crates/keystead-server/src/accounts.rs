//! Setup, sign-in, invites, owner approval, the directory, recovery and devices.

use std::collections::HashMap;
use std::hash::Hash;
use std::time::{Duration, Instant};

use axum::Json;
use axum::extract::{FromRequestParts, Path, Query, State};
use axum::http::StatusCode;
use axum::http::header::AUTHORIZATION;
use axum::http::request::Parts;
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use keystead_core::api::{
    AcceptInviteRequest, ApprovalRequest, ApproveRecoveryRequest, Challenge, ChallengeRequest,
    ClaimRecoveryRequest, DeviceInfo, DeviceList, Directory, Enrolled, EscrowRequest, Invite,
    InviteRequest, Invites, PendingInvite, RecoverRequest, RecoveryChallenge,
    RecoveryChallengeRequest, RecoveryClaimed, RecoveryInProgress, RecoveryStarted, RecoveryState,
    RecoveryTokenRequest, Session, SetupRequest, SignInRequest,
};
use keystead_core::directory::{DirectoryEntry, SignedBefore, verify_escrow_consent};
use keystead_core::encoding::Bytes;
use keystead_core::folders::FolderEntry;
use keystead_core::groups::GroupEntry;
use keystead_core::ids::{DeviceId, UserId};
use keystead_core::items::EncryptedItem;
use keystead_core::keys::{AccountPublicKeys, DevicePublicKey, recovery_message, sign_in_message};
use rand::RngCore;
use rand::rngs::OsRng;
use serde::Deserialize;
use sha2::{Digest, Sha256};
use sqlx::SqliteConnection;
use subtle::ConstantTimeEq;

use crate::groups::{is_owner, leave_group, parse_group};
use crate::vault::{leave, leave_item, parse_folder, recovered};
use crate::{
    ApiError, AppState, USER_COLUMNS, UserRow, all_retired, entry_from_row, stored_key, user_entry,
};

const SESSION_LIFETIME: Duration = Duration::from_secs(15 * 60);
/// How long after signing in with its key a device can keep renewing its session, so a
/// copied session token can't be kept alive for good.
const RENEWAL_LIMIT: Duration = Duration::from_secs(24 * 60 * 60);
const CHALLENGE_LIFETIME: Duration = Duration::from_secs(60);
/// How many sessions one device has at a time. An app has two while it renews, and each
/// command-line command signs in for its own; one more ends the oldest. With this the
/// server keeps a few per device, however often one signs in or renews.
const SESSIONS_PER_DEVICE: usize = 8;
/// How many sign-in challenges wait for one device, and recovery challenges for one
/// account, at a time; one more drops the oldest.
const CHALLENGES_EACH: usize = 4;
/// How long an invite works: long enough for a new colleague to get to it, short enough
/// that a line left in an old message isn't a way in for good.
const INVITE_LASTS: Duration = Duration::from_secs(7 * 24 * 60 * 60);
/// `invites.used` for an invite the owner took back; 1 is one someone joined with.
const TAKEN_BACK: i64 = 2;
const MAX_NAME_LENGTH: usize = 100;
/// How long a line for recovering with the owner's help works.
const RECOVERY_LIFETIME_SECONDS: i64 = 7 * 24 * 60 * 60;
const NOW: &str = "CAST(strftime('%s', 'now') AS INTEGER)";

pub(crate) struct SessionInfo {
    user_id: UserId,
    device_id: DeviceId,
    expires: Instant,
    /// When renewing stops working: `RENEWAL_LIMIT` after the device signed in with its
    /// key, carried over to each renewed session.
    renewable_until: Instant,
}

/// Makes room in `map` for one more of `mine`: drops everything that has run out, then
/// the oldest of `mine` until fewer than `most` are left. What's kept for each device or
/// account is bounded, so the whole map is, and going through it stays quick.
fn make_room<K, V>(
    map: &mut HashMap<K, V>,
    most: usize,
    expires: impl Fn(&V) -> Instant,
    mine: impl Fn(&V) -> bool,
) where
    K: Clone + Eq + Hash,
{
    let now = Instant::now();
    map.retain(|_, value| expires(value) > now);
    let mut own: Vec<(K, Instant)> = map
        .iter()
        .filter(|(_, value)| mine(value))
        .map(|(key, value)| (key.clone(), expires(value)))
        .collect();
    if own.len() < most {
        return;
    }
    own.sort_by_key(|(_, expires)| *expires);
    for (key, _) in &own[..=own.len() - most] {
        map.remove(key);
    }
}

pub(crate) struct PendingChallenge {
    device_id: DeviceId,
    expires: Instant,
}

/// A recovery challenge, for the account it was asked for.
pub(crate) struct PendingRecovery {
    user_id: UserId,
    expires: Instant,
}

/// The signed-in user and device behind a request, from its bearer token.
pub(crate) struct Auth {
    pub user_id: UserId,
    pub device_id: DeviceId,
    pub renewable_until: Instant,
}

impl FromRequestParts<AppState> for Auth {
    type Rejection = ApiError;

    async fn from_request_parts(parts: &mut Parts, state: &AppState) -> Result<Self, ApiError> {
        let token = parts
            .headers
            .get(AUTHORIZATION)
            .and_then(|value| value.to_str().ok())
            .and_then(|value| value.strip_prefix("Bearer "))
            .ok_or(ApiError::Unauthorized)?;
        let bytes = URL_SAFE_NO_PAD
            .decode(token)
            .map_err(|_| ApiError::Unauthorized)?;
        let sessions = state.sessions.lock().expect("session lock poisoned");
        match sessions.get(&hash(&bytes)) {
            Some(session) if session.expires > Instant::now() => Ok(Self {
                user_id: session.user_id,
                device_id: session.device_id,
                renewable_until: session.renewable_until,
            }),
            _ => Err(ApiError::Unauthorized),
        }
    }
}

/// `POST /v1/setup`: whoever runs the server claims it and becomes user 1, the team owner.
pub(crate) async fn setup(
    State(state): State<AppState>,
    Json(request): Json<SetupRequest>,
) -> Result<Json<Enrolled>, ApiError> {
    check_name(&request.name)?;
    let owner = UserId(1);
    let mut entry = DirectoryEntry::new(owner, &request.name, request.keys.clone());
    entry.approval = Some(request.approval.clone());
    entry
        .verify(&request.keys)
        .map_err(|_| ApiError::BadRequest("the owner's self-approval does not verify".into()))?;

    // Checked without the writer first (see `AppState::writer`), then again with it.
    check_setup_code(&mut *state.readers.acquire().await?, &request.setup_code).await?;
    let mut tx = state.writer.begin().await?;
    check_setup_code(&mut tx, &request.setup_code).await?;
    sqlx::query(
        "INSERT INTO users (id, name, encryption_key, signing_key, approval, is_owner)
         VALUES (?, ?, ?, ?, ?, 1)",
    )
    .bind(owner.0)
    .bind(&request.name)
    .bind(&request.keys.encryption.0[..])
    .bind(&request.keys.signing.0[..])
    .bind(request.approval.as_slice())
    .execute(&mut *tx)
    .await?;
    add_device(
        &mut tx,
        request.device_id,
        owner,
        &request.device_key,
        &request.device_name,
    )
    .await?;
    sqlx::query("DELETE FROM settings WHERE name IN ('setup_code', 'setup_code_expires')")
        .execute(&mut *tx)
        .await?;
    tx.commit().await?;
    Ok(Json(Enrolled { user_id: owner }))
}

/// Whether `given` is this server's setup code and still works. The comparison takes the
/// same time wherever the two differ, so how long an answer takes says nothing about the
/// code.
async fn check_setup_code(conn: &mut SqliteConnection, given: &str) -> Result<(), ApiError> {
    let code: Option<(String, bool)> = sqlx::query_as(&format!(
        "SELECT value, COALESCE((SELECT CAST(value AS INTEGER) > {NOW} FROM settings
                                 WHERE name = 'setup_code_expires'), 0)
         FROM settings WHERE name = 'setup_code'"
    ))
    .fetch_optional(conn)
    .await?;
    let Some((code, works)) = code else {
        return Err(ApiError::Conflict("this server is already set up".into()));
    };
    if !bool::from(code.as_bytes().ct_eq(given.as_bytes())) {
        return Err(ApiError::Forbidden("wrong setup code".into()));
    }
    if !works {
        return Err(ApiError::Forbidden(
            "this setup code has run out: it works for a day. Restart the server and use \
             the new code it prints"
                .into(),
        ));
    }
    Ok(())
}

/// `POST /v1/sign-in/challenge`.
pub(crate) async fn challenge(
    State(state): State<AppState>,
    Json(request): Json<ChallengeRequest>,
) -> Result<Json<Challenge>, ApiError> {
    if device_key(&state, request.device_id).await?.is_none() {
        return Err(ApiError::Unauthorized);
    }
    let mut challenge = vec![0u8; 32];
    OsRng.fill_bytes(&mut challenge);
    let mut challenges = state.challenges.lock().expect("challenge lock poisoned");
    make_room(
        &mut challenges,
        CHALLENGES_EACH,
        |pending| pending.expires,
        |pending| pending.device_id == request.device_id,
    );
    challenges.insert(
        challenge.clone(),
        PendingChallenge {
            device_id: request.device_id,
            expires: Instant::now() + CHALLENGE_LIFETIME,
        },
    );
    Ok(Json(Challenge {
        challenge: Bytes(challenge),
    }))
}

/// `POST /v1/sign-in`: checks the device's signature over a fresh challenge. Each
/// challenge works once.
pub(crate) async fn sign_in(
    State(state): State<AppState>,
    Json(request): Json<SignInRequest>,
) -> Result<Json<Session>, ApiError> {
    let pending = state
        .challenges
        .lock()
        .expect("challenge lock poisoned")
        .remove(request.challenge.as_slice());
    match pending {
        Some(pending)
            if pending.device_id == request.device_id && pending.expires > Instant::now() => {}
        _ => return Err(ApiError::Unauthorized),
    }
    let (user_id, key) = device_key(&state, request.device_id)
        .await?
        .ok_or(ApiError::Unauthorized)?;
    key.verify(
        &sign_in_message(request.device_id, request.challenge.as_slice()),
        request.signature.as_slice(),
    )
    .map_err(|_| ApiError::Unauthorized)?;
    let renewable_until = Instant::now() + RENEWAL_LIMIT;
    Ok(Json(
        start_session(&state, user_id, request.device_id, renewable_until).await?,
    ))
}

/// `POST /v1/sign-in/renew`: a fresh session for the device making the request, without
/// its key. A Mac's key needs Touch ID or the Mac's password for every use, so renewing
/// this way lets it ask only when it unlocks. The current session still ends when it
/// would have; signing out or removing the device ends both. Sessions renew for up to
/// `RENEWAL_LIMIT` after the device signed in with its key; then it signs in again.
pub(crate) async fn renew(
    State(state): State<AppState>,
    auth: Auth,
    _body: axum::body::Bytes,
) -> Result<Json<Session>, ApiError> {
    if Instant::now() >= auth.renewable_until {
        return Err(ApiError::Forbidden(
            "this session can't be renewed any more; sign in again".into(),
        ));
    }
    Ok(Json(
        start_session(&state, auth.user_id, auth.device_id, auth.renewable_until).await?,
    ))
}

async fn start_session(
    state: &AppState,
    user_id: UserId,
    device_id: DeviceId,
    renewable_until: Instant,
) -> Result<Session, ApiError> {
    let mut token = [0u8; 32];
    OsRng.fill_bytes(&mut token);
    {
        let mut sessions = state.sessions.lock().expect("session lock poisoned");
        make_room(
            &mut sessions,
            SESSIONS_PER_DEVICE,
            |session| session.expires,
            |session| session.device_id == device_id,
        );
        sessions.insert(
            hash(&token),
            SessionInfo {
                user_id,
                device_id,
                expires: Instant::now() + SESSION_LIFETIME,
                renewable_until,
            },
        );
    }
    // A device removed meanwhile (removing someone, or approving their recovery) has its
    // sessions cleared after its row is gone; a session made after that clearing ends here.
    if device_key(state, device_id).await?.is_none() {
        state
            .sessions
            .lock()
            .expect("session lock poisoned")
            .remove(&hash(&token));
        return Err(ApiError::Unauthorized);
    }
    Ok(Session {
        token: URL_SAFE_NO_PAD.encode(token),
        user_id,
        expires_in_seconds: SESSION_LIFETIME.as_secs(),
    })
}

/// `POST /v1/invites` (owner only).
pub(crate) async fn create_invite(
    State(state): State<AppState>,
    auth: Auth,
    Json(request): Json<InviteRequest>,
) -> Result<Json<Invite>, ApiError> {
    check_name(&request.name)?;
    let mut tx = state.writer.begin().await?;
    require_owner(&mut tx, auth.user_id).await?;
    let mut token = [0u8; 32];
    OsRng.fill_bytes(&mut token);
    // Rows stay, used or not, so an id is never given to another invite: a list of them
    // on the owner's screen can't end up taking back someone else's.
    let expires_at: i64 = sqlx::query_scalar(&format!(
        "INSERT INTO invites (token_hash, name, id, created_at, expires_at)
         VALUES (?, ?, (SELECT COALESCE(MAX(id), 0) + 1 FROM invites), {NOW}, {NOW} + ?)
         RETURNING expires_at"
    ))
    .bind(&hash(&token)[..])
    .bind(&request.name)
    .bind(INVITE_LASTS.as_secs() as i64)
    .fetch_one(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(Json(Invite {
        token: URL_SAFE_NO_PAD.encode(token),
        expires_at: Some(expires_at),
    }))
}

/// `GET /v1/invites` (owner only): the invites not used yet that still work, oldest first.
pub(crate) async fn invites(
    State(state): State<AppState>,
    auth: Auth,
) -> Result<Json<Invites>, ApiError> {
    let mut conn = state.readers.acquire().await?;
    require_owner(&mut conn, auth.user_id).await?;
    let rows: Vec<(i64, String, i64, i64)> = sqlx::query_as(&format!(
        "SELECT id, name, created_at, expires_at FROM invites
         WHERE used = 0 AND expires_at > {NOW} ORDER BY id"
    ))
    .fetch_all(&mut *conn)
    .await?;
    Ok(Json(Invites {
        invites: rows
            .into_iter()
            .map(|(id, name, created_at, expires_at)| PendingInvite {
                id,
                name,
                created_at,
                expires_at,
            })
            .collect(),
    }))
}

/// `DELETE /v1/invites/{id}` (owner only): takes back an invite nobody has used. Its line
/// stops working at once. One already used is a person by now: removing them is
/// `DELETE /v1/users/{id}`.
pub(crate) async fn revoke_invite(
    State(state): State<AppState>,
    auth: Auth,
    Path(id): Path<i64>,
) -> Result<StatusCode, ApiError> {
    let mut tx = state.writer.begin().await?;
    require_owner(&mut tx, auth.user_id).await?;
    let gone = sqlx::query(&format!(
        "UPDATE invites SET used = {TAKEN_BACK} WHERE id = ? AND used = 0"
    ))
    .bind(id)
    .execute(&mut *tx)
    .await?
    .rows_affected();
    tx.commit().await?;
    if gone == 0 {
        return Err(ApiError::NotFound);
    }
    Ok(StatusCode::NO_CONTENT)
}

/// `POST /v1/invites/accept`: registers the invitee's keys and first device. The new
/// user can sign in right away but stays unapproved until the owner checks them.
pub(crate) async fn accept_invite(
    State(state): State<AppState>,
    Json(request): Json<AcceptInviteRequest>,
) -> Result<Json<Enrolled>, ApiError> {
    let token = URL_SAFE_NO_PAD
        .decode(&request.token)
        .map_err(|_| ApiError::Forbidden("invalid invite".into()))?;
    let waiting = format!(
        "SELECT name FROM invites WHERE token_hash = ? AND used = 0 AND expires_at > {NOW}"
    );
    let gone = || {
        ApiError::Forbidden(
            "this invite doesn't work: it was used, revoked, or is more than seven days \
             old. Ask the owner for a new one"
                .into(),
        )
    };
    // Looked up without the writer first (see `AppState::writer`), then again with it.
    sqlx::query_scalar::<_, String>(&waiting)
        .bind(&hash(&token)[..])
        .fetch_optional(&state.readers)
        .await?
        .ok_or_else(gone)?;
    let mut tx = state.writer.begin().await?;
    let name: String = sqlx::query_scalar(&waiting)
        .bind(&hash(&token)[..])
        .fetch_optional(&mut *tx)
        .await?
        .ok_or_else(gone)?;
    sqlx::query("UPDATE invites SET used = 1 WHERE token_hash = ?")
        .bind(&hash(&token)[..])
        .execute(&mut *tx)
        .await?;
    let user_id: i64 = sqlx::query_scalar(
        "INSERT INTO users (name, encryption_key, signing_key) VALUES (?, ?, ?) RETURNING id",
    )
    .bind(&name)
    .bind(&request.keys.encryption.0[..])
    .bind(&request.keys.signing.0[..])
    .fetch_one(&mut *tx)
    .await?;
    add_device(
        &mut tx,
        request.device_id,
        UserId(user_id),
        &request.device_key,
        &request.device_name,
    )
    .await?;
    tx.commit().await?;
    Ok(Json(Enrolled {
        user_id: UserId(user_id),
    }))
}

/// `POST /v1/users/{user_id}/approval` (owner only): stores the owner's signature over
/// the user's directory entry after checking it.
pub(crate) async fn approve(
    State(state): State<AppState>,
    auth: Auth,
    Path(user_id): Path<i64>,
    Json(request): Json<ApprovalRequest>,
) -> Result<StatusCode, ApiError> {
    let mut tx = state.writer.begin().await?;
    let owner = require_owner(&mut tx, auth.user_id).await?;
    let mut entry = user_entry(&mut tx, UserId(user_id))
        .await?
        .ok_or(ApiError::NotFound)?;
    // Keys after a recovery are approved with the recovery, at their revision.
    if entry.revision != 0 {
        return Err(ApiError::Conflict(
            "their keys were replaced in a recovery, and were approved with it".into(),
        ));
    }
    entry.approval = Some(request.approval.clone());
    entry
        .verify(&owner.keys)
        .map_err(|_| ApiError::BadRequest("approval does not verify".into()))?;
    sqlx::query("UPDATE users SET approval = ? WHERE id = ?")
        .bind(request.approval.as_slice())
        .bind(user_id)
        .execute(&mut *tx)
        .await?;
    tx.commit().await?;
    Ok(StatusCode::NO_CONTENT)
}

/// `POST /v1/recover/challenge`: a challenge for a new device to sign with the account
/// key of the account it wants to recover, plus the owner's entry for it to check first.
/// Each challenge works once.
pub(crate) async fn recovery_challenge(
    State(state): State<AppState>,
    Json(request): Json<RecoveryChallengeRequest>,
) -> Result<Json<RecoveryChallenge>, ApiError> {
    let user_id: Option<i64> = sqlx::query_scalar(
        "SELECT id FROM users
             WHERE encryption_key = ? AND signing_key = ? AND removed_at IS NULL",
    )
    .bind(&request.keys.encryption.0[..])
    .bind(&request.keys.signing.0[..])
    .fetch_optional(&state.readers)
    .await?;
    let user_id = user_id.ok_or_else(|| {
        ApiError::Forbidden("this server has no account for that recovery kit".into())
    })?;
    let mut conn = state.readers.acquire().await?;
    let owner = user_entry(&mut conn, UserId(1))
        .await?
        .ok_or_else(|| ApiError::Internal("the server has no owner".into()))?;
    let mut challenge = vec![0u8; 32];
    OsRng.fill_bytes(&mut challenge);
    let mut recoveries = state.recoveries.lock().expect("recovery lock poisoned");
    make_room(
        &mut recoveries,
        CHALLENGES_EACH,
        |pending| pending.expires,
        |pending| pending.user_id == UserId(user_id),
    );
    recoveries.insert(
        challenge.clone(),
        PendingRecovery {
            user_id: UserId(user_id),
            expires: Instant::now() + CHALLENGE_LIFETIME,
        },
    );
    Ok(Json(RecoveryChallenge {
        challenge: Bytes(challenge),
        owner,
    }))
}

/// `POST /v1/recover`: registers a new device for an account whose key signed the
/// challenge, the device id and the device's key. Only the account secret, from a
/// recovery kit, makes that signature.
pub(crate) async fn recover(
    State(state): State<AppState>,
    Json(request): Json<RecoverRequest>,
) -> Result<Json<Enrolled>, ApiError> {
    let pending = state
        .recoveries
        .lock()
        .expect("recovery lock poisoned")
        .remove(request.challenge.as_slice());
    let user = match pending {
        Some(pending) if pending.expires > Instant::now() => pending.user_id,
        _ => return Err(ApiError::Unauthorized),
    };
    let message = recovery_message(
        request.challenge.as_slice(),
        request.device_id,
        &request.device_key,
    );
    // The signature is checked without the writer (see `AppState::writer`): anyone who
    // knows an account's public keys can get a challenge for it.
    let entry = {
        let mut conn = state.readers.acquire().await?;
        user_entry(&mut conn, user).await?
    }
    .ok_or(ApiError::Unauthorized)?;
    entry
        .keys
        .verify(&message, request.signature.as_slice())
        .map_err(|_| ApiError::Unauthorized)?;
    let mut tx = state.writer.begin().await?;
    // Removed, or given new keys in a recovery, since the challenge was given out: a
    // challenge isn't a way back in.
    match user_entry(&mut tx, user).await? {
        Some(now) if !now.removed && now.keys == entry.keys => {}
        _ => return Err(ApiError::Unauthorized),
    }
    add_device(
        &mut tx,
        request.device_id,
        user,
        &request.device_key,
        &request.device_name,
    )
    .await?;
    tx.commit().await?;
    Ok(Json(Enrolled { user_id: user }))
}

/// `GET /v1/devices`: the signed-in user's devices, oldest first.
pub(crate) async fn devices(
    State(state): State<AppState>,
    auth: Auth,
) -> Result<Json<DeviceList>, ApiError> {
    let rows: Vec<(String, String, Option<i64>)> = sqlx::query_as(
        "SELECT id, name, added_at FROM devices WHERE user_id = ?
         ORDER BY COALESCE(added_at, 0), id",
    )
    .bind(auth.user_id.0)
    .fetch_all(&state.readers)
    .await?;
    let devices = rows
        .into_iter()
        .map(|(id, name, added_at)| {
            let device_id: DeviceId = id
                .parse()
                .map_err(|_| ApiError::Internal("stored device id isn't a UUID".into()))?;
            Ok(DeviceInfo {
                current: device_id == auth.device_id,
                device_id,
                name,
                added_at,
            })
        })
        .collect::<Result<_, ApiError>>()?;
    Ok(Json(DeviceList { devices }))
}

/// `DELETE /v1/devices/{device_id}`: removes one of the user's other devices and ends its
/// sessions, for a lost or retired device.
/// `POST /v1/sign-out`: the device making the request removes itself. Its sessions end and
/// its key can't sign in again; the account and its other devices carry on.
///
/// Any body is read and ignored before answering. A reply sent while body bytes are still
/// arriving makes the connection close with unread data, which resets it, and the client
/// can lose the reply.
pub(crate) async fn sign_out(
    State(state): State<AppState>,
    auth: Auth,
    _body: axum::body::Bytes,
) -> Result<StatusCode, ApiError> {
    sqlx::query("DELETE FROM devices WHERE id = ? AND user_id = ?")
        .bind(auth.device_id.to_string())
        .bind(auth.user_id.0)
        .execute(&state.writer)
        .await?;
    state
        .sessions
        .lock()
        .expect("session lock poisoned")
        .retain(|_, session| session.device_id != auth.device_id);
    Ok(StatusCode::NO_CONTENT)
}

pub(crate) async fn remove_device(
    State(state): State<AppState>,
    auth: Auth,
    Path(device_id): Path<DeviceId>,
) -> Result<StatusCode, ApiError> {
    if device_id == auth.device_id {
        return Err(ApiError::Conflict(
            "this is the device you're using; remove it from another one".into(),
        ));
    }
    let removed = sqlx::query("DELETE FROM devices WHERE id = ? AND user_id = ?")
        .bind(device_id.to_string())
        .bind(auth.user_id.0)
        .execute(&state.writer)
        .await?
        .rows_affected();
    if removed == 0 {
        return Err(ApiError::NotFound);
    }
    state
        .sessions
        .lock()
        .expect("session lock poisoned")
        .retain(|_, session| session.device_id != device_id);
    Ok(StatusCode::NO_CONTENT)
}

/// `GET /v1/directory`: everyone, approved or not. Clients trust only approved entries.
pub(crate) async fn directory(
    State(state): State<AppState>,
    _auth: Auth,
) -> Result<Json<Directory>, ApiError> {
    let mut conn = state.readers.acquire().await?;
    let rows: Vec<UserRow> = sqlx::query_as(&format!("{USER_COLUMNS} ORDER BY id"))
        .fetch_all(&mut *conn)
        .await?;
    let mut retired = all_retired(&mut conn).await?;
    let entries = rows
        .into_iter()
        .map(|row| {
            let user_retired = retired.remove(&row.0).unwrap_or_default();
            entry_from_row(row, user_retired)
        })
        .collect::<Result<_, _>>()?;
    Ok(Json(Directory { entries }))
}

/// `DELETE /v1/users/{user_id}` (owner only): removes someone from the team. Their devices
/// stop working at once, they leave every group and folder and lose every login shared
/// with them, and each group and folder they were in is marked for a new key. Their directory entry stays,
/// marked removed, so what they signed before still verifies.
pub(crate) async fn remove_user(
    State(state): State<AppState>,
    auth: Auth,
    Path(user_id): Path<i64>,
) -> Result<StatusCode, ApiError> {
    let user = UserId(user_id);
    let mut tx = state.writer.begin().await?;
    require_owner(&mut tx, auth.user_id).await?;
    if user == auth.user_id {
        return Err(ApiError::BadRequest("the owner can't be removed".into()));
    }
    match user_entry(&mut tx, user).await? {
        Some(entry) if !entry.removed => {}
        // Already removed. Whatever device is still there goes too, so removing again is
        // the way to evict one that got in around the removal (possible up to 0.14.2).
        Some(_) => {
            sqlx::query("DELETE FROM devices WHERE user_id = ?")
                .bind(user.0)
                .execute(&mut *tx)
                .await?;
            tx.commit().await?;
            forget_sessions(&state, user);
            return Err(ApiError::NotFound);
        }
        None => return Err(ApiError::NotFound),
    }
    sqlx::query(
        "UPDATE users SET removed_at = CAST(strftime('%s', 'now') AS INTEGER) WHERE id = ?",
    )
    .bind(user.0)
    .execute(&mut *tx)
    .await?;
    sqlx::query("DELETE FROM devices WHERE user_id = ?")
        .bind(user.0)
        .execute(&mut *tx)
        .await?;
    sqlx::query("DELETE FROM recoveries WHERE user_id = ?")
        .bind(user.0)
        .execute(&mut *tx)
        .await?;

    let groups: Vec<String> =
        sqlx::query_scalar("SELECT group_id FROM group_members WHERE user_id = ?")
            .bind(user.0)
            .fetch_all(&mut *tx)
            .await?;
    for group_id in groups {
        leave_group(&mut tx, user, parse_group(&group_id)?).await?;
    }

    let folders: Vec<String> =
        sqlx::query_scalar("SELECT folder_id FROM members WHERE user_id = ?")
            .bind(user.0)
            .fetch_all(&mut *tx)
            .await?;
    for folder_id in folders {
        leave(&mut tx, user, parse_folder(&folder_id)?).await?;
        // A folder left without a manager who can open it gets one: whoever has been in it
        // longest and can open it. A group that manages it is a manager.
        sqlx::query(
            "UPDATE members SET role = 'manage'
             WHERE folder_id = ?1 AND NOT pending
               AND NOT EXISTS (SELECT 1 FROM members
                               WHERE folder_id = ?1 AND role = 'manage' AND NOT pending)
               AND NOT EXISTS (SELECT 1 FROM folder_groups
                               WHERE folder_id = ?1 AND role = 'manage')
               AND joined_seq = (SELECT MIN(joined_seq) FROM members
                                 WHERE folder_id = ?1 AND NOT pending)",
        )
        .bind(&folder_id)
        .execute(&mut *tx)
        .await?;
    }
    let items: Vec<String> =
        sqlx::query_scalar("SELECT item_id FROM item_access WHERE user_id = ?")
            .bind(user.0)
            .fetch_all(&mut *tx)
            .await?;
    for item_id in items {
        leave_item(&mut tx, user, &item_id).await?;
        // A login outside folders that has lost its owner is managed by everyone it was
        // shared with, unless a group it's shared with manages it.
        sqlx::query(
            "UPDATE item_access SET role = 'manage'
             WHERE item_id = ?1
               AND NOT EXISTS (SELECT 1 FROM item_access WHERE item_id = ?1 AND role = 'manage')
               AND NOT EXISTS (SELECT 1 FROM item_groups WHERE item_id = ?1 AND role = 'manage')
               AND (SELECT folder_id FROM items WHERE id = ?1) IS NULL",
        )
        .bind(&item_id)
        .execute(&mut *tx)
        .await?;
    }
    tx.commit().await?;
    forget_sessions(&state, user);
    Ok(StatusCode::NO_CONTENT)
}

/// Ends a removed person's sessions, and the recovery challenges given out for their
/// account, so neither outlives the removal.
fn forget_sessions(state: &AppState, user: UserId) {
    state
        .sessions
        .lock()
        .expect("session lock poisoned")
        .retain(|_, session| session.user_id != user);
    state
        .recoveries
        .lock()
        .expect("recovery lock poisoned")
        .retain(|_, pending| pending.user_id != user);
}

// MARK: - Recovering with the owner's help

#[derive(Deserialize)]
pub(crate) struct StartRecoveryParams {
    /// Sign out the person's devices now (0.13.0 and later).
    #[serde(default)]
    sign_out_devices: bool,
}

/// `POST /v1/users/{user_id}/recovery?sign_out_devices=true` (owner): starts helping
/// someone who lost every device and their recovery kit. Returns a one-time token to send
/// them; an earlier one stops working. With `sign_out_devices`, their devices stop working
/// at once, so a lost one that still works can't cancel the recovery or change escrow; if
/// they still have one after all, their recovery kit gets them back in.
pub(crate) async fn start_recovery(
    State(state): State<AppState>,
    auth: Auth,
    Path(user_id): Path<i64>,
    Query(params): Query<StartRecoveryParams>,
) -> Result<Json<RecoveryStarted>, ApiError> {
    let user = UserId(user_id);
    let mut tx = state.writer.begin().await?;
    require_owner(&mut tx, auth.user_id).await?;
    if user == auth.user_id {
        return Err(ApiError::BadRequest(
            "nobody can approve new keys for the owner; the owner's recovery kit is the way back"
                .into(),
        ));
    }
    let entry = user_entry(&mut tx, user).await?.ok_or(ApiError::NotFound)?;
    if entry.removed {
        return Err(ApiError::BadRequest(
            "they were removed from the team".into(),
        ));
    }
    if entry.approval.is_none() {
        return Err(ApiError::BadRequest(
            "they aren't approved yet: approve them, or invite them again".into(),
        ));
    }
    let mut token = [0u8; 32];
    OsRng.fill_bytes(&mut token);
    sqlx::query(&format!(
        "INSERT INTO recoveries (user_id, token_hash, expires_at) VALUES (?, ?, {NOW} + ?)
         ON CONFLICT (user_id) DO UPDATE SET token_hash = excluded.token_hash,
             expires_at = excluded.expires_at, approved = 0, encryption_key = NULL,
             signing_key = NULL, device_id = NULL, device_key = NULL, device_name = NULL"
    ))
    .bind(user.0)
    .bind(&hash(&token)[..])
    .bind(RECOVERY_LIFETIME_SECONDS)
    .execute(&mut *tx)
    .await?;
    if params.sign_out_devices {
        sqlx::query("DELETE FROM devices WHERE user_id = ?")
            .bind(user.0)
            .execute(&mut *tx)
            .await?;
    }
    tx.commit().await?;
    if params.sign_out_devices {
        state
            .sessions
            .lock()
            .expect("session lock poisoned")
            .retain(|_, session| session.user_id != user);
    }
    Ok(Json(RecoveryStarted {
        token: URL_SAFE_NO_PAD.encode(token),
    }))
}

/// `GET /v1/users/{user_id}/recovery` (owner): the recovery waiting for approval: the new
/// keys once claimed, and the person's personal key in escrow, if they turned it on.
pub(crate) async fn recovery_in_progress(
    State(state): State<AppState>,
    auth: Auth,
    Path(user_id): Path<i64>,
) -> Result<Json<RecoveryInProgress>, ApiError> {
    let mut conn = state.readers.acquire().await?;
    require_owner(&mut conn, auth.user_id).await?;
    // The new keys, if claimed, and the escrowed personal key, if any.
    type Waiting = (Option<Vec<u8>>, Option<Vec<u8>>, Option<String>);
    let row: Option<Waiting> = sqlx::query_as(&format!(
        "SELECT r.encryption_key, r.signing_key, u.escrow
             FROM recoveries r JOIN users u ON u.id = r.user_id
             WHERE r.user_id = ? AND NOT r.approved AND r.expires_at > {NOW}"
    ))
    .bind(user_id)
    .fetch_optional(&mut *conn)
    .await?;
    let (encryption, signing, escrow) = row.ok_or(ApiError::NotFound)?;
    let keys = match (encryption, signing) {
        (Some(encryption), Some(signing)) => Some(AccountPublicKeys {
            encryption: stored_key(encryption)?,
            signing: stored_key(signing)?,
        }),
        _ => None,
    };
    Ok(Json(RecoveryInProgress {
        keys,
        escrow: escrow.as_deref().map(serde_json::from_str).transpose()?,
        signed: signed_digests(&mut conn, UserId(user_id)).await?,
    }))
}

/// Digests of everything `user` signed that the server holds: every login version, current
/// or in history, deleted or not, and every group change.
async fn signed_digests(conn: &mut SqliteConnection, user: UserId) -> Result<Vec<Bytes>, ApiError> {
    let items: Vec<String> = sqlx::query_scalar(
        "SELECT body FROM items WHERE json_extract(body, '$.author') = ?1
         UNION ALL
         SELECT body FROM item_history WHERE json_extract(body, '$.author') = ?1",
    )
    .bind(user.0)
    .fetch_all(&mut *conn)
    .await?;
    let groups: Vec<String> = sqlx::query_scalar(
        "SELECT body FROM group_entries WHERE json_extract(body, '$.signer') = ?1
         UNION ALL
         SELECT body FROM former_group_entries WHERE json_extract(body, '$.signer') = ?1",
    )
    .bind(user.0)
    .fetch_all(&mut *conn)
    .await?;
    let folders: Vec<String> = sqlx::query_scalar(
        "SELECT body FROM folder_entries WHERE json_extract(body, '$.signer') = ?",
    )
    .bind(user.0)
    .fetch_all(&mut *conn)
    .await?;
    let mut digests = Vec::with_capacity(items.len() + groups.len() + folders.len());
    for body in folders {
        digests.push(serde_json::from_str::<FolderEntry>(&body)?.signature_digest());
    }
    for body in items {
        digests.push(serde_json::from_str::<EncryptedItem>(&body)?.signature_digest());
    }
    for body in groups {
        digests.push(serde_json::from_str::<GroupEntry>(&body)?.signature_digest());
    }
    Ok(digests)
}

/// `GET /v1/users/{user_id}/retired/{revision}`: the owner's list of what someone's keys
/// at that revision had signed when they were replaced, for anyone signed in.
pub(crate) async fn signed_before(
    State(state): State<AppState>,
    _auth: Auth,
    Path((user_id, revision)): Path<(i64, u32)>,
) -> Result<Json<SignedBefore>, ApiError> {
    let list: Option<Option<String>> = sqlx::query_scalar(
        "SELECT signed_before FROM retired_keys WHERE user_id = ? AND revision = ?",
    )
    .bind(user_id)
    .bind(revision)
    .fetch_optional(&state.readers)
    .await?;
    let list = list.flatten().ok_or(ApiError::NotFound)?;
    Ok(Json(serde_json::from_str(&list)?))
}

/// `DELETE /v1/users/{user_id}/recovery`: the owner, or the person on a device they still
/// have, stops a recovery that isn't approved yet.
pub(crate) async fn cancel_recovery(
    State(state): State<AppState>,
    auth: Auth,
    Path(user_id): Path<i64>,
) -> Result<StatusCode, ApiError> {
    let mut tx = state.writer.begin().await?;
    if auth.user_id.0 != user_id {
        require_owner(&mut tx, auth.user_id).await?;
    }
    let removed = sqlx::query("DELETE FROM recoveries WHERE user_id = ? AND NOT approved")
        .bind(user_id)
        .execute(&mut *tx)
        .await?
        .rows_affected();
    if removed == 0 {
        return Err(ApiError::NotFound);
    }
    tx.commit().await?;
    Ok(StatusCode::NO_CONTENT)
}

/// `POST /v1/recovery/claim`: the new device sends the account's new keys and its own
/// device key with the token. Nothing changes until the owner approves them; the same
/// device may send them again, but no other.
pub(crate) async fn claim_recovery(
    State(state): State<AppState>,
    Json(request): Json<ClaimRecoveryRequest>,
) -> Result<Json<RecoveryClaimed>, ApiError> {
    let token = URL_SAFE_NO_PAD
        .decode(request.token.trim())
        .map_err(|_| ApiError::Forbidden("that isn't a recovery line".into()))?;
    if request.device_name.chars().count() > MAX_NAME_LENGTH {
        return Err(ApiError::BadRequest(format!(
            "device name must be at most {MAX_NAME_LENGTH} characters"
        )));
    }
    type Waiting = (i64, Option<String>, Option<Vec<u8>>);
    let waiting = format!(
        "SELECT user_id, device_id, encryption_key FROM recoveries
         WHERE token_hash = ? AND NOT approved AND expires_at > {NOW}"
    );
    let gone = || {
        ApiError::Forbidden(
            "this recovery line was cancelled, has expired or was already approved; ask the \
             owner for a new one"
                .into(),
        )
    };
    // Looked up without the writer first (see `AppState::writer`), then again with it.
    sqlx::query_as::<_, Waiting>(&waiting)
        .bind(&hash(&token)[..])
        .fetch_optional(&state.readers)
        .await?
        .ok_or_else(gone)?;
    let mut tx = state.writer.begin().await?;
    let (user_id, device_id, encryption): Waiting = sqlx::query_as(&waiting)
        .bind(&hash(&token)[..])
        .fetch_optional(&mut *tx)
        .await?
        .ok_or_else(gone)?;
    match device_id {
        Some(device_id) => {
            if device_id != request.device_id.to_string()
                || encryption.as_deref() != Some(&request.keys.encryption.0[..])
            {
                return Err(ApiError::Conflict(
                    "this recovery line was already used on another device; ask the owner to \
                     start again"
                        .into(),
                ));
            }
        }
        None => {
            let taken: bool =
                sqlx::query_scalar("SELECT EXISTS (SELECT 1 FROM devices WHERE id = ?)")
                    .bind(request.device_id.to_string())
                    .fetch_one(&mut *tx)
                    .await?;
            if taken {
                return Err(ApiError::Conflict("device id already registered".into()));
            }
            sqlx::query(
                "UPDATE recoveries SET encryption_key = ?, signing_key = ?, device_id = ?,
                     device_key = ?, device_name = ?
                 WHERE user_id = ?",
            )
            .bind(&request.keys.encryption.0[..])
            .bind(&request.keys.signing.0[..])
            .bind(request.device_id.to_string())
            .bind(serde_json::to_string(&request.device_key)?)
            .bind(request.device_name.trim())
            .bind(user_id)
            .execute(&mut *tx)
            .await?;
        }
    }
    let name: String = sqlx::query_scalar("SELECT name FROM users WHERE id = ?")
        .bind(user_id)
        .fetch_one(&mut *tx)
        .await?;
    tx.commit().await?;
    Ok(Json(RecoveryClaimed {
        user_id: UserId(user_id),
        name,
    }))
}

/// `POST /v1/recovery/state`: whether the owner has approved the new keys; then the new
/// device can sign in. A cancelled or expired recovery answers 404.
pub(crate) async fn recovery_state(
    State(state): State<AppState>,
    Json(request): Json<RecoveryTokenRequest>,
) -> Result<Json<RecoveryState>, ApiError> {
    let token = URL_SAFE_NO_PAD
        .decode(request.token.trim())
        .map_err(|_| ApiError::NotFound)?;
    let approved: bool = sqlx::query_scalar(&format!(
        "SELECT approved FROM recoveries WHERE token_hash = ? AND expires_at > {NOW}"
    ))
    .bind(&hash(&token)[..])
    .fetch_optional(&state.readers)
    .await?
    .ok_or(ApiError::NotFound)?;
    Ok(Json(RecoveryState { approved }))
}

/// `POST /v1/users/{user_id}/recovery/approval` (owner): after checking the new keys'
/// fingerprint with the person, the owner approves them at the next revision. The current
/// keys are retired, kept so what they signed still verifies; the old devices stop working
/// and the new one is registered; everything the old keys could open waits for a copy for
/// the new ones, and gets new keys itself.
pub(crate) async fn approve_recovery(
    State(state): State<AppState>,
    auth: Auth,
    Path(user_id): Path<i64>,
    Json(request): Json<ApproveRecoveryRequest>,
) -> Result<StatusCode, ApiError> {
    let user = UserId(user_id);
    let mut tx = state.writer.begin().await?;
    let owner = require_owner(&mut tx, auth.user_id).await?;
    let entry = user_entry(&mut tx, user).await?.ok_or(ApiError::NotFound)?;
    type Claim = (
        Option<Vec<u8>>,
        Option<Vec<u8>>,
        Option<String>,
        Option<String>,
        Option<String>,
    );
    let claim: Option<Claim> = sqlx::query_as(&format!(
        "SELECT encryption_key, signing_key, device_id, device_key, device_name FROM recoveries
         WHERE user_id = ? AND NOT approved AND expires_at > {NOW}"
    ))
    .bind(user.0)
    .fetch_optional(&mut *tx)
    .await?;
    let (Some(encryption), Some(signing), Some(device_id), Some(device_key), device_name) =
        claim.ok_or(ApiError::NotFound)?
    else {
        return Err(ApiError::Conflict(
            "they haven't used the recovery line on their new device yet".into(),
        ));
    };
    if request.revision != entry.revision + 1 {
        return Err(ApiError::Conflict(format!(
            "their keys are at revision {}; sync and try again",
            entry.revision
        )));
    }
    let old_approval = entry
        .approval
        .clone()
        .ok_or_else(|| ApiError::BadRequest("they were never approved".into()))?;
    let mut approved = entry.clone();
    approved.keys = AccountPublicKeys {
        encryption: stored_key(encryption)?,
        signing: stored_key(signing)?,
    };
    approved.revision = request.revision;
    approved.approval = Some(request.approval.clone());
    approved
        .verify(&owner.keys)
        .map_err(|_| ApiError::BadRequest("approval does not verify".into()))?;
    // What the old keys had signed, as the owner signed it; they verify nothing else.
    let signed = &request.signed_before;
    if signed.user_id != user || signed.revision != entry.revision {
        return Err(ApiError::BadRequest(
            "the list of what their keys signed is for other keys".into(),
        ));
    }
    signed.verify(&owner.keys).map_err(|_| {
        ApiError::BadRequest("the list of what their keys signed doesn't verify".into())
    })?;

    sqlx::query(
        "INSERT INTO retired_keys
             (user_id, revision, name, encryption_key, signing_key, approval, signed_before,
              escrow_consent)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
    )
    .bind(user.0)
    .bind(entry.revision)
    .bind(&entry.name)
    .bind(&entry.keys.encryption.0[..])
    .bind(&entry.keys.signing.0[..])
    .bind(old_approval.as_slice())
    .bind(serde_json::to_string(signed)?)
    // Their agreement to escrow goes with the keys that made it.
    .bind(entry.escrow_consent.as_ref().map(Bytes::as_slice))
    .execute(&mut *tx)
    .await?;
    // The escrowed personal key stays until the new device puts its own in escrow, so if
    // it never gets that far, another recovery still brings everything back.
    sqlx::query(
        "UPDATE users SET encryption_key = ?, signing_key = ?, approval = ?, revision = ?,
             escrow_consent = NULL, recovered_key = ?
         WHERE id = ?",
    )
    .bind(&approved.keys.encryption.0[..])
    .bind(&approved.keys.signing.0[..])
    .bind(request.approval.as_slice())
    .bind(request.revision)
    .bind(
        request
            .personal_key
            .as_ref()
            .map(serde_json::to_string)
            .transpose()?,
    )
    .bind(user.0)
    .execute(&mut *tx)
    .await?;
    sqlx::query("DELETE FROM devices WHERE user_id = ?")
        .bind(user.0)
        .execute(&mut *tx)
        .await?;
    let device_id: DeviceId = device_id
        .parse()
        .map_err(|_| ApiError::Internal("stored device id doesn't parse".into()))?;
    add_device(
        &mut tx,
        device_id,
        user,
        &serde_json::from_str(&device_key)?,
        device_name.as_deref().unwrap_or_default(),
    )
    .await?;
    sqlx::query("UPDATE recoveries SET approved = 1 WHERE user_id = ?")
        .bind(user.0)
        .execute(&mut *tx)
        .await?;
    // Folders in escrow open with the earlier personal key; without it they can't.
    if request.personal_key.is_none() {
        sqlx::query("DELETE FROM folder_escrow WHERE user_id = ?")
            .bind(user.0)
            .execute(&mut *tx)
            .await?;
    }
    recovered(&mut tx, user).await?;
    tx.commit().await?;
    state
        .sessions
        .lock()
        .expect("session lock poisoned")
        .retain(|_, session| session.user_id != user);
    Ok(StatusCode::NO_CONTENT)
}

/// `PUT /v1/escrow`: this account's personal key, wrapped for the owner, so the owner can
/// bring its own logins back after a recovery, with the account's signed agreement. Not
/// for the owner's own account, and not while a recovery for it is waiting.
pub(crate) async fn put_escrow(
    State(state): State<AppState>,
    auth: Auth,
    Json(request): Json<EscrowRequest>,
) -> Result<StatusCode, ApiError> {
    let mut tx = state.writer.begin().await?;
    if is_owner(&mut tx, auth.user_id).await? {
        return Err(ApiError::BadRequest(
            "the owner's own logins can't be in escrow; the owner's recovery kit is the way back"
                .into(),
        ));
    }
    refuse_while_recovering(&mut tx, auth.user_id).await?;
    let me = user_entry(&mut tx, auth.user_id)
        .await?
        .ok_or(ApiError::Unauthorized)?;
    verify_escrow_consent(&me.keys, me.user_id, me.revision, &request.consent)
        .map_err(|_| ApiError::BadRequest("the agreement to escrow doesn't verify".into()))?;
    sqlx::query(
        "UPDATE users SET escrow = ?, escrow_on = 1, escrow_consent = ?, escrow_revision = ?
         WHERE id = ?",
    )
    .bind(serde_json::to_string(&request.wrapped_key)?)
    .bind(request.consent.as_slice())
    .bind(me.revision)
    .bind(auth.user_id.0)
    .execute(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(StatusCode::NO_CONTENT)
}

/// Escrow can't change while a recovery is waiting for approval: whoever has a lost device
/// could otherwise take away, or swap, what the owner is about to bring back.
pub(crate) async fn refuse_while_recovering(
    conn: &mut SqliteConnection,
    user: UserId,
) -> Result<(), ApiError> {
    let recovering: bool = sqlx::query_scalar(&format!(
        "SELECT EXISTS (SELECT 1 FROM recoveries
                        WHERE user_id = ? AND NOT approved AND expires_at > {NOW})"
    ))
    .bind(user.0)
    .fetch_one(conn)
    .await?;
    if recovering {
        return Err(ApiError::Conflict(
            "escrow can't change while a recovery of this account is waiting; cancel it first"
                .into(),
        ));
    }
    Ok(())
}

/// `DELETE /v1/escrow`: turns escrow off and forgets the escrowed key, and the folder
/// keys sealed with it.
pub(crate) async fn delete_escrow(
    State(state): State<AppState>,
    auth: Auth,
) -> Result<StatusCode, ApiError> {
    let mut tx = state.writer.begin().await?;
    refuse_while_recovering(&mut tx, auth.user_id).await?;
    sqlx::query(
        "UPDATE users SET escrow = NULL, escrow_on = 0, escrow_consent = NULL WHERE id = ?",
    )
    .bind(auth.user_id.0)
    .execute(&mut *tx)
    .await?;
    // And the agreements kept with their earlier keys, or their next device after a
    // recovery would take those as still standing.
    sqlx::query("UPDATE retired_keys SET escrow_consent = NULL WHERE user_id = ?")
        .bind(auth.user_id.0)
        .execute(&mut *tx)
        .await?;
    sqlx::query("DELETE FROM folder_escrow WHERE user_id = ?")
        .bind(auth.user_id.0)
        .execute(&mut *tx)
        .await?;
    tx.commit().await?;
    Ok(StatusCode::NO_CONTENT)
}

async fn require_owner(
    conn: &mut SqliteConnection,
    user: UserId,
) -> Result<DirectoryEntry, ApiError> {
    let is_owner: bool = sqlx::query_scalar("SELECT is_owner FROM users WHERE id = ?")
        .bind(user.0)
        .fetch_optional(&mut *conn)
        .await?
        .unwrap_or(false);
    if !is_owner {
        return Err(ApiError::Forbidden("only the owner can do this".into()));
    }
    user_entry(conn, user).await?.ok_or(ApiError::NotFound)
}

async fn add_device(
    conn: &mut SqliteConnection,
    device_id: DeviceId,
    user: UserId,
    key: &DevicePublicKey,
    name: &str,
) -> Result<(), ApiError> {
    if name.chars().count() > MAX_NAME_LENGTH {
        return Err(ApiError::BadRequest(format!(
            "device name must be at most {MAX_NAME_LENGTH} characters"
        )));
    }
    let taken: bool = sqlx::query_scalar("SELECT EXISTS (SELECT 1 FROM devices WHERE id = ?)")
        .bind(device_id.to_string())
        .fetch_one(&mut *conn)
        .await?;
    if taken {
        return Err(ApiError::Conflict("device id already registered".into()));
    }
    sqlx::query(
        "INSERT INTO devices (id, user_id, public_key, name, added_at)
         VALUES (?, ?, ?, ?, CAST(strftime('%s', 'now') AS INTEGER))",
    )
    .bind(device_id.to_string())
    .bind(user.0)
    .bind(serde_json::to_string(key)?)
    .bind(name.trim())
    .execute(conn)
    .await?;
    Ok(())
}

async fn device_key(
    state: &AppState,
    device_id: DeviceId,
) -> Result<Option<(UserId, DevicePublicKey)>, ApiError> {
    let row: Option<(i64, String)> =
        sqlx::query_as("SELECT user_id, public_key FROM devices WHERE id = ?")
            .bind(device_id.to_string())
            .fetch_optional(&state.readers)
            .await?;
    row.map(|(user, key)| Ok((UserId(user), serde_json::from_str(&key)?)))
        .transpose()
}

pub(crate) fn check_name(name: &str) -> Result<(), ApiError> {
    if name.trim().is_empty() || name.chars().count() > MAX_NAME_LENGTH {
        return Err(ApiError::BadRequest(format!(
            "name must be 1 to {MAX_NAME_LENGTH} characters"
        )));
    }
    Ok(())
}

pub(crate) fn hash(bytes: &[u8]) -> [u8; 32] {
    Sha256::digest(bytes).into()
}

#[cfg(test)]
mod tests {
    use axum::Router;
    use axum::body::Body;
    use axum::http::Request;
    use keystead_core::keys::SoftwareDeviceKey;
    use tower::ServiceExt;

    use super::*;

    async fn renew(app: &Router, token: &str) -> (StatusCode, Option<Session>) {
        let request = Request::post("/v1/sign-in/renew")
            .header(AUTHORIZATION, format!("Bearer {token}"))
            .body(Body::empty())
            .unwrap();
        let response = app.clone().oneshot(request).await.unwrap();
        let status = response.status();
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        (status, serde_json::from_slice(&body).ok())
    }

    fn session<'a>(
        sessions: &'a mut HashMap<[u8; 32], SessionInfo>,
        token: &str,
    ) -> &'a mut SessionInfo {
        let bytes = URL_SAFE_NO_PAD.decode(token).unwrap();
        sessions.get_mut(&hash(&bytes)).unwrap()
    }

    /// Each renewed session keeps the limit set when the device signed in with its key,
    /// so renewing stops then, however often it happened; the session itself still works.
    #[tokio::test]
    async fn sessions_renew_only_until_the_limit_set_at_sign_in() {
        let path = std::env::temp_dir().join(format!(
            "keystead-renewal-limit-{}.sqlite",
            std::process::id()
        ));
        let state = AppState::open(&path).await.unwrap();
        let device_id = DeviceId::random();
        let key = serde_json::to_string(&SoftwareDeviceKey::generate().public()).unwrap();
        sqlx::query(
            "INSERT INTO users (id, name, encryption_key, signing_key) VALUES (1, 'Alice', x'', x'')",
        )
        .execute(&state.writer)
        .await
        .unwrap();
        sqlx::query("INSERT INTO devices (id, user_id, public_key) VALUES (?, 1, ?)")
            .bind(device_id.to_string())
            .bind(key)
            .execute(&state.writer)
            .await
            .unwrap();
        let app = crate::router(state.clone());

        let limit = Instant::now() + RENEWAL_LIMIT;
        let signed_in = start_session(&state, UserId(1), device_id, limit)
            .await
            .unwrap();
        let (status, renewed) = renew(&app, &signed_in.token).await;
        assert_eq!(status, StatusCode::OK);
        let renewed = renewed.unwrap();
        let (status, again) = renew(&app, &renewed.token).await;
        assert_eq!(status, StatusCode::OK);
        let again = again.unwrap();
        {
            let mut sessions = state.sessions.lock().unwrap();
            assert_eq!(session(&mut sessions, &again.token).renewable_until, limit);
            // As if a day had passed since signing in.
            session(&mut sessions, &again.token).renewable_until = Instant::now();
        }
        let (status, _) = renew(&app, &again.token).await;
        assert_eq!(status, StatusCode::FORBIDDEN);
        let request = Request::get("/v1/devices")
            .header(AUTHORIZATION, format!("Bearer {}", again.token))
            .body(Body::empty())
            .unwrap();
        let response = app.clone().oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);

        for suffix in ["", "-wal", "-shm"] {
            let _ = std::fs::remove_file(format!("{}{suffix}", path.display()));
        }
    }
}
