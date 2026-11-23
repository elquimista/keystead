//! Setup, sign-in, invites, owner approval and the directory.

use std::time::{Duration, Instant};

use axum::Json;
use axum::extract::{FromRequestParts, Path, State};
use axum::http::StatusCode;
use axum::http::header::AUTHORIZATION;
use axum::http::request::Parts;
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use keystead_core::api::{
    AcceptInviteRequest, ApprovalRequest, Challenge, ChallengeRequest, Directory, Enrolled, Invite,
    InviteRequest, Session, SetupRequest, SignInRequest,
};
use keystead_core::directory::DirectoryEntry;
use keystead_core::encoding::Bytes;
use keystead_core::ids::{DeviceId, UserId};
use keystead_core::keys::{DevicePublicKey, sign_in_message};
use rand::RngCore;
use rand::rngs::OsRng;
use sha2::{Digest, Sha256};
use sqlx::SqliteConnection;

use crate::{ApiError, AppState, USER_COLUMNS, UserRow, entry_from_row, user_entry};

const SESSION_LIFETIME: Duration = Duration::from_secs(15 * 60);
const CHALLENGE_LIFETIME: Duration = Duration::from_secs(60);
const MAX_NAME_LENGTH: usize = 100;

pub(crate) struct SessionInfo {
    user_id: UserId,
    expires: Instant,
}

pub(crate) struct PendingChallenge {
    device_id: DeviceId,
    expires: Instant,
}

/// The signed-in user behind a request, from its bearer token.
pub(crate) struct Auth {
    pub user_id: UserId,
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
            }),
            _ => Err(ApiError::Unauthorized),
        }
    }
}

/// `POST /v1/setup`: the first admin claims the server and becomes user 1, the owner.
pub(crate) async fn setup(
    State(state): State<AppState>,
    Json(request): Json<SetupRequest>,
) -> Result<Json<Enrolled>, ApiError> {
    check_name(&request.name)?;
    let owner = UserId(1);
    let entry = DirectoryEntry {
        user_id: owner,
        name: request.name.clone(),
        keys: request.keys.clone(),
        approval: Some(request.approval.clone()),
    };
    entry
        .verify(&request.keys)
        .map_err(|_| ApiError::BadRequest("the owner's self-approval does not verify".into()))?;

    let mut tx = state.writer.begin().await?;
    let code: Option<String> =
        sqlx::query_scalar("SELECT value FROM settings WHERE name = 'setup_code'")
            .fetch_optional(&mut *tx)
            .await?;
    match code {
        None => return Err(ApiError::Conflict("this server is already set up".into())),
        Some(code) if code != request.setup_code => {
            return Err(ApiError::Forbidden("wrong setup code".into()));
        }
        Some(_) => {}
    }
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
    add_device(&mut tx, request.device_id, owner, &request.device_key).await?;
    sqlx::query("DELETE FROM settings WHERE name = 'setup_code'")
        .execute(&mut *tx)
        .await?;
    tx.commit().await?;
    Ok(Json(Enrolled { user_id: owner }))
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
    let now = Instant::now();
    challenges.retain(|_, pending| pending.expires > now);
    challenges.insert(
        challenge.clone(),
        PendingChallenge {
            device_id: request.device_id,
            expires: now + CHALLENGE_LIFETIME,
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

    let mut token = [0u8; 32];
    OsRng.fill_bytes(&mut token);
    let mut sessions = state.sessions.lock().expect("session lock poisoned");
    let now = Instant::now();
    sessions.retain(|_, session| session.expires > now);
    sessions.insert(
        hash(&token),
        SessionInfo {
            user_id,
            expires: now + SESSION_LIFETIME,
        },
    );
    Ok(Json(Session {
        token: URL_SAFE_NO_PAD.encode(token),
        user_id,
        expires_in_seconds: SESSION_LIFETIME.as_secs(),
    }))
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
    sqlx::query("INSERT INTO invites (token_hash, name) VALUES (?, ?)")
        .bind(&hash(&token)[..])
        .bind(&request.name)
        .execute(&mut *tx)
        .await?;
    tx.commit().await?;
    Ok(Json(Invite {
        token: URL_SAFE_NO_PAD.encode(token),
    }))
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
    let mut tx = state.writer.begin().await?;
    let name: String =
        sqlx::query_scalar("SELECT name FROM invites WHERE token_hash = ? AND used = 0")
            .bind(&hash(&token)[..])
            .fetch_optional(&mut *tx)
            .await?
            .ok_or_else(|| ApiError::Forbidden("invalid or used invite".into()))?;
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

/// `GET /v1/directory`: everyone, approved or not. Clients trust only approved entries.
pub(crate) async fn directory(
    State(state): State<AppState>,
    _auth: Auth,
) -> Result<Json<Directory>, ApiError> {
    let rows: Vec<UserRow> = sqlx::query_as(&format!("{USER_COLUMNS} ORDER BY id"))
        .fetch_all(&state.readers)
        .await?;
    let entries = rows
        .into_iter()
        .map(entry_from_row)
        .collect::<Result<_, _>>()?;
    Ok(Json(Directory { entries }))
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
) -> Result<(), ApiError> {
    let taken: bool = sqlx::query_scalar("SELECT EXISTS (SELECT 1 FROM devices WHERE id = ?)")
        .bind(device_id.to_string())
        .fetch_one(&mut *conn)
        .await?;
    if taken {
        return Err(ApiError::Conflict("device id already registered".into()));
    }
    sqlx::query("INSERT INTO devices (id, user_id, public_key) VALUES (?, ?, ?)")
        .bind(device_id.to_string())
        .bind(user.0)
        .bind(serde_json::to_string(key)?)
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

fn check_name(name: &str) -> Result<(), ApiError> {
    if name.trim().is_empty() || name.chars().count() > MAX_NAME_LENGTH {
        return Err(ApiError::BadRequest(format!(
            "name must be 1 to {MAX_NAME_LENGTH} characters"
        )));
    }
    Ok(())
}

fn hash(bytes: &[u8]) -> [u8; 32] {
    Sha256::digest(bytes).into()
}
