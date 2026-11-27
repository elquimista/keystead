//! Adding a device to an account from a device the account already has.
//!
//! The server only relays: the new device's name and one-time key one way, and the account
//! secret, sealed for that key, the other. It can't open the secret, and the person checks
//! that the key it relayed is the one the new device made, by typing the code the new
//! device shows into the other one (see `keystead_core::keys::transfer_code`). The new
//! device then registers itself the way recovery does, proving it holds the secret.

use axum::Json;
use axum::extract::{Path, State};
use axum::http::StatusCode;
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use keystead_core::api::{
    ClaimDeviceTransferRequest, ClaimedAccountSecret, DeviceTransfer, DeviceTransferState,
    JoinDeviceTransferRequest, SendAccountSecretRequest,
};
use rand::RngCore;
use rand::rngs::OsRng;

use crate::accounts::{Auth, MAX_DEVICES, check_name, device_count, hash};
use crate::{ApiError, AppState};
use sqlx::AssertSqlSafe;

/// How long a transfer waits for the new device and the approval.
const LIFETIME_SECONDS: i64 = 10 * 60;
/// Unfinished transfers an account can have at once; starting another drops the oldest.
const OPEN_PER_ACCOUNT: i64 = 3;
const NOW: &str = "CAST(strftime('%s', 'now') AS INTEGER)";

/// `POST /v1/device-transfers`: starts adding a device to the caller's account.
pub(crate) async fn start(
    State(state): State<AppState>,
    auth: Auth,
) -> Result<Json<DeviceTransfer>, ApiError> {
    let mut id = [0u8; 16];
    OsRng.fill_bytes(&mut id);
    let id = URL_SAFE_NO_PAD.encode(id);
    let mut token = [0u8; 32];
    OsRng.fill_bytes(&mut token);
    let mut tx = state.writer.begin().await?;
    if device_count(&mut tx, auth.user_id).await? >= MAX_DEVICES {
        return Err(ApiError::Conflict(format!(
            "this account has {MAX_DEVICES} devices, the most it can have. Remove one you no \
             longer use first: in Keystead under People, You, or with `keystead devices \
             remove`"
        )));
    }
    sqlx::query(AssertSqlSafe(format!(
        "DELETE FROM device_transfers WHERE expires_at < {NOW}"
    )))
    .execute(&mut *tx)
    .await?;
    sqlx::query(
        "DELETE FROM device_transfers WHERE user_id = ?1 AND id NOT IN (
             SELECT id FROM device_transfers WHERE user_id = ?1
             ORDER BY expires_at DESC LIMIT ?2)",
    )
    .bind(auth.user_id.0)
    .bind(OPEN_PER_ACCOUNT - 1)
    .execute(&mut *tx)
    .await?;
    sqlx::query(AssertSqlSafe(format!(
        "INSERT INTO device_transfers (id, token_hash, user_id, expires_at)
         VALUES (?, ?, ?, {NOW} + ?)"
    )))
    .bind(&id)
    .bind(&hash(&token)[..])
    .bind(auth.user_id.0)
    .bind(LIFETIME_SECONDS)
    .execute(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(Json(DeviceTransfer {
        id,
        token: URL_SAFE_NO_PAD.encode(token),
        expires_in_seconds: LIFETIME_SECONDS as u64,
    }))
}

/// `POST /v1/device-transfers/join`: the new device gives its name and one-time key.
pub(crate) async fn join(
    State(state): State<AppState>,
    Json(request): Json<JoinDeviceTransferRequest>,
) -> Result<StatusCode, ApiError> {
    check_name(&request.device_name)?;
    let token_hash = token_hash(&request.token)?;
    // Looked up without the writer first (see `AppState::writer`).
    let waiting: bool = sqlx::query_scalar(AssertSqlSafe(format!(
        "SELECT EXISTS (SELECT 1 FROM device_transfers
         WHERE token_hash = ? AND transfer_key IS NULL AND expires_at >= {NOW})"
    )))
    .bind(&token_hash[..])
    .fetch_one(&state.readers)
    .await?;
    if !waiting {
        return Err(ApiError::NotFound);
    }
    let mut tx = state.writer.begin().await?;
    let joined = sqlx::query(AssertSqlSafe(format!(
        "UPDATE device_transfers SET device_name = ?, transfer_key = ?
         WHERE token_hash = ? AND transfer_key IS NULL AND expires_at >= {NOW}"
    )))
    .bind(&request.device_name)
    .bind(serde_json::to_string(&request.transfer_key)?)
    .bind(&token_hash[..])
    .execute(&mut *tx)
    .await?
    .rows_affected();
    if joined == 0 {
        // Unknown, expired, or already joined by a device.
        return Err(ApiError::NotFound);
    }
    tx.commit().await?;
    Ok(StatusCode::NO_CONTENT)
}

/// `GET /v1/device-transfers/{id}`: whether the new device has joined, for the account
/// that started the transfer.
pub(crate) async fn state(
    State(state): State<AppState>,
    auth: Auth,
    Path(id): Path<String>,
) -> Result<Json<DeviceTransferState>, ApiError> {
    let row: Option<(Option<String>, Option<String>)> = sqlx::query_as(AssertSqlSafe(format!(
        "SELECT device_name, transfer_key FROM device_transfers
         WHERE id = ? AND user_id = ? AND expires_at >= {NOW}"
    )))
    .bind(&id)
    .bind(auth.user_id.0)
    .fetch_optional(&state.readers)
    .await?;
    let (device_name, transfer_key) = row.ok_or(ApiError::NotFound)?;
    Ok(Json(DeviceTransferState {
        device_name,
        transfer_key: transfer_key
            .map(|key| serde_json::from_str(&key))
            .transpose()?,
    }))
}

/// `PUT /v1/device-transfers/{id}/secret`: the account secret, sealed for the new device.
pub(crate) async fn send_secret(
    State(state): State<AppState>,
    auth: Auth,
    Path(id): Path<String>,
    Json(request): Json<SendAccountSecretRequest>,
) -> Result<StatusCode, ApiError> {
    let mut tx = state.writer.begin().await?;
    let sent = sqlx::query(AssertSqlSafe(format!(
        "UPDATE device_transfers SET wrapped_secret = ?
         WHERE id = ? AND user_id = ? AND transfer_key IS NOT NULL AND wrapped_secret IS NULL
           AND expires_at >= {NOW}"
    )))
    .bind(serde_json::to_string(&request.wrapped_secret)?)
    .bind(&id)
    .bind(auth.user_id.0)
    .execute(&mut *tx)
    .await?
    .rows_affected();
    if sent == 0 {
        return Err(ApiError::Conflict(
            "no new device is waiting for this: it expired, or already has the secret".into(),
        ));
    }
    tx.commit().await?;
    Ok(StatusCode::NO_CONTENT)
}

/// `POST /v1/device-transfers/claim`: the new device asks for the sealed secret. Once
/// it's handed over, the transfer is gone.
pub(crate) async fn claim(
    State(state): State<AppState>,
    Json(request): Json<ClaimDeviceTransferRequest>,
) -> Result<Json<ClaimedAccountSecret>, ApiError> {
    let token_hash = token_hash(&request.token)?;
    let sealed = format!(
        "SELECT wrapped_secret FROM device_transfers
         WHERE token_hash = ? AND transfer_key IS NOT NULL AND expires_at >= {NOW}"
    );
    // The new device asks every few seconds while it waits. Until the secret is there,
    // and for a token that doesn't work, the answer comes without the writer (see
    // `AppState::writer`).
    let waiting: Option<String> =
        sqlx::query_scalar::<_, Option<String>>(AssertSqlSafe(sealed.as_str()))
            .bind(&token_hash[..])
            .fetch_optional(&state.readers)
            .await?
            .ok_or(ApiError::NotFound)?;
    if waiting.is_none() {
        return Ok(Json(ClaimedAccountSecret {
            wrapped_secret: None,
        }));
    }
    let mut tx = state.writer.begin().await?;
    let wrapped_secret = sqlx::query_scalar::<_, Option<String>>(AssertSqlSafe(sealed.as_str()))
        .bind(&token_hash[..])
        .fetch_optional(&mut *tx)
        .await?
        .ok_or(ApiError::NotFound)?
        .map(|wrapped| serde_json::from_str(&wrapped))
        .transpose()?;
    if wrapped_secret.is_some() {
        sqlx::query("DELETE FROM device_transfers WHERE token_hash = ?")
            .bind(&token_hash[..])
            .execute(&mut *tx)
            .await?;
    }
    tx.commit().await?;
    Ok(Json(ClaimedAccountSecret { wrapped_secret }))
}

/// `DELETE /v1/device-transfers/{id}`: stops waiting for a new device.
pub(crate) async fn cancel(
    State(state): State<AppState>,
    auth: Auth,
    Path(id): Path<String>,
) -> Result<StatusCode, ApiError> {
    sqlx::query("DELETE FROM device_transfers WHERE id = ? AND user_id = ?")
        .bind(&id)
        .bind(auth.user_id.0)
        .execute(&state.writer)
        .await?;
    Ok(StatusCode::NO_CONTENT)
}

fn token_hash(token: &str) -> Result<[u8; 32], ApiError> {
    let token = URL_SAFE_NO_PAD
        .decode(token.trim())
        .map_err(|_| ApiError::NotFound)?;
    Ok(hash(&token))
}
