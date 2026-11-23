use axum::Json;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use keystead_core::api::{Conflict, ErrorBody};
use keystead_core::items::EncryptedItem;

/// Every way a request can fail. Internal details are logged, never sent to clients.
#[derive(Debug)]
pub enum ApiError {
    BadRequest(String),
    Unauthorized,
    Forbidden(String),
    NotFound,
    Conflict(String),
    /// Someone saved the item first; the body carries their version.
    ItemConflict(Box<EncryptedItem>),
    Internal(String),
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let (status, message) = match self {
            Self::ItemConflict(current) => {
                return (StatusCode::CONFLICT, Json(Conflict { current: *current }))
                    .into_response();
            }
            Self::BadRequest(message) => (StatusCode::BAD_REQUEST, message),
            Self::Unauthorized => (StatusCode::UNAUTHORIZED, "sign in first".into()),
            Self::Forbidden(message) => (StatusCode::FORBIDDEN, message),
            Self::NotFound => (StatusCode::NOT_FOUND, "not found".into()),
            Self::Conflict(message) => (StatusCode::CONFLICT, message),
            Self::Internal(detail) => {
                eprintln!("internal error: {detail}");
                (StatusCode::INTERNAL_SERVER_ERROR, "internal error".into())
            }
        };
        (status, Json(ErrorBody { error: message })).into_response()
    }
}

impl From<sqlx::Error> for ApiError {
    fn from(error: sqlx::Error) -> Self {
        Self::Internal(format!("database: {error}"))
    }
}

impl From<serde_json::Error> for ApiError {
    fn from(error: serde_json::Error) -> Self {
        Self::Internal(format!("stored JSON: {error}"))
    }
}
