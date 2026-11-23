//! Keystead server: stores and relays encrypted data for one organization.

use std::net::SocketAddr;

use axum::{Json, Router, routing::get};
use serde_json::{Value, json};

const DEFAULT_LISTEN: &str = "127.0.0.1:8080";

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let listen: SocketAddr = std::env::var("KEYSTEAD_LISTEN")
        .unwrap_or_else(|_| DEFAULT_LISTEN.to_owned())
        .parse()?;
    let listener = tokio::net::TcpListener::bind(listen).await?;
    println!(
        "keystead-server {} listening on {listen}",
        keystead_core::VERSION
    );
    axum::serve(listener, app()).await?;
    Ok(())
}

fn app() -> Router {
    Router::new().route("/v1/health", get(health))
}

async fn health() -> Json<Value> {
    Json(json!({ "status": "ok", "version": keystead_core::VERSION }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn health_reports_ok_and_version() {
        let Json(body) = health().await;
        assert_eq!(body["status"], "ok");
        assert_eq!(body["version"], keystead_core::VERSION);
    }
}
