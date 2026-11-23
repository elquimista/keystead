//! Starts the Keystead server.
//!
//! Configuration comes from environment variables:
//! - `KEYSTEAD_LISTEN`: address to listen on (default `127.0.0.1:8080`)
//! - `KEYSTEAD_DATA`: folder for the database (default `./keystead-data`)

use std::net::SocketAddr;
use std::path::PathBuf;

use keystead_server::AppState;

const DEFAULT_LISTEN: &str = "127.0.0.1:8080";
const DEFAULT_DATA: &str = "keystead-data";

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let listen: SocketAddr = std::env::var("KEYSTEAD_LISTEN")
        .unwrap_or_else(|_| DEFAULT_LISTEN.to_owned())
        .parse()?;
    let data =
        PathBuf::from(std::env::var("KEYSTEAD_DATA").unwrap_or_else(|_| DEFAULT_DATA.to_owned()));
    std::fs::create_dir_all(&data)?;

    let state = AppState::open(&data.join("keystead.sqlite")).await?;
    if let Some(code) = state.pending_setup_code().await? {
        println!("This server isn't set up yet. Setup code: {code}");
        println!("Use it once to become the owner, for example: keystead setup <server> {code}");
    }

    let listener = tokio::net::TcpListener::bind(listen).await?;
    println!(
        "keystead-server {} listening on {listen}, data in {}",
        keystead_core::VERSION,
        data.display()
    );
    axum::serve(listener, keystead_server::router(state)).await?;
    Ok(())
}
