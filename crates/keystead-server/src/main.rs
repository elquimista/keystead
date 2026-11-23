//! Starts the Keystead server.
//!
//! Configuration comes from environment variables:
//! - `KEYSTEAD_LISTEN`: address to listen on (default `127.0.0.1:8080`)
//! - `KEYSTEAD_DATA`: folder for the database (default `./keystead-data`)
//!
//! `keystead-server healthcheck` asks a running server for `/v1/health` and exits
//! non-zero if it doesn't answer. Container images without `curl` use it as their health
//! check.

use std::io::{Read, Write};
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr, TcpStream};
use std::path::PathBuf;
use std::time::Duration;

use keystead_server::AppState;

const DEFAULT_LISTEN: &str = "127.0.0.1:8080";
const DEFAULT_DATA: &str = "keystead-data";

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let listen: SocketAddr = std::env::var("KEYSTEAD_LISTEN")
        .unwrap_or_else(|_| DEFAULT_LISTEN.to_owned())
        .parse()?;
    if std::env::args().nth(1).as_deref() == Some("healthcheck") {
        return healthcheck(listen);
    }

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
    axum::serve(listener, keystead_server::router(state))
        .with_graceful_shutdown(shutdown_signal())
        .await?;
    println!("keystead-server stopped");
    Ok(())
}

/// Resolves on Ctrl-C or SIGTERM, which is how `docker stop` asks a container to end. As
/// a container's first process, the server would otherwise ignore SIGTERM.
async fn shutdown_signal() {
    let ctrl_c = async {
        let _ = tokio::signal::ctrl_c().await;
    };
    #[cfg(unix)]
    let terminate = async {
        match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()) {
            Ok(mut signal) => {
                signal.recv().await;
            }
            Err(_) => std::future::pending().await,
        }
    };
    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();
    tokio::select! {
        () = ctrl_c => {}
        () = terminate => {}
    }
}

fn healthcheck(listen: SocketAddr) -> Result<(), Box<dyn std::error::Error>> {
    let target = match listen {
        SocketAddr::V4(addr) if addr.ip().is_unspecified() => {
            SocketAddr::new(Ipv4Addr::LOCALHOST.into(), addr.port())
        }
        SocketAddr::V6(addr) if addr.ip().is_unspecified() => {
            SocketAddr::new(Ipv6Addr::LOCALHOST.into(), addr.port())
        }
        other => other,
    };
    let mut stream = TcpStream::connect_timeout(&target, Duration::from_secs(3))?;
    stream.set_read_timeout(Some(Duration::from_secs(3)))?;
    stream.write_all(b"GET /v1/health HTTP/1.0\r\nHost: localhost\r\n\r\n")?;
    let mut response = String::new();
    stream.read_to_string(&mut response)?;
    let status_line = response.lines().next().unwrap_or_default();
    if status_line.split_whitespace().nth(1) == Some("200") {
        Ok(())
    } else {
        Err(format!("unhealthy: {status_line}").into())
    }
}
