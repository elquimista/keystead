//! A small blocking client for the server's JSON API.

use std::fmt;
use std::io::Read;
use std::sync::{Arc, OnceLock};
use std::time::Duration;

use anyhow::bail;
use keystead_core::api::{Challenge, ChallengeRequest, Session, SignInRequest};
use keystead_core::ids::DeviceId;
use keystead_core::keys::sign_in_message;
use serde::Serialize;
use serde::de::DeserializeOwned;
use serde_json::Value;
use url::{Host, Url};

use crate::DeviceSigner;

/// Whether what goes between this device and `server` is out of the network's reach:
/// over https://, or over http:// to this computer only (localhost, 127.0.0.1, ::1).
/// Over http:// to anywhere else, anyone on the way could read the session token and
/// stand in for the server.
pub fn private_connection(server: &str) -> bool {
    let Ok(url) = Url::parse(server.trim()) else {
        return false;
    };
    match url.scheme() {
        "https" => true,
        "http" => match url.host() {
            Some(Host::Domain(name)) => {
                let name = name.to_ascii_lowercase();
                name == "localhost" || name.ends_with(".localhost")
            }
            Some(Host::Ipv4(address)) => address.is_loopback(),
            Some(Host::Ipv6(address)) => address.is_loopback(),
            None => false,
        },
        _ => false,
    }
}

/// Refuses a server address for a new account or device (0.18.0 and later): anything but
/// https://, except http:// to this computer. Devices added before keep their address,
/// and say it isn't private (see [`private_connection`]).
pub fn check_server_address(server: &str) -> anyhow::Result<()> {
    let web = Url::parse(server.trim())
        .is_ok_and(|url| matches!(url.scheme(), "https" | "http") && url.host().is_some());
    if !web {
        bail!("a server address starts with https://, like https://keys.example.com");
    }
    if !private_connection(server) {
        bail!(
            "Keystead connects only to https:// addresses, so nobody on the network can read \
             or change what it sends; http:// works only for a server on this computer. Use \
             the server's https:// address"
        );
    }
    Ok(())
}

/// TLS settings that leave the server's certificate to the operating system, as a browser
/// does: certificates it trusts count, a company's own included, and revoked ones don't.
/// Made once. `None` if the system's verifier can't be set up; then ureq's bundled roots
/// are used, as before 0.18.0.
fn tls_config() -> Option<Arc<rustls::ClientConfig>> {
    static CONFIG: OnceLock<Option<Arc<rustls::ClientConfig>>> = OnceLock::new();
    CONFIG
        .get_or_init(|| {
            use rustls_platform_verifier::BuilderVerifierExt;
            let provider = Arc::new(rustls::crypto::ring::default_provider());
            let config = rustls::ClientConfig::builder_with_provider(provider)
                .with_safe_default_protocol_versions()
                .ok()?
                .with_platform_verifier()
                .ok()?
                .with_no_client_auth();
            Some(Arc::new(config))
        })
        .clone()
}

/// Why a request failed: the server refused it, or it never got an answer.
#[derive(Debug)]
pub enum Failure {
    Status { code: u16, body: Value },
    Transport(String),
}

impl fmt::Display for Failure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Status { code, body } => match body["error"].as_str() {
                Some(message) => write!(f, "server answered {code}: {message}"),
                None => write!(f, "server answered {code}"),
            },
            Self::Transport(error) => write!(f, "couldn't reach the server: {error}"),
        }
    }
}

impl std::error::Error for Failure {}

#[derive(Clone)]
pub struct Client {
    agent: ureq::Agent,
    base: String,
    token: Option<String>,
}

impl Client {
    pub fn new(server: &str) -> Self {
        // A server that can't be reached says so in 10 seconds; one that answers gets 30
        // for each request, enough for a page of several MB on a slow line.
        let mut agent = ureq::AgentBuilder::new()
            .timeout_connect(Duration::from_secs(10))
            .timeout(Duration::from_secs(30));
        if let Some(tls) = tls_config() {
            agent = agent.tls_config(tls);
        }
        Self {
            agent: agent.build(),
            base: server.trim_end_matches('/').to_owned(),
            token: None,
        }
    }

    /// Signs in by having the device key sign a fresh challenge.
    pub fn sign_in(
        &mut self,
        device_id: DeviceId,
        signer: &dyn DeviceSigner,
    ) -> anyhow::Result<Session> {
        let challenge: Challenge =
            self.post("/v1/sign-in/challenge", &ChallengeRequest { device_id })?;
        let signature = signer.sign(&sign_in_message(device_id, challenge.challenge.as_slice()))?;
        let session: Session = self.post(
            "/v1/sign-in",
            &SignInRequest {
                device_id,
                challenge: challenge.challenge,
                signature,
            },
        )?;
        self.token = Some(session.token.clone());
        Ok(session)
    }

    /// Swaps the session for a fresh one, without the device key. Servers from before
    /// renewing existed answer 404.
    pub fn renew(&mut self) -> Result<Session, Failure> {
        let session: Session = self.post_empty("/v1/sign-in/renew")?;
        self.token = Some(session.token.clone());
        Ok(session)
    }

    pub fn get<T: DeserializeOwned>(
        &self,
        path: &str,
        query: &[(&str, String)],
    ) -> Result<T, Failure> {
        let mut request = self.request("GET", path);
        for (name, value) in query {
            request = request.query(name, value);
        }
        read(request.call())
    }

    pub fn post<B: Serialize, T: DeserializeOwned>(
        &self,
        path: &str,
        body: &B,
    ) -> Result<T, Failure> {
        read(self.request("POST", path).send_json(body))
    }

    /// A POST with no body, for requests that only need the session.
    pub fn post_empty<T: DeserializeOwned>(&self, path: &str) -> Result<T, Failure> {
        read(self.request("POST", path).call())
    }

    pub fn delete<T: DeserializeOwned>(&self, path: &str) -> Result<T, Failure> {
        read(self.request("DELETE", path).call())
    }

    pub fn put<B: Serialize, T: DeserializeOwned>(
        &self,
        path: &str,
        body: &B,
    ) -> Result<T, Failure> {
        read(self.request("PUT", path).send_json(body))
    }

    fn request(&self, method: &str, path: &str) -> ureq::Request {
        let request = self.agent.request(method, &format!("{}{path}", self.base));
        match &self.token {
            Some(token) => request.set("Authorization", &format!("Bearer {token}")),
            None => request,
        }
    }
}

/// The most this reads of one answer. A server on 0.17.0 or later keeps a sync page to a
/// few megabytes; an older one sends a folder someone just joined in one piece, however
/// big, so this is far above any real one and only stops a server sending without end.
const MAX_RESPONSE: u64 = 256 * 1024 * 1024;

/// Decodes a response body. Empty bodies (201, 204) decode as `()`.
fn read<T: DeserializeOwned>(result: Result<ureq::Response, ureq::Error>) -> Result<T, Failure> {
    let unexpected =
        |error: serde_json::Error| Failure::Transport(format!("unexpected response: {error}"));
    match result {
        Ok(response) => {
            let mut body = Vec::new();
            response
                .into_reader()
                .take(MAX_RESPONSE + 1)
                .read_to_end(&mut body)
                .map_err(|error| Failure::Transport(error.to_string()))?;
            if body.len() as u64 > MAX_RESPONSE {
                return Err(Failure::Transport(
                    "the server's answer is too big to read".into(),
                ));
            }
            if body.iter().all(u8::is_ascii_whitespace) {
                serde_json::from_value(Value::Null).map_err(unexpected)
            } else {
                serde_json::from_slice(&body).map_err(unexpected)
            }
        }
        Err(ureq::Error::Status(code, response)) => Err(Failure::Status {
            code,
            body: response.into_json().unwrap_or(Value::Null),
        }),
        Err(error) => Err(Failure::Transport(error.to_string())),
    }
}

#[cfg(test)]
mod tests {
    use super::{Client, Failure, check_server_address, private_connection};

    #[test]
    fn only_https_or_this_computer_is_private() {
        for server in [
            "https://keys.example.com",
            "https://192.168.1.10:8443/",
            "HTTPS://Keys.Example.com",
            "http://localhost:8080",
            "http://LOCALHOST",
            "http://keystead.localhost:8080",
            "http://127.0.0.1:8080",
            "http://127.1.2.3",
            "http://[::1]:8080",
            " http://127.0.0.1:8080/ ",
        ] {
            assert!(private_connection(server), "{server}");
            assert!(check_server_address(server).is_ok(), "{server}");
        }
        for server in [
            "http://keys.example.com",
            "http://192.168.1.10:8080",
            "http://10.0.0.2",
            "http://[fe80::1]:8080",
            "http://localhost.example.com",
            "http://127.0.0.1.example.com",
            "http://user@127.0.0.1.evil.example",
        ] {
            assert!(!private_connection(server), "{server}");
            let error = check_server_address(server).unwrap_err().to_string();
            assert!(error.contains("only to https://"), "{server}: {error}");
        }
        for server in ["keys.example.com", "ftp://keys.example.com", "https://", ""] {
            assert!(!private_connection(server), "{server}");
            let error = check_server_address(server).unwrap_err().to_string();
            assert!(error.contains("starts with https://"), "{server}: {error}");
        }
    }

    /// Reaches real servers: run with `cargo test -p keystead-client -- --ignored`.
    #[test]
    #[ignore = "needs the internet"]
    fn certificates_are_checked_by_the_operating_system() {
        // A certificate the system trusts: the server answers, whatever it says.
        let answer = Client::new("https://example.com").get::<serde_json::Value>("/v1/health", &[]);
        if let Err(Failure::Transport(error)) = answer {
            panic!("example.com: {error}");
        }
        for bad in [
            "https://self-signed.badssl.com",
            "https://expired.badssl.com",
            "https://wrong.host.badssl.com",
        ] {
            let answer = Client::new(bad).get::<serde_json::Value>("/", &[]);
            assert!(matches!(answer, Err(Failure::Transport(_))), "{bad}");
        }
    }
}
