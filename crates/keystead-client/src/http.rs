//! A small blocking client for the server's JSON API.

use std::fmt;
use std::io::Read;
use std::time::Duration;

use keystead_core::api::{Challenge, ChallengeRequest, Session, SignInRequest};
use keystead_core::ids::DeviceId;
use keystead_core::keys::sign_in_message;
use serde::Serialize;
use serde::de::DeserializeOwned;
use serde_json::Value;

use crate::DeviceSigner;

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

pub struct Client {
    agent: ureq::Agent,
    base: String,
    token: Option<String>,
}

impl Client {
    pub fn new(server: &str) -> Self {
        Self {
            agent: ureq::AgentBuilder::new()
                .timeout(Duration::from_secs(30))
                .build(),
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
