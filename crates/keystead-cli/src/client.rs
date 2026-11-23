//! A small blocking client for the server's JSON API.

use std::fmt;
use std::time::Duration;

use keystead_core::api::{Challenge, ChallengeRequest, Session, SignInRequest};
use keystead_core::ids::{DeviceId, UserId};
use keystead_core::keys::{SoftwareDeviceKey, sign_in_message};
use serde::Serialize;
use serde::de::DeserializeOwned;
use serde_json::Value;

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
        key: &SoftwareDeviceKey,
    ) -> Result<UserId, Failure> {
        let challenge: Challenge =
            self.post("/v1/sign-in/challenge", &ChallengeRequest { device_id })?;
        let signature = key.sign(&sign_in_message(device_id, challenge.challenge.as_slice()));
        let session: Session = self.post(
            "/v1/sign-in",
            &SignInRequest {
                device_id,
                challenge: challenge.challenge,
                signature,
            },
        )?;
        self.token = Some(session.token);
        Ok(session.user_id)
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

/// Decodes a response body. Empty bodies (201, 204) decode as `()`.
fn read<T: DeserializeOwned>(result: Result<ureq::Response, ureq::Error>) -> Result<T, Failure> {
    let unexpected =
        |error: serde_json::Error| Failure::Transport(format!("unexpected response: {error}"));
    match result {
        Ok(response) => {
            let text = response
                .into_string()
                .map_err(|error| Failure::Transport(error.to_string()))?;
            let value = if text.trim().is_empty() {
                Value::Null
            } else {
                serde_json::from_str(&text).map_err(unexpected)?
            };
            serde_json::from_value(value).map_err(unexpected)
        }
        Err(ureq::Error::Status(code, response)) => Err(Failure::Status {
            code,
            body: response.into_json().unwrap_or(Value::Null),
        }),
        Err(error) => Err(Failure::Transport(error.to_string())),
    }
}
