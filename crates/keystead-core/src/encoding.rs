//! How bytes travel in JSON, and how signed messages are built.

use std::fmt;

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use serde::de::Error as _;
use serde::{Deserialize, Deserializer, Serialize, Serializer};

/// Bytes that travel as unpadded base64url text.
#[derive(Clone, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Bytes(pub Vec<u8>);

impl Bytes {
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    pub fn as_slice(&self) -> &[u8] {
        &self.0
    }
}

impl From<Vec<u8>> for Bytes {
    fn from(bytes: Vec<u8>) -> Self {
        Self(bytes)
    }
}

/// Shows only the length, so ciphertexts and keys never end up in logs.
impl fmt::Debug for Bytes {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Bytes({} bytes)", self.0.len())
    }
}

impl Serialize for Bytes {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&URL_SAFE_NO_PAD.encode(&self.0))
    }
}

impl<'de> Deserialize<'de> for Bytes {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let text = String::deserialize(deserializer)?;
        URL_SAFE_NO_PAD
            .decode(text)
            .map(Bytes)
            .map_err(D::Error::custom)
    }
}

/// A 32-byte public key, as unpadded base64url text.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct Key32(pub [u8; 32]);

impl fmt::Debug for Key32 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Key32({})", URL_SAFE_NO_PAD.encode(self.0))
    }
}

impl Serialize for Key32 {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&URL_SAFE_NO_PAD.encode(self.0))
    }
}

impl<'de> Deserialize<'de> for Key32 {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let bytes = Bytes::deserialize(deserializer)?.0;
        let key: [u8; 32] = bytes
            .try_into()
            .map_err(|_| D::Error::custom("expected a 32-byte key"))?;
        Ok(Self(key))
    }
}

/// Builds the exact bytes that get signed or bound as associated data: a domain string,
/// then each part, every one prefixed with its length as a 4-byte big-endian number.
/// The prefixes mean different splits of the same bytes can never collide.
pub fn transcript(domain: &str, parts: &[&[u8]]) -> Vec<u8> {
    let mut out = Vec::new();
    for part in std::iter::once(domain.as_bytes()).chain(parts.iter().copied()) {
        out.extend_from_slice(&(part.len() as u32).to_be_bytes());
        out.extend_from_slice(part);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bytes_are_unpadded_base64url() {
        let json = serde_json::to_string(&Bytes(vec![0xfb, 0xff])).unwrap();
        assert_eq!(json, "\"-_8\"");
        assert_eq!(
            serde_json::from_str::<Bytes>(&json).unwrap().0,
            [0xfb, 0xff]
        );
    }

    #[test]
    fn key32_rejects_the_wrong_length() {
        assert!(serde_json::from_str::<Key32>("\"AAAA\"").is_err());
    }

    #[test]
    fn transcript_separates_parts() {
        assert_ne!(
            transcript("d", &[b"ab", b"c"]),
            transcript("d", &[b"a", b"bc"])
        );
    }
}
