//! Invites the owner's app approves on its own (0.18.0 and later).
//!
//! An invite line carries a key that never reaches the server. The new person's app uses
//! it to prove that the keys it registers are the ones it made; the owner's app makes the
//! same key again, from the invite's random nonce and the name it was made for, checks
//! the proof, and signs the person's directory entry without a fingerprint check. A server
//! that swapped in keys of its own can't make the proof. Someone who reads the line before
//! the person it was meant for could still join with it: the invite works once, so that
//! person finds it used, and comparing fingerprints remains the stronger check.

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use rand::RngCore;
use rand::rngs::OsRng;
use sha2::Sha256;
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use crate::Error;
use crate::encoding::{Bytes, transcript};
use crate::keys::AccountPublicKeys;

/// How long an invite's nonce is, in bytes.
pub const NONCE_LEN: usize = 16;
/// How long a proof made with an invite's key is, in bytes.
pub const PROOF_LEN: usize = 32;

/// An invite's key: HKDF-SHA256 from the owner's invite seed (see
/// `AccountKeys::invite_key`), for one invite's nonce and name.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct InviteKey([u8; 32]);

impl InviteKey {
    pub(crate) fn derive(seed: &[u8; 32], nonce: &[u8], name: &str) -> Self {
        let mut key = [0u8; 32];
        Hkdf::<Sha256>::new(None, seed)
            .expand(
                &transcript("keystead/invite-key/v1", &[nonce, name.as_bytes()]),
                &mut key,
            )
            .expect("32 bytes is a valid HKDF output length");
        Self(key)
    }

    /// A random nonce for a new invite. It isn't secret: the server keeps it, and gives it
    /// back to the owner with the person who joined.
    pub fn new_nonce() -> [u8; NONCE_LEN] {
        let mut nonce = [0u8; NONCE_LEN];
        OsRng.fill_bytes(&mut nonce);
        nonce
    }

    /// The key as the invite line carries it: unpadded base64url.
    pub fn encode(&self) -> String {
        URL_SAFE_NO_PAD.encode(self.0)
    }

    /// Reads the key back from an invite line.
    pub fn decode(text: &str) -> Result<Self, Error> {
        let bytes = Zeroizing::new(
            URL_SAFE_NO_PAD
                .decode(text.trim())
                .map_err(|_| Error::InvalidKey)?,
        );
        let key: [u8; 32] = bytes.as_slice().try_into().map_err(|_| Error::InvalidKey)?;
        Ok(Self(key))
    }

    /// Proves that `keys` are the ones the person this invite was for registered:
    /// HMAC-SHA256 with the key over `transcript("keystead/invite-proof/v1", encryption
    /// key, signing key)`.
    pub fn prove(&self, keys: &AccountPublicKeys) -> Bytes {
        Bytes(self.mac(keys).finalize().into_bytes().to_vec())
    }

    /// Whether `proof` is this key's for `keys`, compared in constant time.
    pub fn verify(&self, keys: &AccountPublicKeys, proof: &Bytes) -> bool {
        self.mac(keys).verify_slice(proof.as_slice()).is_ok()
    }

    fn mac(&self, keys: &AccountPublicKeys) -> Hmac<Sha256> {
        let mut mac = Hmac::<Sha256>::new_from_slice(&self.0).expect("HMAC takes any key length");
        mac.update(&transcript(
            "keystead/invite-proof/v1",
            &[&keys.encryption.0, &keys.signing.0],
        ));
        mac
    }
}

#[cfg(test)]
mod tests {
    use crate::encoding::Bytes;
    use crate::keys::{AccountKeys, AccountSecret};

    use super::InviteKey;

    #[test]
    fn only_the_invites_key_proves_the_keys_it_was_used_with() {
        let owner = AccountKeys::derive(&AccountSecret::generate());
        let nonce = InviteKey::new_nonce();
        let line = owner.invite_key(&nonce, "Sam").encode();
        let sam = AccountKeys::derive(&AccountSecret::generate()).public();
        let proof = InviteKey::decode(&line).unwrap().prove(&sam);

        // The owner makes the same key again from the nonce and the name.
        assert!(owner.invite_key(&nonce, "Sam").verify(&sam, &proof));
        // Not for other keys, such as a server's own; nor for another invite's nonce or
        // name, so a server can't move a proof to someone else; nor for another owner.
        let server = AccountKeys::derive(&AccountSecret::generate()).public();
        assert!(!owner.invite_key(&nonce, "Sam").verify(&server, &proof));
        let other_nonce = InviteKey::new_nonce();
        assert!(!owner.invite_key(&other_nonce, "Sam").verify(&sam, &proof));
        assert!(!owner.invite_key(&nonce, "Sammy").verify(&sam, &proof));
        let impostor = AccountKeys::derive(&AccountSecret::generate());
        assert!(!impostor.invite_key(&nonce, "Sam").verify(&sam, &proof));
        let mut bent = proof.clone();
        bent.0[0] ^= 1;
        assert!(!owner.invite_key(&nonce, "Sam").verify(&sam, &bent));
        assert!(
            !owner
                .invite_key(&nonce, "Sam")
                .verify(&sam, &Bytes(Vec::new()))
        );
    }

    #[test]
    fn a_key_that_isnt_32_bytes_of_base64url_is_refused() {
        assert!(InviteKey::decode("not a key!").is_err());
        assert!(InviteKey::decode("AAAA").is_err());
        let owner = AccountKeys::derive(&AccountSecret::generate());
        let key = owner.invite_key(&InviteKey::new_nonce(), "Sam").encode();
        assert_eq!(key.len(), 43);
        assert!(InviteKey::decode(&format!(" {key}\n")).is_ok());
    }
}
