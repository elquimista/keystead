//! Prototype: how fast can a device unlock a vault and search it?
//!
//! Models the design's key chain. The account key pair opens one key per folder (HPKE),
//! and folder keys open items (XChaCha20-Poly1305). Each item has a small overview with
//! the searchable fields, decrypted at unlock, and details (password, notes) that stay
//! encrypted until used.

use std::fmt;
use std::time::{Duration, Instant};

use chacha20poly1305::aead::{Aead, AeadCore, KeyInit, Payload};
use chacha20poly1305::{Key, XChaCha20Poly1305, XNonce};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use hpke::aead::ChaCha20Poly1305;
use hpke::kdf::HkdfSha256;
use hpke::kem::X25519HkdfSha256;
use hpke::{Kem as _, OpModeR, OpModeS};
use nucleo_matcher::Matcher;
use nucleo_matcher::pattern::{CaseMatching, Normalization, Pattern};
use rand::rngs::{OsRng, StdRng};
use rand::{Rng, RngCore, SeedableRng};
use serde::{Deserialize, Serialize};

type Kem = X25519HkdfSha256;
type KemPrivateKey = <Kem as hpke::Kem>::PrivateKey;
type KemPublicKey = <Kem as hpke::Kem>::PublicKey;
type EncappedKey = <Kem as hpke::Kem>::EncappedKey;

const FOLDER_KEY_INFO: &[u8] = b"keystead/folder-key/v1";

/// The account key pair, derived from the 32-byte account key that the device key
/// unwraps (see the Secure Enclave prototype).
pub struct Account {
    private_key: KemPrivateKey,
    public_key: KemPublicKey,
}

impl Account {
    pub fn from_account_key(account_key: &[u8; 32]) -> Self {
        let (private_key, public_key) = Kem::derive_keypair(account_key);
        Self {
            private_key,
            public_key,
        }
    }
}

/// The searchable fields of an item.
#[derive(Serialize, Deserialize)]
pub struct Overview {
    pub name: String,
    pub username: String,
    pub url: String,
    pub tags: Vec<String>,
}

#[derive(Serialize, Deserialize)]
struct Details {
    password: String,
    notes: String,
}

struct WrappedFolderKey {
    folder_id: u32,
    encapped_key: EncappedKey,
    ciphertext: Vec<u8>,
}

struct EncryptedItem {
    id: u32,
    folder_id: u32,
    overview_nonce: XNonce,
    overview: Vec<u8>,
    details_nonce: XNonce,
    details: Vec<u8>,
    signature: Signature,
}

/// Everything a device stores locally: wrapped folder keys and encrypted items.
pub struct Vault {
    folder_keys: Vec<WrappedFolderKey>,
    items: Vec<EncryptedItem>,
    author: VerifyingKey,
}

#[derive(Debug, PartialEq, Eq)]
pub enum UnlockError {
    FolderKey(u32),
    Item(u32),
    Signature(u32),
}

impl fmt::Display for UnlockError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::FolderKey(id) => write!(f, "folder key {id} could not be opened"),
            Self::Item(id) => write!(f, "item {id} could not be opened"),
            Self::Signature(id) => write!(f, "item {id} has an invalid signature"),
        }
    }
}

impl std::error::Error for UnlockError {}

/// How long each unlock step took.
#[derive(Default)]
pub struct UnlockTimings {
    pub folder_keys: Duration,
    pub overviews: Duration,
    pub parse: Duration,
    pub index: Duration,
}

impl UnlockTimings {
    pub fn total(&self) -> Duration {
        self.folder_keys + self.overviews + self.parse + self.index
    }
}

impl Vault {
    /// Builds a vault of `item_count` items spread over `folder_count` folders, all
    /// shared with `account`. `seed` makes the item contents repeatable; keys and nonces
    /// are always fresh.
    pub fn generate(account: &Account, item_count: usize, folder_count: usize, seed: u64) -> Self {
        let mut content = StdRng::seed_from_u64(seed);
        let author = SigningKey::generate(&mut OsRng);

        let mut folder_keys = Vec::with_capacity(folder_count);
        let mut folder_ciphers = Vec::with_capacity(folder_count);
        for folder_id in 0..folder_count as u32 {
            let mut key = [0u8; 32];
            OsRng.fill_bytes(&mut key);
            let (encapped_key, ciphertext) =
                hpke::single_shot_seal::<ChaCha20Poly1305, HkdfSha256, Kem>(
                    &OpModeS::Base,
                    &account.public_key,
                    FOLDER_KEY_INFO,
                    &key,
                    &folder_id.to_le_bytes(),
                )
                .expect("sealing a folder key");
            folder_keys.push(WrappedFolderKey {
                folder_id,
                encapped_key,
                ciphertext,
            });
            folder_ciphers.push(XChaCha20Poly1305::new(Key::from_slice(&key)));
        }

        let items = (0..item_count as u32)
            .map(|id| {
                let folder_id = content.gen_range(0..folder_count as u32);
                let cipher = &folder_ciphers[folder_id as usize];
                let overview = serde_json::to_vec(&random_overview(&mut content, id))
                    .expect("serializing an overview");
                let details =
                    serde_json::to_vec(&random_details(&mut content)).expect("serializing details");
                let (overview_nonce, overview) =
                    seal(cipher, id, folder_id, b"overview", &overview);
                let (details_nonce, details) = seal(cipher, id, folder_id, b"details", &details);
                let signature = author.sign(&signed_bytes(id, folder_id, &overview, &details));
                EncryptedItem {
                    id,
                    folder_id,
                    overview_nonce,
                    overview,
                    details_nonce,
                    details,
                    signature,
                }
            })
            .collect();

        Self {
            folder_keys,
            items,
            author: author.verifying_key(),
        }
    }

    pub fn item_count(&self) -> usize {
        self.items.len()
    }

    pub fn folder_count(&self) -> usize {
        self.folder_keys.len()
    }

    /// Opens every folder key, decrypts every overview and builds the search index.
    /// Folder and item ids are assumed to match their positions, which `generate`
    /// guarantees.
    pub fn unlock(&self, account: &Account) -> Result<(Unlocked<'_>, UnlockTimings), UnlockError> {
        let mut timings = UnlockTimings::default();

        let start = Instant::now();
        let ciphers = self
            .folder_keys
            .iter()
            .map(|wrapped| {
                let key = hpke::single_shot_open::<ChaCha20Poly1305, HkdfSha256, Kem>(
                    &OpModeR::Base,
                    &account.private_key,
                    &wrapped.encapped_key,
                    FOLDER_KEY_INFO,
                    &wrapped.ciphertext,
                    &wrapped.folder_id.to_le_bytes(),
                )
                .map_err(|_| UnlockError::FolderKey(wrapped.folder_id))?;
                if key.len() != 32 {
                    return Err(UnlockError::FolderKey(wrapped.folder_id));
                }
                Ok(XChaCha20Poly1305::new(Key::from_slice(&key)))
            })
            .collect::<Result<Vec<_>, _>>()?;
        timings.folder_keys = start.elapsed();

        let start = Instant::now();
        let plaintexts = self
            .items
            .iter()
            .map(|item| {
                let cipher = ciphers
                    .get(item.folder_id as usize)
                    .ok_or(UnlockError::Item(item.id))?;
                let aad = item_aad(item.id, item.folder_id, b"overview");
                cipher
                    .decrypt(
                        &item.overview_nonce,
                        Payload {
                            msg: &item.overview,
                            aad: &aad,
                        },
                    )
                    .map_err(|_| UnlockError::Item(item.id))
            })
            .collect::<Result<Vec<_>, _>>()?;
        timings.overviews = start.elapsed();

        let start = Instant::now();
        let overviews = plaintexts
            .iter()
            .zip(&self.items)
            .map(|(bytes, item)| {
                serde_json::from_slice::<Overview>(bytes).map_err(|_| UnlockError::Item(item.id))
            })
            .collect::<Result<Vec<_>, _>>()?;
        timings.parse = start.elapsed();

        let start = Instant::now();
        let entries = overviews
            .iter()
            .zip(&self.items)
            .map(|(overview, item)| Entry {
                item_id: item.id,
                haystack: format!(
                    "{} {} {} {}",
                    overview.name,
                    overview.username,
                    overview.url,
                    overview.tags.join(" ")
                ),
            })
            .collect();
        timings.index = start.elapsed();

        let unlocked = Unlocked {
            vault: self,
            ciphers,
            index: SearchIndex { entries },
        };
        Ok((unlocked, timings))
    }

    /// Checks the signatures of the first `count` items and returns how long it took.
    pub fn verify_signatures(&self, count: usize) -> Result<Duration, UnlockError> {
        let start = Instant::now();
        for item in self.items.iter().take(count) {
            let bytes = signed_bytes(item.id, item.folder_id, &item.overview, &item.details);
            self.author
                .verify(&bytes, &item.signature)
                .map_err(|_| UnlockError::Signature(item.id))?;
        }
        Ok(start.elapsed())
    }
}

/// An unlocked vault: open folder keys plus the search index, held only in memory.
pub struct Unlocked<'a> {
    vault: &'a Vault,
    ciphers: Vec<XChaCha20Poly1305>,
    pub index: SearchIndex,
}

impl Unlocked<'_> {
    /// Decrypts one item's details and returns its password, as when the user copies it.
    pub fn password(&self, item_id: u32) -> Result<String, UnlockError> {
        let item = self
            .vault
            .items
            .get(item_id as usize)
            .ok_or(UnlockError::Item(item_id))?;
        let cipher = self
            .ciphers
            .get(item.folder_id as usize)
            .ok_or(UnlockError::Item(item_id))?;
        let aad = item_aad(item.id, item.folder_id, b"details");
        let bytes = cipher
            .decrypt(
                &item.details_nonce,
                Payload {
                    msg: &item.details,
                    aad: &aad,
                },
            )
            .map_err(|_| UnlockError::Item(item_id))?;
        let details: Details =
            serde_json::from_slice(&bytes).map_err(|_| UnlockError::Item(item_id))?;
        Ok(details.password)
    }
}

/// In-memory search index over decrypted overviews. Never written to disk.
pub struct SearchIndex {
    entries: Vec<Entry>,
}

struct Entry {
    item_id: u32,
    haystack: String,
}

impl AsRef<str> for Entry {
    fn as_ref(&self) -> &str {
        &self.haystack
    }
}

impl SearchIndex {
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Ids of the items matching `query`, best match first.
    pub fn search(&self, query: &str, matcher: &mut Matcher) -> Vec<u32> {
        Pattern::parse(query, CaseMatching::Ignore, Normalization::Smart)
            .match_list(&self.entries, matcher)
            .into_iter()
            .map(|(entry, _score)| entry.item_id)
            .collect()
    }

    /// Rough memory use of the index.
    pub fn approx_bytes(&self) -> usize {
        self.entries.capacity() * size_of::<Entry>()
            + self
                .entries
                .iter()
                .map(|e| e.haystack.capacity())
                .sum::<usize>()
    }
}

fn seal(
    cipher: &XChaCha20Poly1305,
    id: u32,
    folder_id: u32,
    part: &[u8],
    plaintext: &[u8],
) -> (XNonce, Vec<u8>) {
    let nonce = XChaCha20Poly1305::generate_nonce(&mut OsRng);
    let aad = item_aad(id, folder_id, part);
    let ciphertext = cipher
        .encrypt(
            &nonce,
            Payload {
                msg: plaintext,
                aad: &aad,
            },
        )
        .expect("encrypting an item");
    (nonce, ciphertext)
}

/// Binds each ciphertext to its item, folder and part, so parts can't be swapped.
fn item_aad(id: u32, folder_id: u32, part: &[u8]) -> Vec<u8> {
    [&id.to_le_bytes()[..], &folder_id.to_le_bytes(), part].concat()
}

fn signed_bytes(id: u32, folder_id: u32, overview: &[u8], details: &[u8]) -> Vec<u8> {
    [
        &id.to_le_bytes()[..],
        &folder_id.to_le_bytes(),
        overview,
        details,
    ]
    .concat()
}

const SERVICES: &[&str] = &[
    "GitHub",
    "GitLab",
    "AWS",
    "Google Workspace",
    "Slack",
    "Stripe",
    "Cloudflare",
    "Datadog",
    "Jira",
    "Confluence",
    "Figma",
    "Notion",
    "Zoom",
    "Salesforce",
    "HubSpot",
    "Twilio",
    "SendGrid",
    "PagerDuty",
    "Sentry",
    "Docker Hub",
    "npm",
    "Azure",
    "DigitalOcean",
    "Hetzner",
    "Postgres",
    "Redis",
    "MongoDB Atlas",
    "Vercel",
    "Netlify",
    "QuickBooks",
    "Xero",
    "Shopify",
    "Mailchimp",
    "Dropbox",
    "Adobe",
    "Apple Developer",
    "Google Ads",
    "Bank portal",
];
const ENVIRONMENTS: &[&str] = &["prod", "staging", "dev", "test", "eu", "us", "backup"];
const ROLES: &[&str] = &[
    "admin", "deploy", "readonly", "billing", "api", "root", "support", "ci",
];
const USERS: &[&str] = &[
    "alex", "sam", "jordan", "taylor", "morgan", "casey", "riley", "jamie", "drew", "quinn",
    "avery", "parker", "jdoe", "msmith", "lchen", "rpatel",
];
const DOMAINS: &[&str] = &["example.com", "corp.example", "acme.test"];
const TAGS: &[&str] = &[
    "finance",
    "engineering",
    "ops",
    "marketing",
    "shared",
    "legacy",
    "critical",
];
const PASSWORD_CHARS: &[u8] = b"abcdefghijkmnopqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789-_.!@#%";

fn pick<'a>(rng: &mut StdRng, list: &[&'a str]) -> &'a str {
    list[rng.gen_range(0..list.len())]
}

fn random_overview(rng: &mut StdRng, id: u32) -> Overview {
    let service = pick(rng, SERVICES);
    let environment = pick(rng, ENVIRONMENTS);
    let role = pick(rng, ROLES);
    let domain = pick(rng, DOMAINS);
    let slug: String = service
        .to_lowercase()
        .chars()
        .filter(char::is_ascii_alphanumeric)
        .collect();
    Overview {
        name: format!("{service} {environment} {role} {id}"),
        username: format!("{}@{domain}", pick(rng, USERS)),
        url: format!("https://{slug}.{domain}/{environment}"),
        tags: (0..rng.gen_range(0..3))
            .map(|_| pick(rng, TAGS).to_owned())
            .collect(),
    }
}

fn random_details(rng: &mut StdRng) -> Details {
    let mut text = |len: usize| -> String {
        (0..len)
            .map(|_| PASSWORD_CHARS[rng.gen_range(0..PASSWORD_CHARS.len())] as char)
            .collect()
    };
    Details {
        password: text(24),
        notes: text(80),
    }
}

#[cfg(test)]
mod tests {
    use nucleo_matcher::Config;

    use super::*;

    fn account() -> Account {
        let mut key = [0u8; 32];
        OsRng.fill_bytes(&mut key);
        Account::from_account_key(&key)
    }

    #[test]
    fn unlock_indexes_every_item_and_search_finds_one() {
        let account = account();
        let vault = Vault::generate(&account, 200, 4, 7);
        let (unlocked, _) = vault.unlock(&account).unwrap();
        assert_eq!(unlocked.index.len(), 200);

        let target = &unlocked.index.entries[123];
        let results = unlocked
            .index
            .search(&target.haystack, &mut Matcher::new(Config::DEFAULT));
        assert_eq!(results.first(), Some(&target.item_id));
    }

    #[test]
    fn copying_decrypts_the_password() {
        let account = account();
        let vault = Vault::generate(&account, 20, 2, 3);
        let (unlocked, _) = vault.unlock(&account).unwrap();
        assert_eq!(unlocked.password(7).unwrap().len(), 24);
        assert_eq!(unlocked.password(99), Err(UnlockError::Item(99)));
    }

    #[test]
    fn unlock_fails_for_another_account() {
        let vault = Vault::generate(&account(), 10, 2, 1);
        assert!(matches!(
            vault.unlock(&account()),
            Err(UnlockError::FolderKey(_))
        ));
    }

    #[test]
    fn unlock_fails_when_an_overview_is_tampered() {
        let account = account();
        let mut vault = Vault::generate(&account, 10, 2, 1);
        vault.items[3].overview[0] ^= 1;
        assert!(matches!(vault.unlock(&account), Err(UnlockError::Item(3))));
    }

    #[test]
    fn signatures_verify_and_catch_tampering() {
        let account = account();
        let mut vault = Vault::generate(&account, 10, 2, 1);
        assert!(vault.verify_signatures(10).is_ok());
        vault.items[5].details[0] ^= 1;
        assert_eq!(vault.verify_signatures(10), Err(UnlockError::Signature(5)));
    }
}
