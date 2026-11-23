# Keystead data format, version 1 (draft)

This is the format the server, the CLI and the apps agree on. `crates/keystead-core` is
its reference implementation; change the two together. The server stores and relays
only the encrypted forms described here and never holds a key that can open them.

## Encoding

- Messages are JSON over HTTPS, under `/v1`.
- Bytes (keys, nonces, ciphertexts, signatures) are **unpadded base64url** strings.
- Folder, item and device ids are random UUIDs (version 4) chosen by the client, so
  things can be created and encrypted offline. User ids are integers from the server.
- Integers inside signed or bound data are big-endian: user ids as 8-byte signed,
  versions as 8-byte unsigned.

### Transcripts

Everything signed, and all associated data for encryption, is built as a *transcript*:
a domain string followed by fields, each prefixed with its length as a 4-byte
big-endian number. The prefixes mean different splits of the same bytes never collide,
and the domain strings (all ending in `/v1`) mean a signature for one purpose can't be
reused for another.

```
transcript(domain, f1, f2, …) = len(domain) ‖ domain ‖ len(f1) ‖ f1 ‖ len(f2) ‖ f2 ‖ …
```

## Keys

| Key | What it is | Where it lives |
| --- | --- | --- |
| Account secret | 32 random bytes per user | On each device, wrapped by that device's hardware key |
| Account encryption key | X25519, derived from the secret | Derived in memory at unlock |
| Account signing key | Ed25519, derived from the secret | Derived in memory at unlock |
| Folder key | 32 random bytes per folder | Wrapped for each member's account encryption key |
| Device key | Signs the device in to the server | Secure Enclave, TPM, or (CLI) a local file |

**Deriving account keys.** HKDF-SHA256 with no salt, input = the account secret:

- `info = "keystead/account/encryption/v1"` gives 32 bytes, fed to HPKE `DeriveKeyPair`
  for DHKEM(X25519, HKDF-SHA256).
- `info = "keystead/account/signing/v1"` gives the 32-byte Ed25519 seed.

**Fingerprint.** `SHA-256("keystead/fingerprint/v1" ‖ encryption public key ‖ signing
public key)`, first 10 bytes, written as five groups of four hex digits
(`3f2a-9c1e-5b7d-4e8a-9c21`). People compare it to confirm a key belongs to who they
think.

### Wrapped keys

Every wrapped key says how it was wrapped:

```json
{ "scheme": "hpke-x25519-sha256-chacha20poly1305",
  "encapsulated_key": "…", "ciphertext": "…" }
```

| Scheme | Construction | Used for |
| --- | --- | --- |
| `hpke-x25519-sha256-chacha20poly1305` | HPKE (RFC 9180) base mode: DHKEM(X25519, HKDF-SHA256), HKDF-SHA256, ChaCha20-Poly1305 | Folder keys wrapped for account keys |
| `hpke-p256-sha256-aes256gcm` | HPKE base mode: DHKEM(P-256, HKDF-SHA256), HKDF-SHA256, AES-256-GCM | The account secret wrapped for a macOS Secure Enclave key (Swift side) |

Unknown schemes are rejected, never guessed. New platforms add new schemes; existing
data stays readable.

**Folder keys** use `info = "keystead/folder-key/v1"` and associated data = the
folder id's 16 bytes, so a wrapped key can't be moved to another folder.

**The account secret on a Mac** is wrapped for the device's Secure Enclave key with
`hpke-p256-sha256-aes256gcm`, `info = "keystead/account-secret/v1"` and no associated
data. It stays on that Mac, next to the Secure Enclave key's handle; the handle only works
in that Mac's Secure Enclave, after Touch ID or the Mac password.

### Device keys and sign-in

A device registers a public key with one of these schemes:

| Scheme | Key encoding | Signature encoding | Used by |
| --- | --- | --- | --- |
| `ed25519` | 32 bytes | 64 bytes | CLI |
| `ecdsa-p256-sha256` | SEC1 (65-byte uncompressed) | raw r ‖ s, 64 bytes | macOS Secure Enclave |

To sign in, the device asks for a random challenge and signs
`transcript("keystead/sign-in/v1", device id, challenge)`. The server answers with a
short-lived bearer token.

## Items

An item version has two encrypted parts:

- **Overview** (decrypted at unlock, searchable): `{"name", "username", "url", "tags"}`.
- **Details** (decrypted only when used): `{"password", "notes"}`.

Each part is its JSON encoding, encrypted with **XChaCha20-Poly1305** under the folder
key, with a fresh random 24-byte nonce and associated data:

```
transcript("keystead/item/v1", item id, folder id, version, "overview" | "details")
```

So a part can't be swapped with the other part, moved to another item or folder, or
replayed as a different version.

```json
{ "id": "…", "folder_id": "…", "version": 3, "author": 2, "deleted": false,
  "overview": { "nonce": "…", "ciphertext": "…" },
  "details":  { "nonce": "…", "ciphertext": "…" },
  "signature": "…" }
```

- `version` starts at 1 and goes up by exactly one per saved change.
- `author` is the user who saved this version. Their **account signing key** signs:

  ```
  transcript("keystead/item-signature/v1", item id, folder id, version, author,
             deleted (1 byte), overview nonce, overview ciphertext,
             details nonce, details ciphertext)
  ```

- A deletion is a signed version with `"deleted": true` and empty parts.
- Clients must verify the signature against the author's approved directory entry,
  and that the author was a member of the folder.

**Folder info** (`{"name"}`) is encrypted the same way with associated data
`transcript("keystead/folder-info/v1", folder id)`.

## Directory

The server lists every user's public keys, but a server that swapped in its own key
could read everything shared with that user. So each entry carries the **org owner's
signature**, given after the owner compares the user's fingerprint in person or on a
call:

```
transcript("keystead/directory-entry/v1", user id, name, encryption key, signing key)
```

The owner approves their own entry at setup. A client joining the org pins the owner's
keys (by fingerprint, from the invite) and shares only with entries whose signature
verifies against them.

## API

All requests except setup, sign-in and accepting an invite need
`Authorization: Bearer <token>`. Errors return `{"error": "…"}` with the usual status
codes (400, 401, 403, 404, 409).

| Method and path | Request | Response | Who |
| --- | --- | --- | --- |
| `POST /v1/setup` | `SetupRequest` | `Enrolled` | First admin, with the code the server printed |
| `POST /v1/sign-in/challenge` | `ChallengeRequest` | `Challenge` | Any device |
| `POST /v1/sign-in` | `SignInRequest` | `Session` | Any device |
| `POST /v1/invites` | `InviteRequest` | `Invite` | Owner |
| `POST /v1/invites/accept` | `AcceptInviteRequest` | `Enrolled` | Invitee, with the token |
| `POST /v1/users/{id}/approval` | `ApprovalRequest` | 204 | Owner |
| `GET /v1/directory` | | `Directory` | Members |
| `POST /v1/folders` | `CreateFolderRequest` | 201 | Members |
| `POST /v1/folders/{id}/members` | `AddMemberRequest` | 204 | Folder members |
| `PUT /v1/items/{id}` | `PutItemRequest` | 200 with the saved item, or 409 `Conflict` | Folder members |
| `GET /v1/sync?cursor=N&limit=M` | | `SyncPage` | Members |

When saving an item, the server checks that the path and body ids match, the session's
user is the author and a folder member, and the version is `base_version + 1` (or 1 for
a new item). If another version was saved first, it answers 409 with that version.

**Sync** returns feed entries after the cursor, in change-number order, from one
consistent snapshot: `item` entries for the latest version of each changed item,
`joined` entries carrying the folder key wrapped for the user plus the folder's info
and items, and `left` entries telling the device to drop a folder. The prototype in
`prototypes/change-feed` shows why each item arrives exactly once.

## Not in version 1 yet

- Adding a second device to an account, and recovery (recovery kit, recovery by admins).
- Group keys.
- Read-only and manage roles (every folder member can edit).
- Paginating a large folder that arrives with a join.
