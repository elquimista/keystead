# Keystead data format (draft)

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
big-endian number. The prefixes mean different splits of the same bytes never collide
(an absent field is an empty one), and the domain strings (each ending in a version like
`/v1`) mean a signature for one purpose can't be reused for another.

```
transcript(domain, f1, f2, …) = len(domain) ‖ domain ‖ len(f1) ‖ f1 ‖ len(f2) ‖ f2 ‖ …
```

## Keys

| Key | What it is | Where it lives |
| --- | --- | --- |
| Account secret | 32 random bytes per user | On each device, wrapped by that device's hardware key |
| Account encryption key | X25519, derived from the secret | Derived in memory at unlock |
| Account signing key | Ed25519, derived from the secret | Derived in memory at unlock |
| Account personal key | 32 bytes, derived from the secret | Derived in memory at unlock |
| Folder key | 32 random bytes per folder | Wrapped for each member's account encryption key |
| Item key | 32 random bytes per item | With the item: sealed with its folder key or its owner's personal key, and wrapped for each person it's shared with |
| Device key | Signs the device in to the server | Secure Enclave, TPM, or (CLI) a local file |
| Recovery kit | The account secret as 24 words | On paper, with the user |

**Deriving account keys.** HKDF-SHA256 with no salt, input = the account secret:

- `info = "keystead/account/encryption/v1"` gives 32 bytes, fed to HPKE `DeriveKeyPair`
  for DHKEM(X25519, HKDF-SHA256).
- `info = "keystead/account/signing/v1"` gives the 32-byte Ed25519 seed.
- `info = "keystead/account/personal/v1"` gives the personal key, an XChaCha20-Poly1305
  key only this account can make. It seals the keys of the account's own items outside
  folders, so opening those costs no public-key operation.

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
| `hpke-x25519-sha256-chacha20poly1305` | HPKE (RFC 9180) base mode: DHKEM(X25519, HKDF-SHA256), HKDF-SHA256, ChaCha20-Poly1305 | Folder and item keys wrapped for account keys |
| `hpke-p256-sha256-aes256gcm` | HPKE base mode: DHKEM(P-256, HKDF-SHA256), HKDF-SHA256, AES-256-GCM | The account secret wrapped for a macOS Secure Enclave key (Swift side) |

Unknown schemes are rejected, never guessed. New platforms add new schemes; existing
data stays readable.

**Folder keys** use `info = "keystead/folder-key/v1"` and associated data = the
folder id's 16 bytes, so a wrapped key can't be moved to another folder.

**Item keys** shared with a person directly use `info = "keystead/item-key/v1"` and
associated data = the item id's 16 bytes.

**The account secret on a Mac** is wrapped for the device's Secure Enclave key with
`hpke-p256-sha256-aes256gcm`, `info = "keystead/account-secret/v1"` and no associated
data. It stays on that Mac, next to the Secure Enclave key's handle; the handle only works
in that Mac's Secure Enclave, after Touch ID or the Mac password.

### Recovery kit

The recovery kit is the account secret written as words, so a user can bring their account
back on a new device when every device they had is gone:

- **The words** are the BIP 39 English mnemonic of the 32-byte secret: 24 words, the last of
  which also carries a checksum. Readers ignore case, spacing, line breaks, commas and
  numbering, and report a word that isn't on the list or a checksum that doesn't match.
- **Alongside the words** the kit shows the server address and the owner's fingerprint. A
  recovering device needs the fingerprint to check the owner, just as an invite carries it.
- The kit is printed or written down and kept offline. Apps only show it after the user
  unlocks with their device key, and never store it.

### Device keys and sign-in

A device registers a public key with one of these schemes:

| Scheme | Key encoding | Signature encoding | Used by |
| --- | --- | --- | --- |
| `ed25519` | 32 bytes | 64 bytes | CLI |
| `ecdsa-p256-sha256` | SEC1 (65-byte uncompressed) | raw r ‖ s, 64 bytes | macOS Secure Enclave |

To sign in, the device asks for a random challenge and signs
`transcript("keystead/sign-in/v1", device id, challenge)`. The server answers with a
short-lived bearer token.

An account can have several devices. Each has an optional name, like "Ana's MacBook Pro",
and the time it was added. A signed-in device can list the account's devices and remove the
others (not itself); a removed device's sessions end at once.

**Recovering an account on a new device** uses the account signing key instead of an
existing device:

1. The device derives the account keys from the kit's secret and sends their public half
   to `POST /v1/recover/challenge`. The server answers with a random challenge and the
   owner's directory entry.
2. The device checks the owner's fingerprint against the kit and the owner's
   self-approval, before registering anything.
3. It signs `transcript("keystead/recover/v1", challenge, device id, device key scheme,
   device key)` with the account signing key, and sends that with its new device key to
   `POST /v1/recover`. The server checks the signature against the account's registered
   signing key, so only the account secret can add a device this way.
4. The device signs in as usual and checks the directory: the owner's keys must still match
   the kit's fingerprint, and the account's own entry must carry the keys it derived.

## Items

An item version has two encrypted parts:

- **Overview** (decrypted at unlock, searchable): `{"name", "username", "url", "tags"}`.
- **Details** (decrypted only when used): `{"password", "notes"}`.

Each part is its JSON encoding, encrypted with **XChaCha20-Poly1305** under the item's
own key, with a fresh random 24-byte nonce and associated data:

```
transcript("keystead/item/v2", item id, version, "overview" | "details")
```

So a part can't be swapped with the other part, moved to another item, or replayed as a
different version.

### Who can open an item

An item is either **in a folder** or **outside folders**, owned by the user who made it.
Its key travels with it, in `keys`, once for each way in:

| Copy | When | How |
| --- | --- | --- |
| `folder` | The item is in a folder | XChaCha20-Poly1305 under the folder key, associated data `transcript("keystead/item-key/folder/v1", item id, folder id)` |
| `owner` | The item is outside folders | XChaCha20-Poly1305 under the owner's personal key, associated data `transcript("keystead/item-key/personal/v1", item id, owner user id)` |
| `people` | For each person it's shared with directly | `{"user_id", "wrapped_key"}`, the item key wrapped for their account key (see Wrapped keys) |

So folder members open an item through the folder, its owner through their personal key,
and anyone it was shared with through their own copy. Sharing an item with someone is
saving a new version with a copy for them. They get that item only, not the rest of its
folder. A person gets at most one copy, and the owner none in `people`.

```json
{ "id": "…", "format": 2, "folder_id": "…", "version": 3, "author": 2, "deleted": false,
  "keys": { "folder": { "nonce": "…", "ciphertext": "…" },
            "people": [ { "user_id": 4, "wrapped_key": { … } } ] },
  "overview": { "nonce": "…", "ciphertext": "…" },
  "details":  { "nonce": "…", "ciphertext": "…" },
  "signature": "…" }
```

An item outside folders has `"owner": <user id>` and `keys.owner` instead of `folder_id`
and `keys.folder`. Absent fields are left out.

- `version` starts at 1 and goes up by exactly one per saved change. An item never moves
  to another folder or owner.
- `author` is the user who saved this version. Their **account signing key** signs the
  whole version, key copies included, so the server can't add anyone:

  ```
  transcript("keystead/item-signature/v2", format (1 byte), item id, folder id or empty,
             owner or empty, version, author, deleted (1 byte),
             has folder copy (1 byte), its nonce, its ciphertext,
             has owner copy (1 byte), its nonce, its ciphertext,
             number of people (4 bytes),
             then per person: user id, wrapped key scheme name, encapsulated key, ciphertext,
             overview nonce, overview ciphertext, details nonce, details ciphertext)
  ```

  An absent copy has empty nonce and ciphertext fields.
- A deletion is a signed version with `"deleted": true`, empty parts and the same key
  copies, so everyone who could open the item hears about it.
- Clients must verify the signature against the author's approved directory entry,
  and that the author could open the item.

### Format 1

Items saved by Keystead 0.1 have no `format` field, no `owner` and no `keys`: they are
format 1. Their parts are encrypted with the **folder key itself**, with associated data
`transcript("keystead/item/v1", item id, folder id, version, part)`, and signed as
`transcript("keystead/item-signature/v1", item id, folder id, version, author, deleted,
overview nonce, overview ciphertext, details nonce, details ciphertext)`. Clients still
open them, and save the next version as format 2 with a new item key. An item never goes
back to format 1.

**Folder info** (`{"name"}`) is encrypted with the folder key, with associated data
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

All requests except health, setup, sign-in, accepting an invite and recovery need
`Authorization: Bearer <token>`. Errors return `{"error": "…"}` with the usual status
codes (400, 401, 403, 404, 409).

| Method and path | Request | Response | Who |
| --- | --- | --- | --- |
| `GET /v1/health` | | `Health` | Anyone |
| `POST /v1/setup` | `SetupRequest` | `Enrolled` | First admin, with the code the server printed |
| `POST /v1/sign-in/challenge` | `ChallengeRequest` | `Challenge` | Any device |
| `POST /v1/sign-in` | `SignInRequest` | `Session` | Any device |
| `POST /v1/invites` | `InviteRequest` | `Invite` | Owner |
| `POST /v1/invites/accept` | `AcceptInviteRequest` | `Enrolled` | Invitee, with the token |
| `POST /v1/recover/challenge` | `RecoveryChallengeRequest` | `RecoveryChallenge` | A device with the account secret |
| `POST /v1/recover` | `RecoverRequest` | `Enrolled` | A device with the account secret |
| `GET /v1/devices` | | `DeviceList` | Members |
| `DELETE /v1/devices/{id}` | | 204 | The device's own account, from another device |
| `POST /v1/users/{id}/approval` | `ApprovalRequest` | 204 | Owner |
| `GET /v1/directory` | | `Directory` | Members |
| `POST /v1/folders` | `CreateFolderRequest` | 201 | Members |
| `POST /v1/folders/{id}/members` | `AddMemberRequest` | 204 | Folder members |
| `PUT /v1/items/{id}` | `PutItemRequest` | 200 with the saved item, or 409 `Conflict` | Anyone who can open the item; for a new one, folder members or its owner |
| `GET /v1/sync?cursor=N&limit=M` | | `SyncPage` | Members |

`Health` is `{"status", "version", "item_format"}`. `item_format` is the newest item
format the server stores; servers older than 0.2.0 leave it out and store only format 1,
so clients check it before saving.

When saving an item, the server checks that the path and body ids match, the session's
user is the author and the version is `base_version + 1` (or 1 for a new item). The
author must be able to open the current version: in its folder, its owner, or in its
`people`. A new item must be in a folder the author is in, or be the author's own. The
item can't change folder, owner or go back a format, everyone newly in `people` must be
approved, and for now nobody can be dropped from `people`. If another version was saved
first, it answers 409 with that version.

**Sync** returns feed entries after the cursor, in change-number order, from one
consistent snapshot: `item` entries for the latest version of each changed item the user
can open (in their folders, their own, or shared with them directly), `joined` entries
carrying the folder key wrapped for the user plus the folder's info and items, and `left`
entries telling the device to drop a folder (keeping its items that were also shared with
the user directly). An item shared directly arrives as an `item` entry: sharing saved a
new version, with a new change number. The prototype in `prototypes/change-feed` shows
why each item arrives exactly once.

## Not in this format yet

- Adding a second device by approving it from an existing one, and recovery by admins.
  (A recovery kit can already add a device.)
- Group keys.
- Read-only and manage roles (everyone who can open an item can edit and share it).
- Removing someone's access to a folder or an item, with new keys afterwards.
- Moving an item to another folder.
- Paginating a large folder that arrives with a join.
