# Keystead data format (draft)

This is the format the server, the CLI and the apps agree on. `crates/keystead-core` is
its reference implementation; change the two together. The server stores and relays
only the encrypted forms described here and never holds a key that can open them.

## Who's who

- The **team owner** (or just "the owner") is the server's first user, who claimed it with
  the setup code. There's one per server. They invite and approve everyone (see
  Directory), remove people from the team and make groups. Whoever runs the server isn't
  a role: unless they're also the owner, they hold no keys.
- An **item's owner** (its `owner` field) is the person who made an item outside folders.
  Apps show it as "Shared by" and "Made it", so it's never confused with the team owner.
- **Managers** run a group or a folder; folders and items give people and groups a
  **role** (see Roles).

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
| Folder key | 32 random bytes per folder, replaced after someone loses access | Wrapped for each member's account encryption key and each group's key; each older key sealed with the next |
| Item key | 32 random bytes per item version | With the item: sealed with its folder key or its owner's personal key, and wrapped for each person and group it's shared with |
| Group secret | 32 random bytes per group, replaced after someone leaves | Wrapped for each member's account encryption key; each older secret sealed with the next |
| Group keys | An X25519 key and a chain key, derived from the group secret | Derived in memory; the public key is in the group's signed entry |
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
| `hpke-x25519-sha256-chacha20poly1305` | HPKE (RFC 9180) base mode: DHKEM(X25519, HKDF-SHA256), HKDF-SHA256, ChaCha20-Poly1305 | Folder and item keys wrapped for account or group keys; group secrets wrapped for account keys |
| `hpke-p256-sha256-aes256gcm` | HPKE base mode: DHKEM(P-256, HKDF-SHA256), HKDF-SHA256, AES-256-GCM | The account secret wrapped for a macOS Secure Enclave key (Swift side) |

Unknown schemes are rejected, never guessed. New platforms add new schemes; existing
data stays readable.

**Folder keys** use `info = "keystead/folder-key/v1"` and associated data = the
folder id's 16 bytes, so a wrapped key can't be moved to another folder.

**Item keys** shared with a person directly use `info = "keystead/item-key/v1"` and
associated data = the item id's 16 bytes.

Folder and item keys shared with a **group** are wrapped the same way, for the group's
public key instead of a person's.

**Group secrets** use `info = "keystead/group-secret/v1"` and associated data =
`transcript("keystead/group-secret/v1", group id, generation)`, so a wrapped secret can't
pass for another group's or another generation's.

**The account secret on a Mac** is wrapped for the device's Secure Enclave key with
`hpke-p256-sha256-aes256gcm`, `info = "keystead/account-secret/v1"` and no associated
data. It stays on that Mac, next to the Secure Enclave key's handle; the handle only works
in that Mac's Secure Enclave, after Touch ID or the Mac password.

### Recovery kit

The recovery kit is the account secret written as words, so a user can bring their account
back on a new device when every device they had is gone:

- **The words** are the BIP 39 English mnemonic of the 32-byte secret: 24 words, the last of
  which also carries a checksum. Kits show them in six rows of four, numbered across the
  rows. Readers take exactly the 24 words, in order, separated by spaces or line breaks;
  capitals read as lowercase. Anything else, such as numbers or punctuation, is refused, as
  is a word that isn't on the list or a checksum that doesn't match.
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
others; a removed device's sessions end at once. A device removes itself by **signing out**
(`POST /v1/sign-out`), and then deletes its profile and keys. Servers before sign-out
existed answer 404; the device still deletes its own data, and stays listed until removed
from another device.

**Recovering an account on a new device** uses the account signing key instead of an
existing device:

1. The device derives the account keys from the kit's secret and sends their public half
   to `POST /v1/recover/challenge`. The server answers with a random challenge and the
   owner's directory entry.
2. The device checks the owner's fingerprint against the kit and the owner's
   self-approval, before registering anything. The owner may leave the fingerprint out:
   the device then checks that the owner's keys are the ones it derived, which is just as
   strong, since only the account secret gives those keys.
3. It signs `transcript("keystead/recover/v1", challenge, device id, device key scheme,
   device key)` with the account signing key, and sends that with its new device key to
   `POST /v1/recover`. The server checks the signature against the account's registered
   signing key, so only the account secret can add a device this way.
4. The device signs in as usual and checks the directory: the owner's keys must still match
   the kit's fingerprint (or the derived keys), and the account's own entry must carry the
   keys it derived.

**Adding a device from another** (0.8.0 and later) lets a device the account already has
hand the account secret to a new one, without the recovery kit:

1. The existing device starts a transfer (`POST /v1/device-transfers`) and shows a setup
   line: `keystead add-device <server> <token> --owner <owner's fingerprint>`. The person
   copies it to the new device. It holds nothing secret.
2. The new device makes a one-time X25519 **transfer key** and joins with the token, its
   name and the key's public half (`POST …/join`, no session; once per transfer). It shows
   the **transfer code**: the first 80 bits of
   `SHA-256(transcript("keystead/device-transfer-code/v1", token, transfer key))`, in five
   groups of four hex digits like a fingerprint.
3. The existing device fetches the key (`GET …/{id}`) and computes the code itself. The
   person types the new device's code into it; only if they match does it seal the account
   secret for the key with HPKE (as for wrapped keys, info `keystead/device-transfer/v1`,
   associated data `transcript("keystead/device-transfer/v1", token, transfer key)`) and
   send it (`PUT …/{id}/secret`). A server that swapped in a key of its own would show a
   different code, and can't find a key whose code matches.
4. The new device asks for the sealed secret (`POST …/claim`, no session) until it's there,
   opens it, and then registers itself exactly as recovery does, with the line's owner
   fingerprint, so a secret the server made up wouldn't match the owner-signed directory.

Transfers expire after ten minutes, an account has at most three open at once, and a
claimed or cancelled one is gone. The server only ever sees the public key and the sealed
secret.

## Items

An item version has two encrypted parts:

- **Overview** (decrypted at unlock, searchable): `{"name", "username", "url", "tags"}`,
  plus `"one_time_code": true` when the details hold a one-time code setup, so lists can
  offer the code without opening every item.
- **Details** (decrypted only when used): `{"password", "notes"}`, plus `"otp"` for
  one-time codes (format 4).

**One-time codes** (0.6.0 and later) are time-based codes (TOTP, RFC 6238) for sites that
ask for a second factor. `otp` holds their setup as the `otpauth://totp/…` link a site's
QR code carries (algorithm SHA1, SHA256 or SHA512, 6 to 8 digits, any period); a setup key
typed in instead becomes `otpauth://totp/?secret=<base32>`. Counter-based codes (HOTP)
aren't supported. Clients make the codes from the link and the clock, with the `totp-rs`
crate, and never store them.

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
| `groups` | For each group it's shared with directly (format 3) | `{"group_id", "generation", "wrapped_key"}`, the item key wrapped for that generation of the group's key |

So folder members open an item through the folder, its owner through their personal key,
and anyone it was shared with through their own copy or their group's. Sharing an item
with someone or a group is saving a new version with a copy for them. They get that item
only, not the rest of its folder. A person or group gets at most one copy, and the owner
none in `people`.

An item with copies for groups is **format 3**; one without is format 2, which apps from
before groups can still open. The two differ only in the group copies and in signing
them: format 3 signs `transcript("keystead/item-signature/v3", …)` with the same parts as
below, plus, after the people, the number of groups (4 bytes) and per group: group id,
generation (4 bytes), wrapped key scheme name, encapsulated key, ciphertext. An item goes
back to format 2 when its last group copy is removed.

An item whose details hold a one-time code is **format 4**, with or without group copies.
It's laid out and signed exactly like format 3 (the format number is the first signed
part); only its details differ. The new number is what protects the code: apps from before
0.6.0 can't open format 4, where they would otherwise open the item, save it without the
`otp` they don't know, and lose it. Removing the code takes the item back to format 3 or 2.
Clients that meet a format newer than theirs leave the item out and say how many there are,
rather than failing.

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
- Saving gives every group its copy at the group's current generation (see Groups).

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
could read everything shared with that user. So each entry carries the **team owner's
signature**, given after the owner compares the user's fingerprint in person or on a
call:

```
transcript("keystead/directory-entry/v1", user id, name, encryption key, signing key)
```

The owner approves their own entry at setup. A client joining the team pins the owner's
keys (by fingerprint, from the invite) and shares only with entries whose signature
verifies against them, and that aren't marked `"removed": true` (see Removing access).

## Groups

A group is people shared with as one. Sharing a folder or item with a group is one copy
of its key, wrapped for the group's key, however many people are in it; adding someone to
the group is one copy of the group's secret for them, and they get everything shared with
it. Groups don't contain groups.

**Deriving group keys.** HKDF-SHA256 with no salt, input = the group secret:

- `info = "keystead/group/encryption/v1"` gives 32 bytes, fed to HPKE `DeriveKeyPair`
  for DHKEM(X25519, HKDF-SHA256): the key folder and item keys are wrapped for.
- `info = "keystead/group/chain/v1"` gives the chain key, an XChaCha20-Poly1305 key that
  seals the previous secret.

**Entries.** Whoever shares with a group needs its real public key, so a group's public
facts form a signed entry, with a new revision for each change:

```json
{ "group_id": "…", "revision": 2, "name": "Engineering", "generation": 1,
  "encryption": "…", "managers": [1, 4], "signer": 1, "signature": "…" }
```

`managers` are user ids in ascending order. The signer's account signing key signs:

```
transcript("keystead/group-entry/v1", group id, revision (4 bytes), name,
           generation (4 bytes), encryption public key, number of managers (4 bytes),
           then each manager's user id, signer)
```

Clients check every revision, oldest first, before using a group's key: revision 1 is at
generation 1 and signed by the owner; each later revision is the next number, signed by
the owner or by a manager named in the revision before it; and its key is either the same
at the same generation, or a new one at the next generation. Each signer must be in the
approved directory. A member also checks that the secret they were given derives the
latest revision's key.

The owner makes groups, and is the first member and manager of each one they make.
Managers add people, but only managers who are in the group, since that hands over its
secret; the owner and managers in the group remove people, rename it and change its
managers. A manager who has left the group stops being one at its next revision, and the
server stops taking their changes at once.

**Deleting a group** (0.10.0 and later; `DELETE /v1/groups/{id}`, the owner and managers in
it). Everyone in it loses what only the group gave them, as if each had left: their feeds
get `left_group` and the `left` and `left_item` entries that follow, folders they lost are
marked for new keys, those who keep a folder another way get its key again (`rekeyed`),
and what they could see goes on the passwords to change. The server forgets the group's
entries and keys. It refuses while the group is the only manager of a folder. Items keep
their copy for the deleted group until next saved; clients then drop it, and anyone who
can save may (as for people removed from the team).

**New secrets.** When someone leaves, the group needs a new secret, the next generation:
a manager in it makes one, wraps it for exactly the remaining members, signs the next
revision with the new key, and seals the previous secret with the new chain key:

```
link = XChaCha20-Poly1305 under the new chain key, of the previous secret, with associated
       data transcript("keystead/group-key-chain/v1", group id, new generation)
```

Members holding the newest secret open every older one through the chain, so whatever
was shared with older generations still opens; whoever left never gets a newer one. Each
sync tells a group's managers in it when it needs a new secret (`group_rekey_needed`).

Sharing a folder with a group names both the folder key's generation and the group's,
and both must be current. `Groups` (from `GET /v1/groups`) lists every group with its
`entries`, its `members` and whether it `needs_rekey`. `Members` also lists the `groups` a folder or item is shared
with, with their roles.

## API

All requests except health, setup, sign-in, accepting an invite and recovery need
`Authorization: Bearer <token>`. Errors return `{"error": "…"}` with the usual status
codes (400, 401, 403, 404, 409).

| Method and path | Request | Response | Who |
| --- | --- | --- | --- |
| `GET /v1/health` | | `Health` | Anyone |
| `POST /v1/setup` | `SetupRequest` | `Enrolled` | Whoever runs the server, with the code it printed |
| `POST /v1/sign-in/challenge` | `ChallengeRequest` | `Challenge` | Any device |
| `POST /v1/sign-in` | `SignInRequest` | `Session` | Any device |
| `POST /v1/invites` | `InviteRequest` | `Invite` | Owner |
| `POST /v1/invites/accept` | `AcceptInviteRequest` | `Enrolled` | Invitee, with the token |
| `POST /v1/recover/challenge` | `RecoveryChallengeRequest` | `RecoveryChallenge` | A device with the account secret |
| `POST /v1/recover` | `RecoverRequest` | `Enrolled` | A device with the account secret |
| `GET /v1/devices` | | `DeviceList` | Members |
| `DELETE /v1/devices/{id}` | | 204 | The device's own account, from another device |
| `POST /v1/sign-out` | | 204 | The device itself, which is then forgotten |
| `POST /v1/users/{id}/approval` | `ApprovalRequest` | 204 | Owner |
| `GET /v1/directory` | | `Directory` | Members |
| `DELETE /v1/users/{id}` | | 204 | Owner, for anyone but themselves |
| `POST /v1/device-transfers` | | `DeviceTransfer` | Any signed-in device |
| `POST /v1/device-transfers/join` | `JoinDeviceTransferRequest` | 204 | The new device, with the token |
| `GET /v1/device-transfers/{id}` | | `DeviceTransferState` | The account that started it |
| `PUT /v1/device-transfers/{id}/secret` | `SendAccountSecretRequest` | 204 | The account that started it |
| `POST /v1/device-transfers/claim` | `ClaimDeviceTransferRequest` | `ClaimedAccountSecret` | The new device, with the token |
| `DELETE /v1/device-transfers/{id}` | | 204 | The account that started it |
| `POST /v1/folders` | `CreateFolderRequest` | 201 | Members; they manage it |
| `POST /v1/folders/{id}/members` | `AddMemberRequest` | 204 | Folder managers |
| `GET /v1/folders/{id}/members` | | `Members` | Folder members |
| `PUT /v1/folders/{id}/members/{user}` | `RoleRequest` | 204 | Folder managers |
| `DELETE /v1/folders/{id}/members/{user}` | | 204 | Folder managers, or the member themselves |
| `POST /v1/folders/{id}/rekey` | `RekeyRequest` | 204 | Folder managers |
| `POST /v1/folders/{id}/groups` | `AddFolderGroupRequest` | 204 | Folder managers |
| `PUT /v1/folders/{id}/groups/{group}` | `RoleRequest` | 204 | Folder managers |
| `DELETE /v1/folders/{id}/groups/{group}` | | 204 | Folder managers |
| `POST /v1/groups` | `CreateGroupRequest` | 201 | Owner |
| `GET /v1/groups` | | `Groups` | Members |
| `PUT /v1/groups/{id}` | `UpdateGroupRequest` | 204 | Owner, and the group's managers in it |
| `POST /v1/groups/{id}/members` | `AddGroupMemberRequest` | 204 | The group's managers in it (the owner too, if in it) |
| `DELETE /v1/groups/{id}/members/{user}` | | 204 | Owner and the group's managers in it, or the member themselves |
| `POST /v1/groups/{id}/rekey` | `GroupRekeyRequest` | 204 | The group's managers in it (the owner too, if in it) |
| `DELETE /v1/groups/{id}` | | 204 | Owner, and the group's managers in it |
| `PUT /v1/items/{id}` | `PutItemRequest` | 200 with the saved item, or 409 `Conflict` | Editors and managers of the item (see Roles) |
| `GET /v1/items/{id}/people` | | `Members` | Anyone who can open the item |
| `GET /v1/items/{id}/history` | | `ItemHistory` | Editors and managers of the item |
| `GET /v1/deleted` | | `DeletedItems` | Members; only items they can change |
| `DELETE /v1/deleted/{id}` | | 204 | Editors and managers of the deleted item |
| `PUT /v1/items/{id}/people/{user}` | `RoleRequest` | 204 | Managers of the item |
| `PUT /v1/items/{id}/groups/{group}` | `RoleRequest` | 204 | Managers of the item |
| `DELETE /v1/items/{id}/exposures/{user}` | | 204 | Editors and managers of the item |
| `GET /v1/exposures` | | `Exposures` | Members; only items they can change |
| `GET /v1/sync?cursor=N&limit=M` | | `SyncPage` | Members |

`Health` is `{"status", "version", "item_format"}`. `item_format` is the newest item
format the server stores; servers older than 0.2.0 leave it out and store only format 1,
so clients check it before saving. Servers with groups (0.4.0 and later) say 3, and with
one-time codes (0.6.0 and later) 4.

When saving an item, the server checks that the path and body ids match, the session's
user is the author and the version is `base_version + 1` (or 1 for a new item). The
author must be an editor or manager of the current version (see Roles); a new item must
be in a folder where the author edits or manages, or be the author's own. Adding anyone
to `people`, or dropping anyone, takes a manager, except that anyone who can save may
drop people the owner removed from the team. The item can't change folder, owner or go
back to format 1, and everyone newly in `people` must be approved and not removed. Adding
or dropping a group also takes a manager; a group new to the item gets its copy at the
group's current generation, and no copy may name a generation the group hasn't reached.
`PutItemRequest.roles` gives the roles of people new to `people`, and `group_roles` those
of groups new to `groups`, and `password_changed` (left out when false) that its password
differs from the previous version's (see Passwords to change). A live version may follow a
deletion marker, which brings the item back (see Recently deleted). If another version was
saved first, it answers 409 with that version.

### Roles

Everyone who can open a folder or an item has a role there:

| Role | Can |
| --- | --- |
| `view` | Open and copy |
| `edit` | Also save new versions: change and delete items |
| `manage` | Also share, change roles, remove people, and give a folder a new key |

A folder's creator manages it, and so does an item's owner. A folder or item shared with
a group gives the group a role, which is everyone's in it. Someone with access more than
one way (through a folder, directly, through groups) gets the highest role. A folder
always keeps at least one manager, a person or a group. Members and shares from before roles existed are managers, since everyone could
do everything then. Roles are kept and enforced by the server; reading depends only on the
keys someone holds.

### Removing access, and new keys

A manager removes someone from a folder (`DELETE …/members/{user}`), or a member leaves.
Their access ends at once, their feed gets a `left` entry, and the folder is marked as
needing a new key. A manager's client then **rekeys** it: it makes a new folder key,
wraps it for exactly the remaining members and the groups it's shared with (each at the
group's current generation), seals the folder info with it, and seals the previous key
with it:

```
link = XChaCha20-Poly1305 under the new key, of the previous key, with associated data
       transcript("keystead/folder-key-chain/v1", folder id, new generation)
```

Generations count up from 0. A member holding the newest key opens every older one
through the chain, so items saved under any of them still open; someone removed never
gets a newer key. Adding a member names the generation it wrapped, which must still be
the current one. Each sync tells managers which of their folders need a new key
(`SyncPage.rekey_needed`), so it happens even if the manager who removed someone wasn't
the one to do it.

Clients give an item a **new item key every time they save it**, with fresh copies for
its folder (under the folder's current key), its owner, its people and its groups (under
each group's current key), so what's saved after someone lost access is out of their
reach. The exception is an item outside
folders saved by someone other than its owner: only the owner can seal the owner's copy,
so the key stays until the owner saves it.

Taking someone's copy of an item away is a new version without it; their feed gets a
`left_item` entry, and their devices drop the item unless one of their folders still has
it.

**Leaving a group.** The owner or a manager takes someone out of a group, or a member
leaves. Whatever only the group gave them ends at once: their feed gets `left_group`, then
`left` and `left_item` entries for what they lost. The group is marked for a new secret,
and each folder they lost for a new key. A manager in the group rekeys it first (see
Groups); a folder shared with a group waiting for its new secret isn't in anyone's
`rekey_needed`, and the server refuses its rekey, because the folder's new key would go to
the group's old one. Stopping sharing a folder with a group works like removing each of
its members who has no other way in. Someone who keeps a folder another way gets its
current key again (`rekeyed`), as their copy may have been the group's.

**Removing someone from the team** (`DELETE /v1/users/{id}`, owner only) ends their
sessions and removes their devices, takes them out of every group and folder (marking
each for a new key) and every item shared with them. Their directory entry stays, with `"removed":
true`, so what they signed still verifies; nobody can share with them again, and their
account can't be recovered. A folder left without a manager gets one: whoever has been
in it longest. Clients drop removed people's copies from items as they save them.

**History** (0.7.0 and later). When a version replaces another, the server keeps the one
replaced, as stored, with when it was saved (`saved_at`, seconds since 1970, set by the
server and not signed; absent for versions saved before 0.7.0). It keeps the last 10
earlier versions of each item. `GET …/history` returns
the current version and the kept ones, newest first, to the item's editors and managers;
viewers get only the current version, through sync. Clients verify each version's
signature like any other and leave out ones that fail, so a server can't slip in a version
nobody saved. A version opens with the keys of its time: a folder's members open them all
through the folder's key chain, but someone an item was shared with directly opens only
versions that had a copy for them. Bringing a version back saves its overview and details
as a new version, and doesn't count as a new password (see below), since it isn't one.

**Recently deleted** (0.9.0 and later). Deleting an item saves its deletion marker as
usual, and the server keeps its earlier versions (and passwords to change) for 30 days
after it, then forgets them; the marker stays, for everyone's devices. `GET /v1/deleted`
lists the items deleted in that time that the caller can change, each with its signed
marker, its last version before it, and when it was deleted. Clients verify both and
decrypt the last version to show it. Saving a live version on top of a deletion marker
brings the item back (to everyone with a key copy, as for any version); clients save the
last version's overview and details, which doesn't count as a new password.
`DELETE /v1/deleted/{id}` forgets a deleted item's history at once. Items deleted on
servers before 0.9.0 lost their history when deleted, so they can't come back.

**Passwords to change** (0.5.0 and later). New keys protect what's saved afterwards, but
passwords someone already saw can't be taken back. So whenever someone loses access to an
item (any of the ways above, or leaving), the server records an **exposure**: the item,
the user and when (`since`, seconds since 1970). It ends when:

- a version with a new password is saved: the client compares it with the previous
  version's and says so with `PutItemRequest.password_changed`, as only clients can read
  passwords;
- the item is deleted;
- someone who can change the item dismisses it
  (`DELETE /v1/items/{id}/exposures/{user}`), for example when the person only moved to
  another team;
- or, for as long as they can open the item again (and aren't removed from the team), it
  isn't listed.

`GET /v1/exposures` lists them for the items the caller can change (edit or manage), so
the remover sees what they can fix, and the managers of folders the remover can't open see
the rest. Servers before 0.5.0 record nothing and answer 404; clients then show no list.

**Sync** returns feed entries after the cursor, in change-number order, from one
consistent snapshot:

- `item`: the latest version of each changed item the user can open (in their folders,
  their own, or shared with them or their groups directly). An item shared directly
  arrives this way: sharing saved a new version, with a new change number. So does an
  item reached through a group joined after its latest version, at the join's number.
- `joined`: the folder key wrapped for the user, or for a group they're in
  (`via_group`: `{"group_id", "generation"}`), with its `generation` and `chain`, plus the
  folder's info and items.
- `left`: drop a folder, keeping its items that were also shared with the user directly.
- `rekeyed`: a folder the user can open has a new key: the new one wrapped for them or
  their group (`via_group`), its generation, the whole chain and the info sealed with it.
- `left_item`: the user lost direct access to an item.
- `group`: the user joined a group, or one they're in changed: its `entries`, its current
  secret wrapped for them with its `generation`, and the `chain` to older ones. It comes
  before anything that needs the group's keys.
- `left_group`: forget a group's keys.

The last page also carries the user's `roles` (in each folder, and on each item shared
with them or their groups directly, the highest of the ways in), and every page
`rekey_needed` and `group_rekey_needed`. The prototype in
`prototypes/change-feed` shows why each item arrives exactly once.

## Not in this format yet

- Recovery that the team owner approves. (A recovery kit, or another of the account's
  devices, can already add a device.)
- Signed membership changes. Roles and memberships are enforced by the server; a
  server that lied could let someone save who shouldn't, though every version stays
  signed by its author. A group's managers and key are signed; who is in it isn't.
- Groups inside groups (on purpose: no loops, and access stays easy to follow).
- Moving an item to another folder.
- Paginating a large folder that arrives with a join.
