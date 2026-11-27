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
short-lived bearer token (15 minutes).

Before a session ends, the device can swap it for a fresh one without its key
(`POST /v1/sign-in/renew`). A Mac's key needs Touch ID or the Mac's password for every
use, so renewing lets it ask only when it unlocks; when it would have to sign in again
while unlocked, the Mac app locks instead of asking. Clients renew once half the session
has passed, and sign in again only when it has ended or the server has forgotten it
(after a restart). The old session still ends when it would have. Sessions renew for up
to 24 hours after the device signed in with its key, so a copied token can't be kept
alive for good; after that the server answers 403, and the device uses the session until
it ends, then signs in with its key. Older servers answer 404, and the device signs in
each time instead.

A device has at most eight sessions at a time, and four challenges waiting; one more ends
or drops its oldest (0.16.0 and later). An app has two sessions while it renews, and each
command-line command signs in for its own, so this is only met by a device that signs in
or renews over and over. The same goes for an account's recovery challenges (see below).

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
   keys it derived and, unless it's the owner's, the owner's approval. Without that the
   device signs itself out again and keeps nothing: an account the owner hasn't approved
   yet takes no second device, by kit or from another device, until they have. A server
   can register keys of its own under anyone's name, but can't make the owner's approval.

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

**Recovering with the owner's help** (0.13.0 and later) is for someone who lost every
device and their recovery kit. Their old keys are gone, so they get new ones:

1. The owner starts it (`POST /v1/users/{id}/recovery`) and sends the person the line it
   gives: `keystead recover-with-help <server> <token> --owner <owner's fingerprint>`. It
   works once, for a week; starting again replaces it. Devices the person still has see
   `recovering` on their directory entry and can cancel (`DELETE …/recovery`). With
   `?sign_out_devices=true` the server removes their devices at once instead, so a lost one
   that still works can't cancel it or change escrow; if they still have one after all,
   their recovery kit registers it again (see Recovery kit).
2. The new device makes a new account secret and device key and sends their public halves
   with the token (`POST /v1/recovery/claim`, no session). Only that device may send them
   again. It then asks `POST /v1/recovery/state` until the owner approves.
3. The owner fetches the new keys (`GET …/recovery`) and compares their fingerprint with
   the person, in person or on a call. Only if it matches does the owner sign the person's
   entry with the new keys at the next revision, and the list of what the old keys had
   signed (see Directory), and send both (`POST …/recovery/approval`).
4. The server keeps the old keys as retired, removes the old devices and registers the new
   one. The new device signs in, checks the owner against the line's fingerprint, and
   checks that the owner approved its keys.

Everything wrapped for the old keys then waits for a copy for the new ones. Each sync's
`restore` lists what the caller can give back: any member of a folder or group wraps its
current key or secret again (`PUT /v1/folders/{id}/members/{user}/key`,
`PUT /v1/groups/{id}/members/{user}/secret`), and anyone who can change a login shared
with them directly saves it again. Folders and groups they had also get new keys, as when
someone leaves, since the old keys were on a lost device. A save always wraps each
person's copy again for their current keys. Until a copy is made, it gives no access.
Nothing goes on passwords to change: it's the same person.

**Escrow** (opt-in, not for the owner) lets what only the person could open come back
too: their own items outside folders, and folders nobody else can open. Their app wraps
the account's personal key for the owner (`PUT /v1/escrow`, `DELETE /v1/escrow` to stop),
with HPKE, info `keystead/personal-key/v1` and associated data
`transcript("keystead/personal-key/v1", user id)`, and sends the person's agreement,
signed with their account key, as `consent`:

```
transcript("keystead/escrow-consent/v1", user id, revision)
```

The server keeps it in their directory entry (`escrow_consent`), and apps do what a sync
asks for escrow (`escrow_needed`, `escrow_folders`) only when it verifies against the
account's current keys, so a server can't turn escrow on for anyone. The server refuses
escrow changes while a recovery of the account is waiting for approval, so a lost device
can't take escrow away or swap it just before.

When approving, the owner's app opens the escrowed key and wraps it the same way for the
new keys; the person's sync gets it as `recovered_key`, opens their own items with it
and saves them again under the new personal key. The escrowed key stays until the
account escrows a key for its new revision, so a recovery the new device never finished
can be done again without losing anything. The new device agrees to escrow again with its
new keys, and escrows its new personal key (`escrow_needed`), only if the person's earlier
keys had agreed: from 0.15.0 the server keeps the `escrow_consent` that stood with each set
of retired keys (see Directory), and the device checks that signature against keys the
owner approved. Otherwise escrow stays off until the person turns it on. What comes back
from escrow doesn't count, as that is the server's say: anyone can wrap a key for an
account and call it its earlier personal key. Turning escrow off also drops the
agreements kept with earlier keys.
Turning escrow off doesn't take back a key the owner may already have opened: the
personal key comes from the account secret and stays the same.

For each folder they're in themselves that nobody else can open, directly or through a
group, their app also puts a copy of the folder's current key in escrow, sealed with
XChaCha20-Poly1305 under the personal key with associated data
`transcript("keystead/folder-key/escrow/v1", folder id, generation, user id)`
(`PUT /v1/folders/{id}/escrow`). Each sync's `escrow_folders` lists the folders whose
current key has no copy yet: new ones, and ones with a new key. A client puts a folder's key
in escrow only if the folder's signed members name its own account and nobody else (see
Signed members), whatever the list says. The server drops a
folder's copy as soon as anyone else can open the folder, since they can give it back,
and when the person leaves it or turns escrow off. After a recovery, `restore.escrowed`
lists these folders with their copies. The person's app opens each with the earlier
personal key and gives itself the folder back with the same
`PUT /v1/folders/{id}/members/{user}/key`, which the server allows for oneself only with a
copy at the folder's current generation. The folder then gets a new key like any other
the old keys opened, and a copy of that goes back in escrow. Folders reached only through
a group stay out of escrow.

The owner can open an escrowed account's own items and those folders at any time; apps
say so. Without escrow, they don't come back for them.

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

- `version` starts at 1 and goes up by exactly one per saved change. Since 0.12.0 a
  version may put the item in another folder, or out of folders as its author's own
  (see Moving an item).
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
- Clients must verify the signature against the author's approved directory entry. For
  an item in a folder with signed roles they also check that its author could save it
  there, and open it only through the folder's copy of its key (see Signed roles).
- A version must have the shape of its format, and clients and servers refuse one that
  doesn't, whatever its signature: either a folder with the folder's copy or an owner with
  the owner's, each person and each group once and never the owner among the people, and
  copies for groups only from format 3 on (always in format 3, optionally in format 4).
  A format's signature covers only the fields that format has, so one of them added to an
  older format's version would ride along unsigned.
- Saving gives every group its copy at the group's current generation (see Groups).

### Format 1

Items saved by Keystead 0.1 have no `format` field, no `owner` and no `keys`: they are
format 1, and one that has an owner or key copies is refused. Their parts are encrypted with the **folder key itself**, with associated data
`transcript("keystead/item/v1", item id, folder id, version, part)`, and signed as
`transcript("keystead/item-signature/v1", item id, folder id, version, author, deleted,
overview nonce, overview ciphertext, details nonce, details ciphertext)`. Clients still
open them, and save the next version as format 2 with a new item key. An item never goes
back to format 1.

**Folder info** (`{"name"}`) is encrypted with the folder key, with associated data
`transcript("keystead/folder-info/v1", folder id)`. **Renaming** a folder is a rekey (see
Removing access, and new keys) with the new name in its info: members get it as a
`rekeyed` entry, so it works with every server and app that has rekeys.

Folders nest by name only: apps show "Engineering / Databases" (parts joined by
`" / "`) inside "Engineering". Each folder still has its own key and its own people and
groups; sharing one never shares another. A folder made inside another may start out
shared like it, which is just sharing it with the same people and groups. Renaming a
folder renames the folders inside it that the renamer manages; the rest keep their names.

**Deleting a folder** (0.13.0 and later; `DELETE /v1/folders/{id}?logins=N`, managers)
deletes it for everyone with the items in it, their history and their passwords to
change, for good: they don't go to Recently Deleted. `logins` is how many live items the
manager agreed to delete; if the folder has another number, the server refuses. Everyone
who could open the folder gets `left`, and then `left_item` for any of its items they had
without it, as when they're removed. Folders inside it by name stay.

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
A plain approval is always of revision 0 (`POST /v1/users/{id}/approval`, which the server
refuses for later revisions), and the owner's app never approves someone again it has
seen approved: keys after a recovery are approved with the recovery.

After a recovery with the owner's help, an entry has new keys at a higher `revision`
(0.13.0 and later; absent means 0), signed as

```
transcript("keystead/directory-entry/v2", user id, revision, name, encryption key, signing key)
```

Clients remember the highest revision the owner approved for each person and never share
with an earlier one, so a server can't swap old keys back in. The owner's app remembers
the revision it approves as it approves it. The earlier keys stay
listed under `retired`, each with its revision, name and the owner's approval as given
(and, from 0.15.0, the person's `escrow_consent` if it stood when the keys were replaced),
so what they signed still verifies, but only what they had signed by the recovery.
Someone holding the lost device's secret can't sign anything new with them.

When approving, the owner's app signs a list of it (`SignedBefore`): the SHA-256 digest of
each signature, of item versions and group entries, sorted, without repeats, as

```
transcript("keystead/signed-before-recovery/v1", user id, revision, digest, digest, …)
```

where `revision` is the retired keys'. The digests come from the server, which lists
everything the person signed that it holds (`GET …/recovery`'s `signed`: every item
version, current or in history, deleted or not, and every group entry), and from the
owner's own copy, in case the server left some out. The list goes with the approval and
is served at `GET /v1/users/{id}/retired/{revision}`. Clients fetch each list once,
check the owner's signature, and keep it. A retired key then verifies a version or an
entry only if its signature's digest is on that list; clients treat anything else as
unsigned. Digests of signatures, not of messages, so a server can't list a message
prepared in advance for whoever holds the old keys to sign later: only the key's holder
can make a signature. What was signed before the approval still verifies, as with any
lost device until then.

Unsigned flags show who has `escrow` on, as the server says, and who is `recovering`. Clients before 0.13.0
can't check a revision above 0, and stop trusting that person until they're updated.

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

**Members** (0.15.0 and later). An entry also names who is in the group: `"members"`, user
ids in ascending order, and its signature then covers them, under its own domain:

```
transcript("keystead/group-entry/v2", group id, revision, name, generation, encryption
           public key, number of managers, each manager, number of members (4 bytes),
           then each member's user id, signer)
```

An entry without `members` is from before, and signs as above. Once an entry names them,
every later one does. With the same key people are only added, since whoever holds the
secret keeps it; an entry for a new key names those who stay, and nobody new. So someone
who left stays on the list until the group's next key, which they don't get. Adding
someone comes with the next entry, naming them too. The first entry to name a group's
members, for a group from before, names exactly who the server lists: the owner's app, or
a manager's in it, signs it at its next sync.

Clients give a group's secret only to whom its latest entry names: when the group gets a
new one, to those of them the server still lists, and refusing if the server lists anyone
else; and to someone who recovered, only if they're named (see Recovering with the owner's
help). The server's list is only ever taken as who has left.

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
keys, and keeps its entries on record (`Groups.former`, 0.15.0 and later), as folder
entries its members signed are checked against them. It refuses while the group is the only manager of a folder. Items keep
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
`entries`, its `members` and whether it `needs_rekey`, and in `former` the entries of
each group since deleted; for an account the owner hasn't approved, both are empty. `Members` also lists the `groups` a folder or item is shared
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
| `POST /v1/sign-in/renew` | | `Session` | A signed-in device |
| `POST /v1/invites` | `InviteRequest` | `Invite` | Owner |
| `GET /v1/invites` | | `Invites` | Owner |
| `DELETE /v1/invites/{id}` | | 204 | Owner |
| `POST /v1/invites/accept` | `AcceptInviteRequest` | `Enrolled` | Invitee, with the token |
| `POST /v1/recover/challenge` | `RecoveryChallengeRequest` | `RecoveryChallenge` | A device with the account secret |
| `POST /v1/recover` | `RecoverRequest` | `Enrolled` | A device with the account secret |
| `GET /v1/devices` | | `DeviceList` | Members |
| `DELETE /v1/devices/{id}` | | 204 | The device's own account, from another device |
| `POST /v1/sign-out` | | 204 | The device itself, which is then forgotten |
| `POST /v1/users/{id}/approval` | `ApprovalRequest` | 204 | Owner |
| `GET /v1/directory` | | `Directory` | Members |
| `DELETE /v1/users/{id}` | | 204 | Owner, for anyone but themselves |
| `GET /v1/users/{id}/removal` | | `Removal` | Owner (0.17.0) |
| `POST /v1/users/{id}/removal` | `RemoveUserRequest` | 204 | Owner, for anyone but themselves (0.17.0) |
| `POST /v1/users/{id}/recovery` | | `RecoveryStarted` | Owner, for anyone approved but themselves |
| `GET /v1/users/{id}/recovery` | | `RecoveryInProgress` | Owner |
| `DELETE /v1/users/{id}/recovery` | | 204 | Owner, or the person themselves |
| `POST /v1/users/{id}/recovery/approval` | `ApproveRecoveryRequest` | 204 | Owner |
| `GET /v1/users/{id}/retired/{revision}` | | `SignedBefore` | Anyone signed in |
| `POST /v1/recovery/claim` | `ClaimRecoveryRequest` | `RecoveryClaimed` | The new device, with the token |
| `POST /v1/recovery/state` | `RecoveryTokenRequest` | `RecoveryState` | The new device, with the token |
| `PUT /v1/escrow` | `EscrowRequest` | 204 | Anyone but the owner, for themselves |
| `DELETE /v1/escrow` | | 204 | Anyone, for themselves |
| `PUT /v1/folders/{id}/escrow` | `FolderEscrowRequest` | 204 | Anyone with escrow on, for a folder only they can open |
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
| `PUT /v1/folders/{id}/members/{user}/key` | `RestoreFolderKeyRequest` | 204 | Folder members, for someone who recovered; themselves, from escrow |
| `DELETE /v1/folders/{id}?logins=N` | | 204 | Folder managers |
| `POST /v1/folders/{id}/rekey` | `RekeyRequest` | 204 | Folder managers |
| `PUT /v1/folders/{id}/entries` | `FolderEntryRequest` | 204 | Folder managers: once for its members (0.15.0), once for its roles (0.17.0) |
| `POST /v1/folders/{id}/groups` | `AddFolderGroupRequest` | 204 | Folder managers |
| `PUT /v1/folders/{id}/groups/{group}` | `RoleRequest` | 204 | Folder managers |
| `DELETE /v1/folders/{id}/groups/{group}` | | 204 | Folder managers |
| `POST /v1/groups` | `CreateGroupRequest` | 201 | Owner |
| `GET /v1/groups` | | `Groups` | Members |
| `PUT /v1/groups/{id}` | `UpdateGroupRequest` | 204 | Owner, and the group's managers in it |
| `POST /v1/groups/{id}/members` | `AddGroupMemberRequest` | 204 | The group's managers in it (the owner too, if in it) |
| `DELETE /v1/groups/{id}/members/{user}` | | 204 | Owner and the group's managers in it, or the member themselves |
| `POST /v1/groups/{id}/rekey` | `GroupRekeyRequest` | 204 | The group's managers in it (the owner too, if in it) |
| `PUT /v1/groups/{id}/members/{user}/secret` | `RestoreGroupSecretRequest` | 204 | Group members, for someone who recovered |
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
| `GET /v1/password-ages` | | `PasswordAges` | Members; items they can open |
| `GET /v1/sync?cursor=N&limit=M` | | `SyncPage` | Members |

`Health` is `{"status", "version", "item_format"}`. `item_format` is the newest item
format the server stores; servers older than 0.2.0 leave it out and store only format 1,
so clients check it before saving. Servers with groups (0.4.0 and later) say 3, and with
one-time codes (0.6.0 and later) 4.

**Setup.** The setup code works once, and (0.16.0 and later) for a day from the server's
first start: after that `POST /v1/setup` answers 403 to the right code too, and an
unclaimed server makes a new code when it's restarted. A wrong code is 403, a server
already set up 409.

**Too many requests.** A proxy in front of the server may limit how many requests one
address makes, as the nginx configuration in `deploy/` does, and answer 429 without
asking the server.

**Invites.** An invite's token works once, and (0.16.0 and later) for seven days:
`Invite` is `{"token", "expires_at"}`. The server keeps only the token's SHA-256, so the
owner can't be shown an invite's line again. `Invites` lists the ones nobody has used and
that haven't run out, oldest first, each as `{"id", "name", "created_at", "expires_at"}`;
ids are never used again. Deleting one revokes it: its token stops working at once.
Accepting a token that was used, revoked or has run out answers 403. Invites made before
0.16.0 run out seven days after the server is updated. Servers before 0.16.0 answer 404
or 405 to listing and revoking, leave out `expires_at`, and their invites work until
used; clients say to update the server instead of failing.

When saving an item, the server checks that the path and body ids match, the session's
user is the author and the version is `base_version + 1`, or from 0.17.0 up to 1,000,000
past that (see Older copies), or 1 for a new item. The
author must be an editor or manager of the current version (see Roles); a new item must
be in a folder where the author edits or manages, or be the author's own. Adding anyone
to `people`, or dropping anyone, takes a manager, except that anyone who can save may
drop people the owner removed from the team. The item can't go back to format 1, and
everyone newly in `people` must be approved and not removed.

**Moving an item** (0.12.0 and later) is saving a version with another `folder_id`, or
none and the author as `owner`, under a new item key sealed for the new place; people and
groups it's shared with directly keep their copies. The author must be able to change it
(edit or manage) and to add items to the new folder; an item in no folder can only be
moved by its owner. Members of the old folder who can't reach it now lose it like anyone
removed: their feed gets `left_item` with `"moved": true`, telling devices to drop the
copy that still says it's in one of their folders, and it goes on their passwords to
change. Servers before 0.12.0 refuse moves. Apps before 0.12.0 ignore `moved`, so they
keep showing a moved item in its old folder until they're updated. Adding
or dropping a group also takes a manager; a group new to the item gets its copy at the
group's current generation, and no copy may name a generation the group hasn't reached.
`PutItemRequest.roles` gives the roles of people new to `people`, and `group_roles` those
of groups new to `groups`, and `password_changed` (left out when false) that its password
differs from the previous version's (see Passwords to change). A live version may follow a
deletion marker, which brings the item back (see Recently deleted). If another version was
saved first, it answers 409 with that version. A client keeps the answer to a save only
if it's the version it sent, and a 409's version only if it's of the same item and signed
by an approved author. If that version is older than the client's own copy, the server is
behind, and the client saves its version again on top of it (see Older copies). A first
version under an id already in use
gets the item there back the same way only if the caller can open it; anyone else gets a
409 with just an error, so an id kept by someone who lost access shows them nothing.

### Roles

Everyone who can open a folder or an item has a role there:

| Role | Can |
| --- | --- |
| `view` | Open and copy |
| `edit` | Also save new versions: change and delete items |
| `manage` | Also share, change roles, remove people, and give a folder a new key |

A folder's creator manages it, and so does an item's owner. Sharing also takes the owner's
approval: an account that joined with an invite and isn't approved yet keeps folders and
items of its own, but the server refuses (403) its sharing a folder or an item with
anyone or any group. A folder or item shared with
a group gives the group a role, which is everyone's in it. Someone with access more than
one way (through a folder, directly, through groups) gets the highest role. A folder
always keeps at least one manager, a person or a group. Members and shares from before roles existed are managers, since everyone could
do everything then. The server keeps and enforces roles; reading depends only on the keys
someone holds. In a folder, roles are also signed by its managers, and clients go by that
(0.17.0 and later; see Signed roles). On a single item shared directly they are the
server's alone.

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
account can't be recovered: recovery challenges given out before the removal stop working
with it. Removing someone already removed answers 404, and removes any device the account
still has. A folder left without a manager, a person or a group, gets one: whoever has
been in it longest. Where the folder's roles are signed, the owner signs that person in
(see Signed roles), and a plain `DELETE` answers 409. An item outside folders left
without one is managed by everyone it was shared with. Clients drop removed people's
copies from items as they save them.

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

**Password health** (0.13.0 and later) is worked out by apps from the passwords they can
open, in memory: weak ones (zxcvbn scores them below 3), ones other items share, and ones
set over a year ago. Only that last part comes from the server: it records when each
item's password was last set, when the item is created or saved with `password_changed`,
and `GET /v1/password-ages` lists it for the items the caller can open. Items saved before
0.13.0 count from when they were last saved; before 0.7.0, from nothing.

**Sync** returns feed entries after the cursor, in change-number order, from one
consistent snapshot:

- `item`: the latest version of each changed item the user can open (in their folders,
  their own, or shared with them or their groups directly). An item shared directly
  arrives this way: sharing saved a new version, with a new change number. So does an
  item reached through a group joined after its latest version, at the join's number.
- `joined`: the folder key wrapped for the user, or for a group they're in
  (`via_group`: `{"group_id", "generation"}`), with its `generation` and `chain`, plus the
  folder's info, items and signed `entries` (see Signed members). A folder too big for a
  page comes in parts (see below).
- `left`: drop a folder, keeping its items that were also shared with the user directly.
- `rekeyed`: a folder the user can open has a new key: the new one wrapped for them or
  their group (`via_group`), its generation, the whole chain and the info sealed with it.
  A client takes a `joined` or `rekeyed` for a folder it has had only if it's one of the
  folder's own keys: it opens, isn't of an earlier generation than the one the client
  has, and its chain leads back to the folder's first key. The client remembers that
  key's fingerprint, SHA-256 of `transcript("keystead/folder-key-pin/v1", folder id,
  key)`, for every folder it has had, also after leaving, and keeps it on the device.
  Anyone can wrap a key for an account, the server included; a made-up key has no chain to
  the first one. A folder the client has never had is taken on its key opening alone
  (see Not in this format yet).
- `left_item`: the user lost direct access to an item; with `"moved": true`, it moved to a
  folder they can't open, so drop it whatever folder the local copy names.
- `group`: the user joined a group, or one they're in changed: its `entries`, its current
  secret wrapped for them with its `generation`, and the `chain` to older ones. It comes
  before anything that needs the group's keys.
- `left_group`: forget a group's keys.

Change numbers only go up. From 0.17.0 each is also at least the time it was given out, in
milliseconds since 1970, so a server restored from a backup numbers its new changes past
anything a device saw before the restore, instead of giving the same numbers to other
changes, which devices would skip. When caught up, a page's `cursor` is the newest change
number, from 0.17.0 even if the cursor asked with is higher: that happens only if the
server went back, and the client takes the lower number and says so. Servers before then
answer with the higher one.

**Pages.** A page holds up to `limit` entries (500 unless asked, 1,000 at most) and, from
0.17.0, about 4 MB of items: it ends before the entry that would take it over, though it
always takes one. `more` says to ask again from `cursor`. So an answer stays under the
10 MB that apps before 0.17.0 can read, with one exception, next.

**A big folder, in parts** (0.17.0 and later). A folder with more than a page of items
when someone joins it comes first on a page, alone. A client that asks with `parts=true`
gets the `joined` entry with the first of the folder's items, then pages of `item` entries
with the rest, oldest change first. Until the last part the page's `cursor` is the one
asked with, `more` is true, and `resume` says where the part ended: the client asks again
with the same cursor and `resume` set to it. A `resume` that isn't of the join now first
is ignored, so a client that stopped halfway starts the folder again. The last part has
no `resume` and moves the cursor to the join. Only items from before the join are in the
parts; whatever changed in the folder since follows the join, like any change.

A client that doesn't ask for parts gets all those items on the `joined` entry at once,
as before 0.17.0, however big that is. Servers before 0.17.0 ignore `parts` and send
every joined folder whole, with what changed since; a client reads such an answer up to
256 MB.

The last page also carries the user's `roles` (in each folder, and on each item shared
with them or their groups directly, the highest of the ways in), and every page
`rekey_needed` and `group_rekey_needed`, plus, from 0.13.0, `restore`, `recovered_key`,
`escrow_needed` and `escrow_folders` (see Recovering with the owner's help). The prototype in
`prototypes/change-feed` shows why each item arrives exactly once.

### Signed members

(0.15.0 and later; `"membership": 1` in `GET /v1/health`.) The server keeps who is in each
folder, but clients hand a folder's key on: to everyone in it when it gets a new key, and
to someone who recovered. A server that could say who the members are could get the key
handed to anyone the owner approved. So who is in a folder is signed, in entries with
numbered revisions like a group's:

```json
{
  "folder_id": "…", "revision": 3, "generation": 1, "key": "…",
  "members": [1, 2], "groups": ["…"], "previous": "…", "signer": 1, "signature": "…"
}
```

`members` are the user ids the folder is shared with directly, and `groups` the groups,
both in ascending order. `key` is a fingerprint of the folder key of `generation`:
SHA-256 of `transcript("keystead/folder-key-pin/v1", folder id, key)`. `previous` is
SHA-256 of the previous entry's signature, left out in the first. The signer's account
signing key signs:

```
transcript("keystead/folder-entry/v1", folder id, revision (4 bytes), generation (4 bytes),
           key fingerprint, number of members (4 bytes), each member's user id, number of
           groups (4 bytes), each group's id, previous, signer)
```

Clients check every entry, oldest first:

- Revision 1 is signed by someone it names, or someone in a group it names. Each later
  one is the next number, names the one before it in `previous`, and is signed by someone
  the one before it names, or someone in a group it names.
- With the same key (same `generation` and `key`), people and groups are only added. An
  entry for the next generation is for a new key, and names those who stay and nobody new.
- Each signer must be in the approved directory, with the keys they had (see Directory).
- Who is in a group comes from the group's own signed members: for an entry the client is
  seeing for the first time on a folder it already has, the group's latest entry (or, for
  a group since deleted, its last); for earlier entries, any of the group's entries, as its
  members may have been others then.

A folder's entries come with it (`joined`, `rekeyed`, and `Members.entries`). A client
takes a folder only if its entries check out, continue the ones the client has, are for
the folder's current key (the latest entry's `generation` and `key` match the key the
client was given) and name the client's account or a group it's in. A folder that has had
entries never goes back to having none.

Every change to who a folder is shared with comes with its next entry, which the server
checks says exactly that change: making a folder (its maker alone), sharing it with a
person or a group (one more name), and giving it a new key (exactly who's in it now).
Removing someone doesn't: they stay named until the folder's next key, which they don't
get. A change without an entry, to a folder that has entries, is refused (409), so apps
before 0.15.0 can't share or re-key such folders.

Clients give a folder's key only to whom its latest entry names. A new key goes to those
of them the server still lists, and a client refuses to make one if the server lists
anyone the entry doesn't name. Someone who recovered gets their copy again only if they're
named. The server's list is only ever taken as who has left.

**Folders from before.** A folder made before 0.15.0 has no entries. One of its managers'
apps signs its first at its next sync (`PUT /v1/folders/{id}/entries`), naming exactly who
the server lists, for the folder's current key. That once, the server's list is taken at
its word. Until then clients open the folder but put nothing new into it, since a folder
only its key vouches for could be anyone's. A manager who has the folder only through a
group signs once the group's own members are signed.

**What this doesn't cover.** A removal is the server's word until the folder's next key. A
device with no history of a folder, such as a new one, checks the entries it's given from
the first, so a server can still show it an earlier state of the folder as the current
one. And clients that only ever talk to a server from before 0.15.0 take its lists at its
word, as before; once a client has seen a server keep signed members, it doesn't go back.

### Older copies

Everything a server hands out is signed, but so is an older copy: an earlier version of an
item, an earlier key of a folder with the entries it had then, a group's entries cut back
to an earlier revision. A server could hand one out as if it were the current one, to put
back a password that was changed or someone who was taken out.

A client keeps the newest it has seen of each item (its `version`), each folder (its key's
`generation` and its latest entry's `revision`) and each group (its latest entry's
`revision`). What it holds says that. When it drops something, after losing a login,
leaving a folder or seeing a group deleted, it remembers how far it had seen it, until it
holds something at least that new again. Then:

- An item older than the client's copy, or than what it remembers of one it dropped, is
  ignored. So is a folder record or group with an earlier generation or fewer entries.
  The client keeps what it has and the sync says so.
- An equal version is the same one, and is taken: as when someone is added back.
- A save answered with an older version than the client's (409) means the server is
  behind. The client sends the version it sealed again, on top of the server's copy
  (`base_version` set to the server's). Its number is past everything the client has
  seen, so every client takes it. Servers before 0.17.0 take only the version right after
  their own, and refuse it (400); the client then says to update the server.
- A save answered 404 says the server doesn't have the item: deleted for good, or a
  server restored from before it existed. The client says so and doesn't re-create it.

**A server restored from a backup** looks exactly like this. Clients keep their newer
copies, follow the server's change numbers down and warn. A device that first syncs again
after new changes were made isn't warned, as nothing it gets is older. What was saved after the backup
was made isn't on the server, and only each author can save their versions again: people
save their recent changes again. Their newer copies are what they edit, and their saves go
past the versions others saw.

**What this doesn't cover.** A device that has never seen something has nothing to compare
with: a new device, or one that never had a folder, can be shown an older state as the
current one. Only a log of every change, signed and kept by every device, would close that.

### Signed roles

(0.17.0 and later; `"membership": 2` in `GET /v1/health`.) Before, the entries said who is
in a folder and the server alone said what each may do. A server that lied could let a
viewer's changes through to everyone, or let a viewer share the folder. So an entry also
carries the roles:

```json
{ "…": "as above", "roles": { "members": ["manage", "view"], "groups": ["edit"] } }
```

`roles.members` are the roles of `members`, in their order, and `roles.groups` those of
`groups`. With roles, the signature is over another domain and two more parts, so an
entry can't pass for one without them and its roles can't be taken off:

```
transcript("keystead/folder-entry/v2", …the parts above…,
           each member's role (1 byte each: 1 view, 2 edit, 3 manage), each group's role)
```

Apps before 0.17.0 can't check such an entry: they keep what they have of the folder and
take no change to it until they're updated.

Clients check, with the rest:

- An entry with roles has one for each member and each group, and at least one of them
  is `manage`. Once an entry has roles, every later one does.
- It is signed by someone the entry before makes a manager: by their own role, or that of
  a group they're in. The first entry of a folder is signed by someone it makes a manager
  itself.
- The team's owner may sign an entry that changes roles and nothing else, whether or not
  they're in the folder. That is for a folder whose only manager leaves the team.
- An entry from before roles were signed makes everyone it names a manager, as everyone
  was. The first entry with roles after such ones is signed by anyone they name.

Every change to a folder then comes with its next entry, roles included, and the server
checks they say what its own lists say: sharing with a person or a group (their role),
changing a role (`RoleRequest.entry`, which is new), and a new key (those who stay, as
they were). A change without roles to a folder that has them is refused (409), as is a
change of role without an entry.

**Saving.** A client refuses a version of an item in one of its folders if the most its
author ever was in that folder, by its entries, is a viewer: the version counts as not
signed. The server refuses such a save too (403), also from someone the item is shared
with directly to edit: in a folder with signed roles, a viewer of the folder views its
items. Someone the entries never named passes, as an item in a folder can also be shared
with someone outside it, whose role only the server keeps. And in a folder with signed
roles a client opens an item only through the copy of its key sealed with the folder's
key, never through a copy made out to its own account or a group: whoever wrote a version
that opens either knew one of the folder's keys or kept a copy sealed by someone who did.
A version put there by someone outside, under a key of their own, doesn't open.

**Changing things.** A client signs the next entry of a folder only if the latest makes
its account a manager, whatever the server says.

**Removing a folder's only manager from the team.** The server can't pick the next one:
its choice wouldn't be signed. `GET /v1/users/{id}/removal` lists the folders with signed
roles that the person alone manages and others are in, each with its entries and whom the
server suggests (`promote`: whoever has been in it longest). The owner's client checks
each folder's entries, that they make the person a manager, and that they name the one
suggested; it signs the next entry, the same but with that one a manager, and sends them
with `POST /v1/users/{id}/removal` (`{"promotions": [entry, …]}`). The server makes them
managers in its lists too, takes only a rise to manager, and refuses the removal (409) if
one is missing. The new manager then gives the folder its new key.

**Folders from before.** A folder with entries but no roles gets them from one of its
managers' apps at its next sync: an entry that changes nothing else, with the roles the
server lists (`PUT /v1/folders/{id}/entries`). That once, the server's list of roles is
taken at its word. Someone it no longer lists, who stays named until the folder's next
key, is written down as a manager, like everyone from before roles.

**What this doesn't cover.** Roles on a single item shared directly, and so what someone
outside a folder may do to an item in it. Someone who could once edit a folder can still
be passed off as the author of a later version, since nothing signed says when a version
was written. A new device, which a server can show an earlier state of a folder (see Older
copies), can be shown one from before its roles were signed. And a group's managers are the server's to
name: anyone in a group can sign its next entry.

## Not in this format yet

- Signed roles on single items. In a folder roles are signed (see Signed roles); on an
  item shared directly, and for a group's managers, they are kept and enforced by the
  server alone.
- Groups inside groups (on purpose: no loops, and access stays easy to follow).
