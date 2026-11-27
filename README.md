# Keystead

A self-hosted team password manager with native desktop apps. Keystead keeps the
simple, local-first design of the Unix [`pass`](https://www.passwordstore.org/) tool
and adds what teams need: sharing with people and groups, account recovery, and an
app for colleagues who never open a terminal.

**Status:** early setup. Nothing is usable yet.

## Layout

| Path | What it is |
| --- | --- |
| `crates/keystead-core` | Shared Rust library: data format, crypto, sync and search |
| `crates/keystead-server` | The server (`keystead-server`), one binary per organization |
| `crates/keystead-client` | The client side shared by the CLI and the apps: sign-in, sync, verification, actions |
| `crates/keystead-cli` | The command-line tool (`keystead`) with pass-style commands |
| `crates/keystead-ffi` | The core's Swift bindings (UniFFI), linked into the Mac app |
| `apps/macos` | The macOS app, with a main window and a menu bar icon (SwiftUI, Xcode project); see its [README](apps/macos/README.md) |
| `docs/format.md` | The data format and API spec (version 1 draft) |
| `prototypes/change-feed` | Prototype: the server's change feed on SQLite with 50 devices editing at once |
| `prototypes/secure-enclave` | Prototype: a Secure Enclave device key unlocking the account key |
| `prototypes/unlock-search` | Prototype: unlock and search speed for vaults of up to 100,000 items |

Windows and Ubuntu apps come after macOS.

## Building

Requirements: Rust (stable, via rustup) and, for the macOS app, Xcode 16 or later.

```sh
cargo build --workspace
cargo test --workspace
cargo clippy --workspace --all-targets -- -D warnings
cargo fmt --all --check
```

Run the server. It listens on `127.0.0.1:8080` (set `KEYSTEAD_LISTEN` to change it) and
keeps its database in `./keystead-data` (set `KEYSTEAD_DATA`). On first start it prints a
one-time setup code, which works for a day; after that, restarting a server nobody has
claimed prints a new one. Whoever uses it, in the Mac app (Set up a new team) or with
`keystead setup`, becomes the team's **owner**: the one account that invites and approves
people, removes them from the team and makes groups. Running the server doesn't make you
the owner, and the server holds no key that opens anything.

```sh
cargo run -p keystead-server
curl http://127.0.0.1:8080/v1/health
```

Or run it in Docker. The image is small (about 57 MB), runs as a non-root user and keeps
its database in a named volume, so data survives restarts and rebuilds:

```sh
docker compose up -d              # build and start on 127.0.0.1:8080 (KEYSTEAD_PORT to change)
docker compose logs server        # shows the one-time setup code on first start
docker compose down               # stop; add -v to also delete the data
```

Each release publishes the image as `ghcr.io/elquimista/keystead-server` (see
[Releasing](#releasing)). To run it for your team on a server with a domain name and HTTPS,
see [`deploy/README.md`](deploy/README.md).

The API is specified in [`docs/format.md`](docs/format.md).

## Try it with the CLI

With the server running, use `KEYSTEAD_HOME` to keep two accounts apart in separate
terminals:

```sh
cargo build -p keystead-cli          # builds target/debug/keystead

# Alice: claim the server and invite Bob
export KEYSTEAD_HOME=/tmp/alice
keystead setup http://127.0.0.1:8080 <setup code> --name Alice
keystead invite Bob                  # prints the join command for Bob; it works once, for a week
                                     # (`keystead invites` lists and revokes unused ones)

# Bob, in another terminal
export KEYSTEAD_HOME=/tmp/bob
keystead join http://127.0.0.1:8080 <token> --owner <Alice's fingerprint> --key <key>

# Alice: her next sync approves Bob, as the invite's key proves his keys are his; then share
keystead users                       # syncs the list; Bob shows as approved
keystead folder create Production
keystead folder share Production 2
keystead add "AWS root" --folder Production --username root@example.com

# Alice: a login of her own, then share just that one with Bob
keystead add Bank
keystead share Bank 2

# Bob
keystead ls
keystead show "AWS root"             # the password; --notes for the notes
keystead edit "AWS root"             # new password; or --rename, --username, --url, --notes
keystead rm Bank                     # delete for everyone who can open it (asks first)
keystead mv "AWS root" --to Staging  # move to another folder; --own takes it out of folders
```

To move from Passbolt, export from it in the KDBX format (with a passphrase), then import
the file; a KeePass or KeePassXC file works the same way. Passbolt folders become folders
(nested ones named like "Engineering / Databases"), one-time codes come along, and extra
fields go into the notes. It shows what it would do and asks first; logins already here
are left out, so importing twice adds nothing:

```sh
keystead import passbolt-export.kdbx                          # asks for the export's passphrase
keystead import passbolt-export.kdbx --unfiled-folder Imported   # logins in no folder go here
```

New folders are yours alone until shared. Passbolt's sharing doesn't come with the export:
share the folders with your groups afterwards.

To keep a copy of your own, export every login you can open to a KeePass file, encrypted
with a passphrase of at least 12 characters (Argon2id over 128 MiB per guess). Folders
become groups and one-time codes come along; KeePassXC and KeePass open it, and `import`
reads it back. Only you can read the new file, and it never overwrites one:

```sh
keystead export keystead-backup.kdbx   # asks for a passphrase, twice
```

A deleted login can be brought back for 30 days (needs a 0.9.0 server):

```sh
keystead deleted                     # what was deleted, by whom, and until when it's kept
keystead undelete Bank               # bring it back, for everyone who had it
keystead purge Bank                  # delete it for good now (asks first)
```

For sites that ask for a one-time code, keep its setup with the login: the `otpauth://`
link from the site's QR code, or the setup key it shows for typing in (needs a 0.6.0
server).

```sh
keystead edit GitHub --otp "JBSW Y3DP EHPK 3PXP"   # or --otp 'otpauth://totp/…'; --no-otp removes it
keystead otp GitHub                               # the current code
```

The server keeps each login's last 10 earlier versions (needs a 0.7.0 server), for its
editors and managers:

```sh
keystead history Bank                # versions, who saved each, when, and what changed
keystead history Bank --show 3       # version 3's password
keystead restore Bank 3              # bring version 3 back, as a new version
```

Everyone who can open a folder or a login has a role: `view`, `edit` or `manage`.
Managers share (`--role`, edit by default), change roles and remove people; removing
someone from a folder gives it a new key, so they can't read what's saved afterwards.

```sh
keystead folder share Production 3 --role view
keystead folder members Production   # who is in it, with roles
keystead folder role Production 3 edit
keystead folder remove Production 3  # takes them out and changes the folder's key
keystead folder leave Production
keystead folder create Databases --inside Production   # "Production / Databases", shared like Production
keystead folder create Keys --inside Production --private
keystead folder rename Production Prod   # and the folders inside it you manage
keystead folder delete Old               # with its logins, for good (asks first)
keystead unshare Bank 2              # take away someone's copy of one login
keystead remove-user 3               # owner: remove someone from the team (asks first)
```

A login added without `--folder` is yours alone until you share it. `keystead share`
shares one login, from a folder or not, without the rest of its folder.

New keys protect what's saved after someone loses access, but not passwords they already
saw. Keystead keeps a list of those for everyone who can change them, until a new password
is saved (needs a 0.5.0 server):

```sh
keystead to-change                       # who lost access, and which passwords they could see
keystead edit "AWS root"                 # a new password takes it off the list
keystead to-change dismiss Bank          # keep a password as it is
keystead to-change dismiss --user 3      # everything user 3 could see, if they only moved teams
```

Password health lists the logins you can change whose password is weak, used for other
logins too, or unchanged for over a year (old ones need a 0.13.0 server). It's worked out
on your machine; nothing about the passwords is kept:

```sh
keystead health
```

Groups share folders and logins with several people at once, and people added later get
them too. The owner makes groups; a group's managers add and remove people. Taking
someone out gives the group, and the folders shared with it, new keys.

```sh
keystead group create Engineering 2 3   # owner: a group with Bob and Carol, Alice managing
keystead group list
keystead folder share Production --group Engineering --role edit
keystead share Bank --group Engineering --role view
keystead group add Engineering 4
keystead group remove Engineering 3     # takes Carol out; new keys for the group and its folders
keystead group manager Engineering 2    # Bob can add and remove people too (--remove undoes it)
keystead group rename Engineering Platform
keystead folder group-role Production Platform view
keystead folder remove Production --group Platform
keystead unshare Bank --group Platform
keystead group leave Platform
keystead group delete Platform          # everyone loses what only it gave them (asks first)
```

To use the account on another machine too, add it from one that has it (needs a 0.8.0
server). The new machine shows a code; typing it on the old one sends the account across,
sealed so only the new machine can open it:

```sh
keystead devices add                 # Alice: prints a line for the new machine, then asks for its code
keystead add-device http://127.0.0.1:8080 <token> --owner <owner's fingerprint>  # on the new machine
```

Each account has a recovery kit: its secret as 24 words, to bring it back on a new device.

```sh
keystead recovery-kit                # Alice: show the words, server and fingerprints
keystead recover http://127.0.0.1:8080 --owner <owner's fingerprint>  # on a new device
keystead recover http://127.0.0.1:8080  # the owner can leave out --owner
keystead devices                     # list this account's devices
keystead devices remove <device id>  # lock out a lost one
keystead sign-out                    # this machine forgets the account (asks first)
```

Lost every device and the recovery kit too? The owner can help you back in with new keys
(needs a 0.13.0 server). Once the owner approves them, what's shared with you comes back as
everyone's apps sync. Your own logins, and the folders only you are in, come back only if
you turned on escrow beforehand, which lets the owner open them. Turning escrow off later
stops new copies, but can't take back what the owner may already have opened:

```sh
keystead escrow on                   # Bob, beforehand: let the owner recover his own logins and folders
keystead recovery start 2            # Alice: prints a line to send Bob (--sign-out-devices: his devices stop working now)
keystead recover-with-help http://127.0.0.1:8080 <token> --owner <owner's fingerprint>  # Bob, on a new machine: shows his new fingerprint and waits; if it stops, run it again
keystead recovery approve 2 --fingerprint <Bob's new fingerprint>  # Alice, after he reads it out
keystead recovery cancel             # Bob, on a device he still has, if he didn't ask for it
```

The CLI keeps the shared `profile.json` (the same format the Mac app uses) and
`device.json`. On a Mac its keys, the account secret and this machine's sign-in key, are in
your login Keychain under "Keystead CLI", and `device.json` only names the item; keys from
an older CLI move there the next time you run a command. The first run of a newly built
`keystead` may ask to use them: choose Always Allow. Elsewhere the keys are in
`$KEYSTEAD_HOME/device.json`, readable only by you but not encrypted.

Build the macOS app (signing is covered in [apps/macos/README.md](apps/macos/README.md)):

```sh
cd apps/macos
scripts/build-core.sh       # once after cloning; Xcode keeps it up to date afterwards
open Keystead.xcodeproj
```

If you installed rustup with Homebrew, `cargo` isn't on your PATH by default. Add
`/opt/homebrew/opt/rustup/bin` to it, for example in `~/.zshrc`:

```sh
export PATH="/opt/homebrew/opt/rustup/bin:$PATH"
```

## Releasing

### One version for everything

The server, the CLI and the apps share one version number and one tag, `v<version>`. A
release that changes only the Mac app, or only the server, still takes the next version, and
the release workflow publishes the server image under it either way. The image may then be
the same as the previous release's; the release notes say so, and updating the server is
optional.

Versions follow semantic versioning: from here on, the patch number for fixes (0.3.1) and
the minor number for new features or format changes (0.4.0). Before 1.0, a minor release may need the server
updated first; the release notes and `deploy/README.md` say so when it does.

### Keeping apps and servers compatible

Matching versions aren't what keeps the parts working together; each side checks what the
other can do:

- **A new app works with an older server.** It checks before using anything newer (the
  `item_format` from `/v1/health`, or a 404 from an endpoint the server doesn't have yet),
  then explains what to update instead of failing. Signing out against a 0.2.0 server, for
  example, still wipes the Mac and says the server couldn't be told.
- **A new server keeps older apps working**, or the release notes say which ones need
  updating and why, as 0.2.0 did for the login format.

Separate versions per part (`server-v…`, `mac-v…`) are worth it only once parts ship on
very different schedules; until then they'd add a compatibility table to keep up to date.

### Release checklist

1. Bump the version in all three places:
   - `version` in the root `Cargo.toml`;
   - `MARKETING_VERSION` in `apps/macos/Config/Base.xcconfig`, plus 1 on
     `CURRENT_PROJECT_VERSION` (the build number);
   - `KEYSTEAD_VERSION` in `deploy/.env.example`.
2. Run the checks (`cargo fmt --all --check`, `cargo clippy --workspace --all-targets -- -D
   warnings`, `cargo test --workspace`), which also updates `Cargo.lock`.
3. If whoever runs the server must do something when updating, such as updating the
   server before the apps, add it to the Updating section of `deploy/README.md`.
4. Add a `## 0.2.1` section at the top of [`CHANGELOG.md`](CHANGELOG.md): what changed in
   the server and in the apps, and whether the server has to be updated first. It becomes
   the top of the tag's GitHub release.
5. Commit as "Release 0.2.1", then tag and push:

   ```sh
   git tag -a v0.2.1 -m "Keystead 0.2.1"
   git push origin main v0.2.1
   ```

The tag must match the version in all three files, a final release needs its section in
`CHANGELOG.md` (the workflow checks both), and CI (the Rust checks and the server image)
must pass on the tagged commit. The
[release workflow](.github/workflows/release.yml) then:

- publishes `ghcr.io/elquimista/keystead-server` for `linux/amd64` and `linux/arm64`,
  tagged `0.2.1`, `0.2` and `latest`. Pre-releases such as `v0.3.0-rc.1` get only their own
  tag;
- builds the Mac app on the tagged commit with the [macOS workflow](.github/workflows/macos.yml),
  checks it's the tag's version and runs on Apple silicon and Intel, and attaches
  `Keystead-0.2.1.zip` and its SHA-256 checksum to the tag's GitHub release, making the
  release if there isn't one yet: the version's notes from `CHANGELOG.md`, then install
  notes. A release made by hand before keeps its notes. Its build provenance is recorded, so
  `gh attestation verify Keystead-0.2.1.zip --repo elquimista/keystead` shows it was built
  by this workflow from the tag. A pre-release's GitHub release is marked as one.

The image doesn't wait for the Mac app: GitHub's macOS runners can queue for a long time.
If the Mac app's job fails or never gets a runner, use **Re-run failed jobs** on the run;
the image is unaffected, and the app is attached when it succeeds.

After the first release, GitHub may list the image as private: on the repository's
**Packages** entry, open **Package settings** and change the visibility to public, so
servers can pull it without logging in.

### Publishing the Mac app

The macOS workflow signs the app it attaches with the owner's Apple Development
certificate, from the secrets of the `release` environment, with a secure timestamp. Every version is then
recognised as the same app, so macOS lets an update into the data the last one left, and
the signature stays valid after the certificate expires. Without the secrets, the Mac
app's job stops with an error and nothing is attached; the server image is unaffected.

Once, and again whenever the certificate is renewed (it lasts a year):

1. In Keychain Access, under **login** › **My Certificates**, right-click
   **Apple Development: …** and choose **Export**. Save it as a `.p12` with a strong
   password.
2. Copy it as text:

   ```sh
   base64 -i ~/Desktop/Certificates.p12 | pbcopy
   ```

3. On GitHub, in the repository's **Settings** › **Environments** › **release**, add two
   environment secrets: `MACOS_CERTIFICATE_P12` (the text you copied) and
   `MACOS_CERTIFICATE_PASSWORD` (the export password). The team comes from the
   certificate.
4. Delete the `.p12`.

The `release` environment is set, under **Deployment branches and tags**, to tags matching
`v*` only, so the certificate exists just for release runs: a workflow on any other branch
can't read it, whoever wrote it. Keep the two secrets there and not among the repository's
own secrets, which any workflow can read.

The workflow puts the certificate in a keychain of its own, with a random password, and
deletes it when the job ends.

The workflows run other people's actions with that certificate and the right to publish.
Each is pinned to an exact commit (`uses: owner/action@<commit> # v1.2.3`), not to a label
like `@v4` that its owner could move to other code. To update one, change the commit and
the version in its comment together, after a look at what changed. A release builds the
Mac app without the build cache, so what's signed comes from the tagged commit alone.

The app still isn't notarized, so macOS asks people to choose **Open Anyway** in System
Settings › Privacy & Security for each new version, and Apple means Apple Development
certificates for development rather than for handing apps out. That's fine for a few
testers, not for rolling out to a team: notarizing needs a Developer ID certificate (the
paid Apple Developer Program), then the same secrets for it plus notarization credentials,
for the macOS workflow to sign, notarize and staple with (see
[apps/macos/README.md](apps/macos/README.md)).

## License

Not chosen yet.
