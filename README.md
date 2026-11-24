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
one-time setup code. Whoever uses it, in the Mac app (Set up a new team) or with
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
keystead invite Bob                  # prints the join command for Bob

# Bob, in another terminal
export KEYSTEAD_HOME=/tmp/bob
keystead join http://127.0.0.1:8080 <token> --owner <Alice's fingerprint>

# Alice: approve Bob after he reads out his fingerprint, then share
keystead approve 2 --fingerprint <Bob's fingerprint>
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

The CLI keeps the shared `profile.json` (the same format the Mac app uses) and its keys in
`device.json`. For now those keys are stored unencrypted in `$KEYSTEAD_HOME/device.json` (readable only
by you). Use it for trying things out, not for real secrets yet.

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
4. Commit as "Release 0.2.1", then tag and push:

   ```sh
   git tag -a v0.2.1 -m "Keystead 0.2.1"
   git push origin main v0.2.1
   ```

5. Write short notes for the tag's GitHub release: what changed in the server and in the
   apps, and whether the server has to be updated first.

The tag must match `Cargo.toml`, and all of CI must pass on the tagged commit. The
[release workflow](.github/workflows/release.yml) then publishes
`ghcr.io/elquimista/keystead-server` for `linux/amd64` and `linux/arm64`, tagged `0.2.1`,
`0.2` and `latest`. Pre-releases such as `v0.3.0-rc.1` get only their own tag.

The Mac app isn't published by the workflow yet: build it as described in
[apps/macos/README.md](apps/macos/README.md). Handing it to other people needs a Developer
ID certificate (the paid Apple Developer Program) so it can be notarized; then the same tag
can publish it too.

After the first release, GitHub may list the image as private: on the repository's
**Packages** entry, open **Package settings** and change the visibility to public, so
servers can pull it without logging in.

## License

Not chosen yet.
