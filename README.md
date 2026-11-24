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
one-time setup code that the first admin uses to become the owner, either in the Mac app
(Set up a new team) or with `keystead setup`.

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
keystead show "AWS root"
```

A login added without `--folder` is yours alone until you share it. `keystead share`
shares one login, from a folder or not, without the rest of its folder.

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

Pushing a version tag publishes the server image to the GitHub Container Registry, for
`linux/amd64` and `linux/arm64`. The tag must match the version in `Cargo.toml`, and all of
CI must pass on the tagged commit first. For example, for 0.2.0:

1. Set `version = "0.2.0"` in the root `Cargo.toml`, and commit.
2. Tag and push:

   ```sh
   git tag v0.2.0
   git push origin main v0.2.0
   ```

The [release workflow](.github/workflows/release.yml) then publishes
`ghcr.io/elquimista/keystead-server` tagged `0.2.0`, `0.2` and `latest`. Pre-releases such
as `v0.3.0-rc.1` get only their own tag.

After the first release, GitHub may list the image as private: on the repository's
**Packages** entry, open **Package settings** and change the visibility to public, so
servers can pull it without logging in.

## License

Not chosen yet.
