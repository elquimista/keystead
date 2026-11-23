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
| `crates/keystead-cli` | The command-line tool (`keystead`) with pass-style commands |
| `crates/keystead-ffi` | The core's Swift bindings (UniFFI), linked into the Mac app |
| `apps/macos` | The macOS menu bar app (SwiftUI, Xcode project); see its [README](apps/macos/README.md) |
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
one-time setup code that the first admin uses to become the owner.

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
keystead add Production "AWS root" --username root@example.com

# Bob
keystead ls
keystead show "AWS root"
```

For now the CLI stores its keys unencrypted in `$KEYSTEAD_HOME/state.json` (readable only
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

## License

Not chosen yet.
