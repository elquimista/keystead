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
| `apps/macos` | The macOS menu bar app (SwiftUI) |
| `prototypes/secure-enclave` | Prototype: a Secure Enclave device key unlocking the account key |

Windows and Ubuntu apps come after macOS.

## Building

Requirements: Rust (stable, via rustup) and, for the macOS app, Xcode 16 or later.

```sh
cargo build --workspace
cargo test --workspace
cargo clippy --workspace --all-targets -- -D warnings
cargo fmt --all --check
```

Run the server (listens on `127.0.0.1:8080`; set `KEYSTEAD_LISTEN` to change it):

```sh
cargo run -p keystead-server
curl http://127.0.0.1:8080/v1/health
```

Build and run the macOS app:

```sh
cd apps/macos
swift build
swift run
```

If you installed rustup with Homebrew, `cargo` isn't on your PATH by default. Add
`/opt/homebrew/opt/rustup/bin` to it, for example in `~/.zshrc`:

```sh
export PATH="/opt/homebrew/opt/rustup/bin:$PATH"
```

## License

Not chosen yet.
