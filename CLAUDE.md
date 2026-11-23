# Keystead

Self-hosted team password manager: Rust core, server and CLI, plus native desktop apps
(macOS first). Design doc: https://claude.ai/artifact/Pvq7Y3kA7aj1xVwTvvEBGu

## Commands

`cargo` comes from Homebrew's rustup and may not be on PATH: prefix commands with
`PATH="/opt/homebrew/opt/rustup/bin:$PATH"`.

- Rust: `cargo build --workspace`, `cargo test --workspace`,
  `cargo clippy --workspace --all-targets -- -D warnings`, `cargo fmt --all --check`
- macOS app: `swift build` in `apps/macos`

## Rules

- The server never decrypts anything; all encryption and decryption happens on devices.
- No home-made cryptography: use established constructions and audited crates.
- Never write secrets or decrypted data to disk, logs or error messages.
- `unsafe` is forbidden workspace-wide; only a future FFI crate may opt out.
