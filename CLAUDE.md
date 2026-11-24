# Keystead

Self-hosted team password manager: Rust core, server and CLI, plus native desktop apps
(macOS first). Design doc: https://claude.ai/artifact/Pvq7Y3kA7aj1xVwTvvEBGu

## Commands

`cargo` comes from Homebrew's rustup and may not be on PATH: prefix commands with
`PATH="/opt/homebrew/opt/rustup/bin:$PATH"`.

- Rust: `cargo build --workspace`, `cargo test --workspace`,
  `cargo clippy --workspace --all-targets -- -D warnings`, `cargo fmt --all --check`
- macOS app (in `apps/macos`): `scripts/build-core.sh` first on a fresh clone, then
  `xcodebuild -project Keystead.xcodeproj -scheme Keystead -configuration Release
  -derivedDataPath build/DerivedData build CODE_SIGN_IDENTITY=-`. The user's
  git-ignored `Config/Signing.local.xcconfig` signs their own builds with their Apple
  Development certificate; always pass `CODE_SIGN_IDENTITY=-` so command-line builds stay
  ad hoc and never trigger a keychain prompt.
- Launching the app or unlocking shows UI or a Touch ID prompt on the user's screen; say
  so before doing it
- Server in Docker: `docker compose up -d`, setup code in `docker compose logs server`.
  For throwaway checks use another project and port
  (`KEYSTEAD_PORT=18090 docker compose -p keystead-check up -d`, then `down -v`) so the
  user's own server and data on 8080 are never touched.
- Production deployment: `deploy/` (the server behind nginx, with Cloudflare in front); guide in
  `deploy/README.md`. Test it locally with another project name and ports, never 80/443.
- Releases: pushing a `v<version>` tag matching `Cargo.toml` publishes the server image to
  `ghcr.io/elquimista/keystead-server` (`.github/workflows/release.yml`). Tagging and pushing
  are the user's call.
- Benchmarks (always `--release`; debug numbers are meaningless):
  `cargo run --release -p keystead-proto-unlock-search`,
  `cargo run --release -p keystead-proto-change-feed`
- Secure Enclave prototype: `swift test` in `prototypes/secure-enclave`; `se-proto unlock`
  shows a Touch ID or password prompt, so a person must run it

## Rules

- `docs/format.md` is the data format spec and `crates/keystead-core` its reference
  implementation; change them together.
- The server never decrypts anything; all encryption and decryption happens on devices.
- No home-made cryptography: use established constructions and audited crates.
- Never write secrets or decrypted data to disk, logs or error messages.
- `unsafe` is forbidden workspace-wide; only `keystead-ffi` opts out, because UniFFI's
  generated code needs it. Keep that crate a thin conversion layer.
- Client logic (sign-in, sync, verification, actions) lives in `keystead-client`, shared by
  the CLI and the apps. Platform code only supplies the account secret and a
  `DeviceSigner`; don't duplicate client logic in Swift or the CLI.
- Release builds of the Mac app must stay notarizable: Hardened Runtime on, no
  `get-task-allow`, no unsigned nested binaries. CI checks this.
