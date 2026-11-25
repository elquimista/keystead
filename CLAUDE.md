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
  -derivedDataPath build/DerivedData build CODE_SIGN_IDENTITY=-`. Builds for checking pass
  `CODE_SIGN_IDENTITY=-` so they stay ad hoc and never trigger a keychain prompt. A Release
  app the user will run (the copy in `apps/macos/build/Release`) must be signed with their
  Apple Development certificate, set in their git-ignored `Config/Signing.local.xcconfig`:
  build it without `CODE_SIGN_IDENTITY=-`, and say first that macOS may ask for their
  keychain password.
- Launching the app or unlocking shows UI or a Touch ID prompt on the user's screen; say
  so before doing it
- To check the main window without a server or Touch ID, run the Debug app with
  `-demo [alone] -snapshot` (see apps/macos/README.md); it writes pictures to
  `~/Library/Containers/io.github.elquimista.Keystead.dev/Data/tmp/snapshots` and quits.
  Its window still shows on screen briefly, so say so first.
- Server in Docker: `docker compose up -d`, setup code in `docker compose logs server`.
  For throwaway checks use another project and port
  (`KEYSTEAD_PORT=18090 docker compose -p keystead-check up -d`, then `down -v`) so the
  user's own server and data on 8080 are never touched.
- Production deployment: `deploy/` (the server behind nginx, with Cloudflare in front); guide in
  `deploy/README.md`. Test it locally with another project name and ports, never 80/443.
- Releases: one version and one `v<version>` tag for the server, CLI and apps, even when
  only one part changed; follow the checklist in README.md's Releasing section (the version
  lives in three files). Pushing the tag publishes the server image to
  `ghcr.io/elquimista/keystead-server` and attaches the Mac app to the tag's GitHub release
  (`.github/workflows/release.yml`), signed with the owner's Apple Development certificate
  from repository secrets, not notarized. Tagging, pushing and the secrets are the user's
  call.
- Compatibility: a new app must keep working with older servers, checking what the server
  can do (`item_format` in `/v1/health`, or a 404) and saying what to update instead of
  failing.
- Benchmarks (always `--release`; debug numbers are meaningless):
  `cargo run --release -p keystead-proto-unlock-search`,
  `cargo run --release -p keystead-proto-change-feed`,
  `cargo run --release -p keystead-client --example vault_bench -- 5000` (the Mac app's
  side: `-demo big -measure`, see apps/macos/README.md)
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
  `get-task-allow`, no unsigned nested binaries. The macOS workflow
  (`.github/workflows/macos.yml`) checks this; releases don't wait for it.
