# Unlock and search prototype

Measures how long a device takes to unlock a vault and search it, using the design's
key chain: the account key pair opens one key per folder (HPKE, X25519), folder keys
open items (XChaCha20-Poly1305). Each item has an overview (name, username, URL, tags)
that is decrypted at unlock, and details (password, notes) that stay encrypted until
copied. Search uses the `nucleo-matcher` fuzzy matcher over an in-memory index.

```sh
cargo test -p keystead-proto-unlock-search
cargo run --release -p keystead-proto-unlock-search            # 1k, 10k, 100k items
cargo run --release -p keystead-proto-unlock-search -- 25000   # custom sizes
```

## Results

Apple Silicon Mac, release build, single thread, 50 items per folder:

| Items | Unlock total | Keystroke, median | Keystroke, slowest | Copy a password | Index in memory |
| --- | --- | --- | --- | --- | --- |
| 1,000 | 1.4 ms | 0.15 ms | 0.39 ms | a few µs | 0.1 MB |
| 10,000 | 14.4 ms | 1.4 ms | 3.0 ms | 3.2 µs | 1.4 MB |
| 100,000 | 150–158 ms | 14.2 ms | 32–34 ms | 3.9 µs | 13.9 MB |

Designs the numbers rule out, at 10,000 items:

- One key per item instead of per folder would add about 0.3 s to every unlock.
- Checking every item's signature at unlock would add about 0.17 s, so signatures are
  checked once, when items arrive during sync.

Not included: reading the encrypted local copy from disk, and the Secure Enclave step
(about 8 ms, see `prototypes/secure-enclave`). Overviews are JSON; a binary format would
shorten the parse step.
