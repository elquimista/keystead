# Change feed prototype

Checks the server's sync design on SQLite: many devices editing at once, conflicts,
folder joins and leaves, and whether every device ends up matching the server.

## How the feed works

- Every write takes the next number from one counter and stamps it on the item (or on a
  membership change). Each item keeps only its latest number, so the feed never resends
  history.
- A device sends its cursor and gets one ordered stream: changes to items in its folders,
  plus its own joins and leaves, read from one consistent snapshot.
- When a device joins a folder, the folder's items ride on the join entry, up to the
  page's cursor. The feed leaves those items out until then, so each item arrives once.
- Edits name the version they're based on. A stale edit is refused with the current copy,
  and the device keeps theirs or saves its own on top.
- All writes go through one SQLite connection; reads use a pool in WAL mode. Change
  numbers therefore commit in order, and a reader can never see number N+1 before N.

```sh
cargo test -p keystead-proto-change-feed
cargo run --release -p keystead-proto-change-feed          # two 5 s scenarios
cargo run --release -p keystead-proto-change-feed -- 20    # 20 s each
```

## Results

Apple Silicon Mac, release build: 50 devices, 20 folders (5 per device), 5,000 items, and
5 seconds of nonstop traffic while folder memberships change every 20 ms.

| Measure | `synchronous = FULL` | `synchronous = NORMAL` |
| --- | --- | --- |
| Syncs per second | 15,600 | 14,000 |
| Writes per second | 3,400 | 3,050 |
| Sync latency, median / 99th percentile | 0.25 / 1.3 ms | 0.32 / 1.6 ms |
| Write latency under load, median / 99th | 11.7 / 17.5 ms | 13.0 / 18.9 ms |
| Write latency idle, median / 99th | 0.09 / 0.15 ms | 0.07 / 0.09 ms |
| Conflicts caught and resolved | 1,681 | 1,469 |
| Feed entries out of order | 0 of 290,000 | 0 of 261,000 |
| Devices matching the server at the end | 50 of 50 | 50 of 50 |
| First sync of a new device, 5,000 items | 11 ms | 11 ms |

- The busy-run write latency is queueing behind the single writer; one write on its own
  takes about 0.1 ms.
- The design expects a handful of requests per second for a 500-person org, so this
  leaves roughly a thousandfold headroom.
- `FULL` costs almost nothing here, but macOS's `fsync` is cheap; repeat on the Linux
  hardware a server would run on before choosing.

Not covered: the HTTP layer and push notifications, and splitting a large joined folder
across several pages (the join entry carries the whole folder).
