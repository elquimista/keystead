//! Measures unlock and search speed for generated vaults of several sizes.
//!
//! Usage: `cargo run --release -p keystead-proto-unlock-search -- [ITEMS...]`
//! (default sizes: 1000 10000 100000).

use std::hint::black_box;
use std::time::{Duration, Instant};

use keystead_proto_unlock_search::{Account, Vault};
use nucleo_matcher::{Config, Matcher};
use rand::RngCore;
use rand::rngs::OsRng;

/// Queries typed one keystroke at a time, so every prefix is a search.
const QUERIES: &[&str] = &[
    "github",
    "aws prod",
    "stripe billing",
    "lchen",
    "pager",
    "xyzzy",
];
const ITEMS_PER_FOLDER: usize = 50;
const SIGNATURE_SAMPLE: usize = 2_000;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let sizes = std::env::args()
        .skip(1)
        .map(|arg| arg.replace([',', '_'], "").parse::<usize>())
        .collect::<Result<Vec<_>, _>>()?;
    let sizes = if sizes.is_empty() {
        vec![1_000, 10_000, 100_000]
    } else {
        sizes
    };
    if cfg!(debug_assertions) {
        eprintln!("note: this is a debug build; use --release for meaningful numbers\n");
    }

    let mut account_key = [0u8; 32];
    OsRng.fill_bytes(&mut account_key);
    let account = Account::from_account_key(&account_key);

    for items in sizes {
        let folders = (items / ITEMS_PER_FOLDER).max(1);
        let start = Instant::now();
        let vault = Vault::generate(&account, items, folders, 42);
        let generated = start.elapsed();

        let (unlocked, unlock) = vault.unlock(&account)?;
        let index = &unlocked.index;
        assert_eq!(index.len(), vault.item_count());

        let per_folder_key = unlock.folder_keys / vault.folder_count() as u32;
        let sample = SIGNATURE_SAMPLE.min(items);
        let per_signature = vault.verify_signatures(sample)? / sample as u32;

        let mut matcher = Matcher::new(Config::DEFAULT);
        let mut keystrokes = Vec::new();
        for query in QUERIES {
            for end in 1..=query.len() {
                let typed = &query[..end];
                if typed.ends_with(' ') {
                    continue;
                }
                let start = Instant::now();
                black_box(index.search(typed, &mut matcher));
                keystrokes.push(start.elapsed());
            }
        }
        keystrokes.sort();

        let top_result = index.search(QUERIES[0], &mut matcher)[0];
        let start = Instant::now();
        black_box(unlocked.password(top_result)?);
        let copy = start.elapsed();

        println!(
            "{} items in {} folders (generated in {}, not part of unlock)",
            thousands(items),
            thousands(folders),
            time(generated)
        );
        println!("  Unlock");
        row(
            &format!("Open {} folder keys (HPKE)", thousands(folders)),
            unlock.folder_keys,
        );
        row(
            &format!("Decrypt {} overviews", thousands(items)),
            unlock.overviews,
        );
        row("Parse overviews", unlock.parse);
        row("Build search index", unlock.index);
        row("Total", unlock.total());
        println!("  Search, per keystroke ({} keystrokes)", keystrokes.len());
        row("Median", keystrokes[keystrokes.len() / 2]);
        row("Slowest", keystrokes[keystrokes.len() - 1]);
        row("Decrypt the top result's password to copy it", copy);
        println!(
            "    {:<44}{:>10.1} MB",
            "Index in memory",
            index.approx_bytes() as f64 / 1e6
        );
        println!("  Rejected designs, estimated from the cost of one operation");
        row(
            "One key per item instead of per folder: adds",
            per_folder_key * items as u32,
        );
        row(
            "Checking signatures at every unlock: adds",
            per_signature * items as u32,
        );
        println!();
    }
    Ok(())
}

fn row(label: &str, duration: Duration) {
    println!("    {label:<44}{:>13}", time(duration));
}

fn time(duration: Duration) -> String {
    let ms = duration.as_secs_f64() * 1_000.0;
    if ms >= 1_000.0 {
        format!("{:.2} s", ms / 1_000.0)
    } else if ms < 0.1 {
        format!("{:.1} µs", ms * 1_000.0)
    } else {
        format!("{ms:.2} ms")
    }
}

fn thousands(n: usize) -> String {
    let digits = n.to_string();
    let mut out = String::new();
    for (i, c) in digits.chars().enumerate() {
        if i > 0 && (digits.len() - i).is_multiple_of(3) {
            out.push(',');
        }
        out.push(c);
    }
    out
}
