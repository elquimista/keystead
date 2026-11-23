//! Runs simulated devices against the change feed and reports throughput, latency,
//! conflicts and whether every device converged.
//!
//! Usage: `cargo run --release -p keystead-proto-change-feed -- [SECONDS]` (default 5 per
//! scenario).

use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use keystead_proto_change_feed::simulation::{self, Settings, Stop};
use keystead_proto_change_feed::{Device, Server, Synchronous};

const SETTINGS: Settings = Settings {
    devices: 50,
    folders: 20,
    folders_per_device: 5,
    items: 5_000,
    hot_items: 50,
    page_size: 500,
    ciphertext_bytes: 300,
};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let seconds = std::env::args()
        .nth(1)
        .map(|arg| arg.parse::<u64>())
        .transpose()?
        .unwrap_or(5);
    if cfg!(debug_assertions) {
        eprintln!("note: this is a debug build; use --release for meaningful numbers\n");
    }
    for (label, synchronous) in [
        ("FULL (every commit flushed to disk)", Synchronous::Full),
        (
            "NORMAL (WAL default; may lose the last commits on power loss)",
            Synchronous::Normal,
        ),
    ] {
        scenario(label, synchronous, Duration::from_secs(seconds)).await?;
    }
    Ok(())
}

async fn scenario(
    label: &str,
    synchronous: Synchronous,
    duration: Duration,
) -> Result<(), Box<dyn std::error::Error>> {
    let path = std::env::temp_dir().join(format!(
        "keystead-change-feed-{}.sqlite",
        std::process::id()
    ));
    remove_database(&path);
    let server = Server::open(&path, synchronous).await?;
    let settings = &SETTINGS;
    let seeded = simulation::seed(&server, settings).await?;

    // A brand-new device for someone with access to every folder.
    let newcomer = settings.devices;
    for &folder_id in &seeded.folder_ids {
        server.add_member(folder_id, newcomer).await?;
    }
    let mut device = Device::new(newcomer);
    let started = Instant::now();
    let first_sync_entries = device.sync(&server, settings.page_size).await?;
    let first_sync = started.elapsed();
    let first_sync_items = device.visible_items().len();

    // Writes with nothing else running, to separate the cost of a write from the time
    // spent queueing behind other devices during the busy run.
    let mut idle_writes = Vec::new();
    let mut content = vec![0u8; settings.ciphertext_bytes];
    for item_id in 1..=200 {
        content[0] = item_id as u8;
        let started = Instant::now();
        device.save(&server, item_id, Some(&content)).await?;
        idle_writes.push(started.elapsed());
    }

    let report = simulation::run(&server, settings, &seeded, Stop::After(duration)).await?;
    let seconds = report.elapsed.as_secs_f64();
    let database_bytes = database_size(&path);
    remove_database(&path);

    println!("SQLite change feed, synchronous = {label}");
    println!(
        "  {} devices, {} folders ({} per device), {} items, {:.1} s of nonstop traffic",
        settings.devices,
        settings.folders,
        settings.folders_per_device,
        thousands(settings.items),
        seconds
    );
    println!(
        "  Throughput        {} syncs/s, {} writes/s, {} membership changes",
        thousands((report.syncs as f64 / seconds) as usize),
        thousands((report.writes as f64 / seconds) as usize),
        report.membership_changes
    );
    println!(
        "  Sync latency      median {}, 99th percentile {}",
        time(percentile(&report.sync_latencies, 50)),
        time(percentile(&report.sync_latencies, 99))
    );
    println!(
        "  Write latency     median {}, 99th percentile {} (mostly queueing for the writer)",
        time(percentile(&report.write_latencies, 50)),
        time(percentile(&report.write_latencies, 99))
    );
    println!(
        "  Idle write        median {}, 99th percentile {} (one device, nothing else running)",
        time(percentile(&idle_writes, 50)),
        time(percentile(&idle_writes, 99))
    );
    println!(
        "  Conflicts         {} caught ({} on a second attempt): {} kept mine and saved again, {} kept theirs",
        thousands(report.conflicts),
        thousands(report.conflicts - report.kept_mine - report.kept_theirs),
        thousands(report.kept_mine),
        thousands(report.kept_theirs)
    );
    println!(
        "  Stale writes      {} refused after the device lost access",
        thousands(report.rejected)
    );
    println!(
        "  Feed order        {} entries out of order across {} entries received",
        report.order_violations,
        thousands(report.entries_received)
    );
    println!(
        "  Convergence       {} of {} devices match the server exactly ({} items compared)",
        report.devices_checked - report.devices_mismatched,
        report.devices_checked,
        thousands(report.items_checked)
    );
    println!(
        "  New device        first sync of {} items ({} entries) in {}",
        thousands(first_sync_items),
        thousands(first_sync_entries),
        time(first_sync)
    );
    println!("  Database size     {:.1} MB", database_bytes as f64 / 1e6);
    println!();
    Ok(())
}

fn percentile(samples: &[Duration], percent: usize) -> Duration {
    if samples.is_empty() {
        return Duration::ZERO;
    }
    let mut sorted = samples.to_vec();
    sorted.sort();
    sorted[(sorted.len() * percent / 100).min(sorted.len() - 1)]
}

fn time(duration: Duration) -> String {
    let ms = duration.as_secs_f64() * 1_000.0;
    if ms < 0.1 {
        format!("{:.0} µs", ms * 1_000.0)
    } else {
        format!("{ms:.2} ms")
    }
}

fn thousands(n: usize) -> String {
    let digits = n.to_string();
    let mut out = String::new();
    for (i, c) in digits.chars().enumerate() {
        if i > 0 && (digits.len() - i) % 3 == 0 {
            out.push(',');
        }
        out.push(c);
    }
    out
}

fn database_files(path: &Path) -> [PathBuf; 3] {
    ["", "-wal", "-shm"].map(|suffix| PathBuf::from(format!("{}{suffix}", path.display())))
}

fn database_size(path: &Path) -> u64 {
    database_files(path)
        .iter()
        .filter_map(|file| std::fs::metadata(file).ok())
        .map(|meta| meta.len())
        .sum()
}

fn remove_database(path: &Path) {
    for file in database_files(path) {
        let _ = std::fs::remove_file(file);
    }
}
