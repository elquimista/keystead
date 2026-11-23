//! Simulated devices using one server at the same time, then a check that every device
//! ends up matching the server.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use rand::rngs::StdRng;
use rand::{Rng, RngCore, SeedableRng};

use crate::{Device, Error, Server};

#[derive(Clone)]
pub struct Settings {
    pub devices: i64,
    pub folders: usize,
    pub folders_per_device: usize,
    pub items: usize,
    /// Edits aim at these item ids half the time, to provoke conflicts.
    pub hot_items: i64,
    pub page_size: i64,
    pub ciphertext_bytes: usize,
}

#[derive(Clone, Copy)]
pub enum Stop {
    After(Duration),
    Operations(usize),
}

pub struct Seeded {
    pub folder_ids: Vec<i64>,
    pub max_item_id: i64,
}

#[derive(Default)]
pub struct Report {
    pub syncs: usize,
    pub writes: usize,
    pub conflicts: usize,
    pub kept_mine: usize,
    pub kept_theirs: usize,
    /// Writes refused because the device's view of its memberships was out of date.
    pub rejected: usize,
    pub membership_changes: usize,
    pub entries_received: usize,
    pub sync_latencies: Vec<Duration>,
    pub write_latencies: Vec<Duration>,
    pub elapsed: Duration,
    pub order_violations: u64,
    pub devices_checked: usize,
    pub devices_mismatched: usize,
    pub items_checked: usize,
}

impl Report {
    fn merge(&mut self, other: Report) {
        self.syncs += other.syncs;
        self.writes += other.writes;
        self.conflicts += other.conflicts;
        self.kept_mine += other.kept_mine;
        self.kept_theirs += other.kept_theirs;
        self.rejected += other.rejected;
        self.entries_received += other.entries_received;
        self.sync_latencies.extend(other.sync_latencies);
        self.write_latencies.extend(other.write_latencies);
    }
}

/// Creates folders, random memberships and items.
pub async fn seed(server: &Server, settings: &Settings) -> Result<Seeded, Error> {
    let mut rng = StdRng::seed_from_u64(1);
    let mut folders = Vec::with_capacity(settings.folders);
    for index in 0..settings.folders {
        let owner = index as i64 % settings.devices;
        folders.push((server.create_folder(owner).await?, owner));
    }
    for user in 0..settings.devices {
        for _ in 0..settings.folders_per_device {
            let (folder_id, _) = folders[rng.gen_range(0..folders.len())];
            server.add_member(folder_id, user).await?;
        }
    }
    let mut max_item_id = 0;
    for _ in 0..settings.items {
        let (folder_id, owner) = folders[rng.gen_range(0..folders.len())];
        let content = ciphertext(&mut rng, settings.ciphertext_bytes);
        max_item_id = server.create_item(owner, folder_id, &content).await?.id;
    }
    Ok(Seeded {
        folder_ids: folders.into_iter().map(|(id, _)| id).collect(),
        max_item_id,
    })
}

/// Runs every device concurrently while memberships change underneath them, then syncs
/// each device one last time and compares it with the server.
pub async fn run(
    server: &Server,
    settings: &Settings,
    seeded: &Seeded,
    stop: Stop,
) -> Result<Report, Error> {
    let mut devices = Vec::new();
    for user in 0..settings.devices {
        let mut device = Device::new(user);
        device.sync(server, settings.page_size).await?;
        devices.push(device);
    }

    let start = Instant::now();
    let done = Arc::new(AtomicBool::new(false));
    let churn = tokio::spawn(churn(
        server.clone(),
        seeded.folder_ids.clone(),
        settings.devices,
        done.clone(),
    ));
    let tasks: Vec<_> = devices
        .into_iter()
        .map(|device| {
            let server = server.clone();
            let settings = settings.clone();
            let max_item_id = seeded.max_item_id;
            tokio::spawn(async move { drive(device, &server, &settings, max_item_id, stop).await })
        })
        .collect();

    let mut report = Report::default();
    let mut devices = Vec::new();
    for task in tasks {
        let (device, stats) = task.await.expect("device task panicked")?;
        report.merge(stats);
        devices.push(device);
    }
    done.store(true, Ordering::Relaxed);
    report.membership_changes = churn.await.expect("churn task panicked")?;
    report.elapsed = start.elapsed();

    for device in &mut devices {
        device.sync(server, settings.page_size).await?;
        let expected = server.visible_items(device.user).await?;
        report.devices_checked += 1;
        report.items_checked += expected.len();
        report.order_violations += device.order_violations();
        if expected.iter().collect::<Vec<_>>() != device.visible_items() {
            report.devices_mismatched += 1;
        }
    }
    Ok(report)
}

/// One device's traffic: mostly syncs, then edits, creates and deletes. On a conflict
/// the device keeps the other copy half the time and saves its own on top otherwise.
async fn drive(
    mut device: Device,
    server: &Server,
    settings: &Settings,
    max_item_id: i64,
    stop: Stop,
) -> Result<(Device, Report), Error> {
    let mut rng = StdRng::seed_from_u64(device.user as u64 + 100);
    let mut report = Report::default();
    let start = Instant::now();
    let mut operations = 0;
    loop {
        match stop {
            Stop::After(limit) if start.elapsed() >= limit => break,
            Stop::Operations(limit) if operations >= limit => break,
            _ => {}
        }
        operations += 1;
        let roll = rng.gen_range(0..100);

        if roll < 60 {
            let started = Instant::now();
            report.entries_received += device.sync(server, settings.page_size).await?;
            report.sync_latencies.push(started.elapsed());
            report.syncs += 1;
            continue;
        }

        if roll < 65 {
            let Some(folder_id) = device.random_folder(&mut rng) else {
                continue;
            };
            let content = ciphertext(&mut rng, settings.ciphertext_bytes);
            let started = Instant::now();
            let result = device.create(server, folder_id, &content).await;
            report.write_latencies.push(started.elapsed());
            record(&mut report, result)?;
            continue;
        }

        // Edits (most of the rest) aim at hot items half the time; deletes avoid them.
        let deleting = roll >= 97;
        let item_id = if !deleting && rng.gen_bool(0.5) {
            rng.gen_range(1..=settings.hot_items.min(max_item_id))
        } else {
            rng.gen_range(settings.hot_items.min(max_item_id)..=max_item_id)
        };
        if device.version_of(item_id).is_none() {
            continue;
        }
        let content = (!deleting).then(|| ciphertext(&mut rng, settings.ciphertext_bytes));

        let started = Instant::now();
        let result = device.save(server, item_id, content.as_deref()).await;
        report.write_latencies.push(started.elapsed());
        let Err(Error::Conflict(current)) = result else {
            record(&mut report, result)?;
            continue;
        };

        report.conflicts += 1;
        let keep_mine = content.is_some() && !current.deleted && rng.gen_bool(0.5);
        device.accept(*current);
        if !keep_mine {
            report.kept_theirs += 1;
            continue;
        }
        let started = Instant::now();
        let retry = device.save(server, item_id, content.as_deref()).await;
        report.write_latencies.push(started.elapsed());
        match retry {
            Ok(()) => {
                report.writes += 1;
                report.kept_mine += 1;
            }
            Err(Error::Conflict(newer)) => {
                report.conflicts += 1;
                report.kept_theirs += 1;
                device.accept(*newer);
            }
            other => record(&mut report, other)?,
        }
    }
    Ok((device, report))
}

fn record(report: &mut Report, result: Result<(), Error>) -> Result<(), Error> {
    match result {
        Ok(()) => report.writes += 1,
        Err(Error::Forbidden | Error::NotFound) => report.rejected += 1,
        Err(Error::Conflict(_)) => report.conflicts += 1,
        Err(error) => return Err(error),
    }
    Ok(())
}

/// Adds or removes a random user from a random folder every 20 ms until told to stop.
async fn churn(
    server: Server,
    folder_ids: Vec<i64>,
    devices: i64,
    done: Arc<AtomicBool>,
) -> Result<usize, Error> {
    let mut rng = StdRng::seed_from_u64(7);
    let mut changes = 0;
    while !done.load(Ordering::Relaxed) {
        let user = rng.gen_range(0..devices);
        let folder_id = folder_ids[rng.gen_range(0..folder_ids.len())];
        if server.is_member(user, folder_id).await? {
            server.remove_member(folder_id, user).await?;
        } else {
            server.add_member(folder_id, user).await?;
        }
        changes += 1;
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    Ok(changes)
}

fn ciphertext(rng: &mut StdRng, bytes: usize) -> Vec<u8> {
    let mut content = vec![0; bytes];
    rng.fill_bytes(&mut content);
    content
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tests::TempDb;

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn concurrent_devices_converge_with_the_server() {
        let db = TempDb::new();
        let server = db.server().await;
        let settings = Settings {
            devices: 8,
            folders: 6,
            folders_per_device: 3,
            items: 300,
            hot_items: 20,
            page_size: 50,
            ciphertext_bytes: 64,
        };
        let seeded = seed(&server, &settings).await.unwrap();
        let report = run(&server, &settings, &seeded, Stop::Operations(300))
            .await
            .unwrap();

        assert!(report.writes > 0);
        assert_eq!(report.order_violations, 0);
        assert_eq!(report.devices_checked, 8);
        assert_eq!(report.devices_mismatched, 0);
    }
}
