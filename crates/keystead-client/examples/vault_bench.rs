//! How long a vault with many logins takes to save, open and list, the work behind
//! unlocking and showing the list. Builds the vault offline: half the logins in a folder,
//! half your own. Release builds only give meaningful numbers:
//!
//! ```sh
//! cargo run --release -p keystead-client --example vault_bench -- 5000
//! ```

use std::sync::Arc;
use std::time::Instant;

use keystead_client::profile::{FolderRecord, OWNER, Profile};
use keystead_client::{DeviceSigner, Vault};
use keystead_core::directory::DirectoryEntry;
use keystead_core::ids::{DeviceId, FolderId, ItemId};
use keystead_core::items::{Details, EncryptedItem, FolderInfo, ItemKeys, ItemVersion, Overview};
use keystead_core::keys::{AccountKeys, AccountSecret, FolderKey, ItemKey, SoftwareDeviceKey};

fn main() -> anyhow::Result<()> {
    let count: usize = std::env::args()
        .nth(1)
        .map(|count| count.parse())
        .transpose()?
        .unwrap_or(5000);
    let dir = std::env::temp_dir().join(format!("keystead-bench-{}", std::process::id()));
    std::fs::create_dir_all(&dir)?;
    let path = dir.join("profile.json");

    let secret = AccountSecret::generate();
    let keys = AccountKeys::derive(&secret);
    let mut profile = Profile::new(
        "http://127.0.0.1:1",
        "Bench",
        OWNER,
        DeviceId::random(),
        keys.public(),
    );
    let mut me = DirectoryEntry::new(OWNER, "Bench", keys.public());
    me.approve(&keys);
    profile.set_directory(vec![me]);

    let folder_id = FolderId::random();
    let folder_key = FolderKey::generate();
    profile.folders.insert(
        folder_id,
        FolderRecord {
            entries: Vec::new(),
            info: FolderInfo {
                name: "Production".into(),
            }
            .seal(folder_id, &folder_key)?,
            wrapped_key: keys.public().wrap_folder_key(&folder_key, folder_id)?,
            generation: 0,
            chain: Vec::new(),
            via_group: None,
        },
    );

    let started = Instant::now();
    for index in 0..count {
        let id = ItemId::random();
        let key = ItemKey::generate();
        let mut copies = ItemKeys::default();
        let in_folder = index % 2 == 0;
        if in_folder {
            copies.folder = Some(key.seal_for_folder(id, folder_id, &folder_key));
        } else {
            copies.owner = Some(key.seal_for_owner(id, OWNER, &keys));
        }
        let overview = Overview {
            name: format!("Login {index}"),
            username: format!("user{index}@example.com"),
            url: format!("https://site{index}.example.com"),
            ..Overview::default()
        };
        let details = Details {
            password: format!("password-{index}"),
            notes: String::new(),
            otp: String::new(),
        };
        let at = ItemVersion {
            id,
            folder_id: in_folder.then_some(folder_id),
            owner: (!in_folder).then_some(OWNER),
            version: 1,
            author: OWNER,
        };
        let item = EncryptedItem::seal(at, &key, copies, &keys, &overview, &details)?;
        profile.items.insert(id, item);
    }
    println!("{count} logins sealed in {:?}", started.elapsed());

    let started = Instant::now();
    profile.save(&path)?;
    let size = std::fs::metadata(&path)?.len();
    println!(
        "saved the profile in {:?} ({:.1} MB)",
        started.elapsed(),
        size as f64 / 1e6
    );

    let signer: Arc<dyn DeviceSigner> = Arc::new(SoftwareDeviceKey::generate());
    let started = Instant::now();
    let vault = Vault::open(&path, &secret, signer)?;
    println!("opened the vault in {:?}", started.elapsed());

    for round in 1..=3 {
        let started = Instant::now();
        let rows = vault.list()?;
        println!(
            "listed {} logins in {:?} (round {round})",
            rows.len(),
            started.elapsed()
        );
    }

    let started = Instant::now();
    let rows = vault.list()?;
    let words = ["login", "42"];
    let found = rows
        .iter()
        .filter(|row| {
            let text = format!("{} {} {}", row.name, row.username, row.url).to_lowercase();
            words.iter().all(|word| text.contains(word))
        })
        .count();
    println!(
        "listed and searched in {:?} ({found} found)",
        started.elapsed()
    );

    std::fs::remove_dir_all(&dir)?;
    Ok(())
}
