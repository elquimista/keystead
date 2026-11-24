//! `keystead`: the team password manager from the terminal, with pass-style commands.
//!
//! The profile lives in `~/.config/keystead`, or in `KEYSTEAD_HOME` if set (handy for
//! trying two accounts side by side).

use std::io::{BufRead, IsTerminal};
use std::process::ExitCode;

use anyhow::Result;
use clap::{Parser, Subcommand, ValueEnum};
use keystead_cli::commands::{self, EditOutcome};
use keystead_cli::default_home;
use keystead_core::ids::UserId;
use keystead_core::items::{Details, Overview};

/// Team password manager, from the terminal.
#[derive(Parser)]
#[command(name = "keystead", version, arg_required_else_help = true)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Claim a new server with its setup code and become the owner
    Setup {
        server: String,
        setup_code: String,
        #[arg(long)]
        name: String,
    },
    /// Invite someone to the server (owner only)
    Invite { name: String },
    /// Join a server with an invite
    Join {
        server: String,
        token: String,
        /// The owner's fingerprint, from the invite
        #[arg(long)]
        owner: String,
    },
    /// Show your account and fingerprint
    Whoami,
    /// Show your recovery kit: 24 words that bring your account back on a new device
    RecoveryKit,
    /// Recover your account on this machine with the words from your recovery kit
    Recover {
        server: String,
        /// The owner's fingerprint, from the recovery kit; the owner can leave it out
        #[arg(long)]
        owner: Option<String>,
    },
    /// Sign out: this machine forgets your account; you'll need your recovery kit to use it
    /// here again
    SignOut {
        /// Don't ask for confirmation
        #[arg(long)]
        yes: bool,
    },
    /// List your devices, or remove a lost one
    Devices {
        #[command(subcommand)]
        action: Option<DevicesCommand>,
    },
    /// List users and whether the owner approved them
    Users,
    /// Approve a user after comparing fingerprints with them (owner only)
    Approve {
        user_id: i64,
        /// The fingerprint the user read out to you
        #[arg(long)]
        fingerprint: String,
    },
    /// Create, share and list folders
    #[command(subcommand)]
    Folder(FolderCommand),
    /// Add a login: to a folder, or without one as your own until you share it
    Add {
        name: String,
        #[arg(long)]
        folder: Option<String>,
        #[arg(long)]
        username: Option<String>,
        #[arg(long)]
        url: Option<String>,
        /// Generate a random password instead of asking for one
        #[arg(long)]
        generate: bool,
    },
    /// Share one login with an approved user, without the rest of its folder
    Share {
        name: String,
        user_id: i64,
        #[arg(long)]
        folder: Option<String>,
        #[arg(long, value_enum, default_value_t = RoleArg::Edit)]
        role: RoleArg,
    },
    /// Take away someone's copy of a login (managers)
    Unshare {
        name: String,
        user_id: i64,
        #[arg(long)]
        folder: Option<String>,
    },
    /// Remove someone from the team: their devices stop working and they lose every
    /// folder and login (owner only)
    RemoveUser {
        user_id: i64,
        /// Don't ask for confirmation
        #[arg(long)]
        yes: bool,
    },
    /// List logins
    Ls,
    /// Print a login's password, or its notes
    Show {
        name: String,
        #[arg(long)]
        folder: Option<String>,
        /// Print the notes instead of the password
        #[arg(long)]
        notes: bool,
    },
    /// Change a login: its password by default, or the fields given
    Edit {
        name: String,
        #[arg(long)]
        folder: Option<String>,
        /// A new name for the login
        #[arg(long)]
        rename: Option<String>,
        #[arg(long)]
        username: Option<String>,
        #[arg(long)]
        url: Option<String>,
        #[arg(long)]
        notes: Option<String>,
        /// Also ask for a new password when changing other fields
        #[arg(long)]
        password: bool,
        /// Generate a random password instead of asking for one
        #[arg(long)]
        generate: bool,
    },
    /// Delete a login for everyone who can open it
    Rm {
        name: String,
        #[arg(long)]
        folder: Option<String>,
        /// Don't ask for confirmation
        #[arg(long)]
        yes: bool,
    },
    /// Fetch changes from the server
    Sync,
}

#[derive(Subcommand)]
enum DevicesCommand {
    /// Remove one of your other devices, such as a lost one; it can't sign in any more
    Remove { device_id: String },
}

#[derive(Subcommand)]
enum FolderCommand {
    /// Create a folder
    Create { name: String },
    /// Share a folder with an approved user (managers)
    Share {
        folder: String,
        user_id: i64,
        #[arg(long, value_enum, default_value_t = RoleArg::Edit)]
        role: RoleArg,
    },
    /// List who is in a folder, with their roles
    Members { folder: String },
    /// Change someone's role in a folder (managers)
    Role {
        folder: String,
        user_id: i64,
        #[arg(value_enum)]
        role: RoleArg,
    },
    /// Take someone out of a folder; it then gets a new key (managers)
    Remove { folder: String, user_id: i64 },
    /// Leave a folder
    Leave { folder: String },
    /// List your folders
    List,
}

/// What someone may do with a folder or a login.
#[derive(Clone, Copy, ValueEnum)]
enum RoleArg {
    /// Open and copy
    View,
    /// Also change and delete logins
    Edit,
    /// Also share, change roles and remove people
    Manage,
}

impl From<RoleArg> for commands::Role {
    fn from(role: RoleArg) -> Self {
        match role {
            RoleArg::View => Self::View,
            RoleArg::Edit => Self::Edit,
            RoleArg::Manage => Self::Manage,
        }
    }
}

fn main() -> ExitCode {
    match run(Cli::parse()) {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("error: {error:#}");
            ExitCode::FAILURE
        }
    }
}

fn run(cli: Cli) -> Result<()> {
    let home = default_home()?;
    match cli.command {
        Command::Setup {
            server,
            setup_code,
            name,
        } => {
            let me = commands::setup(&home, &server, &setup_code, &name)?;
            println!("You're now the owner of {}.", me.server);
            println!("Your fingerprint: {}", me.fingerprint);
        }
        Command::Invite { name } => {
            let invite = commands::invite(&home, &name)?;
            println!("Send {name} this command. It works once:\n");
            println!("  {}\n", invite.command());
            println!("Then compare fingerprints with them and run:");
            println!("  keystead approve <their user id> --fingerprint <their fingerprint>");
        }
        Command::Join {
            server,
            token,
            owner,
        } => {
            let me = commands::join(&home, &server, &token, &owner)?;
            println!("Joined {} as {} (user {}).", me.server, me.name, me.user_id);
            println!("Your fingerprint: {}", me.fingerprint);
            println!("Read it to the owner, in person or on a call, so they can approve you.");
        }
        Command::Whoami => {
            let me = commands::whoami(&home)?;
            println!("{} (user {}) on {}", me.name, me.user_id, me.server);
            println!("Fingerprint: {}", me.fingerprint);
        }
        Command::RecoveryKit => {
            let (words, me) = commands::recovery_kit(&home)?;
            println!("Recovery kit for {} on {}\n", me.name, me.server);
            let words: Vec<&str> = words.split(' ').collect();
            for row in 0..6 {
                let line: Vec<String> = (0..4)
                    .map(|column| {
                        let index = row * 4 + column;
                        format!("{:>4}  {:<10}", index + 1, words[index])
                    })
                    .collect();
                println!("{}", line.join("").trim_end());
            }
            println!("\nYour fingerprint:    {}", me.fingerprint);
            println!("Owner's fingerprint: {}\n", me.owner_fingerprint);
            println!("Anyone with these words can be you on this server. Write them down, keep");
            println!("them somewhere safe and offline, and don't store them on a computer.");
            println!(
                "To recover: keystead recover {} --owner {}",
                me.server, me.owner_fingerprint
            );
        }
        Command::Recover { server, owner } => {
            let words = if std::io::stdin().is_terminal() {
                rpassword::prompt_password("The 24 words from your recovery kit (hidden): ")?
            } else {
                let mut text = String::new();
                std::io::Read::read_to_string(&mut std::io::stdin(), &mut text)?;
                text
            };
            let me = commands::recover(&home, &server, owner.as_deref(), &words)?;
            println!(
                "Recovered {} (user {}) on {}.",
                me.name, me.user_id, me.server
            );
            println!("Remove your lost device with `keystead devices remove <id>`.");
        }
        Command::SignOut { yes } => {
            let me = commands::whoami(&home)?;
            if !yes {
                if !std::io::stdin().is_terminal() {
                    anyhow::bail!("add --yes to sign out without being asked");
                }
                println!(
                    "This machine will forget {} on {}. To use the account here again, you'll",
                    me.name, me.server
                );
                println!("need your recovery kit.");
                print!("Sign out? [y/N] ");
                std::io::Write::flush(&mut std::io::stdout())?;
                let mut answer = String::new();
                std::io::stdin().lock().read_line(&mut answer)?;
                if !matches!(answer.trim(), "y" | "Y" | "yes") {
                    println!("Not signed out.");
                    return Ok(());
                }
            }
            match commands::sign_out(&home)? {
                None => println!("Signed out. The server has forgotten this machine."),
                Some(reason) => {
                    println!("Signed out here, but the server couldn't be told ({reason}).");
                    println!(
                        "Remove this machine from another device: keystead devices remove <id>"
                    );
                }
            }
        }
        Command::Devices { action: None } => {
            let rows = commands::devices(&home)?
                .into_iter()
                .map(|device| {
                    let mut name = if device.name.is_empty() {
                        "(unnamed)".to_owned()
                    } else {
                        device.name
                    };
                    if device.current {
                        name.push_str(" (this device)");
                    }
                    let added = device.added_at.map(date).unwrap_or_default();
                    vec![device.id.to_string(), name, added]
                })
                .collect();
            print_table(&["ID", "NAME", "ADDED"], rows);
        }
        Command::Devices {
            action: Some(DevicesCommand::Remove { device_id }),
        } => {
            let device = device_id.parse().map_err(|_| {
                anyhow::anyhow!("{device_id} isn't a device id; see `keystead devices`")
            })?;
            commands::remove_device(&home, device)?;
            println!("Removed {device_id}. It can't sign in any more.");
        }
        Command::Users => {
            let rows = commands::users(&home)?
                .into_iter()
                .map(|user| {
                    let status = if user.removed {
                        "removed"
                    } else if user.approved {
                        "approved"
                    } else {
                        "waiting"
                    };
                    vec![
                        user.user_id.to_string(),
                        user.name,
                        status.to_owned(),
                        user.fingerprint,
                    ]
                })
                .collect();
            print_table(&["ID", "NAME", "STATUS", "FINGERPRINT"], rows);
        }
        Command::Approve {
            user_id,
            fingerprint,
        } => {
            let name = commands::approve(&home, UserId(user_id), &fingerprint)?;
            println!("Approved {name}.");
        }
        Command::Folder(FolderCommand::Create { name }) => {
            commands::create_folder(&home, &name)?;
            println!("Created folder {name}.");
        }
        Command::Folder(FolderCommand::Share {
            folder,
            user_id,
            role,
        }) => {
            let name = commands::share_folder(&home, &folder, UserId(user_id), role.into())?;
            println!("Shared {folder} with {name}.");
        }
        Command::Folder(FolderCommand::Members { folder }) => {
            let rows = commands::folder_members(&home, &folder)?
                .into_iter()
                .map(|member| {
                    let name = if member.me {
                        format!("{} (you)", member.name)
                    } else {
                        member.name
                    };
                    vec![
                        member.user_id.to_string(),
                        name,
                        member.role.name().to_owned(),
                    ]
                })
                .collect();
            print_table(&["ID", "NAME", "ROLE"], rows);
        }
        Command::Folder(FolderCommand::Role {
            folder,
            user_id,
            role,
        }) => {
            commands::set_folder_role(&home, &folder, UserId(user_id), role.into())?;
            println!("Changed their role in {folder}.");
        }
        Command::Folder(FolderCommand::Remove { folder, user_id }) => {
            commands::remove_from_folder(&home, &folder, UserId(user_id))?;
            println!("Removed them from {folder}, and gave it a new key.");
        }
        Command::Folder(FolderCommand::Leave { folder }) => {
            commands::leave_folder(&home, &folder)?;
            println!("Left {folder}.");
        }
        Command::Folder(FolderCommand::List) => {
            for name in commands::folders(&home)? {
                println!("{name}");
            }
        }
        Command::Add {
            name,
            folder,
            username,
            url,
            generate,
        } => {
            let details = Details {
                password: password(generate)?,
                notes: String::new(),
            };
            let overview = Overview {
                name: name.clone(),
                username: username.unwrap_or_default(),
                url: url.unwrap_or_default(),
                tags: Vec::new(),
            };
            commands::add(&home, folder.as_deref(), overview, details)?;
            match folder {
                Some(folder) => println!("Added {name} to {folder}."),
                None => println!("Added {name}. Only you can see it until you share it."),
            }
        }
        Command::Share {
            name,
            user_id,
            folder,
            role,
        } => {
            let who = commands::share(
                &home,
                &name,
                folder.as_deref(),
                UserId(user_id),
                role.into(),
            )?;
            println!("Shared {name} with {who}.");
        }
        Command::Unshare {
            name,
            user_id,
            folder,
        } => {
            let who = commands::unshare(&home, &name, folder.as_deref(), UserId(user_id))?;
            println!("{who} no longer has {name}.");
        }
        Command::RemoveUser { user_id, yes } => {
            if !yes {
                if !std::io::stdin().is_terminal() {
                    anyhow::bail!("add --yes to remove them without being asked");
                }
                println!("Their devices stop working and they lose every folder and login.");
                println!("Passwords they've already seen can't be taken back; change those.");
                print!("Remove user {user_id} from the team? [y/N] ");
                std::io::Write::flush(&mut std::io::stdout())?;
                let mut answer = String::new();
                std::io::stdin().lock().read_line(&mut answer)?;
                if !matches!(answer.trim(), "y" | "Y" | "yes") {
                    println!("Not removed.");
                    return Ok(());
                }
            }
            let name = commands::remove_user(&home, UserId(user_id))?;
            println!("Removed {name} from the team.");
        }
        Command::Ls => {
            let rows = commands::list(&home)?
                .into_iter()
                .map(|item| {
                    let shared = shared(&item);
                    vec![
                        item.folder.unwrap_or_else(|| "-".into()),
                        item.name,
                        item.username,
                        item.url,
                        shared,
                    ]
                })
                .collect();
            print_table(&["FOLDER", "NAME", "USERNAME", "URL", "SHARED"], rows);
        }
        Command::Show {
            name,
            folder,
            notes,
        } => {
            let (_, details) = commands::show(&home, &name, folder.as_deref())?;
            println!(
                "{}",
                if notes {
                    &details.notes
                } else {
                    &details.password
                }
            );
        }
        Command::Edit {
            name,
            folder,
            rename,
            username,
            url,
            notes,
            password: new_password,
            generate,
        } => {
            let other_fields =
                rename.is_some() || username.is_some() || url.is_some() || notes.is_some();
            let changes = commands::Changes {
                name: rename,
                username,
                url,
                notes,
                // Without other fields, edit changes the password, as it always has.
                password: if new_password || generate || !other_fields {
                    Some(password(generate)?)
                } else {
                    None
                },
            };
            match commands::update(&home, &name, folder.as_deref(), changes)? {
                EditOutcome::Saved { version } => println!("Saved {name} (version {version})."),
                EditOutcome::Conflict { version, author } => {
                    println!("Not saved: {author} saved version {version} first.");
                    println!("Your copy now has their version; run edit again to replace it.");
                }
            }
        }
        Command::Rm { name, folder, yes } => {
            if !yes {
                if !std::io::stdin().is_terminal() {
                    anyhow::bail!("add --yes to delete without being asked");
                }
                print!("Delete {name} for everyone who can open it? [y/N] ");
                std::io::Write::flush(&mut std::io::stdout())?;
                let mut answer = String::new();
                std::io::stdin().lock().read_line(&mut answer)?;
                if !matches!(answer.trim(), "y" | "Y" | "yes") {
                    println!("Not deleted.");
                    return Ok(());
                }
            }
            match commands::remove(&home, &name, folder.as_deref())? {
                EditOutcome::Saved { .. } => println!("Deleted {name}."),
                EditOutcome::Conflict { version, author } => {
                    println!("Not deleted: {author} saved version {version} first.");
                    println!("Your copy now has their version; check it, then run rm again.");
                }
            }
        }
        Command::Sync => {
            let summary = commands::sync(&home)?;
            commands::warn_rejected(&summary);
            println!("Synced {} change(s).", summary.received);
        }
    }
    Ok(())
}

/// A generated password, a hidden prompt on a terminal, or one line from piped input.
fn password(generate: bool) -> Result<String> {
    if generate {
        return Ok(commands::generate_password());
    }
    if std::io::stdin().is_terminal() {
        return Ok(rpassword::prompt_password("Password: ")?);
    }
    let mut line = String::new();
    std::io::stdin().lock().read_line(&mut line)?;
    Ok(line.trim_end_matches(['\r', '\n']).to_owned())
}

/// How a login is shared outside its folder: "from Ana", "with you", "with Bob, Carol".
fn shared(item: &commands::ItemRow) -> String {
    let mut parts = Vec::new();
    match &item.owner {
        Some(owner) => parts.push(format!("from {owner}")),
        None if item.shared_with_me => parts.push("with you".to_owned()),
        None => {}
    }
    if !item.shared_with.is_empty() {
        parts.push(format!("with {}", item.shared_with.join(", ")));
    }
    parts.join("; ")
}

/// A Unix timestamp as a UTC date, like 2026-11-23.
fn date(seconds: i64) -> String {
    // Howard Hinnant's days-to-civil algorithm.
    let days = seconds.div_euclid(86_400) + 719_468;
    let era = days.div_euclid(146_097);
    let day_of_era = days - era * 146_097;
    let year_of_era =
        (day_of_era - day_of_era / 1460 + day_of_era / 36_524 - day_of_era / 146_096) / 365;
    let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
    let month_index = (5 * day_of_year + 2) / 153;
    let day = day_of_year - (153 * month_index + 2) / 5 + 1;
    let month = if month_index < 10 {
        month_index + 3
    } else {
        month_index - 9
    };
    let year = year_of_era + era * 400 + i64::from(month <= 2);
    format!("{year:04}-{month:02}-{day:02}")
}

fn print_table(headers: &[&str], rows: Vec<Vec<String>>) {
    let mut widths: Vec<usize> = headers.iter().map(|header| header.len()).collect();
    for row in &rows {
        for (width, cell) in widths.iter_mut().zip(row) {
            *width = (*width).max(cell.chars().count());
        }
    }
    let line = |cells: Vec<&str>| {
        let padded: Vec<String> = cells
            .iter()
            .zip(&widths)
            .map(|(cell, width)| format!("{cell:<width$}"))
            .collect();
        println!("{}", padded.join("  ").trim_end());
    };
    line(headers.to_vec());
    for row in &rows {
        line(row.iter().map(String::as_str).collect());
    }
}

#[cfg(test)]
mod tests {
    use super::date;

    #[test]
    fn dates_are_utc_calendar_days() {
        assert_eq!(date(0), "1970-01-01");
        assert_eq!(date(951_782_400), "2000-02-29");
        assert_eq!(date(1_704_067_199), "2023-12-31");
        assert_eq!(date(1_704_067_200), "2024-01-01");
    }
}
