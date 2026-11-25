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
    /// Claim a new server with its setup code and become your team's owner
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
    /// Add this machine to your account from a device that already has it: run
    /// `keystead devices add` there (or Add a Device in the app) and use the line it shows
    AddDevice {
        server: String,
        token: String,
        /// The owner's fingerprint, from the line
        #[arg(long)]
        owner: String,
        /// How this machine shows in your list of devices
        #[arg(long, default_value = "Command line")]
        name: String,
    },
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
    /// Groups of people that folders and logins can be shared with as one
    #[command(subcommand)]
    Group(GroupCommand),
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
        /// Its one-time codes: the otpauth:// link from the site's QR code, or the setup key
        /// the site shows for typing in
        #[arg(long, value_name = "LINK_OR_KEY")]
        otp: Option<String>,
    },
    /// Share one login with an approved user or a group, without the rest of its folder
    Share {
        name: String,
        #[arg(required_unless_present = "group")]
        user_id: Option<i64>,
        /// Share with this group instead of one person
        #[arg(long, conflicts_with = "user_id")]
        group: Option<String>,
        #[arg(long)]
        folder: Option<String>,
        #[arg(long, value_enum, default_value_t = RoleArg::Edit)]
        role: RoleArg,
    },
    /// Take away someone's or a group's copy of a login (managers)
    Unshare {
        name: String,
        #[arg(required_unless_present = "group")]
        user_id: Option<i64>,
        #[arg(long, conflicts_with = "user_id")]
        group: Option<String>,
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
        /// Set up one-time codes: the otpauth:// link from the site's QR code, or the setup
        /// key the site shows for typing in
        #[arg(long, value_name = "LINK_OR_KEY", conflicts_with = "no_otp")]
        otp: Option<String>,
        /// Stop keeping one-time codes for it
        #[arg(long)]
        no_otp: bool,
    },
    /// List a login's earlier versions and what each changed (editors and managers), or
    /// print one version's password
    History {
        name: String,
        #[arg(long)]
        folder: Option<String>,
        /// Print this version's password instead
        #[arg(long, value_name = "VERSION")]
        show: Option<u64>,
    },
    /// Bring back an earlier version of a login, as a new version
    Restore {
        name: String,
        version: u64,
        #[arg(long)]
        folder: Option<String>,
    },
    /// Print a login's current one-time code
    Otp {
        name: String,
        #[arg(long)]
        folder: Option<String>,
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
    /// Import logins from a Passbolt export, or a KeePass or KeePassXC file (.kdbx). Shows
    /// what it would do first
    Import {
        file: std::path::PathBuf,
        /// Put logins that aren't in a folder into this folder, instead of keeping them as
        /// your own
        #[arg(long, value_name = "FOLDER")]
        unfiled_folder: Option<String>,
        /// Import without asking
        #[arg(long)]
        yes: bool,
    },
    /// Move a login to another folder (--to), or out of folders as your own (--own). Who
    /// had it only through its old folder loses it
    Mv {
        name: String,
        /// The folder it's in now, if several logins have that name
        #[arg(long)]
        folder: Option<String>,
        #[arg(
            long,
            value_name = "FOLDER",
            required_unless_present = "own",
            conflicts_with = "own"
        )]
        to: Option<String>,
        /// Out of folders: only you, and whoever it's shared with directly, keep it
        #[arg(long)]
        own: bool,
    },
    /// List logins deleted in the last 30 days that you can bring back
    Deleted,
    /// Bring back a login deleted in the last 30 days
    Undelete {
        name: String,
        #[arg(long)]
        folder: Option<String>,
    },
    /// Delete a deleted login for good now, instead of after 30 days
    Purge {
        name: String,
        #[arg(long)]
        folder: Option<String>,
        /// Don't ask for confirmation
        #[arg(long)]
        yes: bool,
    },
    /// List passwords to change: logins you can change that someone could open before
    /// losing access
    ToChange {
        #[command(subcommand)]
        action: Option<ToChangeCommand>,
    },
    /// Fetch changes from the server
    Sync,
}

#[derive(Subcommand)]
enum ToChangeCommand {
    /// Take logins off the list without changing them: one login, everything one person
    /// could see, or both
    Dismiss {
        #[arg(required_unless_present = "user")]
        login: Option<String>,
        #[arg(long, requires = "login")]
        folder: Option<String>,
        /// Only for this person
        #[arg(long)]
        user: Option<i64>,
    },
}

#[derive(Subcommand)]
enum DevicesCommand {
    /// Add another device to your account: shows a line for it, then asks for the code it
    /// shows, and sends it your account, sealed so only it can open it
    Add,
    /// Remove one of your other devices, such as a lost one; it can't sign in any more
    Remove { device_id: String },
}

#[derive(Subcommand)]
enum FolderCommand {
    /// Create a folder, or one inside another (named "Parent / Name"), which starts out
    /// shared like its parent
    Create {
        name: String,
        /// Create it inside this folder
        #[arg(long, value_name = "FOLDER")]
        inside: Option<String>,
        /// With --inside: don't share it like its parent; only you can open it
        #[arg(long, requires = "inside")]
        private: bool,
    },
    /// Share a folder with an approved user or a group (managers)
    Share {
        folder: String,
        #[arg(required_unless_present = "group")]
        user_id: Option<i64>,
        /// Share with this group instead of one person
        #[arg(long, conflicts_with = "user_id")]
        group: Option<String>,
        #[arg(long, value_enum, default_value_t = RoleArg::Edit)]
        role: RoleArg,
    },
    /// List who is in a folder and the groups it's shared with, with their roles
    Members { folder: String },
    /// Change someone's role in a folder (managers)
    Role {
        folder: String,
        user_id: i64,
        #[arg(value_enum)]
        role: RoleArg,
    },
    /// Change a group's role in a folder (managers)
    GroupRole {
        folder: String,
        group: String,
        #[arg(value_enum)]
        role: RoleArg,
    },
    /// Take someone or a group out of a folder; it then gets a new key (managers)
    Remove {
        folder: String,
        #[arg(required_unless_present = "group")]
        user_id: Option<i64>,
        #[arg(long, conflicts_with = "user_id")]
        group: Option<String>,
    },
    /// Leave a folder
    Leave { folder: String },
    /// Rename a folder, and the folders inside it you manage (managers)
    Rename { folder: String, name: String },
    /// Delete a folder and its logins for everyone, for good; folders inside it stay
    /// (managers)
    Delete {
        folder: String,
        /// Don't ask for confirmation
        #[arg(long)]
        yes: bool,
    },
    /// List your folders
    List,
}

#[derive(Subcommand)]
enum GroupCommand {
    /// List the team's groups and who is in them
    List,
    /// Make a group with you and these people in it, and you as its manager (owner only)
    Create { name: String, user_ids: Vec<i64> },
    /// Add someone to a group: they get everything shared with it (its managers)
    Add { group: String, user_id: i64 },
    /// Take someone out of a group; it then gets a new key (owner and its managers)
    Remove { group: String, user_id: i64 },
    /// Leave a group
    Leave { group: String },
    /// Delete a group: everyone in it loses what only it gave them (owner and its managers)
    Delete {
        group: String,
        /// Don't ask for confirmation
        #[arg(long)]
        yes: bool,
    },
    /// Rename a group (owner and its managers)
    Rename { group: String, name: String },
    /// Make someone in a group one of its managers (owner and its managers)
    Manager {
        group: String,
        user_id: i64,
        /// Stop them being a manager instead
        #[arg(long)]
        remove: bool,
    },
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
            println!("You're now your team's owner on {}.", me.server);
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
        Command::AddDevice {
            server,
            token,
            owner,
            name,
        } => {
            let line = format!("{server} {token} --owner {owner}");
            let me = commands::add_this_device(&home, &line, &name, |code| {
                println!("On your other device, type this code: {code}");
                println!("Waiting for it, for up to ten minutes…");
            })?;
            println!(
                "Added this machine to {}'s account (user {}) on {}.",
                me.name, me.user_id, me.server
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
            action: Some(DevicesCommand::Add),
        } => {
            let name = commands::add_device(
                &home,
                |line| {
                    println!("On the new device, run this (or paste it into the app):\n");
                    println!("  {line}\n");
                    println!("Waiting for it, for up to ten minutes…");
                },
                |name| {
                    print!("Type the code {name} shows: ");
                    std::io::Write::flush(&mut std::io::stdout())?;
                    let mut code = String::new();
                    std::io::stdin().lock().read_line(&mut code)?;
                    Ok(code)
                },
            )?;
            println!("Sent. {name} now finishes adding itself.");
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
        Command::Folder(FolderCommand::Create {
            name, inside: None, ..
        }) => {
            commands::create_folder(&home, &name)?;
            println!("Created folder {name}.");
        }
        Command::Folder(FolderCommand::Create {
            name,
            inside: Some(parent),
            private,
        }) => {
            let created = commands::create_folder_inside(&home, &parent, &name, !private)?;
            if created.shared_with.is_empty() {
                println!("Created folder {}; only you can open it.", created.name);
            } else {
                println!(
                    "Created folder {}, shared like {parent} with {}.",
                    created.name,
                    created.shared_with.join(", ")
                );
            }
            for problem in &created.problems {
                eprintln!("warning: couldn't share it with {problem}");
            }
        }
        Command::Folder(FolderCommand::Share {
            folder,
            user_id,
            group,
            role,
        }) => {
            let name = match (user_id, group) {
                (Some(user_id), _) => {
                    commands::share_folder(&home, &folder, UserId(user_id), role.into())?
                }
                (None, Some(group)) => {
                    commands::share_folder_with_group(&home, &folder, &group, role.into())?
                }
                (None, None) => unreachable!("clap requires one"),
            };
            println!("Shared {folder} with {name}.");
        }
        Command::Folder(FolderCommand::Members { folder }) => {
            let (members, groups) = commands::folder_members(&home, &folder)?;
            let mut rows: Vec<Vec<String>> = members
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
            rows.extend(groups.into_iter().map(|group| {
                let mine = if group.mine { ", you're in it" } else { "" };
                vec![
                    "-".to_owned(),
                    format!("{} (group{mine})", group.name),
                    group.role.name().to_owned(),
                ]
            }));
            print_table(&["ID", "NAME", "ROLE"], rows);
        }
        Command::Folder(FolderCommand::GroupRole {
            folder,
            group,
            role,
        }) => {
            commands::set_folder_group_role(&home, &folder, &group, role.into())?;
            println!("Changed {group}'s role in {folder}.");
        }
        Command::Folder(FolderCommand::Role {
            folder,
            user_id,
            role,
        }) => {
            commands::set_folder_role(&home, &folder, UserId(user_id), role.into())?;
            println!("Changed their role in {folder}.");
        }
        Command::Folder(FolderCommand::Remove {
            folder,
            user_id,
            group,
        }) => match (user_id, group) {
            (Some(user_id), _) => {
                commands::remove_from_folder(&home, &folder, UserId(user_id))?;
                println!("Removed them from {folder}, and gave it a new key.");
            }
            (None, Some(group)) => {
                let summary = commands::remove_group_from_folder(&home, &folder, &group)?;
                commands::warn_rejected(&summary);
                println!("Removed {group} from {folder}.");
            }
            (None, None) => unreachable!("clap requires one"),
        },
        Command::Group(GroupCommand::List) => {
            let rows = commands::groups(&home)?
                .into_iter()
                .map(|group| {
                    let members: Vec<String> = group
                        .members
                        .iter()
                        .map(|member| {
                            let mut name = format!("{} ({})", member.name, member.user_id);
                            if member.manager {
                                name.push('*');
                            }
                            name
                        })
                        .collect();
                    let you = if group.can_manage {
                        "manage"
                    } else if group.member {
                        "member"
                    } else {
                        "-"
                    };
                    vec![group.name, you.to_owned(), members.join(", ")]
                })
                .collect();
            print_table(&["GROUP", "YOU", "MEMBERS (* MANAGES)"], rows);
        }
        Command::Group(GroupCommand::Create { name, user_ids }) => {
            let members: Vec<UserId> = user_ids.into_iter().map(UserId).collect();
            commands::create_group(&home, &name, &members)?;
            println!("Created group {name}. You're its manager.");
        }
        Command::Group(GroupCommand::Add { group, user_id }) => {
            let name = commands::add_to_group(&home, &group, UserId(user_id))?;
            println!("Added {name} to {group}.");
        }
        Command::Group(GroupCommand::Remove { group, user_id }) => {
            let summary = commands::remove_from_group(&home, &group, UserId(user_id))?;
            commands::warn_rejected(&summary);
            println!("Removed them from {group}.");
            if summary.rekeyed == 0 {
                println!("One of its managers' apps gives it a new key when it next syncs.");
            }
        }
        Command::Group(GroupCommand::Delete { group, yes }) => {
            if !yes {
                if !std::io::stdin().is_terminal() {
                    anyhow::bail!("add --yes to delete the group without being asked");
                }
                println!("Everyone in {group} loses what only the group gave them, and folders");
                println!("shared with it get new keys.");
                print!("Delete {group}? [y/N] ");
                std::io::Write::flush(&mut std::io::stdout())?;
                let mut answer = String::new();
                std::io::stdin().lock().read_line(&mut answer)?;
                if !matches!(answer.trim(), "y" | "Y" | "yes") {
                    println!("Not deleted.");
                    return Ok(());
                }
            }
            let summary = commands::delete_group(&home, &group)?;
            commands::warn_rejected(&summary);
            println!("Deleted {group}.");
        }
        Command::Group(GroupCommand::Leave { group }) => {
            commands::leave_group(&home, &group)?;
            println!("Left {group}.");
        }
        Command::Group(GroupCommand::Rename { group, name }) => {
            commands::rename_group(&home, &group, &name)?;
            println!("Renamed {group} to {name}.");
        }
        Command::Group(GroupCommand::Manager {
            group,
            user_id,
            remove,
        }) => {
            commands::set_group_manager(&home, &group, UserId(user_id), !remove)?;
            if remove {
                println!("They no longer manage {group}.");
            } else {
                println!("They now manage {group}.");
            }
        }
        Command::Folder(FolderCommand::Rename { folder, name }) => {
            let renamed = commands::rename_folder(&home, &folder, &name)?;
            println!("Renamed {folder} to {}.", renamed.name);
            for kept in &renamed.kept {
                println!("{kept} kept its name: you don't manage it.");
            }
            for problem in &renamed.problems {
                eprintln!("warning: couldn't rename {problem}");
            }
        }
        Command::Folder(FolderCommand::Delete { folder, yes }) => {
            let plan = commands::folder_deletion(&home, &folder)?;
            if !yes {
                if !std::io::stdin().is_terminal() {
                    anyhow::bail!("add --yes to delete the folder without being asked");
                }
                println!("Everyone in {folder} loses it.");
                if plan.logins > 0 {
                    let logins = if plan.logins == 1 { "login" } else { "logins" };
                    println!(
                        "Its {} {logins} are deleted with it for everyone, including anyone \
                         they're shared with directly, and can't be brought back.",
                        plan.logins
                    );
                }
                if plan.to_change > 0 {
                    println!(
                        "{} of their passwords are on the list to change; that's forgotten too.",
                        plan.to_change
                    );
                }
                if !plan.inside.is_empty() {
                    println!("Folders inside it stay: {}.", plan.inside.join(", "));
                }
                print!("Delete {folder}? [y/N] ");
                std::io::Write::flush(&mut std::io::stdout())?;
                let mut answer = String::new();
                std::io::stdin().lock().read_line(&mut answer)?;
                if !matches!(answer.trim(), "y" | "Y" | "yes") {
                    println!("Not deleted.");
                    return Ok(());
                }
            }
            let summary = commands::delete_folder(&home, &folder, plan.logins)?;
            commands::warn_rejected(&summary);
            println!("Deleted {folder}.");
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
            otp,
        } => {
            let details = Details {
                password: password(generate)?,
                notes: String::new(),
                otp: otp.unwrap_or_default(),
            };
            let overview = Overview {
                name: name.clone(),
                username: username.unwrap_or_default(),
                url: url.unwrap_or_default(),
                ..Overview::default()
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
            group,
            folder,
            role,
        } => {
            let who = match (user_id, group) {
                (Some(user_id), _) => commands::share(
                    &home,
                    &name,
                    folder.as_deref(),
                    UserId(user_id),
                    role.into(),
                )?,
                (None, Some(group)) => commands::share_with_group(
                    &home,
                    &name,
                    folder.as_deref(),
                    &group,
                    role.into(),
                )?,
                (None, None) => unreachable!("clap requires one"),
            };
            println!("Shared {name} with {who}.");
        }
        Command::Unshare {
            name,
            user_id,
            group,
            folder,
        } => {
            let who = match (user_id, group) {
                (Some(user_id), _) => {
                    commands::unshare(&home, &name, folder.as_deref(), UserId(user_id))?
                }
                (None, Some(group)) => {
                    commands::unshare_group(&home, &name, folder.as_deref(), &group)?
                }
                (None, None) => unreachable!("clap requires one"),
            };
            println!("{who} no longer has {name}.");
        }
        Command::RemoveUser { user_id, yes } => {
            if !yes {
                if !std::io::stdin().is_terminal() {
                    anyhow::bail!("add --yes to remove them without being asked");
                }
                println!("Their devices stop working and they lose every folder and login.");
                println!(
                    "Passwords they've already seen can't be taken back; change those \
                     (`keystead to-change` lists them)."
                );
                print!("Remove user {user_id} from the team? [y/N] ");
                std::io::Write::flush(&mut std::io::stdout())?;
                let mut answer = String::new();
                std::io::stdin().lock().read_line(&mut answer)?;
                if !matches!(answer.trim(), "y" | "Y" | "yes") {
                    println!("Not removed.");
                    return Ok(());
                }
            }
            let (name, to_change) = commands::remove_user(&home, UserId(user_id))?;
            println!("Removed {name} from the team.");
            if to_change > 0 {
                println!(
                    "They could see {to_change} password(s) you can change; \
                     `keystead to-change` lists them."
                );
            }
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
            otp,
            no_otp,
        } => {
            let otp = if no_otp { Some(String::new()) } else { otp };
            let other_fields = rename.is_some()
                || username.is_some()
                || url.is_some()
                || notes.is_some()
                || otp.is_some();
            let changes = commands::Changes {
                name: rename,
                username,
                url,
                notes,
                otp,
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
        Command::History {
            name,
            folder,
            show: Some(version),
        } => {
            let (_, details) = commands::history_version(&home, &name, folder.as_deref(), version)?;
            println!("{}", details.password);
        }
        Command::History {
            name,
            folder,
            show: None,
        } => {
            let rows: Vec<Vec<String>> = commands::history(&home, &name, folder.as_deref())?
                .into_iter()
                .map(|row| {
                    let changed = if !row.readable {
                        "(can't open: from before you had it)".to_owned()
                    } else if row.changes.is_empty() {
                        "-".to_owned()
                    } else {
                        row.changes.join(", ")
                    };
                    vec![
                        format!("{}{}", row.version, if row.current { " (now)" } else { "" }),
                        row.saved_at.map(date).unwrap_or_else(|| "-".into()),
                        row.author,
                        changed,
                    ]
                })
                .collect();
            print_table(&["VERSION", "SAVED", "BY", "CHANGED"], rows);
        }
        Command::Restore {
            name,
            version,
            folder,
        } => match commands::restore(&home, &name, folder.as_deref(), version)? {
            EditOutcome::Saved { version: saved } => {
                println!("Brought back version {version} of {name} as version {saved}.");
            }
            EditOutcome::Conflict { version, author } => {
                println!("Not saved: {author} saved version {version} first; try again.");
            }
        },
        Command::Otp { name, folder } => {
            let code = commands::one_time_code(&home, &name, folder.as_deref())?;
            println!("{}", code.code);
            if std::io::stdout().is_terminal() {
                eprintln!("Good for {} more second(s).", code.remaining);
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
                EditOutcome::Saved { .. } => {
                    println!(
                        "Deleted {name}. `keystead undelete {name}` brings it back for 30 days."
                    );
                }
                EditOutcome::Conflict { version, author } => {
                    println!("Not deleted: {author} saved version {version} first.");
                    println!("Your copy now has their version; check it, then run rm again.");
                }
            }
        }
        Command::Import {
            file,
            unfiled_folder,
            yes,
        } => {
            let passphrase = if std::io::stdin().is_terminal() {
                rpassword::prompt_password(format!(
                    "The passphrase {} was exported with (hidden): ",
                    file.display()
                ))?
            } else {
                let mut line = String::new();
                std::io::stdin().lock().read_line(&mut line)?;
                line.trim_end_matches(['\r', '\n']).to_owned()
            };
            let logins = commands::read_export(&file, &passphrase)?;
            let plan = commands::plan_import(&home, &logins, unfiled_folder.as_deref())?;
            println!("{} has {} login(s):", file.display(), logins.len());
            for folder in &plan.folders {
                let new = if folder.new {
                    " (new folder, yours alone)"
                } else {
                    ""
                };
                println!("  {}: {}{new}", folder.name, folder.logins);
            }
            if plan.own > 0 {
                println!("  Your own, in no folder: {}", plan.own);
            }
            if plan.duplicates > 0 {
                println!("  Already here, left out: {}", plan.duplicates);
            }
            for (folder, count) in &plan.view_only {
                println!("  {folder}: {count} left out, as you can only view it");
            }
            if plan.one_time_codes > 0 {
                println!("  With one-time codes: {}", plan.one_time_codes);
            }
            if !yes {
                if !std::io::stdin().is_terminal() {
                    println!("Nothing imported yet; add --yes to import.");
                    return Ok(());
                }
                print!("Import them? [y/N] ");
                std::io::Write::flush(&mut std::io::stdout())?;
                let mut answer = String::new();
                std::io::stdin().lock().read_line(&mut answer)?;
                if !matches!(answer.trim(), "y" | "Y" | "yes") {
                    println!("Not imported.");
                    return Ok(());
                }
            }
            let summary = commands::import(&home, &logins, unfiled_folder.as_deref())?;
            println!(
                "Imported {} login(s), into {} new folder(s).",
                summary.added, summary.folders_created
            );
            if summary.folders_created > 0 {
                println!(
                    "New folders are yours alone until shared: keystead folder share NAME --group GROUP"
                );
            }
        }
        Command::Mv {
            name, folder, to, ..
        } => match commands::move_item(&home, &name, folder.as_deref(), to.as_deref())? {
            EditOutcome::Saved { .. } => match to {
                Some(to) => println!("Moved {name} to {to}."),
                None => println!("Moved {name} out of folders; it's your own now."),
            },
            EditOutcome::Conflict { author, .. } => {
                println!("Not moved: {author} changed it first; try again.");
            }
        },
        Command::Deleted => {
            let rows: Vec<Vec<String>> = commands::deleted(&home)?
                .into_iter()
                .map(|row| {
                    vec![
                        row.folder.unwrap_or_else(|| "-".into()),
                        row.name,
                        date(row.deleted_at),
                        row.deleted_by,
                        date(row.kept_until),
                    ]
                })
                .collect();
            if rows.is_empty() {
                println!("Nothing deleted in the last 30 days.");
            } else {
                print_table(&["FOLDER", "NAME", "DELETED", "BY", "UNTIL"], rows);
            }
        }
        Command::Undelete { name, folder } => {
            match commands::undelete(&home, &name, folder.as_deref())? {
                EditOutcome::Saved { .. } => println!("Brought back {name}."),
                EditOutcome::Conflict { author, .. } => {
                    println!("Not brought back: {author} changed it first.");
                }
            }
        }
        Command::Purge { name, folder, yes } => {
            if !yes {
                if !std::io::stdin().is_terminal() {
                    anyhow::bail!("add --yes to delete for good without being asked");
                }
                print!("Delete {name} for good? It can't be brought back. [y/N] ");
                std::io::Write::flush(&mut std::io::stdout())?;
                let mut answer = String::new();
                std::io::stdin().lock().read_line(&mut answer)?;
                if !matches!(answer.trim(), "y" | "Y" | "yes") {
                    println!("Kept.");
                    return Ok(());
                }
            }
            commands::purge(&home, &name, folder.as_deref())?;
            println!("Deleted {name} for good.");
        }
        Command::ToChange { action: None } => {
            let rows = commands::to_change(&home)?;
            if rows.is_empty() {
                println!("Nothing to change.");
            }
            // One heading per person and day they lost access, most recent first.
            let mut heading = None;
            for row in rows {
                let this = (row.user_id, date(row.since));
                if heading.as_ref() != Some(&this) {
                    println!(
                        "{} (user {}) lost access {} and could have seen:",
                        row.user_name, row.user_id, this.1
                    );
                    heading = Some(this);
                }
                match row.folder {
                    Some(folder) => println!("  {}  ({folder})", row.name),
                    None => println!("  {}", row.name),
                }
            }
        }
        Command::ToChange {
            action:
                Some(ToChangeCommand::Dismiss {
                    login,
                    folder,
                    user,
                }),
        } => {
            let count =
                commands::dismiss(&home, login.as_deref(), folder.as_deref(), user.map(UserId))?;
            match count {
                0 => println!("Nothing like that to dismiss."),
                count => println!("Dismissed {count}."),
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
    let mut with = item.shared_with.clone();
    with.extend(
        item.shared_with_groups
            .iter()
            .map(|group| format!("{group} (group)")),
    );
    if !with.is_empty() {
        parts.push(format!("with {}", with.join(", ")));
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
