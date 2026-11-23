//! `keystead`: the team password manager from the terminal, with pass-style commands.
//!
//! The profile lives in `~/.config/keystead`, or in `KEYSTEAD_HOME` if set (handy for
//! trying two accounts side by side).

use std::io::{BufRead, IsTerminal};
use std::process::ExitCode;

use anyhow::Result;
use clap::{Parser, Subcommand};
use keystead_cli::commands::{self, EditOutcome};
use keystead_cli::state::default_home;
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
    /// Add a login to a folder
    Add {
        folder: String,
        name: String,
        #[arg(long)]
        username: Option<String>,
        #[arg(long)]
        url: Option<String>,
        /// Generate a random password instead of asking for one
        #[arg(long)]
        generate: bool,
    },
    /// List logins
    Ls,
    /// Print a login's password
    Show {
        name: String,
        #[arg(long)]
        folder: Option<String>,
    },
    /// Change a login's password
    Edit {
        name: String,
        #[arg(long)]
        folder: Option<String>,
        /// Generate a random password instead of asking for one
        #[arg(long)]
        generate: bool,
    },
    /// Fetch changes from the server
    Sync,
}

#[derive(Subcommand)]
enum FolderCommand {
    /// Create a folder
    Create { name: String },
    /// Share a folder with an approved user
    Share { folder: String, user_id: i64 },
    /// List your folders
    List,
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
            println!(
                "  keystead join {} {} --owner {}\n",
                invite.server, invite.token, invite.owner_fingerprint
            );
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
        Command::Users => {
            let rows = commands::users(&home)?
                .into_iter()
                .map(|user| {
                    vec![
                        user.user_id.to_string(),
                        user.name,
                        if user.approved { "yes" } else { "no" }.to_owned(),
                        user.fingerprint,
                    ]
                })
                .collect();
            print_table(&["ID", "NAME", "APPROVED", "FINGERPRINT"], rows);
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
        Command::Folder(FolderCommand::Share { folder, user_id }) => {
            let name = commands::share_folder(&home, &folder, UserId(user_id))?;
            println!("Shared {folder} with {name}.");
        }
        Command::Folder(FolderCommand::List) => {
            for name in commands::folders(&home)? {
                println!("{name}");
            }
        }
        Command::Add {
            folder,
            name,
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
            commands::add(&home, &folder, overview, details)?;
            println!("Added {name} to {folder}.");
        }
        Command::Ls => {
            let rows = commands::list(&home)?
                .into_iter()
                .map(|item| vec![item.folder, item.name, item.username, item.url])
                .collect();
            print_table(&["FOLDER", "NAME", "USERNAME", "URL"], rows);
        }
        Command::Show { name, folder } => {
            let (_, details) = commands::show(&home, &name, folder.as_deref())?;
            println!("{}", details.password);
        }
        Command::Edit {
            name,
            folder,
            generate,
        } => {
            let new_password = password(generate)?;
            match commands::edit(&home, &name, folder.as_deref(), &new_password)? {
                EditOutcome::Saved { version } => println!("Saved {name} (version {version})."),
                EditOutcome::Conflict { version, author } => {
                    println!("Not saved: {author} saved version {version} first.");
                    println!("Your copy now has their version; run edit again to replace it.");
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
