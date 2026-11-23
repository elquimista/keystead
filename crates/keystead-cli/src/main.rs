//! `keystead` command-line tool, with pass-style commands for terminal users.

use clap::Parser;

/// Team password manager, from the terminal.
#[derive(Parser)]
#[command(name = "keystead", version, arg_required_else_help = true)]
struct Cli {}

fn main() {
    let _cli = Cli::parse();
}
