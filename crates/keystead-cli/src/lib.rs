//! The library behind the `keystead` command: local state, the HTTP client and commands.
//! Commands return data; `main.rs` decides how to print it.

pub mod client;
pub mod commands;
pub mod state;
