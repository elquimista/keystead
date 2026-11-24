//! The library behind the `keystead` command. The real work happens in `keystead-client`;
//! this crate keeps the CLI's keys and turns commands into calls. `main.rs` prints.

pub mod commands;
pub mod device;

pub use device::default_home;
