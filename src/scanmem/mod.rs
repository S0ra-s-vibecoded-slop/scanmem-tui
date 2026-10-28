//! Driver for the interactive `scanmem` CLI.
//!
//! The CLI has no machine-readable mode (that only exists in libscanmem), so
//! `backend` runs it with stdin/stdout piped and frames each batch of commands
//! with a sentinel line, and `parse` turns the text it prints into data.

mod backend;
mod parse;

pub use backend::{Backend, BackendEvent};
pub use parse::{parse_output, Match, Parsed};
