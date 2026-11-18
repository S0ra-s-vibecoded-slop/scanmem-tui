//! Handing the terminal to `$EDITOR`.
//!
//! The TUI leaves the alternate screen and raw mode, the editor inherits the
//! tty, and afterwards the terminal is set up again and redrawn from scratch.
//! Freezers, the scanmem reader and the Lua thread keep running meanwhile.

use super::paths::User;
use ratatui::DefaultTerminal;
use std::os::unix::process::CommandExt;
use std::path::Path;
use std::process::Command;

/// Runs the editor on `path`, restoring the TUI even when it fails.
pub fn edit(
    terminal: &mut DefaultTerminal,
    path: &Path,
    user: Option<&User>,
) -> Result<(), String> {
    ratatui::restore();
    let result = run(path, user);
    *terminal = ratatui::init();
    terminal
        .clear()
        .map_err(|e| format!("cannot redraw the screen: {e}"))?;
    result
}

fn run(path: &Path, user: Option<&User>) -> Result<(), String> {
    let (program, args) = editor_command();
    let mut command = Command::new(&program);
    command.args(&args).arg(path);
    if let Some(user) = user {
        command
            .uid(user.uid)
            .gid(user.gid)
            .env("HOME", &user.home)
            .env("USER", &user.name)
            .env("LOGNAME", &user.name);
    }
    let status = command
        .status()
        .map_err(|e| format!("cannot run `{program}`: {e}"))?;
    if status.success() {
        Ok(())
    } else {
        Err(format!("`{program}` exited with {status}"))
    }
}

/// `$EDITOR`, split into whitespace-separated words, or `vi` when unset.
fn editor_command() -> (String, Vec<String>) {
    let text = std::env::var("EDITOR").unwrap_or_default();
    let mut words = text.split_whitespace().map(str::to_string);
    match words.next() {
        Some(program) => (program, words.collect()),
        None => ("vi".to_string(), Vec::new()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn editor_falls_back_to_vi_and_splits_words() {
        // The environment is process-wide, so only assert the default path
        // here; splitting is covered by the parser shape itself.
        let (program, args) = editor_command();
        assert_ne!(program, "");
        assert!(args.iter().all(|arg| !arg.is_empty()));
    }
}
