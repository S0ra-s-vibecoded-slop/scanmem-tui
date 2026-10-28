//! scanmem-tui: a terminal frontend for scanmem.

mod app;
mod args;
mod datatype;
mod freezer;
mod gpu;
mod keymap;
mod memio;
mod scanmem;
mod stats;
mod ui;

use anyhow::{bail, Result};
use app::App;
use args::Args;
use clap::Parser;
use ratatui::crossterm::event::{self, Event};
use ratatui::DefaultTerminal;
use std::io::ErrorKind;
use std::process::Command;
use std::time::Duration;

/// How long to wait for input before checking on scanmem and the timers.
const POLL_INTERVAL: Duration = Duration::from_millis(80);

fn main() -> Result<()> {
    let args = Args::parse();
    ensure_scanmem_installed(&args.scanmem)?;
    let mut app = App::start(&args)?;
    run_tui(&mut app)
}

fn ensure_scanmem_installed(path: &str) -> Result<()> {
    match Command::new(path).arg("--version").output() {
        Ok(_) => Ok(()),
        Err(e) if e.kind() == ErrorKind::NotFound => {
            bail!("could not find `{path}`. Install scanmem, or point --scanmem (or $SCANMEM) at it.")
        }
        Err(e) => bail!("could not run `{path}`: {e}"),
    }
}

fn run_tui(app: &mut App) -> Result<()> {
    let mut terminal = ratatui::init();
    let result = event_loop(&mut terminal, app);
    ratatui::restore();
    result
}

fn event_loop(terminal: &mut DefaultTerminal, app: &mut App) -> Result<()> {
    while !app.should_quit {
        if app.take_redraw() {
            terminal.draw(|frame| ui::draw(frame, app))?;
        }
        handle_input(app)?;
        app.tick();
    }
    Ok(())
}

/// Waits for input, then drains everything already queued before returning.
fn handle_input(app: &mut App) -> Result<()> {
    let mut wait = POLL_INTERVAL;
    while event::poll(wait)? {
        match event::read()? {
            Event::Key(key) => app.on_key(key),
            Event::Resize(..) => app.request_redraw(),
            _ => {}
        }
        wait = Duration::ZERO;
    }
    Ok(())
}
