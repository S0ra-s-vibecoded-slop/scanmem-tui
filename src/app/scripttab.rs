//! What the Scripts tab does: running scripts, files, and $EDITOR handoff.
//!
//! The Lua states live on the engine thread; everything here only sends
//! commands and turns the events that come back into UI state.

use super::{App, Confirm, Level, Mode};
use crate::scripts::engine::Event;
use crate::scripts::paths::User;
use ratatui::crossterm::event::{KeyCode, KeyEvent};
use std::path::{Path, PathBuf};
use std::sync::mpsc::TryRecvError;

impl App {
    pub(super) fn drain_script_events(&mut self) {
        loop {
            match self.engine.events.try_recv() {
                Ok(event) => self.on_script_event(event),
                Err(TryRecvError::Empty | TryRecvError::Disconnected) => return,
            }
        }
    }

    fn on_script_event(&mut self, event: Event) {
        self.redraw = true;
        match event {
            Event::Output { id, line } => self.scripts.log_line(id, line),
            Event::Disabled { id, reason } => {
                self.scripts.mark_off(id, reason.clone());
                if reason == "stopped" {
                    self.say(Level::Info, "Script stopped.");
                } else {
                    self.say(Level::Warn, format!("Script stopped: {reason}"));
                }
            }
            Event::Freeze {
                label,
                bytes,
                display,
            } => self.apply_script_freeze(&label, bytes, &display),
            Event::Unfreeze { label } => self.apply_script_unfreeze(&label),
        }
    }

    fn apply_script_freeze(&mut self, label: &str, bytes: Vec<u8>, display: &str) {
        let Some(index) = self
            .saved
            .items
            .iter()
            .position(|item| item.label.eq_ignore_ascii_case(label))
        else {
            return; // the row disappeared between the call and its event
        };
        let item = &mut self.saved.items[index];
        item.set_value = Some(bytes);
        item.frozen = true;
        let name = item.label.clone();
        self.sync_freezer();
        self.sync_script_labels();
        self.say(Level::Ok, format!("Script froze `{name}` at {display}"));
    }

    fn apply_script_unfreeze(&mut self, label: &str) {
        let Some(index) = self
            .saved
            .items
            .iter()
            .position(|item| item.label.eq_ignore_ascii_case(label))
        else {
            return;
        };
        let item = &mut self.saved.items[index];
        item.frozen = false;
        let name = item.label.clone();
        self.sync_freezer();
        self.sync_script_labels();
        self.say(Level::Info, format!("Script unfroze `{name}`"));
    }

    /// Space on the Scripts tab: compile and start, or stop.
    pub(super) fn toggle_script(&mut self) {
        let Some(script) = self.scripts.selected_script() else {
            return self.say(
                Level::Info,
                "No script selected. Press i to import one, or n to create one.",
            );
        };
        let (id, name, enabled) = (script.id, script.name.clone(), script.enabled);
        if enabled {
            self.engine.disable(id);
            if let Some(script) = self.scripts.by_id_mut(id) {
                script.enabled = false;
                script.problem = None;
            }
            return self.say(Level::Info, format!("Stopping `{name}`…"));
        }
        if self.target.is_none() {
            return self.say(Level::Warn, "Pick a process first (p)");
        }
        if self.target.as_ref().is_some_and(|t| t.memory().is_err()) {
            return self.say(
                Level::Warn,
                "Cannot access the target's memory (try running as root)",
            );
        }
        let (id, name, source) = match self.scripts.source() {
            Ok(source) => source,
            Err(reason) => return self.say(Level::Error, reason),
        };
        self.sync_script_memory();
        self.sync_script_labels();
        self.engine.enable(id, name.clone(), source);
        if let Some(script) = self.scripts.by_id_mut(id) {
            script.enabled = true;
            script.problem = None;
        }
        self.say(Level::Info, format!("Starting `{name}`…"));
    }

    /// Enter on the Scripts tab: suspend the TUI and run `$EDITOR`.
    pub(super) fn edit_script(&mut self) {
        let Some(script) = self.scripts.selected_script() else {
            return;
        };
        let path = script.path.clone();
        if !path.exists() {
            return self.say(Level::Error, format!("{} no longer exists", path.display()));
        }
        self.queue_editor(path);
    }

    fn queue_editor(&mut self, path: PathBuf) {
        let unset = std::env::var("EDITOR")
            .ok()
            .is_none_or(|editor| editor.trim().is_empty());
        if unset {
            self.say(
                Level::Warn,
                "EDITOR is not set; using vi. The TUI returns when it exits.",
            );
        }
        self.editor_request = Some(path);
    }

    pub(super) fn confirm_delist(&mut self) {
        let Some(script) = self.scripts.selected_script() else {
            return;
        };
        self.mode = Mode::Confirm(Confirm::Delist(script.id));
    }

    pub(super) fn confirm_delete(&mut self) {
        let Some(script) = self.scripts.selected_script() else {
            return;
        };
        if !self.scripts.root.is_managed(&script.path) {
            return self.say(
                Level::Warn,
                "That file is outside the scripts folder; use d to delist it, or delete it yourself.",
            );
        }
        self.mode = Mode::Confirm(Confirm::DeleteFile(script.id));
    }

    pub(super) fn on_confirm_key(&mut self, confirm: Confirm, key: KeyEvent) {
        match key.code {
            KeyCode::Char('y' | 'Y') | KeyCode::Enter => {
                self.mode = Mode::Normal;
                self.run_confirmed(confirm);
            }
            KeyCode::Esc | KeyCode::Char('n' | 'N') => self.mode = Mode::Normal,
            _ => {}
        }
    }

    fn run_confirmed(&mut self, confirm: Confirm) {
        let id = match confirm {
            Confirm::Delist(id) | Confirm::DeleteFile(id) => id,
        };
        let Some(script) = self.scripts.selected_script() else {
            return;
        };
        if script.id != id {
            return self.say(Level::Warn, "The selection changed; nothing was done.");
        }
        let name = script.name.clone();
        if script.enabled {
            self.engine.disable(id);
        }
        match confirm {
            Confirm::Delist(_) => {
                if self.scripts.delist_selected().is_some() {
                    self.say(Level::Info, format!("Removed `{name}` from the list"));
                }
            }
            Confirm::DeleteFile(_) => match self.scripts.delete_selected_file() {
                Ok(path) => self.say(Level::Ok, format!("Deleted {}", path.display())),
                Err(reason) => self.say(Level::Error, reason),
            },
        }
    }

    /// `r`: re-read the file, restarting the script if it is running.
    pub(super) fn reload_script(&mut self) {
        let Some(script) = self.scripts.selected_script() else {
            return;
        };
        let enabled = script.enabled;
        let (id, name, source) = match self.scripts.source() {
            Ok(source) => source,
            Err(reason) => return self.say(Level::Error, reason),
        };
        self.scripts.refresh_preview();
        self.scripts.clear_log(id);
        if enabled {
            self.engine.enable(id, name.clone(), source);
            if let Some(script) = self.scripts.by_id_mut(id) {
                script.problem = None;
            }
            self.say(Level::Info, format!("Reloaded `{name}` and restarted it"));
        } else {
            self.say(Level::Info, format!("Reloaded `{name}`"));
        }
    }

    pub(super) fn import_script(&mut self, text: &str) {
        match self.scripts.import(text) {
            Ok(count) => {
                let selected = self
                    .scripts
                    .selected_script()
                    .map_or_else(String::new, |script| script.name.clone());
                if count == 1 {
                    self.say(Level::Ok, format!("Imported `{selected}`"));
                } else {
                    self.say(Level::Ok, format!("Imported {count} scripts"));
                }
            }
            Err(reason) => self.say(Level::Error, reason),
        }
    }

    pub(super) fn create_script(&mut self, text: &str) {
        match self.scripts.create(text) {
            Ok(path) => {
                self.say(Level::Ok, format!("Created {}", path.display()));
                let path = self
                    .scripts
                    .selected_script()
                    .map_or(path, |script| script.path.clone());
                self.queue_editor(path);
            }
            Err(reason) => self.say(Level::Error, reason),
        }
    }

    /// A target change or loss stops every script.
    pub(super) fn disable_all_scripts(&mut self) {
        for id in self.scripts.mark_all_off() {
            self.engine.disable(id);
        }
    }

    /// Hands the pending editor path (and the user to drop to) to the loop.
    pub fn take_editor_request(&mut self) -> Option<(PathBuf, Option<User>)> {
        let path = self.editor_request.take()?;
        let user = self.scripts.root.editor_user(&path).cloned();
        Some((path, user))
    }

    /// After the editor exits: refresh the preview and restart enabled scripts.
    pub fn finish_editor(&mut self, path: &Path) {
        self.request_redraw();
        self.scripts.refresh_preview();
        let Some(script) = self
            .scripts
            .scripts()
            .iter()
            .find(|script| script.path == path)
        else {
            return;
        };
        let (id, _name, enabled) = (script.id, script.name.clone(), script.enabled);
        if !enabled {
            return;
        }
        match self.scripts.source_for(path) {
            Ok((id, name, source)) => {
                self.engine.enable(id, name.clone(), source);
                self.say(Level::Info, format!("Restarted `{name}` from disk"));
            }
            Err(reason) => {
                self.engine.disable(id);
                self.scripts.mark_off(id, reason.clone());
                self.say(Level::Error, reason);
            }
        }
    }

    pub fn editor_failed(&mut self, message: &str) {
        self.say(Level::Error, format!("Editor: {message}"));
        self.request_redraw();
    }
}
