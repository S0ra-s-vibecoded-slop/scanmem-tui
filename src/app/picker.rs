//! The process chooser popup.

use super::keys::edit_line;
use super::{App, Level, Mode};
use ratatui::crossterm::event::{KeyCode, KeyEvent};
use ratatui::widgets::ListState;
use sysinfo::{ProcessesToUpdate, System};

const PAGE: isize = 10;

pub struct Picker {
    pub filter: String,
    pub state: ListState,
    all: Vec<(u32, String)>,
}

pub enum PickerAction {
    Continue,
    Cancel,
    Choose { pid: u32, name: String },
}

impl Picker {
    pub fn empty() -> Picker {
        Picker {
            filter: String::new(),
            state: ListState::default(),
            all: Vec::new(),
        }
    }

    pub fn open() -> Picker {
        let mut picker = Picker {
            all: list_processes(),
            ..Picker::empty()
        };
        picker.clamp_selection();
        picker
    }

    /// Processes whose name or pid contains the filter text.
    pub fn visible(&self) -> Vec<&(u32, String)> {
        let needle = self.filter.to_lowercase();
        self.all
            .iter()
            .filter(|(pid, name)| {
                needle.is_empty()
                    || name.to_lowercase().contains(&needle)
                    || pid.to_string().contains(&needle)
            })
            .collect()
    }

    pub fn on_key(&mut self, key: KeyEvent) -> PickerAction {
        match key.code {
            KeyCode::Esc => return PickerAction::Cancel,
            KeyCode::Enter => {
                if let Some((pid, name)) = self.chosen() {
                    return PickerAction::Choose { pid, name };
                }
            }
            KeyCode::Up => self.move_selection(-1),
            KeyCode::Down => self.move_selection(1),
            KeyCode::PageUp => self.move_selection(-PAGE),
            KeyCode::PageDown => self.move_selection(PAGE),
            _ => self.edit_filter(key),
        }
        PickerAction::Continue
    }

    fn chosen(&self) -> Option<(u32, String)> {
        let index = self.state.selected()?;
        self.visible()
            .get(index)
            .map(|(pid, name)| (*pid, name.clone()))
    }

    fn edit_filter(&mut self, key: KeyEvent) {
        if edit_line(&mut self.filter, key) {
            self.state.select(Some(0));
            self.clamp_selection();
        }
    }

    fn move_selection(&mut self, delta: isize) {
        let count = self.visible().len();
        if count == 0 {
            return;
        }
        let current = self.state.selected().unwrap_or(0).cast_signed();
        self.state.select(Some(
            (current + delta)
                .clamp(0, count.cast_signed() - 1)
                .cast_unsigned(),
        ));
    }

    fn clamp_selection(&mut self) {
        let count = self.visible().len();
        let selected = self
            .state
            .selected()
            .unwrap_or(0)
            .min(count.saturating_sub(1));
        self.state.select((count > 0).then_some(selected));
    }
}

impl App {
    pub(super) fn open_picker(&mut self) {
        self.picker = Picker::open();
        self.mode = Mode::Picker;
    }

    pub(super) fn on_picker_key(&mut self, key: KeyEvent) {
        match self.picker.on_key(key) {
            PickerAction::Continue => {}
            PickerAction::Cancel => self.mode = Mode::Normal,
            PickerAction::Choose { pid, name } => self.attach_chosen(pid, name),
        }
    }

    fn attach_chosen(&mut self, pid: u32, name: String) {
        if self.is_busy() {
            return self.say(Level::Warn, "scanmem is busy; try again in a moment");
        }
        self.mode = Mode::Normal;
        self.attach(pid, name);
    }
}

/// Every process except threads and ourselves, sorted by name.
fn list_processes() -> Vec<(u32, String)> {
    let mut system = System::new();
    system.refresh_processes(ProcessesToUpdate::All, true);
    let me = std::process::id();
    let mut processes: Vec<(u32, String)> = system
        .processes()
        .iter()
        .filter(|(_, process)| process.thread_kind().is_none())
        .map(|(pid, process)| (pid.as_u32(), printable(&process.name().to_string_lossy())))
        .filter(|(pid, name)| *pid != me && !name.is_empty())
        .collect();
    processes.sort_by_cached_key(|(pid, name)| (name.to_lowercase(), *pid));
    processes
}

/// Process names are arbitrary bytes; control characters would corrupt the terminal.
fn printable(name: &str) -> String {
    name.chars()
        .map(|c| if c.is_control() { '?' } else { c })
        .collect()
}
