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
    Choose {
        pid: u32,
        name: String,
    },
    /// Enter asked for something that cannot be attached; say why.
    Problem(String),
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
    ///
    /// A typed pid that matches a process exactly is listed first, so the
    /// highlighted row is the one Enter will attach to.
    pub fn visible(&self) -> Vec<&(u32, String)> {
        let needle = self.filter.to_lowercase();
        let mut rows: Vec<&(u32, String)> = self
            .all
            .iter()
            .filter(|(pid, name)| {
                needle.is_empty()
                    || name.to_lowercase().contains(&needle)
                    || pid.to_string().contains(&needle)
            })
            .collect();
        if let Some(pid) = parsed_pid(&self.filter)
            && let Some(index) = rows.iter().position(|(other, _)| *other == pid)
        {
            let row = rows.remove(index);
            rows.insert(0, row);
        }
        rows
    }

    pub fn on_key(&mut self, key: KeyEvent) -> PickerAction {
        match key.code {
            KeyCode::Esc => return PickerAction::Cancel,
            KeyCode::Enter => return self.enter(),
            KeyCode::Up => self.move_selection(-1),
            KeyCode::Down => self.move_selection(1),
            KeyCode::PageUp => self.move_selection(-PAGE),
            KeyCode::PageDown => self.move_selection(PAGE),
            _ => self.edit_filter(key),
        }
        PickerAction::Continue
    }

    /// Enter attaches the highlighted row. With nothing highlighted, a typed
    /// pid is used directly, which also reaches processes the list does not
    /// show (for example one that started after the picker opened).
    fn enter(&self) -> PickerAction {
        if let Some((pid, name)) = self.selected() {
            return PickerAction::Choose { pid, name };
        }
        let Some(pid) = parsed_pid(&self.filter) else {
            return PickerAction::Continue;
        };
        if pid == std::process::id() {
            return PickerAction::Problem("That is this program's own pid".to_string());
        }
        self.exact_name(pid).map_or_else(
            || PickerAction::Problem(format!("No process with pid {pid}")),
            |name| PickerAction::Choose { pid, name },
        )
    }

    fn selected(&self) -> Option<(u32, String)> {
        let index = self.state.selected()?;
        self.visible()
            .get(index)
            .map(|(pid, name)| (*pid, name.clone()))
    }

    /// The name listed for `pid`, or its `/proc` name if it is not listed.
    fn exact_name(&self, pid: u32) -> Option<String> {
        self.all
            .iter()
            .find(|(other, _)| *other == pid)
            .map(|(_, name)| name.clone())
            .or_else(|| comm_name(pid))
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
            PickerAction::Problem(message) => self.say(Level::Warn, message),
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
        .map(|(pid, process)| {
            let pid = pid.as_u32();
            let name = printable(process.name().to_string_lossy().trim());
            // Wine/Proton processes often have no usable name; keep them in
            // the list anyway so their pid can be searched for.
            let name = if name.is_empty() {
                comm_name(pid).unwrap_or_else(|| "(no name)".to_string())
            } else {
                name
            };
            (pid, name)
        })
        .filter(|(pid, _)| *pid != me)
        .collect();
    processes.sort_by_cached_key(|(pid, name)| (name.to_lowercase(), *pid));
    processes
}

/// A filter that is nothing but digits is read as a pid.
fn parsed_pid(filter: &str) -> Option<u32> {
    filter.trim().parse().ok()
}

/// The name from `/proc/<pid>/comm`, if the pid is alive and readable.
fn comm_name(pid: u32) -> Option<String> {
    let raw = std::fs::read(format!("/proc/{pid}/comm")).ok()?;
    let name = printable(String::from_utf8_lossy(&raw).trim());
    (!name.is_empty()).then_some(name)
}

/// Process names are arbitrary bytes; control characters would corrupt the terminal.
fn printable(name: &str) -> String {
    name.chars()
        .map(|c| if c.is_control() { '?' } else { c })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use ratatui::crossterm::event::KeyModifiers;

    fn picker_with(rows: &[(u32, &str)]) -> Picker {
        Picker {
            filter: String::new(),
            state: ListState::default(),
            all: rows
                .iter()
                .map(|(pid, name)| (*pid, (*name).to_string()))
                .collect(),
        }
    }

    fn enter(picker: &mut Picker) -> PickerAction {
        picker.on_key(KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE))
    }

    #[test]
    fn the_filter_matches_pids_as_well_as_names() {
        let picker = picker_with(&[(100, "bash"), (1234, "game"), (55, "wine")]);
        let mut filter = picker;
        filter.filter = "123".to_string();
        let pids: Vec<u32> = filter.visible().iter().map(|(pid, _)| *pid).collect();
        assert_eq!(pids, vec![1234]);
    }

    #[test]
    fn an_exact_pid_is_listed_first() {
        let mut picker = picker_with(&[(1234, "first"), (99, "1234 helper"), (5, "other")]);
        picker.filter = "1234".to_string();
        let pids: Vec<u32> = picker.visible().iter().map(|(pid, _)| *pid).collect();
        assert_eq!(pids, vec![1234, 99]);
    }

    #[test]
    fn enter_chooses_the_highlighted_row() {
        let mut picker = picker_with(&[(1234, "alpha"), (12345, "beta")]);
        picker.filter = "1234".to_string();
        picker.state.select(Some(1));
        let PickerAction::Choose { pid, name } = enter(&mut picker) else {
            panic!("no choice");
        };
        assert_eq!((pid, name.as_str()), (12345, "beta"));
    }

    #[test]
    fn enter_accepts_a_typed_pid_without_a_matching_row() {
        let mut picker = picker_with(&[(7000, "game")]);
        // The spaces keep the pid from matching the row as a substring, so
        // this can only succeed through the typed-pid fallback.
        picker.filter = " 7000 ".to_string();
        let PickerAction::Choose { pid, name } = enter(&mut picker) else {
            panic!("no choice");
        };
        assert_eq!((pid, name.as_str()), (7000, "game"));
    }

    #[test]
    fn enter_reports_a_pid_that_is_not_running() {
        let mut picker = {
            let mut picker = picker_with(&[(100, "bash")]);
            picker.filter = u32::MAX.to_string();
            picker
        };
        let PickerAction::Problem(message) = enter(&mut picker) else {
            panic!("expected a problem");
        };
        assert!(message.contains(&u32::MAX.to_string()));
    }

    #[test]
    fn enter_refuses_this_programs_own_pid() {
        let mut picker = {
            let mut picker = picker_with(&[(100, "bash")]);
            picker.filter = std::process::id().to_string();
            picker
        };
        assert!(matches!(enter(&mut picker), PickerAction::Problem(_)));
    }
}
