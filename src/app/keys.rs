//! Key presses: which mode handles them, and what each normal-mode action does.

use super::{App, Focus, InputKind, Level, Mode, Tab};
use crate::keymap::{self, Action};
use ratatui::crossterm::event::{KeyCode, KeyEvent, KeyEventKind, KeyModifiers};

const PAGE: isize = 10;
const HELP_PAGE: u16 = 10;
const JUMP_TO_START: isize = isize::MIN / 2;
const JUMP_TO_END: isize = isize::MAX / 2;

impl App {
    pub fn on_key(&mut self, key: KeyEvent) {
        if key.kind != KeyEventKind::Press {
            return;
        }
        self.request_redraw();
        if is_ctrl_c(&key) {
            return self.perform(Action::Quit);
        }
        match self.mode {
            Mode::Normal => self.on_normal_key(key),
            Mode::Input(kind) => self.on_input_key(kind, key),
            Mode::Confirm(confirm) => self.on_confirm_key(confirm, key),
            Mode::Picker => self.on_picker_key(key),
            Mode::Help => self.on_help_key(key),
        }
    }

    /// The help popup scrolls; any other key closes it.
    fn on_help_key(&mut self, key: KeyEvent) {
        match key.code {
            KeyCode::Up | KeyCode::Char('k') => {
                self.help_scroll = self.help_scroll.saturating_sub(1);
            }
            KeyCode::Down | KeyCode::Char('j') => {
                self.help_scroll = self.help_scroll.saturating_add(1);
            }
            KeyCode::PageUp => {
                self.help_scroll = self.help_scroll.saturating_sub(HELP_PAGE);
            }
            KeyCode::PageDown => {
                self.help_scroll = self.help_scroll.saturating_add(HELP_PAGE);
            }
            KeyCode::Home => self.help_scroll = 0,
            KeyCode::End => self.help_scroll = u16::MAX,
            _ => self.mode = Mode::Normal,
        }
    }

    fn on_normal_key(&mut self, key: KeyEvent) {
        if let Some(action) = keymap::action_for(key.code, self.tab, self.focus) {
            self.perform(action);
        }
    }

    fn perform(&mut self, action: Action) {
        if action.needs_idle_backend() && self.is_busy() {
            return;
        }
        match action {
            Action::Quit => self.should_quit = true,
            Action::Help => self.mode = Mode::Help,
            Action::SwitchPane => match self.tab {
                Tab::Memory => self.switch_pane(),
                Tab::Code => self.switch_code_focus(),
                Tab::Scripts => {}
            },
            Action::SwitchToMemory => self.tab = Tab::Memory,
            Action::SwitchToScripts => self.tab = Tab::Scripts,
            Action::SwitchToCode => {
                self.ensure_code();
                self.tab = Tab::Code;
            }
            Action::OpenInCode => self.open_selected_in_code(),
            Action::FindRefs => self.begin_find_refs(),
            Action::GotoCode => self.begin_goto_code(),
            Action::CodeOpen => self.code_open(),
            Action::CodeBack => self.code_back(),
            Action::CodeCancel => self.code_cancel(),
            Action::ToggleBytes => self.toggle_code_bytes(),
            Action::RescanRefs => self.rescan_refs(),
            Action::MoveUp => self.move_selection(-1),
            Action::MoveDown => self.move_selection(1),
            Action::MovePageUp => self.page(-PAGE),
            Action::MovePageDown => self.page(PAGE),
            Action::JumpToStart => self.move_selection(JUMP_TO_START),
            Action::JumpToEnd => self.move_selection(JUMP_TO_END),
            Action::PickProcess => self.open_picker(),
            Action::StartScan => self.begin_scan_input(),
            Action::NewScan => self.start_scan("reset"),
            Action::CycleType => self.cycle_type(),
            Action::StopScan => self.stop_scan(),
            Action::AddAddress => self.begin_input(InputKind::AddAddr, String::new()),
            Action::SaveResult => self.save_selected_result(),
            Action::SetValue => self.begin_set_value(),
            Action::EditLabel => self.begin_label(),
            Action::EditType => self.begin_edit_type(),
            Action::ReorderDown => self.reorder_saved(1),
            Action::ReorderUp => self.reorder_saved(-1),
            Action::ToggleFreeze => self.toggle_freeze(),
            Action::RemoveSaved => self.remove_selected(),
            Action::ToggleScript => self.toggle_script(),
            Action::EditScript => self.edit_script(),
            Action::ImportScript => self.begin_input(InputKind::ImportScript, String::new()),
            Action::NewScript => self.begin_input(InputKind::NewScript, String::new()),
            Action::DelistScript => self.confirm_delist(),
            Action::DeleteScriptFile => self.confirm_delete(),
            Action::ReloadScript => self.reload_script(),
        }
    }

    fn switch_pane(&mut self) {
        self.focus = match self.focus {
            Focus::Results => Focus::Saved,
            Focus::Saved => Focus::Results,
        };
    }

    fn move_selection(&mut self, delta: isize) {
        match self.tab {
            Tab::Scripts => {
                self.scripts.move_selection(delta);
                return;
            }
            Tab::Code => {
                self.code_move(delta);
                return;
            }
            Tab::Memory => {}
        }
        match self.focus {
            Focus::Results => {
                self.results.move_selection(delta);
                self.refresh_live(); // rows that just scrolled into view need values
            }
            Focus::Saved => self.saved.move_selection(delta),
        }
    }

    /// PgUp/PgDn scroll the script preview, or move table selections in memory.
    fn page(&mut self, delta: isize) {
        match self.tab {
            Tab::Scripts => self.scripts.scroll_preview(delta),
            Tab::Code => self.code_move(delta),
            Tab::Memory => self.move_selection(delta),
        }
    }

    /// `x` on a results or saved row: show that address in the Code tab.
    fn open_selected_in_code(&mut self) {
        let addr = match self.focus {
            Focus::Results => self.results.selected().map(|row| row.m.addr),
            Focus::Saved => self
                .saved
                .selected()
                .and_then(|index| self.saved.items.get(index))
                .map(|item| item.addr),
        };
        match addr {
            Some(addr) => self.open_code_at(addr),
            None => self.say(Level::Info, "Select an address first."),
        }
    }

    fn begin_scan_input(&mut self) {
        if self.require_target() {
            self.begin_input(InputKind::Scan, String::new());
        }
    }

    fn stop_scan(&mut self) {
        if let Some(job) = &self.xref_job {
            job.control.cancel();
            self.say(Level::Info, "Stopping the reference scan…");
            return;
        }
        if let Some(job) = &self.range_job {
            job.control.cancel();
            self.say(Level::Info, "Stopping range scan…");
            return;
        }
        if self.is_busy() {
            self.backend.interrupt();
            self.say(Level::Info, "Stopping scan…");
        }
    }
}

/// Backspace and Ctrl-U editing shared by the prompt and the picker filter.
/// Returns whether the key changed the text.
pub(super) fn edit_line(text: &mut String, key: KeyEvent) -> bool {
    let ctrl = key.modifiers.contains(KeyModifiers::CONTROL);
    match key.code {
        KeyCode::Backspace => {
            text.pop();
            true
        }
        KeyCode::Char('u') if ctrl => {
            text.clear();
            true
        }
        KeyCode::Char(c) if !ctrl => {
            text.push(c);
            true
        }
        _ => false,
    }
}

fn is_ctrl_c(key: &KeyEvent) -> bool {
    key.modifiers.contains(KeyModifiers::CONTROL) && key.code == KeyCode::Char('c')
}

#[cfg(test)]
mod tests {
    use super::*;

    fn press(code: KeyCode, modifiers: KeyModifiers) -> KeyEvent {
        KeyEvent::new(code, modifiers)
    }

    #[test]
    fn typing_and_backspace() {
        let mut text = String::new();
        assert!(edit_line(
            &mut text,
            press(KeyCode::Char('h'), KeyModifiers::NONE)
        ));
        assert!(edit_line(
            &mut text,
            press(KeyCode::Char('i'), KeyModifiers::SHIFT)
        ));
        assert_eq!(text, "hi");
        assert!(edit_line(
            &mut text,
            press(KeyCode::Backspace, KeyModifiers::NONE)
        ));
        assert_eq!(text, "h");
    }

    #[test]
    fn ctrl_u_clears_and_other_ctrl_chars_are_ignored() {
        let mut text = String::from("abc");
        assert!(!edit_line(
            &mut text,
            press(KeyCode::Char('x'), KeyModifiers::CONTROL)
        ));
        assert_eq!(text, "abc");
        assert!(edit_line(
            &mut text,
            press(KeyCode::Char('u'), KeyModifiers::CONTROL)
        ));
        assert_eq!(text, "");
    }

    #[test]
    fn non_text_keys_do_not_edit() {
        let mut text = String::from("abc");
        assert!(!edit_line(
            &mut text,
            press(KeyCode::Left, KeyModifiers::NONE)
        ));
        assert_eq!(text, "abc");
    }

    #[test]
    fn ctrl_c_is_recognised() {
        assert!(is_ctrl_c(&press(KeyCode::Char('c'), KeyModifiers::CONTROL)));
        assert!(!is_ctrl_c(&press(KeyCode::Char('c'), KeyModifiers::NONE)));
    }
}
