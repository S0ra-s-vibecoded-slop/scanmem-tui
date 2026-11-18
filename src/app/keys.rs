//! Key presses: which mode handles them, and what each normal-mode action does.

use super::{App, Focus, InputKind, Level, Mode};
use crate::keymap::{self, Action};
use ratatui::crossterm::event::{KeyCode, KeyEvent, KeyEventKind, KeyModifiers};

const PAGE: isize = 10;
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
            Mode::Picker => self.on_picker_key(key),
            Mode::Help => self.mode = Mode::Normal,
        }
    }

    fn on_normal_key(&mut self, key: KeyEvent) {
        if let Some(action) = keymap::action_for(key.code, self.focus) {
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
            Action::SwitchPane => self.switch_pane(),
            Action::MoveUp => self.move_selection(-1),
            Action::MoveDown => self.move_selection(1),
            Action::MovePageUp => self.move_selection(-PAGE),
            Action::MovePageDown => self.move_selection(PAGE),
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
        }
    }

    fn switch_pane(&mut self) {
        self.focus = match self.focus {
            Focus::Results => Focus::Saved,
            Focus::Saved => Focus::Results,
        };
    }

    fn move_selection(&mut self, delta: isize) {
        match self.focus {
            Focus::Results => {
                self.results.move_selection(delta);
                self.refresh_live(); // rows that just scrolled into view need values
            }
            Focus::Saved => self.saved.move_selection(delta),
        }
    }

    fn begin_scan_input(&mut self) {
        if self.require_target() {
            self.begin_input(InputKind::Scan, String::new());
        }
    }

    fn stop_scan(&mut self) {
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
