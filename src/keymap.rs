//! Every normal-mode key binding, defined once.
//!
//! Key handling, the hint bar and the help popup are all generated from
//! `BINDINGS`, so they cannot drift apart.

use crate::app::Focus;
use ratatui::crossterm::event::KeyCode;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Action {
    PickProcess,
    StartScan,
    NewScan,
    CycleType,
    StopScan,
    SaveResult,
    SetValue,
    ToggleFreeze,
    EditDescription,
    RemoveSaved,
    AddAddress,
    SwitchPane,
    MoveUp,
    MoveDown,
    MovePageUp,
    MovePageDown,
    JumpToStart,
    JumpToEnd,
    Help,
    Quit,
}

impl Action {
    /// Scanning commands are ignored while scanmem is still busy.
    pub fn needs_idle_backend(self) -> bool {
        matches!(self, Action::PickProcess | Action::StartScan | Action::NewScan | Action::CycleType)
    }
}

/// Which pane a binding belongs to; also the grouping of the help popup.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Section {
    Scanning,
    Results,
    Saved,
    General,
}

impl Section {
    const ALL: [Section; 4] = [Section::Scanning, Section::Results, Section::Saved, Section::General];

    fn title(self) -> &'static str {
        match self {
            Section::Scanning => "Scanning",
            Section::Results => "Scan results",
            Section::Saved => "Saved addresses",
            Section::General => "General",
        }
    }

    fn works_in(self, focus: Focus) -> bool {
        match self {
            Section::Results => focus == Focus::Results,
            Section::Saved => focus == Focus::Saved,
            Section::Scanning | Section::General => true,
        }
    }

    /// Scanning keys work everywhere but are only advertised next to the results.
    fn hinted_in(self, focus: Focus) -> bool {
        match self {
            Section::Scanning => focus == Focus::Results,
            _ => self.works_in(focus),
        }
    }
}

struct Binding {
    section: Section,
    action: Action,
    keys: &'static [KeyCode],
    /// Keys as written in the help popup.
    label: &'static str,
    /// Text for the hint bar; empty keeps the binding off the bar.
    hint: &'static str,
    /// Text for the help popup; empty keeps the binding out of the popup
    /// (a sibling row already documents its key).
    help: &'static str,
}

const fn ch(c: char) -> KeyCode {
    KeyCode::Char(c)
}

use Action::*;
use Section::*;

#[rustfmt::skip]
static BINDINGS: &[Binding] = &[
    Binding {
        section: Scanning, action: PickProcess, keys: &[ch('p')],
        label: "p", hint: "p process", help: "pick the target process",
    },
    Binding {
        section: Scanning, action: StartScan, keys: &[ch('s'), ch('/')],
        label: "s or /", hint: "s scan", help: "enter a scan: a value (100, 3.5), > N, < N, =, !=, +, -, snapshot",
    },
    Binding {
        section: Scanning, action: NewScan, keys: &[ch('n')],
        label: "n", hint: "n new", help: "new scan (reset matches)",
    },
    Binding {
        section: Scanning, action: CycleType, keys: &[ch('t')],
        label: "t", hint: "t type", help: "cycle value type (int8/16/32/64, float32/64)",
    },
    Binding {
        section: Scanning, action: StopScan, keys: &[KeyCode::Esc],
        label: "Esc", hint: "", help: "stop a running scan",
    },
    Binding {
        section: Results, action: SaveResult, keys: &[ch('a'), KeyCode::Enter],
        label: "a/Enter", hint: "a/Enter save", help: "save the selected address to the list on the right",
    },
    Binding {
        section: Saved, action: SetValue, keys: &[ch('w'), KeyCode::Enter],
        label: "w/Enter", hint: "w/Enter set value", help: "write a value into the process (adds a [ ] checkbox)",
    },
    Binding {
        section: Saved, action: ToggleFreeze, keys: &[ch(' ')],
        label: "Space", hint: "Space freeze", help: "tick/untick the checkbox; while [x] the value is re-written continuously",
    },
    Binding {
        section: Saved, action: EditDescription, keys: &[ch('e')],
        label: "e", hint: "e name", help: "edit the description",
    },
    Binding {
        section: Saved, action: RemoveSaved, keys: &[ch('d'), KeyCode::Delete],
        label: "d", hint: "d delete", help: "remove from the list",
    },
    Binding {
        section: General, action: AddAddress, keys: &[ch('A')],
        label: "A", hint: "A add addr", help: "add an address by hand: 7ffc8dc5328c int32",
    },
    Binding {
        section: General, action: SwitchPane, keys: &[KeyCode::Tab, KeyCode::BackTab],
        label: "Tab", hint: "Tab pane", help: "switch pane",
    },
    Binding {
        section: General, action: MoveUp, keys: &[KeyCode::Up, ch('k')],
        label: "↑ ↓ j k", hint: "", help: "move the selection",
    },
    Binding {
        section: General, action: MoveDown, keys: &[KeyCode::Down, ch('j')],
        label: "", hint: "", help: "",
    },
    Binding {
        section: General, action: MovePageUp, keys: &[KeyCode::PageUp],
        label: "PgUp PgDn", hint: "", help: "move by ten rows",
    },
    Binding {
        section: General, action: MovePageDown, keys: &[KeyCode::PageDown],
        label: "", hint: "", help: "",
    },
    Binding {
        section: General, action: JumpToStart, keys: &[KeyCode::Home, ch('g')],
        label: "g G", hint: "", help: "jump to the first / last row",
    },
    Binding {
        section: General, action: JumpToEnd, keys: &[KeyCode::End, ch('G')],
        label: "", hint: "", help: "",
    },
    Binding {
        section: General, action: Help, keys: &[ch('?'), KeyCode::F(1)],
        label: "? or F1", hint: "? help", help: "show this help",
    },
    Binding {
        section: General, action: Quit, keys: &[ch('q')],
        label: "q", hint: "q quit", help: "quit (Ctrl-C works everywhere)",
    },
];

pub fn action_for(key: KeyCode, focus: Focus) -> Option<Action> {
    BINDINGS
        .iter()
        .find(|binding| binding.section.works_in(focus) && binding.keys.contains(&key))
        .map(|binding| binding.action)
}

/// The one-line key summary under the panes.
pub fn hint_line(focus: Focus) -> String {
    BINDINGS
        .iter()
        .filter(|binding| !binding.hint.is_empty() && binding.section.hinted_in(focus))
        .map(|binding| binding.hint)
        .collect::<Vec<_>>()
        .join("  ")
}

/// The body of the help popup.
pub fn help_text() -> String {
    let mut text = String::new();
    for section in Section::ALL {
        if !text.is_empty() {
            text.push('\n');
        }
        text.push_str(section.title());
        text.push('\n');
        for binding in BINDINGS.iter().filter(|b| b.section == section && !b.help.is_empty()) {
            text.push_str(&format!("  {:<12} {}\n", binding.label, binding.help));
        }
    }
    text
}

#[cfg(test)]
mod tests {
    use super::*;

    const PANES: [Focus; 2] = [Focus::Results, Focus::Saved];

    #[test]
    fn no_key_is_bound_twice_within_a_pane() {
        for focus in PANES {
            let mut seen: Vec<KeyCode> = Vec::new();
            for binding in BINDINGS.iter().filter(|b| b.section.works_in(focus)) {
                for key in binding.keys {
                    assert!(!seen.contains(key), "{key:?} is bound twice in {focus:?}");
                    seen.push(*key);
                }
            }
        }
    }

    #[test]
    fn enter_depends_on_the_pane() {
        assert_eq!(action_for(KeyCode::Enter, Focus::Results), Some(SaveResult));
        assert_eq!(action_for(KeyCode::Enter, Focus::Saved), Some(SetValue));
    }

    #[test]
    fn pane_keys_stay_in_their_pane() {
        assert_eq!(action_for(ch('w'), Focus::Results), None);
        assert_eq!(action_for(ch('a'), Focus::Saved), None);
        assert_eq!(action_for(ch(' '), Focus::Saved), Some(ToggleFreeze));
    }

    #[test]
    fn scanning_keys_work_from_either_pane() {
        for focus in PANES {
            assert_eq!(action_for(ch('s'), focus), Some(StartScan));
            assert_eq!(action_for(ch('/'), focus), Some(StartScan));
            assert_eq!(action_for(ch('q'), focus), Some(Quit));
        }
    }

    #[test]
    fn only_scanning_commands_wait_for_an_idle_backend() {
        assert!(StartScan.needs_idle_backend());
        assert!(!Quit.needs_idle_backend());
        assert!(!StopScan.needs_idle_backend());
    }

    #[test]
    fn hint_bar_follows_the_focused_pane() {
        let results = hint_line(Focus::Results);
        assert!(results.contains("s scan") && results.contains("a/Enter save"));
        assert!(!results.contains("Space freeze"));

        let saved = hint_line(Focus::Saved);
        assert!(saved.contains("Space freeze") && saved.contains("w/Enter set value"));
        assert!(!saved.contains("s scan"));
        assert!(saved.ends_with("q quit"));
    }

    #[test]
    fn help_lists_every_section_and_skips_hidden_rows() {
        let help = help_text();
        for section in Section::ALL {
            assert!(help.contains(section.title()));
        }
        assert!(help.contains("pick the target process"));
        assert!(!help.contains("\n  \n"));
    }
}
