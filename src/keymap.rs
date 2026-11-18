//! Every normal-mode key binding, defined once.
//!
//! Key handling, the hint bar and the help popup are all generated from
//! `BINDINGS`, so they cannot drift apart.

use crate::app::{Focus, Tab};
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
    EditLabel,
    EditType,
    ReorderDown,
    ReorderUp,
    RemoveSaved,
    AddAddress,
    SwitchPane,
    SwitchToMemory,
    SwitchToScripts,
    ToggleScript,
    EditScript,
    ImportScript,
    NewScript,
    DelistScript,
    DeleteScriptFile,
    ReloadScript,
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
        matches!(
            self,
            Action::PickProcess | Action::StartScan | Action::NewScan | Action::CycleType
        )
    }

    /// Some general-looking keys only make sense on one tab.
    fn works_on(self, tab: Tab) -> bool {
        match self {
            Action::AddAddress | Action::SwitchPane => tab == Tab::Memory,
            Action::ToggleScript
            | Action::EditScript
            | Action::ImportScript
            | Action::NewScript
            | Action::DelistScript
            | Action::DeleteScriptFile
            | Action::ReloadScript => tab == Tab::Scripts,
            _ => true,
        }
    }
}

/// Which pane a binding belongs to; also the grouping of the help popup.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Section {
    Scanning,
    Results,
    Saved,
    Scripts,
    General,
}

impl Section {
    const ALL: [Section; 5] = [
        Section::Scanning,
        Section::Results,
        Section::Saved,
        Section::Scripts,
        Section::General,
    ];

    fn title(self) -> &'static str {
        match self {
            Section::Scanning => "Scanning",
            Section::Results => "Scan results",
            Section::Saved => "Saved addresses",
            Section::Scripts => "Scripts",
            Section::General => "General",
        }
    }

    fn works_in(self, tab: Tab, focus: Focus) -> bool {
        match self {
            Section::Results => tab == Tab::Memory && focus == Focus::Results,
            Section::Saved => tab == Tab::Memory && focus == Focus::Saved,
            Section::Scanning => tab == Tab::Memory,
            Section::Scripts => tab == Tab::Scripts,
            Section::General => true,
        }
    }

    /// Scanning keys work everywhere but are only advertised next to the results.
    fn hinted_in(self, tab: Tab, focus: Focus) -> bool {
        match self {
            Section::Scanning => tab == Tab::Memory && focus == Focus::Results,
            _ => self.works_in(tab, focus),
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
        label: "s or /", hint: "s scan", help: "enter a scan: a value (100, 3.5), > N, < N, =, !=, +, -, snapshot, or `range <label|addr> <offset>`",
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
        section: Saved, action: EditLabel, keys: &[ch('e')],
        label: "e", hint: "e label", help: "set the label (letters, digits and _); use it at the scan prompt as `range <label> <offset>`",
    },
    Binding {
        section: Saved, action: EditType, keys: &[ch('T')],
        label: "T", hint: "T type", help: "change the type of the selected address (drops its saved value, if any)",
    },
    Binding {
        section: Saved, action: ReorderDown, keys: &[ch('J')],
        label: "J", hint: "J down", help: "move the selected row down the list",
    },
    Binding {
        section: Saved, action: ReorderUp, keys: &[ch('K')],
        label: "K", hint: "K up", help: "move the selected row up the list",
    },
    Binding {
        section: Saved, action: RemoveSaved, keys: &[ch('d'), KeyCode::Delete],
        label: "d", hint: "d delete", help: "remove from the list",
    },
    Binding {
        section: Scripts, action: ToggleScript, keys: &[ch(' ')],
        label: "Space", hint: "Space run/stop", help: "start or stop the selected script (all scripts start off)",
    },
    Binding {
        section: Scripts, action: EditScript, keys: &[KeyCode::Enter],
        label: "Enter", hint: "Enter edit", help: "open the selected script in $EDITOR (vi when EDITOR is unset)",
    },
    Binding {
        section: Scripts, action: ImportScript, keys: &[ch('i')],
        label: "i", hint: "i import", help: "import a .lua file, or every .lua directly inside a folder",
    },
    Binding {
        section: Scripts, action: NewScript, keys: &[ch('n')],
        label: "n", hint: "n new", help: "create a script inside the scripts folder (a relative path, .lua added)",
    },
    Binding {
        section: Scripts, action: DelistScript, keys: &[ch('d')],
        label: "d", hint: "d delist", help: "remove the selected script from the list; the file stays on disk",
    },
    Binding {
        section: Scripts, action: DeleteScriptFile, keys: &[ch('D')],
        label: "D", hint: "D delete", help: "delete the selected script's file (only inside the scripts folder)",
    },
    Binding {
        section: Scripts, action: ReloadScript, keys: &[ch('r')],
        label: "r", hint: "r reload", help: "re-read the selected file from disk, restarting it when it is running",
    },
    Binding {
        section: General, action: AddAddress, keys: &[ch('A')],
        label: "A", hint: "A add addr", help: "add an address by hand: 7ffc8dc5328c int32, or `label+0x10` / `0xaddr-0x1140`",
    },
    Binding {
        section: General, action: SwitchPane, keys: &[KeyCode::Tab, KeyCode::BackTab],
        label: "Tab", hint: "Tab pane", help: "switch pane (memory tab)",
    },
    Binding {
        section: General, action: SwitchToMemory, keys: &[ch('1')],
        label: "1 2", hint: "1/2 tab", help: "switch between the memory and scripts tabs",
    },
    Binding {
        section: General, action: SwitchToScripts, keys: &[ch('2')],
        label: "", hint: "", help: "",
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
        label: "PgUp PgDn", hint: "", help: "move by ten rows; scrolls the script preview on the scripts tab",
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

pub fn action_for(key: KeyCode, tab: Tab, focus: Focus) -> Option<Action> {
    BINDINGS
        .iter()
        .find(|binding| {
            binding.section.works_in(tab, focus)
                && binding.action.works_on(tab)
                && binding.keys.contains(&key)
        })
        .map(|binding| binding.action)
}

/// The one-line key summary under the panes.
pub fn hint_line(tab: Tab, focus: Focus) -> String {
    BINDINGS
        .iter()
        .filter(|binding| {
            !binding.hint.is_empty()
                && binding.action.works_on(tab)
                && binding.section.hinted_in(tab, focus)
        })
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
        for binding in BINDINGS
            .iter()
            .filter(|b| b.section == section && !b.help.is_empty())
        {
            use std::fmt::Write;
            let _ = writeln!(text, "  {:<12} {}", binding.label, binding.help);
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
        for tab in [Tab::Memory, Tab::Scripts] {
            for focus in PANES {
                let mut seen: Vec<KeyCode> = Vec::new();
                for binding in BINDINGS.iter().filter(|b| b.section.works_in(tab, focus)) {
                    for key in binding.keys {
                        assert!(
                            !seen.contains(key),
                            "{key:?} is bound twice in {tab:?}/{focus:?}"
                        );
                        seen.push(*key);
                    }
                }
            }
        }
    }

    #[test]
    fn enter_depends_on_the_pane() {
        assert_eq!(
            action_for(KeyCode::Enter, Tab::Memory, Focus::Results),
            Some(SaveResult)
        );
        assert_eq!(
            action_for(KeyCode::Enter, Tab::Memory, Focus::Saved),
            Some(SetValue)
        );
        assert_eq!(
            action_for(KeyCode::Enter, Tab::Scripts, Focus::Results),
            Some(EditScript)
        );
    }

    #[test]
    fn pane_keys_stay_in_their_pane() {
        assert_eq!(action_for(ch('w'), Tab::Memory, Focus::Results), None);
        assert_eq!(action_for(ch('a'), Tab::Memory, Focus::Saved), None);
        assert_eq!(
            action_for(ch(' '), Tab::Memory, Focus::Saved),
            Some(ToggleFreeze)
        );
    }

    #[test]
    fn scanning_keys_work_from_either_pane() {
        for focus in PANES {
            assert_eq!(action_for(ch('s'), Tab::Memory, focus), Some(StartScan));
            assert_eq!(action_for(ch('/'), Tab::Memory, focus), Some(StartScan));
            assert_eq!(action_for(ch('q'), Tab::Memory, focus), Some(Quit));
        }
    }

    #[test]
    fn script_keys_only_work_on_the_scripts_tab() {
        assert_eq!(
            action_for(ch(' '), Tab::Scripts, Focus::Results),
            Some(ToggleScript)
        );
        assert_eq!(action_for(ch('s'), Tab::Scripts, Focus::Results), None);
        assert_eq!(action_for(ch('w'), Tab::Scripts, Focus::Results), None);
        assert_eq!(
            action_for(ch('i'), Tab::Scripts, Focus::Results),
            Some(ImportScript)
        );
        assert_eq!(action_for(ch('i'), Tab::Memory, Focus::Results), None);
    }

    #[test]
    fn tabs_are_switched_by_their_digits() {
        for focus in PANES {
            assert_eq!(
                action_for(ch('1'), Tab::Scripts, focus),
                Some(SwitchToMemory)
            );
            assert_eq!(
                action_for(ch('2'), Tab::Memory, focus),
                Some(SwitchToScripts)
            );
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
        let results = hint_line(Tab::Memory, Focus::Results);
        assert!(results.contains("s scan") && results.contains("a/Enter save"));
        assert!(!results.contains("Space freeze"));

        let saved = hint_line(Tab::Memory, Focus::Saved);
        assert!(saved.contains("Space freeze") && saved.contains("w/Enter set value"));
        assert!(!saved.contains("s scan"));
        assert!(saved.ends_with("q quit"));
    }

    #[test]
    fn script_hints_replace_memory_hints() {
        let scripts = hint_line(Tab::Scripts, Focus::Results);
        assert!(scripts.contains("Space run/stop"));
        assert!(scripts.contains("i import"));
        assert!(!scripts.contains("s scan"));
        assert!(!scripts.contains("Space freeze"));
        assert!(!scripts.contains("A add addr"));
        assert!(!scripts.contains("Tab pane"));
    }

    #[test]
    fn help_lists_every_section_and_skips_hidden_rows() {
        let help = help_text();
        for section in Section::ALL {
            assert!(help.contains(section.title()));
        }
        assert!(help.contains("pick the target process"));
        assert!(help.contains("start or stop the selected script"));
        assert!(!help.contains("\n  \n"));
    }
}
