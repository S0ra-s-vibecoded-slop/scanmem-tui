//! The saved-address list and the commands that act on it.

use super::move_table_selection;
use super::{App, InputKind, Level};
use crate::datatype::DataType;
use crate::memio::MemIo;
use ratatui::widgets::TableState;

pub struct Saved {
    pub addr: u64,
    pub ty: DataType,
    /// Short name for the address; usable as `range <label> <offset>`.
    pub label: String,
    pub live: Option<String>,
    /// Bytes of the last value we wrote. `Some` is what makes the checkbox appear.
    pub set_value: Option<Vec<u8>>,
    pub frozen: bool,
}

impl Saved {
    fn new(addr: u64, ty: DataType) -> Saved {
        Saved {
            addr,
            ty,
            label: String::new(),
            live: None,
            set_value: None,
            frozen: false,
        }
    }

    fn freeze_message(&self) -> String {
        if self.frozen {
            let held = self.set_value.as_deref().unwrap_or_default();
            format!(
                "Freezing 0x{:x} at {}",
                self.addr,
                self.ty.format_bytes(held)
            )
        } else {
            format!("Unfroze 0x{:x}", self.addr)
        }
    }
}

pub struct SavedList {
    pub items: Vec<Saved>,
    pub state: TableState,
}

impl SavedList {
    pub fn new() -> SavedList {
        SavedList {
            items: Vec::new(),
            state: TableState::default(),
        }
    }

    pub fn selected(&self) -> Option<usize> {
        self.state.selected().filter(|i| *i < self.items.len())
    }

    /// Adds the address and selects it; false when it was already listed.
    pub fn add(&mut self, addr: u64, ty: DataType) -> bool {
        let existing = self.items.iter().position(|s| s.addr == addr && s.ty == ty);
        if let Some(index) = existing {
            self.state.select(Some(index));
            return false;
        }
        self.items.push(Saved::new(addr, ty));
        self.state.select(Some(self.items.len() - 1));
        true
    }

    pub fn remove_selected(&mut self) -> bool {
        let Some(index) = self.selected() else {
            return false;
        };
        self.items.remove(index);
        self.state
            .select((!self.items.is_empty()).then(|| index.min(self.items.len() - 1)));
        true
    }

    pub fn move_selection(&mut self, delta: isize) {
        move_table_selection(&mut self.state, self.items.len(), delta);
    }

    /// Moves the selected row one slot down (`1`) or up (`-1`), keeping the
    /// selection on the row; false at the ends of the list.
    pub fn reorder(&mut self, delta: isize) -> bool {
        let Some(index) = self.selected() else {
            return false;
        };
        let target = index.cast_signed() + delta;
        if target < 0 || target >= self.items.len().cast_signed() {
            return false;
        }
        let target = target.cast_unsigned();
        self.items.swap(index, target);
        self.state.select(Some(target));
        true
    }

    pub fn frozen_count(&self) -> usize {
        self.items.iter().filter(|s| s.frozen).count()
    }

    /// The (address, bytes) pairs the freezer should keep pinned.
    pub fn freeze_targets(&self) -> Vec<(u64, Vec<u8>)> {
        self.items
            .iter()
            .filter(|s| s.frozen)
            .filter_map(|s| s.set_value.as_ref().map(|value| (s.addr, value.clone())))
            .collect()
    }

    /// Unfreezes everything and forgets the written values.
    pub fn release_all(&mut self) {
        for item in &mut self.items {
            item.frozen = false;
            item.set_value = None;
        }
    }

    /// Re-reads every entry; says whether any value changed.
    pub fn refresh_live(&mut self, memory: Option<&MemIo>) -> bool {
        let mut changed = false;
        for item in &mut self.items {
            let fresh = memory.and_then(|mem| mem.read_as(item.addr, item.ty));
            changed |= fresh != item.live;
            item.live = fresh;
        }
        changed
    }

    /// The address labelled `name` (case-insensitive), if there is one.
    pub fn labelled(&self, name: &str) -> Option<u64> {
        self.items
            .iter()
            .find(|item| item.label.eq_ignore_ascii_case(name))
            .map(|item| item.addr)
    }
}

impl App {
    pub(super) fn save_selected_result(&mut self) {
        let Some(row) = self.results.selected() else {
            return;
        };
        let (addr, ty) = (row.m.addr, row.ty);
        self.add_saved(addr, ty);
    }

    pub(super) fn add_saved(&mut self, addr: u64, ty: DataType) {
        if !self.saved.add(addr, ty) {
            return self.say(Level::Info, format!("0x{addr:x} is already in the list"));
        }
        self.refresh_live();
        self.sync_script_labels();
        self.say(
            Level::Ok,
            format!(
                "Saved 0x{addr:x} ({}). Tab to the list, then w to set a value.",
                ty.scanmem_name()
            ),
        );
    }

    pub(super) fn begin_set_value(&mut self) {
        if let Some(index) = self.saved.selected() {
            self.begin_input(InputKind::SetValue(index), String::new());
        }
    }

    pub(super) fn begin_label(&mut self) {
        if let Some(index) = self.saved.selected() {
            let current = self.saved.items[index].label.clone();
            self.begin_input(InputKind::Label(index), current);
        }
    }

    /// Applies a typed label; empty clears it, anything with characters
    /// outside letters, digits and `_` is rejected so labels stay single words.
    pub(super) fn apply_label(&mut self, index: usize, text: &str) {
        let Some(item) = self.saved.items.get_mut(index) else {
            return;
        };
        let addr = item.addr;
        if text.is_empty() {
            item.label.clear();
            self.sync_script_labels();
            return self.say(Level::Info, "Label cleared");
        }
        if !text.chars().all(|c| c.is_ascii_alphanumeric() || c == '_') {
            return self.say(
                Level::Error,
                "labels are letters, digits and _ only, no spaces",
            );
        }
        item.label = text.to_string();
        self.sync_script_labels();
        self.say(Level::Ok, format!("Labelled 0x{addr:x} as `{text}`"));
    }

    pub(super) fn begin_edit_type(&mut self) {
        if let Some(index) = self.saved.selected() {
            let current = self.saved.items[index].ty.scanmem_name();
            self.begin_input(InputKind::EditType(index), current.to_string());
        }
    }

    /// Applies a typed type change. The old saved value was written in the
    /// previous layout, so it (and any freeze) is dropped on a real change.
    pub(super) fn apply_saved_type(&mut self, index: usize, text: &str) {
        if self.is_busy() {
            return self.say(Level::Warn, "scanmem is busy");
        }
        let Some(item) = self.saved.items.get_mut(index) else {
            return;
        };
        let addr = item.addr;
        let ty = match text.trim().parse::<DataType>() {
            Ok(ty) => ty,
            Err(reason) => return self.say(Level::Error, reason),
        };
        if ty == item.ty {
            return self.say(
                Level::Info,
                format!("0x{addr:x} is already {}", ty.scanmem_name()),
            );
        }
        let was_frozen = item.frozen;
        item.ty = ty;
        item.set_value = None;
        item.frozen = false;
        if was_frozen {
            self.sync_freezer();
        }
        self.refresh_live();
        self.sync_script_labels();
        self.say(
            Level::Ok,
            format!("0x{addr:x} is now {}", ty.scanmem_name()),
        );
    }

    pub(super) fn toggle_freeze(&mut self) {
        let Some(index) = self.saved.selected() else {
            return;
        };
        if self.saved.items[index].set_value.is_none() {
            return self.say(
                Level::Warn,
                "Set a value first (w); the checkbox appears once there is one to hold.",
            );
        }
        let item = &mut self.saved.items[index];
        item.frozen = !item.frozen;
        let message = item.freeze_message();
        self.sync_freezer();
        self.sync_script_labels();
        self.say(Level::Ok, message);
    }

    pub(super) fn remove_selected(&mut self) {
        if self.saved.remove_selected() {
            self.sync_freezer();
            self.sync_script_labels();
            self.say(Level::Info, "Removed from list");
        }
    }

    /// Moves the selected row one slot down (`1`) or up (`-1`); the selection
    /// travels with it. Nothing happens at the ends of the list.
    pub(super) fn reorder_saved(&mut self, delta: isize) {
        self.saved.reorder(delta);
    }

    pub(super) fn write_saved(&mut self, index: usize, text: &str) {
        let Some(item) = self.saved.items.get(index) else {
            return;
        };
        let (addr, ty) = (item.addr, item.ty);
        let bytes = match ty.parse_value(text) {
            Ok(bytes) => bytes,
            Err(e) => return self.say(Level::Error, e),
        };
        if let Err(reason) = self.write_memory(addr, &bytes) {
            return self.say(Level::Error, reason);
        }
        self.saved.items[index].set_value = Some(bytes);
        if self.saved.items[index].frozen {
            self.sync_freezer(); // keep holding, but at the new value
        }
        self.refresh_live();
        self.say(Level::Ok, format!("Wrote {} to 0x{addr:x}", text.trim()));
    }

    fn write_memory(&self, addr: u64, bytes: &[u8]) -> Result<(), String> {
        let target = self.target.as_ref().ok_or("no process attached")?;
        let memory = target.memory()?;
        memory
            .write(addr, bytes)
            .map_err(|e| format!("write to 0x{addr:x} failed: {e}"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn list_with_addresses(addresses: &[u64]) -> SavedList {
        let mut saved = SavedList::new();
        for addr in addresses {
            saved.add(*addr, DataType::I32);
        }
        saved
    }

    fn addresses(saved: &SavedList) -> Vec<u64> {
        saved.items.iter().map(|s| s.addr).collect()
    }

    #[test]
    fn reorder_moves_the_row_and_the_selection() {
        let mut saved = list_with_addresses(&[0x100, 0x200, 0x300]);
        saved.state.select(Some(0));

        assert!(saved.reorder(1));
        assert_eq!(addresses(&saved), vec![0x200, 0x100, 0x300]);
        assert_eq!(saved.selected(), Some(1)); // followed the row

        assert!(saved.reorder(-1));
        assert_eq!(addresses(&saved), vec![0x100, 0x200, 0x300]);
        assert_eq!(saved.selected(), Some(0));
    }

    #[test]
    fn reorder_stops_at_the_ends() {
        let mut saved = list_with_addresses(&[0x100, 0x200]);

        saved.state.select(Some(0));
        assert!(!saved.reorder(-1));
        assert_eq!(saved.selected(), Some(0));

        saved.state.select(Some(1));
        assert!(!saved.reorder(1));
        assert_eq!(addresses(&saved), vec![0x100, 0x200]);
        assert_eq!(saved.selected(), Some(1));
    }

    #[test]
    fn reorder_without_a_selection_does_nothing() {
        let mut saved = list_with_addresses(&[0x100]);
        assert!(!saved.reorder(1));
        assert_eq!(addresses(&saved), vec![0x100]);
    }
}
