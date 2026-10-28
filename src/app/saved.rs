//! The saved-address list and the commands that act on it.

use super::move_table_selection;
use super::{App, InputKind, Level};
use crate::datatype::DataType;
use crate::memio::MemIo;
use ratatui::widgets::TableState;

pub struct Saved {
    pub addr: u64,
    pub ty: DataType,
    pub desc: String,
    pub live: Option<String>,
    /// Bytes of the last value we wrote. `Some` is what makes the checkbox appear.
    pub set_value: Option<Vec<u8>>,
    pub frozen: bool,
}

impl Saved {
    fn new(addr: u64, ty: DataType) -> Saved {
        Saved { addr, ty, desc: String::new(), live: None, set_value: None, frozen: false }
    }

    fn freeze_message(&self) -> String {
        if self.frozen {
            let held = self.set_value.as_deref().unwrap_or_default();
            format!("Freezing 0x{:x} at {}", self.addr, self.ty.format_bytes(held))
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
        SavedList { items: Vec::new(), state: TableState::default() }
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
        let Some(index) = self.selected() else { return false };
        self.items.remove(index);
        self.state.select((!self.items.is_empty()).then(|| index.min(self.items.len() - 1)));
        true
    }

    pub fn set_description(&mut self, index: usize, text: &str) {
        if let Some(item) = self.items.get_mut(index) {
            item.desc = text.to_string();
        }
    }

    pub fn move_selection(&mut self, delta: isize) {
        move_table_selection(&mut self.state, self.items.len(), delta);
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
}

impl App {
    pub(super) fn save_selected_result(&mut self) {
        let Some(row) = self.results.selected() else { return };
        let (addr, ty) = (row.m.addr, row.ty);
        self.add_saved(addr, ty);
    }

    pub(super) fn add_saved(&mut self, addr: u64, ty: DataType) {
        if !self.saved.add(addr, ty) {
            return self.say(Level::Info, format!("0x{addr:x} is already in the list"));
        }
        self.refresh_live();
        self.say(
            Level::Ok,
            format!("Saved 0x{addr:x} ({}). Tab to the list, then w to set a value.", ty.scanmem_name()),
        );
    }

    pub(super) fn begin_set_value(&mut self) {
        if let Some(index) = self.saved.selected() {
            self.begin_input(InputKind::SetValue(index), String::new());
        }
    }

    pub(super) fn begin_describe(&mut self) {
        if let Some(index) = self.saved.selected() {
            let current = self.saved.items[index].desc.clone();
            self.begin_input(InputKind::Describe(index), current);
        }
    }

    pub(super) fn toggle_freeze(&mut self) {
        let Some(index) = self.saved.selected() else { return };
        if self.saved.items[index].set_value.is_none() {
            return self.say(Level::Warn, "Set a value first (w); the checkbox appears once there is one to hold.");
        }
        let item = &mut self.saved.items[index];
        item.frozen = !item.frozen;
        let message = item.freeze_message();
        self.sync_freezer();
        self.say(Level::Ok, message);
    }

    pub(super) fn remove_selected(&mut self) {
        if self.saved.remove_selected() {
            self.sync_freezer();
            self.say(Level::Info, "Removed from list");
        }
    }

    pub(super) fn write_saved(&mut self, index: usize, text: &str) {
        let Some(item) = self.saved.items.get(index) else { return };
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
        memory.write(addr, bytes).map_err(|e| format!("write to 0x{addr:x} failed: {e}"))
    }
}
