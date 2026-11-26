//! The single-line text prompt: starting it, and acting on what was typed.

use super::keys::edit_line;
use super::saved::SavedList;
use super::{App, InputKind, Level, Mode, process_name};
use crate::datatype::DataType;
use ratatui::crossterm::event::{KeyCode, KeyEvent};

impl App {
    pub(super) fn begin_input(&mut self, kind: InputKind, initial: String) {
        self.input = initial;
        self.mode = Mode::Input(kind);
    }

    pub(super) fn on_input_key(&mut self, kind: InputKind, key: KeyEvent) {
        match key.code {
            KeyCode::Esc => self.cancel_input(),
            KeyCode::Enter => self.submit_input(kind),
            _ => {
                edit_line(&mut self.input, key);
            }
        }
    }

    fn cancel_input(&mut self) {
        self.mode = Mode::Normal;
        self.input.clear();
    }

    fn submit_input(&mut self, kind: InputKind) {
        let text = std::mem::take(&mut self.input);
        self.mode = Mode::Normal;
        self.submit(kind, text.trim());
    }

    fn submit(&mut self, kind: InputKind, text: &str) {
        match kind {
            InputKind::Label(index) => self.apply_label(index, text),
            _ if text.is_empty() => {}
            InputKind::Scan => self.submit_scan(text),
            InputKind::SetValue(index) => self.write_saved(index, text),
            InputKind::EditType(index) => self.apply_saved_type(index, text),
            InputKind::AddAddr => self.submit_address(text),
            InputKind::ImportScript => self.import_script(text),
            InputKind::NewScript => self.create_script(text),
            InputKind::GotoCode => self.submit_goto_code(text),
            InputKind::FindRefs => self.submit_find_refs(text),
            InputKind::FindPointers => self.submit_find_pointers(text),
        }
    }

    /// The scan prompt doubles as a tiny command line for the few
    /// scanmem commands that change this program's own state.
    fn submit_scan(&mut self, text: &str) {
        let mut words = text.split_whitespace();
        match words.next() {
            None => {}
            Some("exit" | "quit" | "q") => self.say(Level::Warn, "Use q in the main view to quit."),
            Some("pid") => self.attach_to_typed_pid(words.next()),
            Some("option") if words.next() == Some("scan_data_type") => {
                self.change_to_typed_type(words.next());
            }
            Some("range") => self.apply_range(words.next(), words.next()),
            // A range limit hands every other scan to the built-in scanner.
            _ if self.scan_range.is_some() => self.start_range_scan(text),
            _ => self.start_scan(text),
        }
    }

    fn attach_to_typed_pid(&mut self, argument: Option<&str>) {
        let Some(pid) = argument.and_then(|text| text.parse::<u32>().ok()) else {
            return self.say(Level::Error, "usage: pid <number>");
        };
        if self.is_busy() {
            return self.say(Level::Warn, "scanmem is busy");
        }
        self.attach(pid, process_name(pid));
    }

    fn change_to_typed_type(&mut self, argument: Option<&str>) {
        let Some(name) = argument else {
            return self.say(Level::Error, "usage: option scan_data_type <type>");
        };
        match name.parse::<DataType>() {
            Ok(_) if self.is_busy() => self.say(Level::Warn, "scanmem is busy"),
            Ok(ty) => self.change_type(ty, "Changing type"),
            Err(reason) => self.say(Level::Error, reason),
        }
    }

    fn submit_address(&mut self, text: &str) {
        let saved = &self.saved;
        match parse_address(text, self.scan_type, saved) {
            Ok((addr, ty)) => self.add_saved(addr, ty),
            Err(reason) => self.say(Level::Error, reason),
        }
    }
}

/// `7ffc8dc5328c`, `0x7ffc8dc5328c int32`, `label+0x10`, `0xaddr-0x1140 f64`.
/// The first term is a saved label or a hex address, and any number of
/// `+`/`-` offsets follow; offsets are hex with `0x`, decimal otherwise.
/// The type defaults to `default_type`.
fn parse_address(
    text: &str,
    default_type: DataType,
    saved: &SavedList,
) -> Result<(u64, DataType), String> {
    let mut words = text.split_whitespace();
    let expr = words.next().ok_or("empty address")?;
    let ty = match words.next() {
        Some(name) => name.parse::<DataType>()?,
        None => default_type,
    };
    if words.next().is_some() {
        return Err("unexpected text after the type".into());
    }
    let addr = evaluate_expression(expr, saved)?;
    Ok((addr, ty))
}

/// Sums the terms of an address expression; labels resolve before hex, like
/// `range` does.
fn evaluate_expression(expr: &str, saved: &SavedList) -> Result<u64, String> {
    crate::address::resolve_expression(expr, |name| saved.labelled(name).map(|addr| (addr, None)))
        .map(|resolved| resolved.addr)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::app::saved::SavedList;

    fn list_with(addr: u64, label: &str) -> SavedList {
        let mut saved = SavedList::new();
        saved.add(addr, DataType::I32);
        let last = saved.items.len() - 1;
        saved.items[last].label = label.into();
        saved
    }

    #[test]
    #[expect(clippy::unreadable_literal)]
    fn address_with_and_without_prefix_and_type() {
        let empty = SavedList::new();
        assert_eq!(
            parse_address("7ffc8dc5328c", DataType::I32, &empty),
            Ok((0x7ffc8dc5328c, DataType::I32))
        );
        assert_eq!(
            parse_address("0xFF float64", DataType::I32, &empty),
            Ok((0xff, DataType::F64))
        );
    }

    #[test]
    #[expect(clippy::unreadable_literal)]
    fn offsets_apply_to_a_label_or_an_address() {
        let saved = list_with(0x140902b8a, "health");
        assert_eq!(
            parse_address("health+0x10", DataType::I32, &saved),
            Ok((0x140902b9a, DataType::I32))
        );
        assert_eq!(
            parse_address("HEALTH-16", DataType::I32, &saved),
            Ok((0x140902b7a, DataType::I32))
        );
        assert_eq!(
            parse_address("0x140902b8a-0x1140 float64", DataType::I32, &saved),
            Ok((0x140901a4a, DataType::F64))
        );
        // several steps compose, and a label wins over a hex reading
        assert_eq!(
            parse_address("health+0x100-4", DataType::I32, &saved),
            Ok((0x140902c86, DataType::I32))
        );
    }

    #[test]
    fn bad_addresses_explain_themselves() {
        let empty = SavedList::new();
        assert!(parse_address("", DataType::I32, &empty).is_err());
        assert!(
            parse_address("zz", DataType::I32, &empty)
                .unwrap_err()
                .contains("neither a saved label nor a hex address")
        );
        assert!(
            parse_address("10 banana", DataType::I32, &empty)
                .unwrap_err()
                .contains("unknown type")
        );
        assert!(parse_address("1 2 3", DataType::I32, &empty).is_err());
        assert!(parse_address("0x10+", DataType::I32, &empty).is_err());
        assert!(parse_address("-0x10", DataType::I32, &empty).is_err());
        assert!(
            parse_address("0x10-0x20", DataType::I32, &empty)
                .unwrap_err()
                .contains("does not fit")
        );
    }
}
