//! The single-line text prompt: starting it, and acting on what was typed.

use super::keys::edit_line;
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
            InputKind::Describe(index) => self.saved.set_description(index, text),
            _ if text.is_empty() => {}
            InputKind::Scan => self.submit_scan(text),
            InputKind::SetValue(index) => self.write_saved(index, text),
            InputKind::AddAddr => self.submit_address(text),
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
        match parse_address(text, self.scan_type) {
            Ok((addr, ty)) => self.add_saved(addr, ty),
            Err(reason) => self.say(Level::Error, reason),
        }
    }
}

/// `7ffc8dc5328c` or `0x7ffc8dc5328c int32`; the type defaults to `default_type`.
fn parse_address(text: &str, default_type: DataType) -> Result<(u64, DataType), String> {
    let mut words = text.split_whitespace();
    let address = words.next().ok_or("empty address")?;
    let digits = address.trim_start_matches("0x").trim_start_matches("0X");
    let addr =
        u64::from_str_radix(digits, 16).map_err(|_| format!("`{digits}` is not a hex address"))?;
    let ty = match words.next() {
        Some(name) => name.parse::<DataType>()?,
        None => default_type,
    };
    Ok((addr, ty))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[expect(clippy::unreadable_literal)]
    fn address_with_and_without_prefix_and_type() {
        assert_eq!(
            parse_address("7ffc8dc5328c", DataType::I32),
            Ok((0x7ffc8dc5328c, DataType::I32))
        );
        assert_eq!(
            parse_address("0xFF float64", DataType::I32),
            Ok((0xff, DataType::F64))
        );
    }

    #[test]
    fn bad_addresses_explain_themselves() {
        assert!(parse_address("", DataType::I32).is_err());
        assert!(
            parse_address("zz", DataType::I32)
                .unwrap_err()
                .contains("hex")
        );
        assert!(
            parse_address("10 banana", DataType::I32)
                .unwrap_err()
                .contains("unknown type")
        );
    }
}
