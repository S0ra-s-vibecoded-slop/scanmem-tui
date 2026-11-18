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
    // Labels and hex digits never contain `+` or `-`, so every operator
    // separates two terms and carries that term's sign.
    let mut total: i128 = 0;
    let mut base_seen = false;
    let mut positive = true;
    let mut start = 0;
    for (index, c) in expr.char_indices() {
        if c != '+' && c != '-' {
            continue;
        }
        total = add_term(total, &mut base_seen, positive, &expr[start..index], saved)?;
        positive = c == '+';
        start = index + 1;
    }
    total = add_term(total, &mut base_seen, positive, &expr[start..], saved)?;
    if !(0..=i128::from(u64::MAX)).contains(&total) {
        return Err(format!("{expr} does not fit in an address"));
    }
    #[expect(clippy::cast_sign_loss, clippy::cast_possible_truncation)]
    Ok(total as u64)
}

/// Adds one term: the first must be a label or hex address, the rest are
/// offsets applied with the sign before them.
fn add_term(
    total: i128,
    base_seen: &mut bool,
    positive: bool,
    token: &str,
    saved: &SavedList,
) -> Result<i128, String> {
    if !*base_seen {
        if !positive {
            return Err(format!("`{token}` cannot start an address"));
        }
        *base_seen = true;
        return Ok(i128::from(resolve_term(token, saved)?));
    }
    let Some(offset) = crate::datatype::parse_int(token) else {
        return Err(format!("`{token}` is not a valid offset"));
    };
    Ok(total + if positive { offset } else { -offset })
}

/// A saved label wins over a hex reading of the word.
fn resolve_term(term: &str, saved: &SavedList) -> Result<u64, String> {
    if let Some(addr) = saved.labelled(term) {
        return Ok(addr);
    }
    let digits = term.trim_start_matches("0x").trim_start_matches("0X");
    u64::from_str_radix(digits, 16)
        .map_err(|_| format!("`{term}` is neither a saved label nor a hex address"))
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
