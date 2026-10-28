//! Turning scanmem's text output into data, and framing commands with a sentinel.

use crate::datatype::DataType;

const SENTINEL_PREFIX: &str = "__SMTUI_";

/// The `shell` command that makes scanmem print the sentinel for batch `id`.
pub(super) fn sentinel_command(id: u64) -> String {
    format!("shell printf \"{SENTINEL_PREFIX}%s__\\n\" {id}\n")
}

pub(super) fn parse_sentinel(line: &str) -> Option<u64> {
    let rest = line.trim().strip_prefix(SENTINEL_PREFIX)?;
    rest.strip_suffix("__")?.parse().ok()
}

/// scanmem prints its prompt (`3> `) without a newline, so it ends up glued
/// to the front of the next line of output. Peel those off.
pub(super) fn strip_prompt(mut s: &str) -> &str {
    loop {
        let t = s.trim_start();
        let digits = t.len() - t.trim_start_matches(|c: char| c.is_ascii_digit()).len();
        match t[digits..].strip_prefix('>') {
            Some(rest) => s = rest.strip_prefix(' ').unwrap_or(rest),
            None => return t,
        }
    }
}

/// `01/06 searching 0x... - 0x...: ....ok` -> (1, 6)
pub(super) fn parse_progress(line: &str) -> Option<(u32, u32)> {
    let (head, rest) = line.split_once(' ')?;
    if !rest.starts_with("searching") {
        return None;
    }
    let (done, total) = head.split_once('/')?;
    Some((done.parse().ok()?, total.parse().ok()?))
}

#[derive(Debug, Clone, PartialEq)]
pub struct Match {
    pub addr: u64,
    pub region: String,
    pub value: String,
    pub types: Vec<DataType>,
}

/// `[ 0] 559791c44010,  0 +         3010,   exe, 100, [I32 ]`
fn parse_match_line(line: &str) -> Option<Match> {
    let s = line.trim_start().strip_prefix('[')?;
    let close = s.find(']')?;
    s[..close].trim().parse::<u32>().ok()?;
    let mut fields = s[close + 1..].splitn(4, ',');
    let addr = u64::from_str_radix(fields.next()?.trim(), 16).ok()?;
    let _region_id_and_offset = fields.next()?;
    let region = fields.next()?.trim().to_string();
    let tail = fields.next()?.trim();
    let flags_at = tail.rfind(", [")?;
    let value = tail[..flags_at].trim().to_string();
    let flags = tail[flags_at + 3..].trim_end().trim_end_matches(']');
    Some(Match {
        addr,
        region,
        value,
        types: distinct_types(flags),
    })
}

fn distinct_types(flags: &str) -> Vec<DataType> {
    let mut types: Vec<DataType> = Vec::new();
    for ty in flags.split_whitespace().filter_map(DataType::from_flag) {
        if !types.contains(&ty) {
            types.push(ty);
        }
    }
    types
}

/// `info: we currently have 3 matches.`
fn parse_match_count(line: &str) -> Option<u64> {
    let rest = line.trim().strip_prefix("info: we currently have ")?;
    rest.split_whitespace().next()?.parse().ok()
}

#[derive(Debug, Default)]
pub struct Parsed {
    pub matches: Vec<Match>,
    pub count: Option<u64>,
    /// `error:` lines, prefix stripped.
    pub errors: Vec<String>,
    /// `warn:` lines, prefix stripped.
    pub warnings: Vec<String>,
}

pub fn parse_output(lines: &[String]) -> Parsed {
    let mut parsed = Parsed::default();
    for line in lines {
        if let Some(m) = parse_match_line(line) {
            parsed.matches.push(m);
        } else if let Some(count) = parse_match_count(line) {
            parsed.count = Some(count);
        } else if let Some(error) = line.trim().strip_prefix("error:") {
            parsed.errors.push(error.trim().to_string());
        } else if let Some(warning) = line.trim().strip_prefix("warn:") {
            parsed.warnings.push(warning.trim().to_string());
        }
    }
    parsed
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn strips_prompts() {
        assert_eq!(strip_prompt("3> [ 0] 55, x"), "[ 0] 55, x");
        assert_eq!(strip_prompt("> > 01/06 searching"), "01/06 searching");
        assert_eq!(strip_prompt("12> 5> hi"), "hi");
        assert_eq!(strip_prompt("info: hello"), "info: hello");
        assert_eq!(
            strip_prompt("[ 1] 7f, 5 + 1, heap, 3, [I8 ]"),
            "[ 1] 7f, 5 + 1, heap, 3, [I8 ]"
        );
        // progress lines start with digits but are not prompts
        assert_eq!(strip_prompt("01/06 searching"), "01/06 searching");
    }

    #[test]
    fn sentinel_roundtrip() {
        assert_eq!(parse_sentinel("__SMTUI_17__"), Some(17));
        assert_eq!(parse_sentinel(strip_prompt("3> __SMTUI_2__")), Some(2));
        assert_eq!(parse_sentinel("something else"), None);
        assert!(sentinel_command(5).starts_with("shell printf"));
        assert!(sentinel_command(5).ends_with(" 5\n"));
    }

    #[test]
    fn progress() {
        assert_eq!(
            parse_progress("03/06 searching 0x1 - 0x2..........ok"),
            Some((3, 6))
        );
        assert_eq!(parse_progress("info: 6 suitable regions found."), None);
    }

    #[test]
    #[expect(clippy::unreadable_literal)]
    fn match_line_int() {
        let m =
            parse_match_line("[ 0] 559791c44010,  0 +         3010,   exe, 100, [I32 ]").unwrap();
        assert_eq!(m.addr, 0x559791c44010);
        assert_eq!(m.region, "exe");
        assert_eq!(m.value, "100");
        assert_eq!(m.types, vec![DataType::I32]);
    }

    #[test]
    fn match_line_float_and_multi_flags() {
        let m =
            parse_match_line("[12] 7ffc8dc5328c,  5 +        1e28c, stack, 3.5, [F32 ]").unwrap();
        assert_eq!(m.value, "3.5");
        assert_eq!(m.types, vec![DataType::F32]);
        let m = parse_match_line("[ 3] 1000,  1 + 10, heap, -7, [I64s I32s I16s I8s ]").unwrap();
        assert_eq!(m.value, "-7");
        assert_eq!(
            m.types,
            vec![DataType::I64, DataType::I32, DataType::I16, DataType::I8]
        );
    }

    #[test]
    fn non_match_lines() {
        assert!(parse_match_line("info: we currently have 3 matches.").is_none());
        assert!(parse_match_line("[ x] zz").is_none());
        assert_eq!(
            parse_match_count("info: we currently have 3 matches."),
            Some(3)
        );
    }

    #[test]
    fn output_parse() {
        let lines: Vec<String> = [
            "warn: Run scanmem as root if memory regions are missing.",
            "info: we currently have 2 matches.",
            "[ 0] 10,  0 + 1, exe, 5, [I32 ]",
            "[ 1] 20,  0 + 2, exe, 5, [I32 ]",
            "error: bad value",
        ]
        .iter()
        .map(std::string::ToString::to_string)
        .collect();
        let parsed = parse_output(&lines);
        assert_eq!(parsed.count, Some(2));
        assert_eq!(parsed.matches.len(), 2);
        assert_eq!(parsed.errors, vec!["bad value"]);
        assert_eq!(parsed.warnings.len(), 1);
    }
}
