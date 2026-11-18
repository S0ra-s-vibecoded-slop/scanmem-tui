//! The `range` command and the scans that run while a range limit is active.
//!
//! A range limits later scans to `base ± offset` around a labelled or typed
//! address. Inside a range the built-in scanner (`crate::scanner`) does the
//! searching itself, because scanmem's CLI can only search whole regions and
//! would flood the results with everything else in a partially overlapping
//! one. scanmem is left untouched until `n` resets everything again.

use super::results::MAX_RESULTS;
use super::{App, Level};
use crate::datatype::DataType;
use crate::memio::MemIo;
use crate::scanmem::Match;
use crate::scanner::{self, Candidate, Operand, ScanControl, ScanStep};
use std::sync::Arc;
use std::sync::mpsc::{Receiver, Sender, TryRecvError, channel};
use std::thread;
use std::time::Instant;

/// A range scan running on its own thread, with its results on the way back.
pub(crate) struct RangeJob {
    pub control: Arc<ScanControl>,
    rx: Receiver<RangeOutcome>,
    /// What the scanner took over; restored if the scan stops or fails, so a
    /// narrowed list is not lost to a cancel.
    previous: Option<Vec<Candidate>>,
    pub label: &'static str,
    pub since: Instant,
}

impl RangeJob {
    /// Progress as a percentage, when the total is known.
    pub fn percent(&self) -> Option<u64> {
        let (done, total) = self.control.progress();
        (total > 0).then(|| (done * 100 / total).min(100))
    }
}

enum RangeOutcome {
    Swept {
        candidates: Vec<Candidate>,
        total: u64,
    },
    Narrowed {
        survivors: Vec<Candidate>,
    },
    Failed(String),
}

impl App {
    /// `range <label|address> <offset>`: limit later scans to `base ± offset`.
    pub(super) fn apply_range(&mut self, base: Option<&str>, offset: Option<&str>) {
        let (Some(base), Some(offset)) = (base, offset) else {
            return self.say(Level::Error, "usage: range <label|address> <offset>");
        };
        let Some(base_addr) = self.range_base(base) else {
            return self.say(
                Level::Error,
                format!("`{base}` is neither a saved label nor a hex address"),
            );
        };
        let offset = match parse_offset(offset) {
            Ok(offset) => offset,
            Err(reason) => return self.say(Level::Error, reason),
        };
        let (lo, hi) = (
            base_addr.saturating_sub(offset),
            base_addr.saturating_add(offset),
        );
        if self.is_busy() {
            return self.say(Level::Warn, "scanmem is busy");
        }
        if !self.require_target() {
            return;
        }
        // A range starts a fresh scan context: the built-in scanner owns the
        // matches from here on, and it knows nothing of scanmem's list.
        self.scan_range = Some((lo, hi));
        self.candidates.clear();
        self.results.clear();
        self.say(
            Level::Ok,
            format!("Scans limited to 0x{lo:x} - 0x{hi:x}. Press s to scan inside it; n scans everywhere again."),
        );
    }

    /// A label on the saved list wins; otherwise the word must be an address.
    fn range_base(&self, word: &str) -> Option<u64> {
        self.saved
            .labelled(word)
            .or_else(|| parse_hex_address(word))
    }

    /// A scan command while a range is active: hands it to the built-in
    /// scanner on a background thread, so the UI stays responsive.
    pub(super) fn start_range_scan(&mut self, text: &str) {
        if !self.require_target() {
            return;
        }
        if self.is_busy() {
            return self.say(Level::Warn, "scanmem is busy");
        }
        let Some((lo, hi)) = self.scan_range else {
            return;
        };
        let ty = self.scan_type;
        let step = match parse_step(text, ty) {
            Ok(step) => step,
            Err(reason) => return self.say(Level::Error, reason),
        };
        let pid = self
            .target
            .as_ref()
            .map(|target| target.pid)
            .unwrap_or_default();
        let first = self.candidates.is_empty();
        if first && !step.takes_a_value() {
            return self.say(
                Level::Error,
                "cannot use that search without matches; scan a value inside the range first",
            );
        }

        let control = Arc::new(ScanControl::new());
        let (tx, rx) = channel();
        // Narrowing reads the previous candidates on the scan thread; the
        // App keeps a copy to restore if the scan stops or fails.
        let previous = if first {
            None
        } else {
            Some(std::mem::take(&mut self.candidates))
        };
        let thread_previous = previous.clone().map(Arc::new);
        let thread_control = control.clone();
        let label = if first { "Scanning range" } else { "Narrowing" };
        let spawned = thread::Builder::new()
            .name("range-scan".into())
            .spawn(move || {
                let request = RangeScan {
                    pid,
                    lo,
                    hi,
                    ty,
                    step,
                    first,
                };
                run_range_scan(
                    &request,
                    thread_previous.as_deref().map(Vec::as_slice),
                    &thread_control,
                    &tx,
                );
            });
        match spawned {
            Ok(spawned) => spawned,
            Err(reason) => {
                if let Some(previous) = previous {
                    self.candidates = previous;
                }
                return self.say(Level::Error, format!("could not start the scan: {reason}"));
            }
        };
        self.range_job = Some(RangeJob {
            control,
            rx,
            previous,
            label,
            since: Instant::now(),
        });
        self.say(Level::Info, format!("{label} 0x{lo:x} - 0x{hi:x}…"));
    }

    /// Picks up a finished range scan, if its thread has delivered one.
    pub(super) fn drain_range_job(&mut self) {
        let outcome = match &self.range_job {
            None => return,
            Some(job) => match job.rx.try_recv() {
                Ok(outcome) => outcome,
                Err(TryRecvError::Empty) => return,
                Err(TryRecvError::Disconnected) => {
                    // The thread is gone without a result; treat as stopped.
                    self.range_job = None;
                    return;
                }
            },
        };
        let Some(job) = self.range_job.take() else {
            return;
        };
        self.redraw = true;
        if job.control.cancelled() {
            if let Some(previous) = job.previous {
                self.candidates = previous;
            }
            return self.say(Level::Warn, "Range scan stopped.");
        }
        match outcome {
            RangeOutcome::Swept { candidates, total } => {
                self.candidates = candidates;
                self.show_candidates(total);
                self.report_scan(None);
            }
            RangeOutcome::Narrowed { survivors } => {
                let total = survivors.len() as u64;
                self.candidates = survivors;
                self.show_candidates(total);
                self.report_scan(None);
            }
            RangeOutcome::Failed(reason) => {
                if let Some(previous) = job.previous {
                    self.candidates = previous;
                }
                self.say(Level::Error, reason);
            }
        }
    }

    /// Mirrors the candidate list into the results table, capped like
    /// scanmem's `list`.
    fn show_candidates(&mut self, total: u64) {
        let ty = self.scan_type;
        let matches: Vec<Match> = self
            .candidates
            .iter()
            .take(MAX_RESULTS)
            .map(|c| Match {
                addr: c.addr,
                region: "range".to_string(),
                value: ty.format_bytes(&c.old),
                types: vec![ty],
            })
            .collect();
        self.results.replace(matches, Some(total), ty);
    }
}

/// Everything one range scan needs, owned by the scan thread.
struct RangeScan {
    pid: u32,
    lo: u64,
    hi: u64,
    ty: DataType,
    step: ScanStep,
    first: bool,
}

/// The scan thread's body: opens its own memory handle and reports the
/// result (or the reason there is none) back to the App.
fn run_range_scan(
    request: &RangeScan,
    previous: Option<&[Candidate]>,
    control: &ScanControl,
    tx: &Sender<RangeOutcome>,
) {
    let RangeScan {
        pid,
        lo,
        hi,
        ty,
        step,
        first,
    } = *request;
    let _ = tx.send(match MemIo::open(pid) {
        Err(reason) => RangeOutcome::Failed(format!(
            "cannot open /proc/{pid}/mem: {reason} (try running as root)"
        )),
        Ok(memory) if first => {
            let spans = scanner::clipped_spans(pid, lo, hi);
            let (candidates, total) = scanner::sweep(&memory, &spans, ty, step, control);
            RangeOutcome::Swept { candidates, total }
        }
        Ok(memory) => {
            let previous = previous.expect("narrowing always has previous candidates");
            let survivors = scanner::narrow(&memory, ty, step, previous, control);
            RangeOutcome::Narrowed { survivors }
        }
    });
}

/// `range` offsets: `0x10000` is hex, anything else is decimal.
fn parse_offset(text: &str) -> Result<u64, String> {
    if let Some(hex) = text.strip_prefix("0x").or_else(|| text.strip_prefix("0X")) {
        u64::from_str_radix(hex, 16).map_err(|_| format!("`{text}` is not a hex offset"))
    } else {
        text.parse::<u64>()
            .map_err(|_| format!("`{text}` is not a valid offset"))
    }
}

/// A bare hex address like `140902b8a` or `0x140902b8a`; labels are not hex.
fn parse_hex_address(text: &str) -> Option<u64> {
    u64::from_str_radix(text.trim_start_matches("0x").trim_start_matches("0X"), 16).ok()
}

/// Turns the scan prompt's text into a scan step, in the syntax scanmem
/// takes. Values must fit the current scan type, like scanmem's
/// "unsupported scan for current data type".
fn parse_step(text: &str, ty: DataType) -> Result<ScanStep, String> {
    let text = text.trim();
    if text.is_empty() {
        return Err("empty scan".into());
    }
    if let Some((lo, hi)) = text.split_once("..") {
        let lo = parse_operand(lo.trim(), ty)?;
        let hi = parse_operand(hi.trim(), ty)?;
        if operand_f64(lo) > operand_f64(hi) {
            return Err("empty range".into());
        }
        return Ok(ScanStep::Within(lo, hi));
    }
    let mut words = text.split_whitespace();
    let head = words.next().unwrap_or_default();
    let argument = words.next();
    match (head, argument) {
        ("snapshot", _) => Err("snapshot inside a range is not supported yet".into()),
        ("=", None) => Ok(ScanStep::NotChanged),
        ("=", Some(value)) => Ok(ScanStep::Equal(parse_operand(value, ty)?)),
        ("!=", None) => Ok(ScanStep::Changed),
        ("!=", Some(value)) => Ok(ScanStep::NotEqual(parse_operand(value, ty)?)),
        // with no argument these mean "changed at all", like scanmem's > and <
        (">" | "+", None) => Ok(ScanStep::Increased),
        ("<" | "-", None) => Ok(ScanStep::Decreased),
        (">", Some(value)) => Ok(ScanStep::Greater(parse_operand(value, ty)?)),
        ("<", Some(value)) => Ok(ScanStep::Less(parse_operand(value, ty)?)),
        ("+", Some(value)) => Ok(ScanStep::IncreasedBy(parse_operand(value, ty)?)),
        ("-", Some(value)) => Ok(ScanStep::DecreasedBy(parse_operand(value, ty)?)),
        ("update", _) => Ok(ScanStep::Update),
        (word, None) => Ok(ScanStep::Equal(parse_operand(word, ty)?)),
        (_, Some(_)) => Err(format!("unknown scan `{text}`")),
    }
}

fn parse_operand(text: &str, ty: DataType) -> Result<Operand, String> {
    if ty.is_float() {
        return text
            .parse::<f64>()
            .map(Into::into)
            .map_err(|_| format!("`{text}` is not a valid {}", ty.scanmem_name()));
    }
    match crate::datatype::parse_int(text) {
        Some(v) if fits(v, ty) => Ok(v.into()),
        _ => Err(format!("`{text}` is not a valid {}", ty.scanmem_name())),
    }
}

/// Whether an integer can be interpreted at the type's width at all, either
/// signed or unsigned; scanmem rejects values that fit neither.
fn fits(v: i128, ty: DataType) -> bool {
    let (min, max, umax) = match ty {
        DataType::I8 => (
            i128::from(i8::MIN),
            i128::from(i8::MAX),
            i128::from(u8::MAX),
        ),
        DataType::I16 => (
            i128::from(i16::MIN),
            i128::from(i16::MAX),
            i128::from(u16::MAX),
        ),
        DataType::I32 => (
            i128::from(i32::MIN),
            i128::from(i32::MAX),
            i128::from(u32::MAX),
        ),
        DataType::I64 => (
            i128::from(i64::MIN),
            i128::from(i64::MAX),
            i128::from(u64::MAX),
        ),
        _ => return false,
    };
    (min..=max).contains(&v) || (0..=umax).contains(&v)
}

/// Ranges are checked for emptiness like scanmem does: as floats.
#[expect(clippy::cast_precision_loss)]
fn operand_f64(op: Operand) -> f64 {
    match op {
        Operand::Int(v) => v as f64,
        Operand::Float(f) => f,
    }
}

#[cfg(test)]
mod tests {
    use super::super::saved::SavedList;
    use super::*;

    #[test]
    fn offsets_are_hex_with_prefix_and_decimal_without() {
        assert_eq!(parse_offset("0x10000"), Ok(0x10000));
        assert_eq!(parse_offset("0Xff"), Ok(0xff));
        assert_eq!(parse_offset("65536"), Ok(65536));
        assert!(parse_offset("-5").is_err());
        assert!(parse_offset("").is_err());
        assert_eq!(
            parse_offset("zz").unwrap_err(),
            "`zz` is not a valid offset"
        );
    }

    #[test]
    #[expect(clippy::unreadable_literal)]
    fn hex_addresses() {
        assert_eq!(parse_hex_address("140902b8a"), Some(0x140902b8a));
        assert_eq!(parse_hex_address("0x140902b8a"), Some(0x140902b8a));
        assert_eq!(parse_hex_address("health"), None);
        assert_eq!(parse_hex_address("0x"), None);
    }

    #[test]
    #[expect(clippy::unreadable_literal)]
    fn labels_are_found_case_insensitively() {
        let mut saved = SavedList::new();
        saved.add(0x140902b8a, DataType::I32);
        saved.items[0].label = "health".into();
        assert_eq!(saved.labelled("health"), Some(0x140902b8a));
        assert_eq!(saved.labelled("HEALTH"), Some(0x140902b8a));
        assert_eq!(saved.labelled("other"), None);
    }

    #[test]
    fn steps_parse_like_scanmem() {
        let i32_scan = DataType::I32;
        assert_eq!(parse_step("50", i32_scan), Ok(ScanStep::Equal(50.into())));
        assert_eq!(parse_step("> 1", i32_scan), Ok(ScanStep::Greater(1.into())));
        assert_eq!(parse_step("< 2", i32_scan), Ok(ScanStep::Less(2.into())));
        assert_eq!(parse_step("= 3", i32_scan), Ok(ScanStep::Equal(3.into())));
        assert_eq!(
            parse_step("!= 4", i32_scan),
            Ok(ScanStep::NotEqual(4.into()))
        );
        assert_eq!(
            parse_step("+ 5", i32_scan),
            Ok(ScanStep::IncreasedBy(5.into()))
        );
        assert_eq!(
            parse_step("- 6", i32_scan),
            Ok(ScanStep::DecreasedBy(6.into()))
        );
        assert_eq!(parse_step("=", i32_scan), Ok(ScanStep::NotChanged));
        assert_eq!(parse_step("!=", i32_scan), Ok(ScanStep::Changed));
        // no argument means "changed at all"
        assert_eq!(parse_step(">", i32_scan), Ok(ScanStep::Increased));
        assert_eq!(parse_step("<", i32_scan), Ok(ScanStep::Decreased));
        assert_eq!(parse_step("+", i32_scan), Ok(ScanStep::Increased));
        assert_eq!(parse_step("-", i32_scan), Ok(ScanStep::Decreased));
        assert_eq!(parse_step("update", i32_scan), Ok(ScanStep::Update));
        assert_eq!(
            parse_step("1..10", i32_scan),
            Ok(ScanStep::Within(1.into(), 10.into()))
        );
        assert_eq!(
            parse_step("0x10..0x20", i32_scan),
            Ok(ScanStep::Within(16.into(), 32.into()))
        );
    }

    #[test]
    fn float_steps_parse_as_floats() {
        let f32_scan = DataType::F32;
        assert_eq!(parse_step("3.5", f32_scan), Ok(ScanStep::Equal(3.5.into())));
        // integers are fine for float scans, like scanmem
        assert_eq!(
            parse_step("> 1", f32_scan),
            Ok(ScanStep::Greater(1.0.into()))
        );
        assert_eq!(
            parse_step("1.0..2.5", f32_scan),
            Ok(ScanStep::Within(1.0.into(), 2.5.into()))
        );
    }

    #[test]
    fn bad_steps_are_rejected() {
        let i32_scan = DataType::I32;
        // floats are not integers
        assert!(parse_step("3.5", i32_scan).is_err());
        // 5 billion fits neither i32 nor u32
        assert!(parse_step("5000000000", i32_scan).is_err());
        assert!(parse_step("", i32_scan).is_err());
        assert!(parse_step("1 2", i32_scan).is_err());
        assert!(
            parse_step("5..1", i32_scan)
                .unwrap_err()
                .contains("empty range")
        );
        // but it does fit u64
        assert!(parse_step("5000000000", DataType::I64).is_ok());
        // negative bound of a range: -5..10 with i32 is fine
        assert!(parse_step("-5..10", i32_scan).is_ok());
    }
}
