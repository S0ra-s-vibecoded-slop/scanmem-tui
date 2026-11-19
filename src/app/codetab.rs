//! The Code tab: executable mappings, disassembly, and the reference scan.
//!
//! The tab is a browser, not a decompiler. Its main job is the static
//! cross-reference search: which instructions encode a given address? The
//! disassembly exists to give those hits somewhere to land.

use super::{App, InputKind, Level, Tab};
use crate::code::{self, DecodedLine, RefKind, Reference, Window};
use crate::maps::{self, Mapping};
use crate::memio::MemIo;
use crate::scanner::ScanControl;
use ratatui::widgets::ListState;
use std::collections::{HashMap, VecDeque};
use std::sync::Arc;
use std::sync::mpsc::{Receiver, Sender, TryRecvError, channel};
use std::thread;
use std::time::Instant;

/// How many finished scans stay cached for the session.
const CACHE_LIMIT: usize = 8;
/// How many jumps the `u` history remembers.
const HISTORY_LIMIT: usize = 128;

/// Which half of the Code tab has the keyboard.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CodeFocus {
    Sidebar,
    Disassembly,
}

/// Everything the Code tab shows. Reset whenever the target changes.
pub struct CodeView {
    pub pid: Option<u32>,
    /// Every mapping, so module names and offsets stay available.
    pub mappings: Vec<Mapping>,
    /// Selection index into the executable mappings.
    pub selected_mapping: usize,
    /// The sidebar shows the reference list instead of the mappings.
    pub showing_refs: bool,
    pub refs: Vec<Reference>,
    pub ref_state: ListState,
    pub ref_target: Option<u64>,
    pub ref_label: Option<String>,
    pub anchor: Option<u64>,
    pub lines: Vec<DecodedLine>,
    pub cursor: usize,
    pub scroll: usize,
    pub viewport: usize,
    pub bytes: bool,
    pub focus: CodeFocus,
    /// (anchor, cursor) pairs, so `u` can retrace a jump.
    pub history: Vec<(u64, usize)>,
    /// Finished scans per `(pid, target)`, so reopening is instant.
    cache: HashMap<(u32, u64), Vec<Reference>>,
    /// Insertion order of `cache`, oldest first.
    cache_order: VecDeque<(u32, u64)>,
}

impl CodeView {
    pub fn new() -> CodeView {
        CodeView {
            pid: None,
            mappings: Vec::new(),
            selected_mapping: 0,
            showing_refs: false,
            refs: Vec::new(),
            ref_state: ListState::default(),
            ref_target: None,
            ref_label: None,
            anchor: None,
            lines: Vec::new(),
            cursor: 0,
            scroll: 0,
            viewport: 20,
            bytes: false,
            focus: CodeFocus::Sidebar,
            history: Vec::new(),
            cache: HashMap::new(),
            cache_order: VecDeque::new(),
        }
    }

    /// Forgets the old process's addresses and loads the new one's maps.
    pub fn reset(&mut self, pid: Option<u32>) {
        self.pid = pid;
        self.mappings = pid
            .and_then(|pid| maps::read_maps(pid).ok())
            .unwrap_or_default();
        self.selected_mapping = 0;
        self.showing_refs = false;
        self.refs.clear();
        self.ref_state.select(None);
        self.ref_target = None;
        self.ref_label = None;
        self.anchor = None;
        self.lines.clear();
        self.cursor = 0;
        self.scroll = 0;
        self.focus = CodeFocus::Sidebar;
        self.history.clear();
        self.cache.clear();
        self.cache_order.clear();
    }

    /// Retries a failed maps read for the same process (permissions, or a
    /// process that was still starting when it was attached).
    pub fn reload_maps(&mut self) {
        if let Some(pid) = self.pid {
            self.mappings = maps::read_maps(pid).unwrap_or_default();
        }
    }

    pub fn executable(&self) -> impl Iterator<Item = &Mapping> {
        self.mappings.iter().filter(|mapping| mapping.executable())
    }

    pub fn executable_count(&self) -> usize {
        self.executable().count()
    }

    pub fn selected_mapping(&self) -> Option<&Mapping> {
        self.executable().nth(self.selected_mapping)
    }

    pub fn selected_ref(&self) -> Option<&Reference> {
        self.ref_state
            .selected()
            .and_then(|index| self.refs.get(index))
    }

    pub fn cached(&self, target: u64) -> Option<&[Reference]> {
        let pid = self.pid?;
        self.cache.get(&(pid, target)).map(Vec::as_slice)
    }

    pub fn remember_refs(&mut self, target: u64, refs: Vec<Reference>) -> Vec<Reference> {
        if let Some(pid) = self.pid {
            let key = (pid, target);
            self.cache_order.retain(|other| *other != key);
            self.cache_order.push_back(key);
            while self.cache_order.len() > CACHE_LIMIT {
                if let Some(old) = self.cache_order.pop_front() {
                    self.cache.remove(&old);
                }
            }
            self.cache.insert(key, refs.clone());
        }
        refs
    }

    pub fn forget_refs(&mut self, target: u64) {
        if let Some(pid) = self.pid {
            let key = (pid, target);
            self.cache.remove(&key);
            self.cache_order.retain(|other| *other != key);
        }
    }

    pub fn set_window(&mut self, window: Window, cursor: usize) {
        self.anchor = Some(
            window
                .lines
                .get(cursor)
                .map_or(window.start, |line| line.addr),
        );
        self.lines = window.lines;
        self.cursor = cursor.min(self.lines.len().saturating_sub(1));
        self.scroll = 0;
        self.ensure_visible();
    }

    pub fn ensure_visible(&mut self) {
        let viewport = self.viewport.max(1);
        if self.cursor < self.scroll {
            self.scroll = self.cursor;
        } else if self.cursor >= self.scroll + viewport {
            self.scroll = self.cursor + 1 - viewport;
        }
    }

    pub fn move_cursor(&mut self, delta: isize) {
        if self.lines.is_empty() {
            return;
        }
        let current = self.cursor.cast_signed();
        let max = self.lines.len().cast_signed() - 1;
        self.cursor = current.saturating_add(delta).clamp(0, max).cast_unsigned();
        self.ensure_visible();
    }

    pub fn move_mapping(&mut self, delta: isize) {
        let count = self.executable_count();
        if count == 0 {
            return;
        }
        let current = self.selected_mapping.cast_signed();
        let max = count.cast_signed() - 1;
        self.selected_mapping = current.saturating_add(delta).clamp(0, max).cast_unsigned();
    }

    pub fn move_ref(&mut self, delta: isize) {
        let count = self.refs.len();
        if count == 0 {
            self.ref_state.select(None);
            return;
        }
        let current = self.ref_state.selected().unwrap_or(0).cast_signed();
        let max = count.cast_signed() - 1;
        let next = current.saturating_add(delta).clamp(0, max).cast_unsigned();
        self.ref_state.select(Some(next));
    }
}

/// A reference scan running on its own thread.
pub struct XrefJob {
    pub control: Arc<ScanControl>,
    rx: Receiver<XrefOutcome>,
    pub target: u64,
    pub label: Option<String>,
    pub since: Instant,
}

impl XrefJob {
    /// Progress as a percentage, when the total is known.
    pub fn percent(&self) -> Option<u64> {
        let (done, total) = self.control.progress();
        (total > 0).then(|| (done * 100 / total).min(100))
    }
}

enum XrefOutcome {
    Done(Vec<Reference>),
    Failed(String),
}

impl App {
    /// Keeps the Code tab's maps in step with the target.
    pub(super) fn reset_code(&mut self, pid: Option<u32>) {
        if let Some(job) = self.xref_job.take() {
            job.control.cancel();
        }
        self.code.reset(pid);
    }

    /// Loads the maps the first time the tab is needed, and reloads them when
    /// the earlier read failed.
    pub(super) fn ensure_code(&mut self) {
        let pid = self.target.as_ref().map(|target| target.pid);
        if self.code.pid != pid {
            return self.reset_code(pid);
        }
        if self.code.mappings.is_empty() && pid.is_some() {
            self.code.reload_maps();
        }
    }

    /// `x` from a result/saved row, or Enter on a mapping/ref: display `addr`.
    pub(super) fn open_code_at(&mut self, addr: u64) {
        self.ensure_code();
        self.tab = Tab::Code;
        let Some(mapping) = maps::mapping_at(&self.code.mappings, addr).cloned() else {
            return self.say(
                Level::Error,
                format!("0x{addr:x} is not mapped in this process"),
            );
        };
        if !mapping.executable() {
            return self.say(
                Level::Warn,
                format!(
                    "0x{addr:x} is {} ({}), not executable code",
                    mapping.display_name(),
                    mapping.perms.text()
                ),
            );
        }
        self.jump_code(addr, true);
    }

    /// Decodes around `addr`; `remember` pushes the current view onto the
    /// history first. Keeps the old view when the new one cannot be decoded.
    fn jump_code(&mut self, addr: u64, remember: bool) -> bool {
        self.ensure_code();
        let Some(mapping) = maps::mapping_at(&self.code.mappings, addr).cloned() else {
            self.say(
                Level::Error,
                format!("0x{addr:x} is not mapped in this process"),
            );
            return false;
        };
        let decoded = self.target.as_ref().and_then(|target| {
            let memory = target.memory().ok()?;
            Some(code::decode_window(
                memory,
                addr,
                mapping.start,
                mapping.end,
            ))
        });
        let Some(window) = decoded else {
            self.say(
                Level::Warn,
                "Cannot read this process's memory (try running as root)",
            );
            return false;
        };
        if window.lines.is_empty() {
            self.say(Level::Warn, format!("No bytes to decode at 0x{addr:x}"));
            return false;
        }
        let cursor = window
            .lines
            .iter()
            .position(|line| line.addr == addr)
            .unwrap_or(0);
        if remember && let Some(anchor) = self.code.anchor {
            let here = (anchor, self.code.cursor);
            if self.code.history.last() != Some(&here) {
                if self.code.history.len() >= HISTORY_LIMIT {
                    self.code.history.remove(0);
                }
                self.code.history.push(here);
            }
        }
        self.code.set_window(window, cursor);
        self.code.focus = CodeFocus::Disassembly;
        self.tab = Tab::Code;
        self.redraw = true;
        true
    }

    /// `g`: a label, `module+0x…`, or a hex address.
    pub(super) fn begin_goto_code(&mut self) {
        self.ensure_code();
        self.begin_input(InputKind::GotoCode, String::new());
    }

    pub(super) fn submit_goto_code(&mut self, text: &str) {
        match self.resolve_code_address(text) {
            Ok(addr) => {
                self.open_code_at(addr);
            }
            Err(reason) => self.say(Level::Error, reason),
        }
    }

    fn resolve_code_address(&self, text: &str) -> Result<u64, String> {
        let saved = &self.saved;
        if let Ok(resolved) = crate::address::resolve_expression(text, |name| {
            saved.labelled(name).map(|addr| (addr, None))
        }) {
            return Ok(resolved.addr);
        }
        if let Some(addr) = maps::resolve_module_offset(&self.code.mappings, text) {
            return Ok(addr);
        }
        Err(format!(
            "`{text}` is not a saved label, module+0x… offset, or hex address"
        ))
    }

    /// `f`: find instructions that encode an address.
    pub(super) fn begin_find_refs(&mut self) {
        if self.tab == Tab::Code {
            self.ensure_code();
            let initial = self
                .code
                .ref_target
                .map_or_else(String::new, |addr| format!("0x{addr:x}"));
            return self.begin_input(InputKind::FindRefs, initial);
        }
        let Some(index) = self.saved.selected() else {
            return self.say(
                Level::Info,
                "Select a saved address first (Tab to the list), or use the Code tab.",
            );
        };
        let item = &self.saved.items[index];
        let addr = item.addr;
        let label = (!item.label.is_empty()).then(|| item.label.clone());
        self.find_refs(addr, label);
    }

    pub(super) fn submit_find_refs(&mut self, text: &str) {
        match self.resolve_code_address(text) {
            Ok(addr) => {
                let label = self
                    .saved
                    .items
                    .iter()
                    .find(|item| item.addr == addr && !item.label.is_empty())
                    .map(|item| item.label.clone());
                self.find_refs(addr, label);
            }
            Err(reason) => self.say(Level::Error, reason),
        }
    }

    /// The scan itself: all executable mappings, on a worker thread.
    pub(super) fn find_refs(&mut self, target: u64, label: Option<String>) {
        self.ensure_code();
        self.tab = Tab::Code;
        if self.xref_job.is_some() {
            return self.say(
                Level::Warn,
                "A reference scan is already running (Esc stops it)",
            );
        }
        if self.job.is_some() || self.range_job.is_some() {
            return self.say(Level::Warn, "scanmem is busy");
        }
        let Some(pid) = self.target.as_ref().map(|target| target.pid) else {
            return self.say(Level::Warn, "Pick a process first (p)");
        };
        if self.code.executable_count() == 0 {
            return self.say(
                Level::Warn,
                "No executable mappings to scan (is the process still alive?)",
            );
        }
        if let Some(refs) = self.code.cached(target) {
            let refs = refs.to_vec();
            let count = refs.len();
            let what = label.clone().map_or_else(
                || format!("0x{target:x}"),
                |label| format!("`{label}` (0x{target:x})"),
            );
            self.show_refs(target, label, refs);
            return self.say(
                Level::Info,
                format!("{count} reference(s) to {what}, from the last scan"),
            );
        }
        let mappings = self.code.mappings.clone();
        let control = Arc::new(ScanControl::new());
        let (tx, rx) = channel();
        let thread_control = control.clone();
        let spawned = thread::Builder::new()
            .name("xref-scan".into())
            .spawn(move || {
                run_xref(pid, &mappings, target, &thread_control, &tx);
            });
        match spawned {
            Ok(_) => {}
            Err(reason) => {
                return self.say(
                    Level::Error,
                    format!("could not start the reference scan: {reason}"),
                );
            }
        }
        let what = label.clone().map_or_else(
            || format!("0x{target:x}"),
            |label| format!("`{label}` (0x{target:x})"),
        );
        self.xref_job = Some(XrefJob {
            control,
            rx,
            target,
            label,
            since: Instant::now(),
        });
        self.say(
            Level::Info,
            format!("Searching executable memory for {what}…"),
        );
    }

    /// Picks up a finished scan, or reports that it was stopped.
    pub(super) fn drain_xref_job(&mut self) {
        let outcome = match &self.xref_job {
            None => return,
            Some(job) => match job.rx.try_recv() {
                Ok(outcome) => outcome,
                Err(TryRecvError::Empty) => return,
                Err(TryRecvError::Disconnected) => {
                    self.xref_job = None;
                    return self.say(Level::Error, "The reference scan ended unexpectedly.");
                }
            },
        };
        let Some(job) = self.xref_job.take() else {
            return;
        };
        self.redraw = true;
        if job.control.cancelled() {
            return self.say(Level::Warn, "Reference scan stopped.");
        }
        match outcome {
            XrefOutcome::Done(refs) => {
                let refs = self.code.remember_refs(job.target, refs);
                self.show_refs(job.target, job.label, refs);
            }
            XrefOutcome::Failed(reason) => self.say(Level::Error, reason),
        }
    }

    fn show_refs(&mut self, target: u64, label: Option<String>, refs: Vec<Reference>) {
        self.tab = Tab::Code;
        let count = refs.len();
        self.code.showing_refs = true;
        self.code.refs = refs;
        self.code.ref_target = Some(target);
        self.code.ref_label = label;
        self.code.ref_state.select((count > 0).then_some(0));
        self.code.focus = CodeFocus::Sidebar;
        let what = self.code.ref_label.clone().map_or_else(
            || format!("0x{target:x}"),
            |label| format!("`{label}` (0x{target:x})"),
        );
        if count == 0 {
            let hint = match maps::mapping_at(&self.code.mappings, target) {
                Some(mapping) if !mapping.executable() => {
                    "Static scans only see addresses encoded in instructions; values reached through pointers (heap, stack) usually have none."
                }
                _ => "No instruction encodes that address.",
            };
            self.say(Level::Warn, format!("No references to {what}. {hint}"));
        } else {
            self.say(Level::Ok, format!("{count} reference(s) to {what}"));
        }
    }

    /// `r` on the reference list: run the same search again.
    pub(super) fn rescan_refs(&mut self) {
        let Some(target) = self.code.ref_target else {
            return self.say(Level::Info, "Press f to search for references first.");
        };
        if !self.code.showing_refs {
            return self.say(Level::Info, "Press f to search for references first.");
        }
        if self.xref_job.is_some() {
            return self.say(Level::Warn, "A reference scan is already running");
        }
        let label = self.code.ref_label.clone();
        self.code.forget_refs(target);
        self.find_refs(target, label);
    }

    /// Enter on a mapping, a reference, or a branch.
    pub(super) fn code_open(&mut self) {
        if self.code.focus == CodeFocus::Disassembly {
            let Some(line) = self.code.lines.get(self.code.cursor) else {
                return;
            };
            return match line.target {
                Some(target) => {
                    self.jump_code(target, true);
                }
                None if line.flow == code::Flow::Indirect => self.say(
                    Level::Info,
                    "Indirect branch: its target is only known at runtime.",
                ),
                None => self.say(Level::Info, "This instruction has no direct target."),
            };
        }
        if self.code.showing_refs {
            let Some(reference) = self.code.selected_ref() else {
                return self.say(Level::Info, "No references to open.");
            };
            let addr = reference.addr;
            self.jump_code(addr, false);
        } else if let Some(mapping) = self.code.selected_mapping() {
            let start = mapping.start;
            self.jump_code(start, false);
        } else {
            self.say(Level::Info, "No executable mappings.");
        }
    }

    /// `u`: undo a jump, leave the reference list, or return to the sidebar.
    pub(super) fn code_back(&mut self) {
        if let Some((anchor, cursor)) = self.code.history.pop() {
            if self.jump_code(anchor, false) {
                self.code.cursor = cursor.min(self.code.lines.len().saturating_sub(1));
                self.code.ensure_visible();
            }
            return;
        }
        // A jump from the reference list returns to that list first.
        if self.code.showing_refs && self.code.focus == CodeFocus::Disassembly {
            self.code.focus = CodeFocus::Sidebar;
            return;
        }
        if self.code.showing_refs {
            self.code.showing_refs = false;
            self.code.focus = CodeFocus::Sidebar;
            return;
        }
        self.code.focus = CodeFocus::Sidebar;
    }

    /// Esc on the Code tab: stop a scan, then step back.
    pub(super) fn code_cancel(&mut self) {
        if let Some(job) = &self.xref_job {
            job.control.cancel();
            self.say(Level::Info, "Stopping the reference scan…");
            return;
        }
        self.code_back();
    }

    pub(super) fn toggle_code_bytes(&mut self) {
        self.code.bytes = !self.code.bytes;
    }

    pub(super) fn code_move(&mut self, delta: isize) {
        match self.code.focus {
            CodeFocus::Disassembly => self.code.move_cursor(delta),
            CodeFocus::Sidebar if self.code.showing_refs => self.code.move_ref(delta),
            CodeFocus::Sidebar => self.code.move_mapping(delta),
        }
    }

    pub(super) fn switch_code_focus(&mut self) {
        self.code.focus = match self.code.focus {
            CodeFocus::Sidebar => CodeFocus::Disassembly,
            CodeFocus::Disassembly => CodeFocus::Sidebar,
        };
    }

    /// Label or address of the cursor line, for the pane title.
    pub fn code_cursor_label(&self) -> Option<String> {
        let line = self.code.lines.get(self.code.cursor)?;
        Some(maps::format_module_offset(&self.code.mappings, line.addr))
    }

    /// Kind name used in the reference list.
    pub fn ref_kind_text(kind: RefKind) -> &'static str {
        match kind {
            RefKind::RipRelative => "rip",
            RefKind::Absolute => "abs",
            RefKind::Immediate => "imm",
        }
    }
}

/// The scan thread's body: opens its own memory handle, scans, reports back.
fn run_xref(
    pid: u32,
    mappings: &[Mapping],
    target: u64,
    control: &ScanControl,
    tx: &Sender<XrefOutcome>,
) {
    let outcome = match MemIo::open(pid) {
        Ok(memory) => XrefOutcome::Done(code::scan(&memory, mappings, target, control)),
        Err(reason) => XrefOutcome::Failed(format!(
            "cannot open /proc/{pid}/mem: {reason} (try running as root)"
        )),
    };
    let _ = tx.send(outcome);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mappings_and_cursor_move_within_bounds() {
        let mut view = CodeView::new();
        view.mappings = crate::maps::parse_maps(
            "1000-2000 r-xp 00000000 00:00 1 /bin/a\n\
             3000-4000 r--p 00000000 00:00 1 /bin/a\n\
             5000-6000 r-xp 00000000 00:00 1 /bin/b\n",
        );
        assert_eq!(view.executable_count(), 2);
        view.move_mapping(5);
        assert_eq!(view.selected_mapping().map(|m| m.start), Some(0x5000));
        view.move_mapping(-1);
        assert_eq!(view.selected_mapping().map(|m| m.start), Some(0x1000));
        view.move_mapping(-1);
        assert_eq!(view.selected_mapping().map(|m| m.start), Some(0x1000));
    }

    #[test]
    fn the_cursor_scrolls_the_window() {
        let mut view = CodeView::new();
        view.viewport = 4;
        view.lines = (0..20)
            .map(|i| DecodedLine {
                addr: 0x1000 + i,
                bytes: vec![0x90],
                text: "nop".into(),
                flow: code::Flow::Normal,
                target: None,
            })
            .collect();
        view.move_cursor(10);
        assert_eq!(view.cursor, 10);
        assert_eq!(view.scroll, 7); // cursor is the last visible line
        view.move_cursor(-10);
        assert_eq!(view.scroll, 0);
    }

    #[test]
    fn the_scan_cache_is_cleared_with_the_target() {
        let mut view = CodeView::new();
        view.pid = Some(1);
        view.remember_refs(0x1000, Vec::new());
        assert!(view.cached(0x1000).is_some());
        view.forget_refs(0x1000);
        assert!(view.cached(0x1000).is_none());
        view.remember_refs(0x2000, Vec::new());
        view.reset(None);
        assert!(view.cached(0x2000).is_none());
    }

    #[test]
    fn ref_kinds_have_short_names() {
        assert_eq!(App::ref_kind_text(RefKind::RipRelative), "rip");
        assert_eq!(App::ref_kind_text(RefKind::Absolute), "abs");
        assert_eq!(App::ref_kind_text(RefKind::Immediate), "imm");
    }
}
