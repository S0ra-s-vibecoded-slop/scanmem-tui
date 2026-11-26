//! The Code tab: executable mappings, disassembly, and the reference scan.
//!
//! The tab is a browser, not a decompiler. Its main job is the static
//! cross-reference search: which instructions encode a given address? The
//! disassembly exists to give those hits somewhere to land.

use super::{App, InputKind, Level, Tab};
use crate::code::{
    self, AddrRange, DecodedLine, Mention, Pointer, RefKind, Reference, SavedRef, TraceOptions,
    TracePhase, TraceReport, Window,
};
use crate::maps::{self, Mapping, OffsetBase};
use crate::memio::MemIo;
use crate::scanner::ScanControl;
use ratatui::widgets::ListState;
use std::collections::{HashMap, VecDeque};
use std::hash::Hash;
use std::sync::Arc;
use std::sync::atomic::{AtomicU8, AtomicUsize, Ordering};
use std::sync::mpsc::{Receiver, Sender, TryRecvError, channel};
use std::thread;
use std::time::Instant;

/// How many finished scans stay cached for the session.
const CACHE_LIMIT: usize = 8;
/// How many jumps the `u` history remembers.
const HISTORY_LIMIT: usize = 128;
/// How many pointer hops the `Esc` trail remembers.
const POINTER_TRAIL_LIMIT: usize = 32;
/// Bytes read at a time for the data view.
const DATA_BYTES: usize = 16 * 1024;
/// Context above the cursor when the data view opens or rebases.
const DATA_LOOKBACK: u64 = 1024;

/// What Analyze does first, driven by the mapping's permissions.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AnalyzeRoute {
    Code,
    Data,
}

pub fn analyze_route(mapping: &Mapping) -> AnalyzeRoute {
    if mapping.executable() {
        AnalyzeRoute::Code
    } else {
        AnalyzeRoute::Data
    }
}

/// Which half of the Code tab has the keyboard.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CodeFocus {
    Sidebar,
    Disassembly,
}

/// A byte-oriented view of a mapping, shown instead of disassembly when the
/// address is data.
pub struct DataView {
    pub window: code::ByteWindow,
    /// Bounds of the mapping the window was read from.
    pub lo: u64,
    pub hi: u64,
    pub perms: String,
    pub cursor: u64,
    pub per_row: usize,
    /// First visible row, kept in step with the cursor by the renderer.
    pub scroll: usize,
}

impl DataView {
    pub fn rows(&self) -> Vec<code::HexRow> {
        code::hex_rows(&self.window, self.per_row)
    }

    pub fn cursor_row(&self) -> usize {
        let offset = self.cursor.saturating_sub(self.window.start);
        let offset = usize::try_from(offset).unwrap_or(usize::MAX);
        offset / self.per_row.max(1)
    }

    pub fn contains(&self, addr: u64) -> bool {
        (self.window.start..self.window.end()).contains(&addr)
    }
}

/// A pointer list the `Esc` chain can return to.
pub struct PointerStop {
    pub target: u64,
    pub label: Option<String>,
    pub pointers: Vec<Pointer>,
    pub selected: Option<usize>,
}

/// What the sidebar is listing.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Sidebar {
    Mappings,
    Refs,
    Pointers,
}

/// A small cache: inserting an existing key refreshes it, and the oldest
/// entry is dropped beyond `CACHE_LIMIT`.
struct Recent<K: Eq + Hash + Copy, V> {
    map: HashMap<K, V>,
    order: VecDeque<K>,
}

impl<K: Eq + Hash + Copy, V> Recent<K, V> {
    fn new() -> Recent<K, V> {
        Recent {
            map: HashMap::new(),
            order: VecDeque::new(),
        }
    }

    fn get(&self, key: &K) -> Option<&V> {
        self.map.get(key)
    }

    fn insert(&mut self, key: K, value: V) {
        self.order.retain(|other| *other != key);
        self.order.push_back(key);
        while self.order.len() > CACHE_LIMIT {
            if let Some(old) = self.order.pop_front() {
                self.map.remove(&old);
            }
        }
        self.map.insert(key, value);
    }

    fn remove(&mut self, key: &K) {
        self.map.remove(key);
        self.order.retain(|other| other != key);
    }

    fn clear(&mut self) {
        self.map.clear();
        self.order.clear();
    }
}

/// Everything the Code tab shows. Reset whenever the target changes.
pub struct CodeView {
    pub pid: Option<u32>,
    /// Every mapping, so module names and offsets stay available.
    pub mappings: Vec<Mapping>,
    /// Selection index into the executable mappings.
    pub selected_mapping: usize,
    /// What the sidebar is listing.
    pub sidebar: Sidebar,
    pub refs: Vec<Reference>,
    pub ref_state: ListState,
    pub ref_range: Option<AddrRange>,
    pub ref_label: Option<String>,
    /// Where `Esc` returns from the reference list.
    refs_return: Sidebar,
    pub pointers: Vec<Pointer>,
    pub pointer_state: ListState,
    pub pointer_target: Option<u64>,
    pub pointer_label: Option<String>,
    /// Previous pointer lists, newest last, for `Esc` on a chain.
    pub pointer_trail: Vec<PointerStop>,
    pub anchor: Option<u64>,
    pub lines: Vec<DecodedLine>,
    /// Annotation text per instruction address, for visible lines.
    pub notes: HashMap<u64, String>,
    /// The hex view, when the pane is showing data instead of code.
    pub data: Option<DataView>,
    pub cursor: usize,
    pub scroll: usize,
    pub viewport: usize,
    pub bytes: bool,
    pub focus: CodeFocus,
    /// Bounds of the mapping the current window was decoded from.
    pub view_lo: u64,
    pub view_hi: u64,
    /// (anchor, cursor) pairs, so `u` can retrace a jump.
    pub history: Vec<(u64, usize)>,
    /// Finished scans per `(pid, range)`, so reopening is instant.
    ref_cache: Recent<(u32, AddrRange), Vec<Reference>>,
    /// Finished pointer scans per `(pid, target)`.
    pointer_cache: Recent<(u32, u64), Vec<Pointer>>,
    /// The Analyze report on screen, if any.
    pub trace: Option<TraceReport>,
    /// The address `r` re-traces and `Esc` returns to in the hex view.
    pub trace_target: Option<u64>,
    pub trace_label: Option<String>,
    /// Selected path in the report.
    pub trace_state: ListState,
    /// First report line shown; the renderer keeps the selected path visible.
    pub trace_scroll: usize,
    /// Finished traces per `(pid, target)`.
    trace_cache: Recent<(u32, u64), TraceReport>,
}

impl CodeView {
    pub fn new() -> CodeView {
        CodeView {
            pid: None,
            mappings: Vec::new(),
            selected_mapping: 0,
            sidebar: Sidebar::Mappings,
            refs: Vec::new(),
            ref_state: ListState::default(),
            ref_range: None,
            ref_label: None,
            refs_return: Sidebar::Mappings,
            pointers: Vec::new(),
            pointer_state: ListState::default(),
            pointer_target: None,
            pointer_label: None,
            pointer_trail: Vec::new(),
            anchor: None,
            lines: Vec::new(),
            notes: HashMap::new(),
            data: None,
            cursor: 0,
            scroll: 0,
            viewport: 20,
            bytes: false,
            focus: CodeFocus::Sidebar,
            view_lo: 0,
            view_hi: 0,
            history: Vec::new(),
            ref_cache: Recent::new(),
            pointer_cache: Recent::new(),
            trace: None,
            trace_target: None,
            trace_label: None,
            trace_state: ListState::default(),
            trace_scroll: 0,
            trace_cache: Recent::new(),
        }
    }

    /// Forgets the old process's addresses and loads the new one's maps.
    pub fn reset(&mut self, pid: Option<u32>) {
        self.pid = pid;
        self.mappings = pid
            .and_then(|pid| maps::read_maps(pid).ok())
            .unwrap_or_default();
        self.selected_mapping = 0;
        self.sidebar = Sidebar::Mappings;
        self.refs.clear();
        self.ref_state.select(None);
        self.ref_range = None;
        self.ref_label = None;
        self.refs_return = Sidebar::Mappings;
        self.pointers.clear();
        self.pointer_state.select(None);
        self.pointer_target = None;
        self.pointer_label = None;
        self.pointer_trail.clear();
        self.anchor = None;
        self.lines.clear();
        self.notes.clear();
        self.data = None;
        self.cursor = 0;
        self.scroll = 0;
        self.focus = CodeFocus::Sidebar;
        self.view_lo = 0;
        self.view_hi = 0;
        self.history.clear();
        self.ref_cache.clear();
        self.pointer_cache.clear();
        self.trace = None;
        self.trace_target = None;
        self.trace_label = None;
        self.trace_state.select(None);
        self.trace_scroll = 0;
        self.trace_cache.clear();
    }

    /// Re-reads the maps and keeps the sidebar selection on the same region.
    /// Returns whether anything changed; a failed read leaves the old maps.
    pub fn refresh_maps(&mut self) -> bool {
        let Some(pid) = self.pid else {
            return false;
        };
        let Ok(mappings) = maps::read_maps(pid) else {
            return false;
        };
        if mappings == self.mappings {
            return false;
        }
        let selected = self.selected_mapping().map(|mapping| mapping.start);
        self.mappings = mappings;
        let starts: Vec<u64> = self.executable().map(|mapping| mapping.start).collect();
        self.selected_mapping = maps::reselect_index(&starts, selected, self.selected_mapping);
        true
    }

    /// Retries a failed maps read for the same process (permissions, or a
    /// process that was still starting when it was attached).
    pub fn reload_maps(&mut self) {
        self.refresh_maps();
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

    pub fn selected_pointer(&self) -> Option<&Pointer> {
        self.pointer_state
            .selected()
            .and_then(|index| self.pointers.get(index))
    }

    pub fn cached_refs(&self, range: AddrRange) -> Option<&[Reference]> {
        let pid = self.pid?;
        self.ref_cache.get(&(pid, range)).map(Vec::as_slice)
    }

    pub fn remember_refs(&mut self, range: AddrRange, refs: Vec<Reference>) -> Vec<Reference> {
        if let Some(pid) = self.pid {
            self.ref_cache.insert((pid, range), refs.clone());
        }
        refs
    }

    pub fn forget_refs(&mut self, range: AddrRange) {
        if let Some(pid) = self.pid {
            self.ref_cache.remove(&(pid, range));
        }
    }

    pub fn cached_pointers(&self, target: u64) -> Option<&[Pointer]> {
        let pid = self.pid?;
        self.pointer_cache.get(&(pid, target)).map(Vec::as_slice)
    }

    pub fn remember_pointers(&mut self, target: u64, pointers: Vec<Pointer>) -> Vec<Pointer> {
        if let Some(pid) = self.pid {
            self.pointer_cache.insert((pid, target), pointers.clone());
        }
        pointers
    }

    pub fn forget_pointers(&mut self, target: u64) {
        if let Some(pid) = self.pid {
            self.pointer_cache.remove(&(pid, target));
        }
    }

    pub fn cached_trace(&self, target: u64) -> Option<&TraceReport> {
        let pid = self.pid?;
        self.trace_cache.get(&(pid, target))
    }

    pub fn remember_trace(&mut self, report: TraceReport) -> TraceReport {
        if let Some(pid) = self.pid {
            self.trace_cache
                .insert((pid, report.target), report.clone());
        }
        report
    }

    pub fn forget_trace(&mut self, target: u64) {
        if let Some(pid) = self.pid {
            self.trace_cache.remove(&(pid, target));
        }
    }

    pub fn selected_path(&self) -> Option<&code::TracePath> {
        let report = self.trace.as_ref()?;
        report.paths.get(self.trace_state.selected()?)
    }

    pub fn set_window(&mut self, window: Window, cursor: usize, lo: u64, hi: u64) {
        self.anchor = Some(
            window
                .lines
                .get(cursor)
                .map_or(window.start, |line| line.addr),
        );
        self.lines = window.lines;
        self.cursor = cursor.min(self.lines.len().saturating_sub(1));
        self.scroll = 0;
        self.view_lo = lo;
        self.view_hi = hi;
        self.notes.clear();
        self.ensure_visible();
    }

    /// True when the pointer list has somewhere to return to.
    pub fn pointer_hop(&self) -> usize {
        self.pointer_trail.len() + 1
    }

    pub fn push_pointer_stop(&mut self) {
        let Some(target) = self.pointer_target else {
            return;
        };
        if self.pointer_trail.len() >= POINTER_TRAIL_LIMIT {
            self.pointer_trail.remove(0);
        }
        self.pointer_trail.push(PointerStop {
            target,
            label: self.pointer_label.clone(),
            pointers: self.pointers.clone(),
            selected: self.pointer_state.selected(),
        });
    }

    pub fn pop_pointer_stop(&mut self) -> Option<PointerStop> {
        self.pointer_trail.pop()
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

    pub fn move_sidebar(&mut self, delta: isize) {
        let (state, count) = match self.sidebar {
            Sidebar::Mappings => return self.move_mapping(delta),
            Sidebar::Refs => (&mut self.ref_state, self.refs.len()),
            Sidebar::Pointers => (&mut self.pointer_state, self.pointers.len()),
        };
        if count == 0 {
            state.select(None);
            return;
        }
        let current = state.selected().unwrap_or(0).cast_signed();
        let max = count.cast_signed() - 1;
        let next = current.saturating_add(delta).clamp(0, max).cast_unsigned();
        state.select(Some(next));
    }
}

/// A reference scan running on its own thread.
pub struct XrefJob {
    pub control: Arc<ScanControl>,
    rx: Receiver<XrefOutcome>,
    pub range: AddrRange,
    pub label: Option<String>,
    /// Where the finished list should return to on Esc.
    ret: Sidebar,
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

/// A pointer scan running on its own thread.
pub struct PointerJob {
    pub control: Arc<ScanControl>,
    rx: Receiver<PointerOutcome>,
    pub target: u64,
    pub label: Option<String>,
    pub since: Instant,
}

impl PointerJob {
    /// Progress as a percentage, when the total is known.
    pub fn percent(&self) -> Option<u64> {
        let (done, total) = self.control.progress();
        (total > 0).then(|| (done * 100 / total).min(100))
    }
}

enum PointerOutcome {
    Done(Vec<Pointer>),
    Failed(String),
}

const PHASE_REFS: u8 = 0;
const PHASE_LEVEL: u8 = 1;
const PHASE_ROOTS: u8 = 2;
const PHASE_DONE: u8 = 3;

/// The worker's phase, shared with the status line without waking it up.
pub struct TraceProgress {
    phase: AtomicU8,
    level: AtomicUsize,
    depth: AtomicUsize,
}

impl TraceProgress {
    fn new(depth: usize) -> TraceProgress {
        TraceProgress {
            phase: AtomicU8::new(PHASE_REFS),
            level: AtomicUsize::new(0),
            depth: AtomicUsize::new(depth),
        }
    }

    fn set(&self, phase: TracePhase) {
        match phase {
            TracePhase::Refs => self.phase.store(PHASE_REFS, Ordering::Relaxed),
            TracePhase::Level(level) => {
                self.level.store(level, Ordering::Relaxed);
                self.phase.store(PHASE_LEVEL, Ordering::Relaxed);
            }
            TracePhase::Roots => self.phase.store(PHASE_ROOTS, Ordering::Relaxed),
            TracePhase::Done => self.phase.store(PHASE_DONE, Ordering::Relaxed),
        }
    }

    pub fn text(&self) -> String {
        match self.phase.load(Ordering::Relaxed) {
            PHASE_REFS => "refs".to_string(),
            PHASE_LEVEL => format!(
                "level {}/{}",
                self.level.load(Ordering::Relaxed) + 1,
                self.depth.load(Ordering::Relaxed)
            ),
            PHASE_ROOTS => "roots".to_string(),
            _ => "done".to_string(),
        }
    }
}

/// A trace running on its own thread.
pub struct TraceJob {
    pub control: Arc<ScanControl>,
    rx: Receiver<TraceOutcome>,
    pub target: u64,
    pub label: Option<String>,
    pub since: Instant,
    pub progress: Arc<TraceProgress>,
}

impl TraceJob {
    /// Progress as a percentage, when the total is known.
    pub fn percent(&self) -> Option<u64> {
        let (done, total) = self.control.progress();
        (total > 0).then(|| (done * 100 / total).min(100))
    }
}

enum TraceOutcome {
    Done(Box<TraceReport>),
    Failed(String),
}

impl App {
    /// Keeps the Code tab's maps in step with the target.
    pub(super) fn reset_code(&mut self, pid: Option<u32>) {
        if let Some(job) = self.xref_job.take() {
            job.control.cancel();
        }
        if let Some(job) = self.pointer_job.take() {
            job.control.cancel();
        }
        if let Some(job) = self.trace_job.take() {
            job.control.cancel();
        }
        self.code.reset(pid);
        self.last_maps = Instant::now();
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
        let Some(mapping) = self.mapped_region(addr) else {
            return self.say(
                Level::Error,
                format!("0x{addr:x} is not mapped in this process"),
            );
        };
        if !mapping.executable() {
            self.show_data(addr);
            return;
        }
        self.jump_code(addr, true);
    }

    /// `x`: one action for a saved/result address. Code disassembles; data
    /// opens the hex view and traces backwards automatically.
    pub(super) fn analyze_address(&mut self, addr: u64, label: Option<String>) {
        self.ensure_code();
        self.tab = Tab::Code;
        let Some(mapping) = self.mapped_region(addr) else {
            return self.say(
                Level::Error,
                format!("0x{addr:x} is not mapped in this process"),
            );
        };
        if analyze_route(&mapping) == AnalyzeRoute::Code {
            self.jump_code(addr, true);
            return;
        }
        if !self.show_data(addr) {
            return;
        }
        let function = self.executable_value(addr);
        self.start_trace(addr, label);
        if let Some(target) = function {
            let to = maps::format_module_offset(&self.code.mappings, target);
            self.say(
                Level::Info,
                format!(
                    "This slot holds code at {to}; Enter follows it, or read the trace report."
                ),
            );
        }
    }

    /// Whether `addr` currently holds a pointer into executable memory (a
    /// function pointer or vtable slot worth offering to follow).
    fn executable_value(&self, addr: u64) -> Option<u64> {
        let memory = self.target.as_ref()?.memory().ok()?;
        let mut buf = [0_u8; 8];
        memory.read_into(addr, &mut buf).ok()?;
        let value = u64::from_le_bytes(buf);
        let mapping = maps::mapping_at(&self.code.mappings, value)?;
        mapping.executable().then_some(value)
    }

    /// Starts (or replays) the bounded trace for `target`.
    fn start_trace(&mut self, target: u64, label: Option<String>) {
        if self.trace_job.is_some() {
            return self.say(Level::Warn, "A trace is already running (Esc stops it)");
        }
        if self.xref_job.is_some() || self.pointer_job.is_some() {
            return self.say(Level::Warn, "Another Code scan is running (Esc stops it)");
        }
        if self.job.is_some() || self.range_job.is_some() {
            return self.say(Level::Warn, "scanmem is busy");
        }
        let Some(pid) = self.target.as_ref().map(|target| target.pid) else {
            return self.say(Level::Warn, "Pick a process first (p)");
        };
        if self.code.mappings.is_empty() {
            return self.say(
                Level::Warn,
                "No mappings to trace (is the process still alive?)",
            );
        }
        self.code.trace_target = Some(target);
        self.code.trace_label.clone_from(&label);
        if let Some(report) = self.code.cached_trace(target).cloned() {
            self.show_trace(report);
            return;
        }
        let mappings = self.code.mappings.clone();
        let depth = TraceOptions::default().max_depth;
        let progress = Arc::new(TraceProgress::new(depth));
        let control = Arc::new(ScanControl::new());
        let (tx, rx) = channel();
        let thread_control = control.clone();
        let thread_progress = progress.clone();
        let thread_label = label.clone();
        let spawned = thread::Builder::new().name("trace".into()).spawn(move || {
            run_trace(
                pid,
                &mappings,
                target,
                thread_label.as_deref(),
                &thread_progress,
                &thread_control,
                &tx,
            );
        });
        match spawned {
            Ok(_) => {}
            Err(reason) => {
                return self.say(Level::Error, format!("could not start the trace: {reason}"));
            }
        }
        self.trace_job = Some(TraceJob {
            control,
            rx,
            target,
            label: label.clone(),
            since: Instant::now(),
            progress,
        });
        let described = what(AddrRange::one(target), label);
        self.say(
            Level::Info,
            format!("Analyzing {described}: refs, then pointer levels… (Esc stops)"),
        );
    }

    fn show_trace(&mut self, report: TraceReport) {
        self.tab = Tab::Code;
        self.code.data = None;
        let count = report.paths.len();
        let stats = report.stats;
        let refs = report.refs.len();
        let what = what(
            AddrRange::one(report.target),
            (!report.target_label.is_empty()).then(|| report.target_label.clone()),
        );
        self.code.trace_target = Some(report.target);
        self.code.trace = Some(report);
        self.code.trace_state.select((count > 0).then_some(0));
        self.code.trace_scroll = 0;
        self.code.focus = CodeFocus::Disassembly;
        self.redraw = true;
        if stats.cancelled {
            self.say(
                Level::Warn,
                format!(
                    "Trace stopped after {} level(s); showing partial candidates for {what}.",
                    stats.levels
                ),
            );
        } else if count == 0 {
            let cap = if stats.truncated {
                " The search hit a cap, so it is partial."
            } else {
                ""
            };
            self.say(
                Level::Warn,
                format!(
                    "No static pointer path to {what} at depth {}. {refs} direct ref(s).{cap} Registers and computed accesses cannot be followed statically.",
                    stats.levels.max(1)
                ),
            );
        } else {
            let level = if stats.truncated || stats.cancelled {
                Level::Warn
            } else {
                Level::Ok
            };
            let partial = if stats.truncated {
                " (capped; partial)"
            } else {
                ""
            };
            self.say(
                level,
                format!(
                    "{refs} direct ref(s); {count} candidate path(s); {} static root(s){partial}.",
                    stats.roots
                ),
            );
        }
    }

    /// Closes the report and returns to the hex view it replaced.
    fn close_trace(&mut self) {
        let Some(report) = self.code.trace.take() else {
            return;
        };
        self.redraw = true;
        if self.show_data(report.target) {
            self.say(
                Level::Info,
                "Back to the hex view. Esc returns to the disassembly.",
            );
        } else {
            self.code.focus = CodeFocus::Disassembly;
        }
    }

    /// The mapping containing `addr`, re-reading the maps once when the first
    /// lookup misses. Modules load after attach all the time (Wine, dlopen).
    fn mapped_region(&mut self, addr: u64) -> Option<Mapping> {
        if let Some(mapping) = maps::mapping_at(&self.code.mappings, addr) {
            return Some(mapping.clone());
        }
        self.code.reload_maps();
        maps::mapping_at(&self.code.mappings, addr).cloned()
    }

    /// Opens the hex view at `addr`, replacing any current disassembly view
    /// on screen but keeping it for `Esc`.
    fn show_data(&mut self, addr: u64) -> bool {
        self.ensure_code();
        self.tab = Tab::Code;
        let Some(mapping) = self.mapped_region(addr) else {
            self.say(
                Level::Error,
                format!("0x{addr:x} is not mapped in this process"),
            );
            return false;
        };
        let per_row = self.code.data.as_ref().map_or(16, |data| data.per_row);
        let Some(memory) = self.target.as_ref().and_then(|target| target.memory().ok()) else {
            self.say(
                Level::Warn,
                "Cannot read this process's memory (try running as root)",
            );
            return false;
        };
        let lo = mapping.start;
        let hi = mapping.end;
        let start = addr.saturating_sub(DATA_LOOKBACK).max(lo);
        let len = usize::try_from((hi - start).min(DATA_BYTES as u64)).unwrap_or(0);
        if len == 0 {
            self.say(Level::Warn, format!("No bytes to show at 0x{addr:x}"));
            return false;
        }
        let window = code::read_reporting(memory, start, len);
        self.code.data = Some(DataView {
            window,
            lo,
            hi,
            perms: mapping.perms.text(),
            cursor: addr,
            per_row,
            scroll: 0,
        });
        self.code.focus = CodeFocus::Disassembly;
        self.say(
            Level::Info,
            format!(
                "0x{addr:x} is data ({}, {}); hex view: f refs, P ptrs, b width",
                mapping.display_name(),
                mapping.perms.text()
            ),
        );
        self.redraw = true;
        true
    }

    /// Decodes around `addr`; `remember` pushes the current view onto the
    /// history first. Keeps the old view when the new one cannot be decoded.
    fn jump_code(&mut self, addr: u64, remember: bool) -> bool {
        self.ensure_code();
        let Some(mapping) = self.mapped_region(addr) else {
            self.say(
                Level::Error,
                format!("0x{addr:x} is not mapped in this process"),
            );
            return false;
        };
        if !mapping.executable() {
            return self.show_data(addr);
        }
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
        self.code
            .set_window(window, cursor, mapping.start, mapping.end);
        self.code.data = None;
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
        match self.resolve_code_target(text) {
            Ok((addr, base)) => {
                self.open_code_at(addr);
                if base == Some(OffsetBase::ExecSegment) {
                    self.say(
                        Level::Info,
                        format!("`{text}` used the executable segment's base"),
                    );
                }
            }
            Err(reason) => self.say(Level::Error, reason),
        }
    }

    fn resolve_code_target(&self, text: &str) -> Result<(u64, Option<OffsetBase>), String> {
        let saved = &self.saved;
        if let Ok(resolved) = crate::address::resolve_expression(text, |name| {
            saved.labelled(name).map(|addr| (addr, None))
        }) {
            return Ok((resolved.addr, None));
        }
        if let Some((addr, base)) = maps::resolve_module_offset_with_base(&self.code.mappings, text)
        {
            return Ok((addr, Some(base)));
        }
        Err(format!(
            "`{text}` is not a saved label, module+0x… offset, or hex address"
        ))
    }

    fn resolve_code_address(&self, text: &str) -> Result<u64, String> {
        self.resolve_code_target(text).map(|(addr, _)| addr)
    }

    /// `f`: find instructions that encode an address or a range of them.
    pub(super) fn begin_find_refs(&mut self) {
        if self.tab == Tab::Code {
            self.ensure_code();
            let initial = self
                .code
                .data
                .as_ref()
                .map(|data| format!("0x{:x}", data.cursor))
                .or_else(|| self.code.ref_range.map(|range| range.to_string()))
                .unwrap_or_default();
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
        match self.resolve_code_range(text) {
            Ok(range) => {
                let label = if range.is_single() {
                    self.saved
                        .items
                        .iter()
                        .find(|item| item.addr == range.lo && !item.label.is_empty())
                        .map(|item| item.label.clone())
                } else {
                    None
                };
                self.find_refs_in(range, label, Sidebar::Mappings);
            }
            Err(reason) => self.say(Level::Error, reason),
        }
    }

    /// `P`: find memory slots that hold a pointer to an address.
    pub(super) fn begin_find_pointers(&mut self) {
        self.ensure_code();
        let slot = (self.code.sidebar == Sidebar::Pointers)
            .then(|| self.code.selected_pointer().map(|pointer| pointer.slot))
            .flatten();
        let traced = self
            .code
            .selected_path()
            .and_then(|path| path.hops.first().map(|hop| hop.slot));
        let cursor = traced
            .or(slot)
            .or_else(|| self.code.data.as_ref().map(|data| data.cursor))
            .or_else(|| self.code.lines.get(self.code.cursor).map(|line| line.addr));
        let initial = cursor
            .or(self.code.pointer_target)
            .or(self.code.anchor)
            .map_or_else(String::new, |addr| format!("0x{addr:x}"));
        self.begin_input(InputKind::FindPointers, initial);
    }

    pub(super) fn submit_find_pointers(&mut self, text: &str) {
        match self.resolve_code_address(text) {
            Ok(addr) => {
                let label = self
                    .saved
                    .items
                    .iter()
                    .find(|item| item.addr == addr && !item.label.is_empty())
                    .map(|item| item.label.clone());
                self.find_pointers(addr, label);
            }
            Err(reason) => self.say(Level::Error, reason),
        }
    }

    /// An address, or `a..b`, where each end may be a label, `module+0x…`
    /// offset, or hex address.
    fn resolve_code_range(&self, text: &str) -> Result<AddrRange, String> {
        if let Some((lo, hi)) = text.split_once("..") {
            let lo = self.resolve_code_address(lo.trim())?;
            let hi = self.resolve_code_address(hi.trim())?;
            return Ok(AddrRange::span(lo, hi));
        }
        Ok(AddrRange::one(self.resolve_code_address(text)?))
    }

    /// The scan itself: all executable mappings, on a worker thread.
    pub(super) fn find_refs(&mut self, target: u64, label: Option<String>) {
        self.find_refs_in(AddrRange::one(target), label, Sidebar::Mappings);
    }

    fn find_refs_in(&mut self, range: AddrRange, label: Option<String>, ret: Sidebar) {
        self.ensure_code();
        self.tab = Tab::Code;
        if self.xref_job.is_some() {
            return self.say(
                Level::Warn,
                "A reference scan is already running (Esc stops it)",
            );
        }
        if self.pointer_job.is_some() {
            return self.say(
                Level::Warn,
                "A pointer scan is already running (Esc stops it)",
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
        if let Some(refs) = self.code.cached_refs(range) {
            let refs = refs.to_vec();
            let count = refs.len();
            let what = what(range, label.clone());
            self.show_refs(range, label, refs, ret);
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
                run_xref(pid, &mappings, range, &thread_control, &tx);
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
        let described = what(range, label.clone());
        self.xref_job = Some(XrefJob {
            control,
            rx,
            range,
            label,
            ret,
            since: Instant::now(),
        });
        self.say(
            Level::Info,
            format!("Searching executable memory for {described}…"),
        );
    }

    /// Finds pointers to `target` in every readable mapping, on a worker thread.
    pub(super) fn find_pointers(&mut self, target: u64, label: Option<String>) {
        self.ensure_code();
        self.tab = Tab::Code;
        if self.pointer_job.is_some() {
            return self.say(
                Level::Warn,
                "A pointer scan is already running (Esc stops it)",
            );
        }
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
        if self.code.mappings.is_empty() {
            return self.say(
                Level::Warn,
                "No mappings to scan (is the process still alive?)",
            );
        }
        if let Some(pointers) = self.code.cached_pointers(target) {
            let pointers = pointers.to_vec();
            let count = pointers.len();
            let what = what(AddrRange::one(target), label.clone());
            self.show_pointers(target, label, pointers);
            return self.say(
                Level::Info,
                format!("{count} pointer(s) to {what}, from the last scan"),
            );
        }
        let mappings = self.code.mappings.clone();
        let control = Arc::new(ScanControl::new());
        let (tx, rx) = channel();
        let thread_control = control.clone();
        let spawned = thread::Builder::new()
            .name("pointer-scan".into())
            .spawn(move || {
                run_pointers(pid, &mappings, target, &thread_control, &tx);
            });
        match spawned {
            Ok(_) => {}
            Err(reason) => {
                return self.say(
                    Level::Error,
                    format!("could not start the pointer scan: {reason}"),
                );
            }
        }
        let described = what(AddrRange::one(target), label.clone());
        self.pointer_job = Some(PointerJob {
            control,
            rx,
            target,
            label,
            since: Instant::now(),
        });
        self.say(
            Level::Info,
            format!("Searching readable memory for pointers to {described}…"),
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
                let refs = self.code.remember_refs(job.range, refs);
                self.show_refs(job.range, job.label, refs, job.ret);
            }
            XrefOutcome::Failed(reason) => self.say(Level::Error, reason),
        }
    }

    /// Picks up a finished pointer scan, or reports that it was stopped.
    pub(super) fn drain_pointer_job(&mut self) {
        let outcome = match &self.pointer_job {
            None => return,
            Some(job) => match job.rx.try_recv() {
                Ok(outcome) => outcome,
                Err(TryRecvError::Empty) => return,
                Err(TryRecvError::Disconnected) => {
                    self.pointer_job = None;
                    return self.say(Level::Error, "The pointer scan ended unexpectedly.");
                }
            },
        };
        let Some(job) = self.pointer_job.take() else {
            return;
        };
        self.redraw = true;
        if job.control.cancelled() {
            return self.say(Level::Warn, "Pointer scan stopped.");
        }
        match outcome {
            PointerOutcome::Done(pointers) => {
                let pointers = self.code.remember_pointers(job.target, pointers);
                self.show_pointers(job.target, job.label, pointers);
            }
            PointerOutcome::Failed(reason) => self.say(Level::Error, reason),
        }
    }

    /// Picks up a finished trace, including a partial report after `Esc`.
    pub(super) fn drain_trace_job(&mut self) {
        let outcome = match &self.trace_job {
            None => return,
            Some(job) => match job.rx.try_recv() {
                Ok(outcome) => outcome,
                Err(TryRecvError::Empty) => return,
                Err(TryRecvError::Disconnected) => {
                    self.trace_job = None;
                    return self.say(Level::Error, "The trace ended unexpectedly.");
                }
            },
        };
        self.trace_job.take();
        self.redraw = true;
        match outcome {
            TraceOutcome::Done(report) => {
                let report = self.code.remember_trace(*report);
                let cancelled = report.stats.cancelled;
                self.show_trace(report);
                if cancelled {
                    self.say(
                        Level::Warn,
                        "Trace stopped; partial candidates are still shown.",
                    );
                }
            }
            TraceOutcome::Failed(reason) => self.say(Level::Error, reason),
        }
    }

    fn show_refs(
        &mut self,
        range: AddrRange,
        label: Option<String>,
        refs: Vec<Reference>,
        ret: Sidebar,
    ) {
        self.tab = Tab::Code;
        let count = refs.len();
        self.code.sidebar = Sidebar::Refs;
        self.code.refs = refs;
        self.code.ref_range = Some(range);
        self.code.ref_label = label;
        self.code.refs_return = ret;
        self.code.ref_state.select((count > 0).then_some(0));
        self.code.focus = CodeFocus::Sidebar;
        let described = what(range, self.code.ref_label.clone());
        if count == 0 {
            let hint = if range.is_single() {
                match maps::mapping_at(&self.code.mappings, range.lo) {
                    Some(mapping) if !mapping.executable() => {
                        "Static scans only see addresses encoded in instructions; values reached through pointers (heap, stack) usually have none."
                    }
                    _ => "No instruction encodes that address.",
                }
            } else {
                "No instruction encodes an address in that range."
            };
            self.say(Level::Warn, format!("No references to {described}. {hint}"));
        } else {
            self.say(Level::Ok, format!("{count} reference(s) to {described}"));
        }
    }

    fn show_pointers(&mut self, target: u64, label: Option<String>, pointers: Vec<Pointer>) {
        self.tab = Tab::Code;
        // Going one hop deeper from a pointer list keeps the old list.
        if self.code.sidebar == Sidebar::Pointers
            && self
                .code
                .pointer_target
                .is_some_and(|previous| previous != target)
        {
            self.code.push_pointer_stop();
        }
        let count = pointers.len();
        self.code.sidebar = Sidebar::Pointers;
        self.code.pointers = pointers;
        self.code.pointer_target = Some(target);
        self.code.pointer_label = label;
        self.code.pointer_state.select((count > 0).then_some(0));
        self.code.focus = CodeFocus::Sidebar;
        let described = what(AddrRange::one(target), self.code.pointer_label.clone());
        let hop = self.code.pointer_hop();
        let hop_note = if hop > 1 {
            format!(" (hop {hop})")
        } else {
            String::new()
        };
        if count == 0 {
            self.say(
                Level::Warn,
                format!(
                    "No stored pointers to {described}{hop_note}. The access may be computed from a base register, or the pointer may live in a register or another object."
                ),
            );
        } else {
            self.say(
                Level::Ok,
                format!("{count} pointer slot(s) near {described}{hop_note}"),
            );
        }
    }

    /// `r` on the reference or pointer list: run the same search again.
    pub(super) fn rescan_refs(&mut self) {
        if self.code.trace.is_some() {
            let Some(target) = self.code.trace_target else {
                return self.say(Level::Info, "Analyze an address first (x).");
            };
            if self.trace_job.is_some() {
                return self.say(Level::Warn, "A trace is already running");
            }
            let label = self.code.trace_label.clone();
            self.code.forget_trace(target);
            return self.start_trace(target, label);
        }
        if self.code.sidebar == Sidebar::Pointers {
            let Some(target) = self.code.pointer_target else {
                return self.say(Level::Info, "Press P to search for pointers first.");
            };
            if self.pointer_job.is_some() {
                return self.say(Level::Warn, "A pointer scan is already running");
            }
            let label = self.code.pointer_label.clone();
            self.code.forget_pointers(target);
            return self.find_pointers(target, label);
        }
        let Some(range) = self.code.ref_range else {
            return self.say(Level::Info, "Press f to search for references first.");
        };
        if self.code.sidebar != Sidebar::Refs {
            return self.say(Level::Info, "Press f to search for references first.");
        }
        if self.xref_job.is_some() {
            return self.say(Level::Warn, "A reference scan is already running");
        }
        let label = self.code.ref_label.clone();
        self.code.forget_refs(range);
        self.find_refs_in(range, label, self.code.refs_return);
    }

    /// Enter on a mapping, a reference, a pointer slot, or a branch.
    pub(super) fn code_open(&mut self) {
        if let Some(cursor) = self.code.data.as_ref().map(|data| data.cursor) {
            if let Some(target) = self.executable_value(cursor) {
                self.jump_code(target, true);
                return;
            }
            return self.say(
                Level::Info,
                "This is the hex view; Esc returns to the disassembly.",
            );
        }
        if self.code.trace.is_some() && self.code.focus == CodeFocus::Disassembly {
            return self.open_trace_path();
        }
        if self.code.focus == CodeFocus::Disassembly {
            let Some(line) = self.code.lines.get(self.code.cursor) else {
                return;
            };
            let target = line.target;
            let mention = line.mention;
            let indirect = line.flow == code::Flow::Indirect;
            return match target {
                Some(target) => {
                    self.jump_code(target, true);
                }
                None if indirect => self.follow_indirect(mention),
                None => self.say(Level::Info, "This instruction has no direct target."),
            };
        }
        match self.code.sidebar {
            Sidebar::Refs => {
                let Some(reference) = self.code.selected_ref() else {
                    return self.say(Level::Info, "No references to open.");
                };
                let addr = reference.addr;
                self.jump_code(addr, false);
            }
            Sidebar::Pointers => {
                let Some(slot) = self.code.selected_pointer().map(|pointer| pointer.slot) else {
                    return self.say(Level::Info, "No pointer slots to open.");
                };
                self.find_refs_in(AddrRange::one(slot), None, Sidebar::Pointers);
            }
            Sidebar::Mappings => {
                if let Some(mapping) = self.code.selected_mapping() {
                    let start = mapping.start;
                    self.jump_code(start, false);
                } else {
                    self.say(Level::Info, "No executable mappings.");
                }
            }
        }
    }

    /// Enter on a report path: its loading instruction, else its deepest hop
    /// slot (which opens as data). With no path, the first direct reference.
    fn open_trace_path(&mut self) {
        let destination = {
            let Some(report) = &self.code.trace else {
                return;
            };
            let path = report
                .paths
                .get(self.code.trace_state.selected().unwrap_or(0))
                .or_else(|| report.paths.first());
            match path {
                Some(path) => path
                    .code
                    .as_ref()
                    .map(|code| code.addr)
                    .or_else(|| path.hops.first().map(|hop| hop.slot)),
                None => report.refs.first().map(|reference| reference.addr),
            }
        };
        match destination {
            Some(addr) => {
                self.jump_code(addr, true);
            }
            None => self.say(Level::Info, "This report has nothing to open."),
        }
    }

    /// `Enter` on an indirect branch: follow the slot when the instruction
    /// names one (`call [rip+…]`), even though registers are unknowable.
    fn follow_indirect(&mut self, mention: Option<Mention>) {
        let Some(mention) = mention else {
            return self.say(
                Level::Info,
                "Indirect branch: its target is only known at runtime. A `call [slot]` form can be followed.",
            );
        };
        if mention.indexed {
            return self.say(
                Level::Info,
                "Indexed branch target: the table is known, the chosen entry is not.",
            );
        }
        let Some(memory) = self.target.as_ref().and_then(|target| target.memory().ok()) else {
            return self.say(
                Level::Warn,
                "Cannot read this process's memory (try running as root)",
            );
        };
        let mut bytes = [0_u8; 8];
        if memory.read_into(mention.addr, &mut bytes).is_err() {
            return self.say(
                Level::Warn,
                format!("The slot at 0x{:x} is not readable.", mention.addr),
            );
        }
        let target = u64::from_le_bytes(bytes);
        let slot = maps::format_module_offset(&self.code.mappings, mention.addr);
        match maps::mapping_at(&self.code.mappings, target) {
            Some(mapping) if mapping.executable() => {
                let to = maps::format_module_offset(&self.code.mappings, target);
                if self.jump_code(target, true) {
                    self.say(Level::Ok, format!("Followed [{slot}] → {to}"));
                }
            }
            Some(mapping) => self.say(
                Level::Info,
                format!(
                    "[{slot}] holds 0x{target:x} ({}), not code.",
                    mapping.perms.text()
                ),
            ),
            None => self.say(
                Level::Info,
                format!("[{slot}] holds 0x{target:x}, which is not mapped."),
            ),
        }
    }

    /// `o`: inspect data. On a pointer row that is the pointer's target, on a
    /// disassembly line it is the operand address.
    pub(super) fn open_code_data(&mut self) {
        if self.code.sidebar == Sidebar::Pointers
            && self.code.focus == CodeFocus::Sidebar
            && let Some(pointer) = self.code.selected_pointer()
        {
            let value = pointer.value;
            self.show_data(value);
            return;
        }
        let Some(line) = self.code.lines.get(self.code.cursor) else {
            return self.say(Level::Info, "Nothing to inspect here.");
        };
        match line.mention {
            Some(mention) => {
                self.show_data(mention.addr);
            }
            None => self.say(
                Level::Info,
                "This instruction names no memory address; use g to go to data.",
            ),
        }
    }

    /// `u`: undo a jump, close the hex view, leave a list, or return focus.
    pub(super) fn code_back(&mut self) {
        if self.code.trace.is_some() {
            self.close_trace();
            return;
        }
        if self.code.data.take().is_some() {
            self.code.focus = CodeFocus::Disassembly;
            self.say(Level::Info, "Back to the disassembly.");
            return;
        }
        if let Some((anchor, cursor)) = self.code.history.pop() {
            if self.jump_code(anchor, false) {
                self.code.cursor = cursor.min(self.code.lines.len().saturating_sub(1));
                self.code.ensure_visible();
            }
            return;
        }
        match self.code.sidebar {
            Sidebar::Mappings => self.code.focus = CodeFocus::Sidebar,
            // A jump from a list returns to that list first.
            Sidebar::Refs | Sidebar::Pointers if self.code.focus == CodeFocus::Disassembly => {
                self.code.focus = CodeFocus::Sidebar;
            }
            Sidebar::Refs => {
                self.code.sidebar = self.code.refs_return;
                self.code.focus = CodeFocus::Sidebar;
            }
            Sidebar::Pointers => {
                if let Some(stop) = self.code.pop_pointer_stop() {
                    self.code.pointers = stop.pointers;
                    self.code.pointer_state.select(stop.selected);
                    self.code.pointer_target = Some(stop.target);
                    self.code.pointer_label = stop.label;
                    self.code.focus = CodeFocus::Sidebar;
                    let what = what(AddrRange::one(stop.target), self.code.pointer_label.clone());
                    let count = self.code.pointers.len();
                    self.say(
                        Level::Info,
                        format!(
                            "Back to {count} pointer(s) to {what} (hop {})",
                            self.code.pointer_hop()
                        ),
                    );
                } else {
                    self.code.sidebar = Sidebar::Mappings;
                    self.code.focus = CodeFocus::Sidebar;
                }
            }
        }
    }

    /// Esc on the Code tab: stop a scan, close the hex view, then step back.
    /// `Esc` in the Code tab: stop any worker first, then unwind the view.
    pub(super) fn code_cancel(&mut self) {
        if self.is_busy() {
            self.stop_scan();
        } else {
            self.code_back();
        }
    }

    pub(super) fn toggle_code_bytes(&mut self) {
        if let Some(data) = &mut self.code.data {
            data.per_row = match data.per_row {
                8 => 16,
                16 => 32,
                _ => 8,
            };
            self.redraw = true;
            return;
        }
        self.code.bytes = !self.code.bytes;
    }

    /// Moves the selected path in the trace report.
    fn move_trace(&mut self, delta: isize) {
        let count = self
            .code
            .trace
            .as_ref()
            .map_or(0, |report| report.paths.len());
        if count == 0 {
            return;
        }
        let current = self.code.trace_state.selected().unwrap_or(0).cast_signed();
        let max = count.cast_signed() - 1;
        let next = current.saturating_add(delta).clamp(0, max).cast_unsigned();
        self.code.trace_state.select(Some(next));
        self.redraw = true;
    }

    pub(super) fn code_move(&mut self, delta: isize) {
        if self.code.trace.is_some() && self.code.focus == CodeFocus::Disassembly {
            return self.move_trace(delta);
        }
        if self.code.data.is_some() {
            return self.data_move(delta);
        }
        match self.code.focus {
            CodeFocus::Disassembly => self.move_disassembly(delta),
            CodeFocus::Sidebar => self.code.move_sidebar(delta),
        }
    }

    pub(super) fn code_move_horizontal(&mut self, delta: isize) {
        if self.code.data.is_none() || self.code.trace.is_some() {
            return;
        }
        let Some(cursor) = self.code.data.as_ref().map(|data| data.cursor) else {
            return;
        };
        let target = i128::from(cursor) + i128::try_from(delta).unwrap_or(0);
        let Some(data) = &self.code.data else {
            return;
        };
        let lo = i128::from(data.lo);
        let hi = i128::from(data.hi.saturating_sub(1)).max(lo);
        let addr = u64::try_from(target.clamp(lo, hi)).unwrap_or(data.lo);
        self.set_data_cursor(addr);
    }

    /// Moves the hex cursor by rows, reloading the window when it leaves it.
    fn data_move(&mut self, rows: isize) {
        let Some(data) = &self.code.data else {
            return;
        };
        let step = i128::try_from(rows).unwrap_or(0)
            * i128::from(u64::try_from(data.per_row).unwrap_or(1));
        let target = i128::from(data.cursor) + step;
        let lo = i128::from(data.lo);
        let hi = i128::from(data.hi.saturating_sub(1)).max(lo);
        let addr = u64::try_from(target.clamp(lo, hi)).unwrap_or(data.lo);
        self.set_data_cursor(addr);
    }

    fn set_data_cursor(&mut self, addr: u64) {
        let inside = self
            .code
            .data
            .as_ref()
            .is_some_and(|data| data.contains(addr));
        if inside {
            if let Some(data) = &mut self.code.data {
                data.cursor = addr;
            }
            if let Some(data) = &mut self.code.data {
                let row = data.cursor_row();
                let height = self.code.viewport.max(1);
                if row < data.scroll {
                    data.scroll = row;
                } else if row >= data.scroll + height {
                    data.scroll = row + 1 - height;
                }
            }
            self.redraw = true;
        } else {
            self.show_data(addr);
        }
    }

    /// Down at the last line or up at the first: decode the next/previous
    /// window instead of dead-ending, keeping the cursor's screen position.
    fn move_disassembly(&mut self, delta: isize) {
        let count = self.code.lines.len();
        if count == 0 {
            return;
        }
        let last = count - 1;
        let at_bottom = delta > 0 && self.code.cursor >= last;
        let at_top = delta < 0 && self.code.cursor == 0;
        if at_bottom && self.rebase_forward() {
            return;
        }
        if at_top && self.rebase_backward() {
            return;
        }
        self.code.move_cursor(delta);
    }

    fn rebase_forward(&mut self) -> bool {
        let Some(last) = self.code.lines.last() else {
            return false;
        };
        let next = last
            .addr
            .saturating_add(u64::try_from(last.bytes.len()).unwrap_or(1));
        if next >= self.code.view_hi || self.code.lines.len() <= 1 {
            return false;
        }
        let keep = self.code.cursor.saturating_sub(self.code.viewport / 2);
        let Some(anchor) = self.code.lines.get(keep).map(|line| line.addr) else {
            return false;
        };
        let Some(memory) = self.target.as_ref().and_then(|target| target.memory().ok()) else {
            return false;
        };
        let window = code::decode_window_forward(memory, anchor, self.code.view_hi);
        if window.lines.len() <= 1
            || window
                .lines
                .last()
                .is_some_and(|line| line.addr <= last.addr)
        {
            return false;
        }
        let cursor = self.code.cursor - keep;
        self.code
            .set_window(window, cursor, self.code.view_lo, self.code.view_hi);
        self.redraw = true;
        true
    }

    fn rebase_backward(&mut self) -> bool {
        let Some(first) = self.code.lines.first() else {
            return false;
        };
        if first.addr <= self.code.view_lo || self.code.lines.len() <= 1 {
            return false;
        }
        let anchor = first.addr;
        let Some(memory) = self.target.as_ref().and_then(|target| target.memory().ok()) else {
            return false;
        };
        let window = code::decode_window(memory, anchor, self.code.view_lo, self.code.view_hi);
        let Some(cursor) = window.lines.iter().position(|line| line.addr == anchor) else {
            return false;
        };
        if cursor == 0 {
            return false;
        }
        self.code
            .set_window(window, cursor, self.code.view_lo, self.code.view_hi);
        self.redraw = true;
        true
    }

    /// Re-reads operand annotations for the visible lines. Runs on the live
    /// tick; values change under us, so this is deliberately not cached
    /// across ticks.
    pub(super) fn refresh_code_notes(&mut self) {
        if self.tab != Tab::Code || self.code.data.is_some() {
            return;
        }
        let visible_end = (self.code.scroll + self.code.viewport + 4).min(self.code.lines.len());
        let first = self.code.scroll.min(visible_end);
        let mentions: Vec<(u64, Mention)> = self.code.lines[first..visible_end]
            .iter()
            .filter_map(|line| line.mention.map(|mention| (line.addr, mention)))
            .collect();
        if mentions.is_empty() {
            if !self.code.notes.is_empty() {
                self.code.notes.clear();
                self.redraw = true;
            }
            return;
        }
        let Some(pid) = self.code.pid else {
            return;
        };
        let Ok(memory) = MemIo::open(pid) else {
            return;
        };
        let saved: Vec<SavedRef<'_>> = self
            .saved
            .items
            .iter()
            .filter(|item| !item.label.is_empty())
            .map(|item| SavedRef {
                addr: item.addr,
                ty: item.ty,
                label: &item.label,
            })
            .collect();
        let mut notes = HashMap::with_capacity(mentions.len());
        for (line, mention) in &mentions {
            notes.insert(
                *line,
                code::describe_mention(&memory, &self.code.mappings, &saved, *mention),
            );
        }
        if notes != self.code.notes {
            self.code.notes = notes;
            self.redraw = true;
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
        if let Some(data) = &self.code.data {
            return Some(maps::format_module_offset(&self.code.mappings, data.cursor));
        }
        let line = self.code.lines.get(self.code.cursor)?;
        let where_ = maps::format_module_offset(&self.code.mappings, line.addr);
        Some(
            self.saved
                .items
                .iter()
                .find(|item| item.addr == line.addr && !item.label.is_empty())
                .map_or(where_.clone(), |item| format!("{} ({where_})", item.label)),
        )
    }

    /// Kind name used in the reference list.
    pub fn ref_kind_text(kind: RefKind) -> &'static str {
        match kind {
            RefKind::RipRelative => "rip",
            RefKind::Absolute => "abs",
            RefKind::Indexed => "idx",
            RefKind::Immediate => "imm",
        }
    }
}

/// `label` with its address, or just the address/range.
fn what(range: AddrRange, label: Option<String>) -> String {
    label.map_or_else(|| range.to_string(), |label| format!("`{label}` ({range})"))
}

/// The scan thread's body: opens its own memory handle, scans, reports back.
fn run_xref(
    pid: u32,
    mappings: &[Mapping],
    range: AddrRange,
    control: &ScanControl,
    tx: &Sender<XrefOutcome>,
) {
    let outcome = match MemIo::open(pid) {
        Ok(memory) => XrefOutcome::Done(code::scan(&memory, mappings, range, control)),
        Err(reason) => XrefOutcome::Failed(format!(
            "cannot open /proc/{pid}/mem: {reason} (try running as root)"
        )),
    };
    let _ = tx.send(outcome);
}

/// The pointer scan's thread body, with the same memory-handle rules.
fn run_pointers(
    pid: u32,
    mappings: &[Mapping],
    target: u64,
    control: &ScanControl,
    tx: &Sender<PointerOutcome>,
) {
    let outcome = match MemIo::open(pid) {
        Ok(memory) => PointerOutcome::Done(code::scan_pointers(&memory, mappings, target, control)),
        Err(reason) => PointerOutcome::Failed(format!(
            "cannot open /proc/{pid}/mem: {reason} (try running as root)"
        )),
    };
    let _ = tx.send(outcome);
}

/// The trace thread's body: one memory handle for every pass.
fn run_trace(
    pid: u32,
    mappings: &[Mapping],
    target: u64,
    label: Option<&str>,
    progress: &TraceProgress,
    control: &ScanControl,
    tx: &Sender<TraceOutcome>,
) {
    let options = TraceOptions::default();
    let outcome = match MemIo::open(pid) {
        Ok(memory) => {
            let report = code::trace_with_progress(
                &memory,
                mappings,
                target,
                label,
                &options,
                control,
                &|phase| progress.set(phase),
            );
            TraceOutcome::Done(Box::new(report))
        }
        Err(reason) => TraceOutcome::Failed(format!(
            "cannot open /proc/{pid}/mem: {reason} (try running as root)"
        )),
    };
    let _ = tx.send(outcome);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn analyze_routes_code_and_data_by_permission() {
        let maps = crate::maps::parse_maps(
            "1000-2000 r-xp 00000000 00:00 1 /bin/a\n\
             2000-3000 rw-p 00000000 00:00 0 [heap]\n\
             3000-4000 rw-p 00000000 00:00 1 /bin/a\n\
             5000-6000 r-xp 00000000 00:00 0 \n",
        );
        // Executable wins everywhere: module code and anonymous JIT pages.
        assert_eq!(analyze_route(&maps[0]), AnalyzeRoute::Code);
        assert_eq!(analyze_route(&maps[3]), AnalyzeRoute::Code);
        // Writable module data and the heap are reached through pointers.
        assert_eq!(analyze_route(&maps[1]), AnalyzeRoute::Data);
        assert_eq!(analyze_route(&maps[2]), AnalyzeRoute::Data);
    }

    #[test]
    fn trace_cache_is_per_target_and_forgettable() {
        let mut view = CodeView::new();
        view.pid = Some(7);
        let report = TraceReport {
            target: 0x1000,
            target_label: "health".to_string(),
            target_kind: Some(crate::maps::RegionKind::Heap),
            refs: Vec::new(),
            paths: Vec::new(),
            stats: crate::code::TraceStats::default(),
        };
        view.remember_trace(report);
        assert!(view.cached_trace(0x1000).is_some());
        assert!(view.cached_trace(0x2000).is_none());
        view.forget_trace(0x1000);
        assert!(view.cached_trace(0x1000).is_none());
    }

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
                mention: None,
            })
            .collect();
        view.move_cursor(10);
        assert_eq!(view.cursor, 10);
        assert_eq!(view.scroll, 7); // cursor is the last visible line
        view.move_cursor(-10);
        assert_eq!(view.scroll, 0);
    }

    #[test]
    fn the_scan_caches_are_cleared_with_the_target() {
        let mut view = CodeView::new();
        view.pid = Some(1);
        let range = AddrRange::one(0x1000);
        view.remember_refs(range, Vec::new());
        assert!(view.cached_refs(range).is_some());
        view.forget_refs(range);
        assert!(view.cached_refs(range).is_none());

        view.remember_pointers(0x1000, Vec::new());
        view.remember_refs(range, Vec::new());
        view.reset(Some(1));
        assert!(view.cached_refs(range).is_none());
        assert!(view.cached_pointers(0x1000).is_none());
    }

    #[test]
    fn a_cache_keeps_only_the_newest_entries() {
        let newest = u64::try_from(CACHE_LIMIT).unwrap() + 1;
        let mut cache: Recent<(u32, u64), u64> = Recent::new();
        for target in 0..=newest {
            cache.insert((1, target), target);
        }
        assert!(cache.get(&(1, 0)).is_none());
        assert_eq!(cache.get(&(1, newest)), Some(&newest));
    }

    #[test]
    fn ref_kinds_have_short_names() {
        assert_eq!(App::ref_kind_text(RefKind::RipRelative), "rip");
        assert_eq!(App::ref_kind_text(RefKind::Absolute), "abs");
        assert_eq!(App::ref_kind_text(RefKind::Indexed), "idx");
        assert_eq!(App::ref_kind_text(RefKind::Immediate), "imm");
    }

    #[test]
    fn pointer_trail_keeps_only_the_newest_hops() {
        let mut view = CodeView::new();
        view.sidebar = Sidebar::Pointers;
        for step in 0..=(POINTER_TRAIL_LIMIT + 3) {
            let target = u64::try_from(step).unwrap();
            view.pointer_target = Some(target);
            view.pointer_label = Some(format!("slot{step}"));
            view.pointers = vec![Pointer {
                slot: target,
                value: target,
            }];
            view.pointer_state.select(Some(0));
            view.push_pointer_stop();
        }
        assert_eq!(view.pointer_trail.len(), POINTER_TRAIL_LIMIT);
        assert_eq!(view.pointer_trail.first().map(|stop| stop.target), Some(4));
        assert_eq!(view.pointer_hop(), POINTER_TRAIL_LIMIT + 1);

        let stop = view.pop_pointer_stop().unwrap();
        assert_eq!(stop.label.as_deref(), Some("slot35"));
        assert_eq!(stop.selected, Some(0));
    }

    #[test]
    fn refreshing_maps_keeps_the_selection_on_the_same_region() {
        let mut view = CodeView::new();
        view.reset(Some(std::process::id()));
        if view.executable_count() == 0 {
            return; // no /proc in this environment; nothing to prove
        }
        view.refresh_maps();
        view.selected_mapping = view.executable_count() - 1;
        let start = view.selected_mapping().map(|mapping| mapping.start);
        view.refresh_maps();
        assert!(view.selected_mapping < view.executable_count());
        if let Some(start) = start
            && view.executable().any(|mapping| mapping.start == start)
        {
            assert_eq!(
                view.selected_mapping().map(|mapping| mapping.start),
                Some(start)
            );
        }
    }
}
