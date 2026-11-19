//! Application state.
//!
//! `jobs` talks to scanmem, `keys` and `prompt` turn key presses into actions,
//! `results` and `saved` own the two tables, and `picker` is the process chooser.

mod codetab;
mod jobs;
mod keys;
mod picker;
mod prompt;
mod rangescan;
mod results;
mod saved;
mod scripttab;

use crate::args::Args;
use crate::datatype::DataType;
use crate::freezer::Freezer;
use crate::memio::MemIo;
use crate::scanmem::{Backend, BackendEvent};
use crate::scanner::Candidate;
use crate::scripts::engine::{Engine, Label};
use crate::scripts::paths::ScriptsRoot;
use crate::scripts::store::Scripts;
use crate::stats::Stats;
use anyhow::{Context, Result};
use codetab::{CodeView, PointerJob, XrefJob};
use jobs::Job;
use picker::Picker;
use rangescan::RangeJob;
use ratatui::widgets::TableState;
use results::Results;
use saved::SavedList;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::mpsc::{Receiver, TryRecvError};
use std::time::{Duration, Instant};

pub use codetab::{CodeFocus, Sidebar};
pub use results::ResultRow;
pub use saved::Saved;

const LIVE_REFRESH: Duration = Duration::from_millis(250);
const STATS_REFRESH: Duration = Duration::from_millis(1000);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Tab {
    Memory,
    Scripts,
    Code,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Focus {
    Results,
    Saved,
}

/// The yes/no popups on the Scripts tab.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Confirm {
    /// Remove from the list, leaving the file alone.
    Delist(u64),
    /// Delete the file itself.
    DeleteFile(u64),
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Level {
    Info,
    Ok,
    Warn,
    Error,
}

pub struct Status {
    pub text: String,
    pub level: Level,
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum InputKind {
    Scan,
    SetValue(usize),
    Label(usize),
    /// Change the type of a saved address.
    EditType(usize),
    AddAddr,
    /// Import a `.lua` file, or every `.lua` directly inside a folder.
    ImportScript,
    /// Create a script inside the scripts folder from a relative path.
    NewScript,
    /// Go to a label, `module+0x…` offset, or hex address in the Code tab.
    GotoCode,
    /// Find instructions that encode a label or address.
    FindRefs,
    /// Find memory slots that hold a pointer to a label or address.
    FindPointers,
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    Normal,
    Input(InputKind),
    Confirm(Confirm),
    Picker,
    Help,
}

/// The attached process, and the handle used to read and write its memory.
pub struct Target {
    pub pid: u32,
    pub name: String,
    memory: Result<MemIo, String>,
}

impl Target {
    pub fn attach(pid: u32, name: String) -> Target {
        let memory = MemIo::open(pid).map_err(|e| format!("cannot open /proc/{pid}/mem: {e}"));
        Target { pid, name, memory }
    }

    /// The memory handle, or the reason there isn't one.
    pub fn memory(&self) -> Result<&MemIo, &str> {
        self.memory.as_ref().map_err(String::as_str)
    }
}

pub struct App {
    backend: Backend,
    events: Receiver<BackendEvent>,
    backend_dead: bool,
    pub job: Option<Job>,
    /// The range scan running on its own thread, if any.
    pub range_job: Option<RangeJob>,
    /// The reference scan running on its own thread, if any.
    pub xref_job: Option<XrefJob>,
    /// The pointer scan running on its own thread, if any.
    pub pointer_job: Option<PointerJob>,

    pub freezer: Freezer,
    pub stats: Stats,
    pub target: Option<Target>,
    pub scan_type: DataType,
    /// Active scan limit `(lo, hi)` set by `range`; `None` scans everywhere.
    /// While set, scans run on the built-in scanner instead of scanmem.
    pub scan_range: Option<(u64, u64)>,
    /// The built-in scanner's matches; only meaningful while `scan_range` is.
    pub candidates: Vec<Candidate>,
    pub results: Results,
    pub saved: SavedList,
    pub picker: Picker,

    pub tab: Tab,
    pub scripts: Scripts,
    pub code: CodeView,
    /// The Lua thread; UI talks to it through commands and events only.
    engine: Engine,
    /// Set when the event loop should hand the terminal to `$EDITOR`.
    editor_request: Option<PathBuf>,

    pub focus: Focus,
    pub mode: Mode,
    /// First line shown in the help popup.
    pub help_scroll: u16,
    pub input: String,
    pub status: Status,
    pub should_quit: bool,

    redraw: bool,
    last_live: Instant,
    last_stats: Instant,
}

impl App {
    pub fn start(args: &Args) -> Result<App> {
        let (backend, events) = Backend::spawn(&args.scanmem).context("starting scanmem")?;
        let freezer = Freezer::start(args.freeze_interval());
        let engine = Engine::start(args.lua_full);
        let mut scripts = Scripts::new(ScriptsRoot::from_arg(args.scripts_dir.as_deref()));
        let startup = scripts.load_startup();
        let mut app = App::new(backend, events, freezer, engine, scripts, args.scan_type);
        app.begin_session(args.target_pid());
        if let Some(message) = startup {
            app.say(Level::Warn, message);
        }
        if args.lua_full {
            app.say(
                Level::Warn,
                "--lua-full: scripts can read files, run commands and use package.",
            );
        }
        Ok(app)
    }

    pub fn tick(&mut self) {
        self.drain_backend_events();
        self.drain_range_job();
        self.drain_xref_job();
        self.drain_pointer_job();
        self.drain_script_events();
        self.refresh_live_values_if_due();
        self.refresh_stats_if_due();
        self.keep_spinner_turning();
    }

    pub fn request_redraw(&mut self) {
        self.redraw = true;
    }

    /// True once per change; the event loop draws only when this says so.
    pub fn take_redraw(&mut self) -> bool {
        std::mem::take(&mut self.redraw)
    }

    pub fn is_busy(&self) -> bool {
        self.job.is_some()
            || self.range_job.is_some()
            || self.xref_job.is_some()
            || self.pointer_job.is_some()
    }

    fn new(
        backend: Backend,
        events: Receiver<BackendEvent>,
        freezer: Freezer,
        engine: Engine,
        scripts: Scripts,
        scan_type: DataType,
    ) -> App {
        App {
            backend,
            events,
            backend_dead: false,
            job: None,
            range_job: None,
            xref_job: None,
            pointer_job: None,
            freezer,
            stats: Stats::new(),
            target: None,
            scan_type,
            scan_range: None,
            candidates: Vec::new(),
            results: Results::new(),
            saved: SavedList::new(),
            picker: Picker::empty(),
            tab: Tab::Memory,
            scripts,
            code: CodeView::new(),
            engine,
            editor_request: None,
            focus: Focus::Results,
            mode: Mode::Normal,
            help_scroll: 0,
            input: String::new(),
            status: Status {
                text: "Starting scanmem…".into(),
                level: Level::Info,
            },
            should_quit: false,
            redraw: true,
            last_live: Instant::now(),
            last_stats: Instant::now(),
        }
    }

    fn begin_session(&mut self, initial_pid: Option<u32>) {
        if let Some(pid) = initial_pid {
            self.attach(pid, process_name(pid));
        } else {
            self.change_type(self.scan_type, "Starting scanmem");
            self.open_picker();
        }
    }

    fn say(&mut self, level: Level, text: impl Into<String>) {
        self.status = Status {
            text: text.into(),
            level,
        };
        self.redraw = true;
    }

    fn drain_backend_events(&mut self) {
        loop {
            match self.events.try_recv() {
                Ok(event) => self.on_backend_event(event),
                Err(TryRecvError::Empty) => return,
                Err(TryRecvError::Disconnected) => {
                    self.backend_dead = true;
                    return;
                }
            }
        }
    }

    fn on_backend_event(&mut self, event: BackendEvent) {
        self.redraw = true;
        match event {
            BackendEvent::Progress { done, total } => self.record_progress(done, total),
            BackendEvent::Done { id, lines } => self.finish_job(id, &lines),
            BackendEvent::Exited(lines) => self.on_backend_exited(&lines),
        }
    }

    fn on_backend_exited(&mut self, last_lines: &[String]) {
        self.backend_dead = true;
        self.job = None;
        self.reset_code(None);
        // The session is over as far as scanning goes: scripts stop with it.
        self.disable_all_scripts();
        self.engine.set_memory(None);
        let tail = last_lines[last_lines.len().saturating_sub(2)..].join(" ");
        self.say(Level::Error, format!("scanmem exited. {tail}"));
    }

    fn refresh_live_values_if_due(&mut self) {
        if self.last_live.elapsed() >= LIVE_REFRESH {
            self.refresh_live();
        }
    }

    fn refresh_live(&mut self) {
        self.last_live = Instant::now();
        let memory = self.target.as_ref().and_then(|target| target.memory().ok());
        let changed = self.saved.refresh_live(memory) | self.results.refresh_live(memory);
        self.redraw |= changed;
    }

    fn refresh_stats_if_due(&mut self) {
        if self.last_stats.elapsed() >= STATS_REFRESH {
            self.last_stats = Instant::now();
            self.redraw |= self.stats.refresh();
        }
    }

    fn keep_spinner_turning(&mut self) {
        if self.is_busy() {
            self.redraw = true;
        }
    }

    fn sync_freezer(&self) {
        self.freezer.set_targets(self.saved.freeze_targets());
    }

    /// Points the engine at the current target. It opens its own
    /// `/proc/<pid>/mem`, so the TUI's reads and the scripts' writes never
    /// share a seek position.
    fn sync_script_memory(&self) {
        let memory = self
            .target
            .as_ref()
            .and_then(|target| MemIo::open(target.pid).ok())
            .map(|memory| Arc::new(memory) as Arc<dyn crate::scripts::engine::Memory>);
        self.engine.set_memory(memory);
    }

    /// Pushes labels after the saved list changes; scripts resolve only these.
    fn sync_script_labels(&self) {
        let labels = self
            .saved
            .items
            .iter()
            .filter(|item| !item.label.is_empty())
            .map(|item| Label {
                name: item.label.clone(),
                addr: item.addr,
                ty: item.ty,
                frozen: item.frozen,
            })
            .collect();
        self.engine.set_labels(labels);
    }
}

fn process_name(pid: u32) -> String {
    std::fs::read_to_string(format!("/proc/{pid}/comm"))
        .map_or_else(|_| format!("pid {pid}"), |name| name.trim().to_string())
}

/// Moves a table selection by `delta` rows, clamped to the table.
fn move_table_selection(state: &mut TableState, len: usize, delta: isize) {
    if len == 0 {
        state.select(None);
        return;
    }
    let current = state.selected().unwrap_or(0).cast_signed();
    let next = current
        .saturating_add(delta)
        .clamp(0, len.cast_signed() - 1);
    state.select(Some(next.cast_unsigned()));
}
