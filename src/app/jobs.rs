//! Commands sent to scanmem, and what happens when each one finishes.

use super::results::MAX_RESULTS;
use super::{App, Level, Target};
use crate::datatype::DataType;
use crate::scanmem::{parse_output, Parsed};
use std::time::Instant;

enum JobKind {
    /// A scan-ish command followed by `list`.
    Scan,
    /// Switch the scan type (committed once scanmem accepts it).
    SetType(DataType),
    /// `pid N`, remembering the type that was selected at the time.
    Attach { pid: u32, name: String, ty: DataType },
}

/// The batch scanmem is currently working on.
pub struct Job {
    id: u64,
    kind: JobKind,
    pub label: &'static str,
    pub progress: Option<(u32, u32)>,
    pub since: Instant,
}

impl App {
    pub(super) fn attach(&mut self, pid: u32, name: String) {
        let ty = self.scan_type;
        self.start_job(
            vec![set_type_command(ty), format!("pid {pid}")],
            JobKind::Attach { pid, name, ty },
            "Attaching",
        );
    }

    pub(super) fn change_type(&mut self, ty: DataType, label: &'static str) {
        self.start_job(vec![set_type_command(ty)], JobKind::SetType(ty), label);
    }

    pub(super) fn cycle_type(&mut self) {
        if !self.results.rows.is_empty() {
            self.say(Level::Info, "Type changed; press n for a new scan if results look wrong.");
        }
        self.change_type(self.scan_type.next(), "Changing type");
    }

    pub(super) fn start_scan(&mut self, command: &str) {
        if !self.require_target() {
            return;
        }
        if self.is_busy() {
            return self.say(Level::Warn, "scanmem is busy");
        }
        let commands = vec![command.to_string(), format!("list {MAX_RESULTS}")];
        self.start_job(commands, JobKind::Scan, "Scanning");
    }

    /// True when a process is attached; otherwise tells the user to pick one.
    pub(super) fn require_target(&mut self) -> bool {
        let attached = self.target.is_some();
        if !attached {
            self.say(Level::Warn, "Pick a process first (p)");
        }
        attached
    }

    pub(super) fn record_progress(&mut self, done: u32, total: u32) {
        if let Some(job) = &mut self.job {
            job.progress = Some((done, total));
        }
    }

    pub(super) fn finish_job(&mut self, id: u64, lines: Vec<String>) {
        let Some(job) = self.job.take() else { return };
        if job.id != id {
            self.job = Some(job);
            return;
        }
        let parsed = parse_output(&lines);
        let error = (!parsed.errors.is_empty()).then(|| parsed.errors.join("; "));
        let warning = parsed.warnings.first().cloned();
        match job.kind {
            JobKind::Scan => self.apply_scan(parsed, error),
            JobKind::SetType(ty) => self.finish_set_type(ty, warning, error),
            JobKind::Attach { pid, name, ty } => self.finish_attach(pid, name, ty, warning, error),
        }
    }

    fn start_job(&mut self, commands: Vec<String>, kind: JobKind, label: &'static str) {
        if self.backend_dead {
            return self.say(Level::Error, "scanmem is not running (restart the program)");
        }
        match self.backend.send(&commands) {
            Ok(id) => self.job = Some(Job { id, kind, label, progress: None, since: Instant::now() }),
            Err(e) => {
                self.backend_dead = true;
                self.say(Level::Error, format!("lost connection to scanmem: {e}"));
            }
        }
    }

    fn finish_set_type(&mut self, ty: DataType, warning: Option<String>, error: Option<String>) {
        if let Some(error) = error {
            return self.say(Level::Error, error);
        }
        self.scan_type = ty;
        match warning {
            Some(warning) => self.say(Level::Warn, warning),
            None => self.say(Level::Info, format!("Scan type: {}", ty.scanmem_name())),
        }
    }

    fn finish_attach(&mut self, pid: u32, name: String, ty: DataType, warning: Option<String>, error: Option<String>) {
        if let Some(error) = error {
            return self.say(Level::Error, format!("Could not attach to {pid}: {error}"));
        }
        self.scan_type = ty;
        self.switch_target(pid, name);
        self.report_attached(warning);
    }

    fn switch_target(&mut self, pid: u32, name: String) {
        let is_new_process = self.target.as_ref().map(|target| target.pid) != Some(pid);
        self.target = Some(Target::attach(pid, name));
        self.stats.track(Some(pid));
        self.freezer.set_pid(Some(pid));
        if is_new_process {
            // Saved addresses belong to the old process: stop writing them anywhere.
            self.saved.release_all();
            self.sync_freezer();
        }
        self.results.clear();
        self.refresh_live();
    }

    fn report_attached(&mut self, warning: Option<String>) {
        let Some(target) = &self.target else { return };
        let (level, text) = match (target.memory().err(), warning) {
            (Some(reason), _) => (
                Level::Warn,
                format!("Attached to pid {}, but {reason} (try running as root)", target.pid),
            ),
            (None, Some(warning)) => (Level::Warn, warning),
            (None, None) => (
                Level::Ok,
                format!("Attached to {} (pid {}). Press s to scan.", target.name, target.pid),
            ),
        };
        self.say(level, text);
    }

    fn apply_scan(&mut self, parsed: Parsed, error: Option<String>) {
        self.results.replace(parsed.matches, parsed.count, self.scan_type);
        self.refresh_live();
        self.report_scan(error);
    }

    fn report_scan(&mut self, error: Option<String>) {
        let total = self.results.total;
        let shown = self.results.rows.len();
        if let Some(error) = error {
            self.say(Level::Error, error);
        } else if total == 0 {
            self.say(Level::Warn, "No matches. Press n to start a new scan.");
        } else if self.results.is_truncated() {
            self.say(Level::Ok, format!("{total} matches (showing the first {shown}). Narrow it down with another scan."));
        } else {
            let noun = if total == 1 { "match" } else { "matches" };
            self.say(Level::Ok, format!("{total} {noun}"));
        }
    }
}

fn set_type_command(ty: DataType) -> String {
    format!("option scan_data_type {}", ty.scanmem_name())
}
