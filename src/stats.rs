//! Stats of the attached process for the bottom title bar.

use crate::gpu::GpuMeter;
use sysinfo::{Pid, ProcessesToUpdate, System};

const KIB: f64 = 1024.0;
const MIB: f64 = KIB * 1024.0;
const GIB: f64 = MIB * 1024.0;

/// One reading of the tracked process.
#[derive(Clone, Copy, Debug, Default, PartialEq)]
struct Reading {
    /// Share of one core, like `top`: 100% is one core fully busy, so a
    /// multi-threaded process can go past it.
    cpu_percent: Option<f32>,
    gpu_percent: Option<f32>,
    /// Resident set size in bytes.
    mem_used: Option<u64>,
}

pub struct Stats {
    sys: System,
    gpu: GpuMeter,
    pid: Option<u32>,
    reading: Reading,
}

impl Stats {
    pub fn new() -> Stats {
        Stats { sys: System::new(), gpu: GpuMeter::detect(), pid: None, reading: Reading::default() }
    }

    /// Switches to another process (or to none) and reads it straight away.
    pub fn track(&mut self, pid: Option<u32>) {
        self.pid = pid;
        self.gpu.reset();
        // Drop the old process so its CPU history is not mistaken for the new one's.
        self.sys = System::new();
        self.sample();
    }

    /// Re-reads every metric and says whether the title text changed.
    ///
    /// CPU usage is a delta between two samples, so call this on a timer
    /// (sysinfo needs >= 200 ms between calls for meaningful numbers).
    pub fn refresh(&mut self) -> bool {
        let before = self.title();
        self.sample();
        self.title() != before
    }

    /// `CPU: 12% GPU 3%, Memory: 2.1GiB`, with `n/a` for whatever cannot be read.
    pub fn title(&self) -> String {
        format_title(self.reading)
    }

    fn sample(&mut self) {
        self.reading = match self.pid {
            Some(pid) => self.read(pid),
            None => Reading::default(),
        };
    }

    fn read(&mut self, pid: u32) -> Reading {
        // Process CPU time is measured against the system's, so both refresh together.
        self.sys.refresh_cpu_usage();
        let sys_pid = Pid::from_u32(pid);
        // `true` drops the process from sysinfo once it has exited.
        self.sys.refresh_processes(ProcessesToUpdate::Some(&[sys_pid]), true);
        let Some(process) = self.sys.process(sys_pid) else { return Reading::default() };
        Reading {
            cpu_percent: Some(process.cpu_usage()),
            gpu_percent: self.gpu.percent_of(pid),
            mem_used: Some(process.memory()),
        }
    }
}

fn format_title(reading: Reading) -> String {
    let cpu = reading.cpu_percent.map_or_else(|| "n/a".to_string(), |p| format!("{p:.0}%"));
    let gpu = reading.gpu_percent.map_or_else(|| "n/a".to_string(), |p| format!("{p:.0}%"));
    let mem = reading.mem_used.map_or_else(|| "n/a".to_string(), humanize_bytes);
    format!("CPU: {cpu} GPU {gpu}, Memory: {mem}")
}

/// `10MiB` below 1 GiB, `2.1GiB` from 1 GiB up.
fn humanize_bytes(bytes: u64) -> String {
    let b = bytes as f64;
    // 1023.6 MiB would round to "1024MiB"; promote it to GiB instead.
    if b >= GIB || (b / MIB).round() >= 1024.0 {
        format!("{:.1}GiB", b / GIB)
    } else {
        format!("{:.0}MiB", b / MIB)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn humanize() {
        assert_eq!(humanize_bytes(0), "0MiB");
        assert_eq!(humanize_bytes(10 * 1024 * 1024), "10MiB");
        assert_eq!(humanize_bytes(512 * 1024 * 1024), "512MiB");
        assert_eq!(humanize_bytes(1024 * 1024 * 1024), "1.0GiB");
        assert_eq!(humanize_bytes((2.1 * GIB) as u64), "2.1GiB");
        // just under 1 GiB must not print "1024MiB"
        assert_eq!(humanize_bytes((1023.7 * MIB) as u64), "1.0GiB");
        assert_eq!(humanize_bytes(1023 * 1024 * 1024), "1023MiB");
    }

    #[test]
    fn title_shows_the_process_reading() {
        let reading = Reading { cpu_percent: Some(12.4), gpu_percent: Some(37.2), mem_used: Some(10 * 1024 * 1024) };
        assert_eq!(format_title(reading), "CPU: 12% GPU 37%, Memory: 10MiB");
    }

    #[test]
    fn title_says_n_a_instead_of_inventing_numbers() {
        let reading = Reading { cpu_percent: Some(12.4), gpu_percent: None, mem_used: Some(10 * 1024 * 1024) };
        assert_eq!(format_title(reading), "CPU: 12% GPU n/a, Memory: 10MiB");
        assert_eq!(format_title(Reading::default()), "CPU: n/a GPU n/a, Memory: n/a");
    }

    #[test]
    fn no_target_reads_nothing() {
        let mut stats = Stats::new();
        stats.track(None);
        assert_eq!(stats.title(), "CPU: n/a GPU n/a, Memory: n/a");
    }

    #[test]
    fn tracks_a_live_process_and_forgets_a_dead_one() {
        let mut stats = Stats::new();
        stats.track(Some(std::process::id()));
        assert!(stats.reading.mem_used.unwrap() > 0);
        stats.track(Some(u32::MAX - 1));
        assert_eq!(stats.reading, Reading::default());
    }
}
