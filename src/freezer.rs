//! Background "freeze" writer (the CheatEngine-style checkbox).
//!
//! A single thread re-asserts every frozen value once per interval. To stay
//! light on both sides it
//!   * reads first and only writes when the value actually drifted,
//!   * never ptrace-attaches, so the target is never stopped,
//!   * does one pass per interval no matter how many entries are frozen.

use crate::memio::MemIo;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

/// 50 ms = 20 passes per second: fast enough that games rarely show the
/// un-frozen value, slow enough to be negligible load.
pub const DEFAULT_INTERVAL_MS: u64 = 50;
pub const MIN_INTERVAL_MS: u64 = 10;

type Target = (u64, Vec<u8>);

#[derive(Default)]
struct Shared {
    pid: Option<u32>,
    targets: Vec<Target>,
}

pub struct Freezer {
    shared: Arc<Mutex<Shared>>,
    stop: Arc<AtomicBool>,
    handle: Option<JoinHandle<()>>,
    pub interval: Duration,
}

impl Freezer {
    pub fn start(interval: Duration) -> Freezer {
        let shared = Arc::new(Mutex::new(Shared::default()));
        let stop = Arc::new(AtomicBool::new(false));
        let handle = {
            let shared = Arc::clone(&shared);
            let stop = Arc::clone(&stop);
            thread::Builder::new()
                .name("freezer".into())
                .spawn(move || run(&shared, &stop, interval))
                .expect("spawn freezer thread")
        };
        Freezer {
            shared,
            stop,
            handle: Some(handle),
            interval,
        }
    }

    pub fn set_pid(&self, pid: Option<u32>) {
        self.shared.lock().unwrap().pid = pid;
    }

    /// Replace the full set of (address, bytes) to keep pinned.
    pub fn set_targets(&self, targets: Vec<Target>) {
        self.shared.lock().unwrap().targets = targets;
    }
}

impl Drop for Freezer {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        if let Some(handle) = self.handle.take() {
            let _ = handle.join();
        }
    }
}

fn run(shared: &Arc<Mutex<Shared>>, stop: &Arc<AtomicBool>, interval: Duration) {
    let mut open: Option<(u32, MemIo)> = None;
    while !stop.load(Ordering::Relaxed) {
        let started = Instant::now();
        let (pid, targets) = snapshot(shared);
        let wanted_pid = if targets.is_empty() { None } else { pid };
        open = connection_for(open, wanted_pid);
        if let Some((_, mem)) = &open {
            reassert(mem, &targets);
        }
        if let Some(rest) = interval.checked_sub(started.elapsed()) {
            thread::sleep(rest);
        }
    }
}

fn snapshot(shared: &Mutex<Shared>) -> (Option<u32>, Vec<Target>) {
    let shared = shared.lock().unwrap();
    (shared.pid, shared.targets.clone())
}

/// Keeps the `/proc/<pid>/mem` handle for `wanted`, reopening it when the pid
/// changes and dropping it when there is nothing to hold.
fn connection_for(current: Option<(u32, MemIo)>, wanted: Option<u32>) -> Option<(u32, MemIo)> {
    let pid = wanted?;
    match current {
        Some((open_pid, mem)) if open_pid == pid => Some((open_pid, mem)),
        _ => MemIo::open(pid).ok().map(|mem| (pid, mem)),
    }
}

fn reassert(mem: &MemIo, targets: &[Target]) {
    for (addr, wanted) in targets {
        let mut buf = [0u8; 8];
        let current = &mut buf[..wanted.len().min(8)];
        if mem.read_into(*addr, current).is_ok() && current != wanted.as_slice() {
            let _ = mem.write(*addr, wanted);
        }
    }
}
