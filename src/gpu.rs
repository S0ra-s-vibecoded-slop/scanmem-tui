//! GPU utilisation of one process, for the title bar.
//!
//! There is no vendor-neutral API, so there are two sources:
//! * NVIDIA through NVML (loaded at runtime, so machines without the driver
//!   simply have no NVIDIA source), which reports per-process SM utilisation.
//! * The kernel's DRM `fdinfo` counters (`/proc/<pid>/fdinfo/*`), which the
//!   amdgpu, i915 and xe drivers fill with the GPU time each client has used.
//!
//! A process the sources know nothing about reads as `None` ("n/a"), not 0%.

use nvml_wrapper::Nvml;
use std::collections::{HashMap, HashSet};
use std::fs;
use std::time::Instant;

pub struct GpuMeter {
    nvml: Option<Nvml>,
    /// Per NVML device index: newest process-utilisation sample seen so far.
    nvml_last_seen: HashMap<u32, u64>,
    drm_previous: Option<(Instant, HashMap<String, u64>)>,
}

impl GpuMeter {
    pub fn detect() -> GpuMeter {
        GpuMeter { nvml: Nvml::init().ok(), nvml_last_seen: HashMap::new(), drm_previous: None }
    }

    /// Forgets everything remembered about the previous process.
    pub fn reset(&mut self) {
        self.nvml_last_seen.clear();
        self.drm_previous = None;
    }

    /// Utilisation of `pid`, 0..=100. `None` when no GPU source knows the process.
    ///
    /// DRM utilisation is a delta between calls, so the first call after
    /// [`reset`](Self::reset) reports 0.
    pub fn percent_of(&mut self, pid: u32) -> Option<f32> {
        let nvidia = self.nvidia_percent(pid);
        let drm = self.drm_percent(pid);
        match (nvidia, drm) {
            (Some(a), Some(b)) => Some(a.max(b)),
            (a, b) => a.or(b),
        }
    }

    fn nvidia_percent(&mut self, pid: u32) -> Option<f32> {
        let nvml = self.nvml.as_ref()?;
        let count = nvml.device_count().ok()?;
        let mut busiest: Option<f32> = None;
        for index in 0..count {
            let Ok(device) = nvml.device_by_index(index) else { continue };
            let uses_device = device.running_graphics_processes().unwrap_or_default().iter().any(|p| p.pid == pid)
                || device.running_compute_processes().unwrap_or_default().iter().any(|p| p.pid == pid);
            if !uses_device {
                continue;
            }
            let last_seen = self.nvml_last_seen.get(&index).copied();
            // Only samples newer than `last_seen` come back, so none means idle.
            let Ok(samples) = device.process_utilization_stats(last_seen) else { continue };
            if let Some(newest) = samples.iter().map(|s| s.timestamp).max() {
                self.nvml_last_seen.insert(index, newest);
            }
            let percent = samples
                .iter()
                .filter(|s| s.pid == pid)
                .max_by_key(|s| s.timestamp)
                .map_or(0.0, |s| s.sm_util as f32);
            busiest = Some(busiest.map_or(percent, |best| best.max(percent)));
        }
        busiest
    }

    fn drm_percent(&mut self, pid: u32) -> Option<f32> {
        let now = Instant::now();
        let engines = read_drm_engines(pid);
        let previous = std::mem::replace(&mut self.drm_previous, engines.clone().map(|e| (now, e)));
        let engines = engines?;
        let Some((then, before)) = previous else { return Some(0.0) };
        Some(busiest_engine_percent(&before, &engines, now.duration_since(then).as_nanos() as u64))
    }
}

/// GPU time (ns) per engine name, summed over the process's DRM clients.
/// `None` when the process has no DRM client that reports engine time.
fn read_drm_engines(pid: u32) -> Option<HashMap<String, u64>> {
    let mut clients = HashSet::new();
    let mut engines: HashMap<String, u64> = HashMap::new();
    for entry in fs::read_dir(format!("/proc/{pid}/fdinfo")).ok()?.filter_map(Result::ok) {
        let Ok(text) = fs::read_to_string(entry.path()) else { continue };
        // A client shows up once per open fd (dup, fork); count it once.
        if let Some((client, times)) = parse_drm_fdinfo(&text) {
            if clients.insert(client) {
                for (engine, ns) in times {
                    *engines.entry(engine).or_insert(0) += ns;
                }
            }
        }
    }
    (!engines.is_empty()).then_some(engines)
}

/// Reads one fdinfo file: the client's identity and its time per engine.
/// `None` for fds that are not DRM clients or report no engine time.
fn parse_drm_fdinfo(text: &str) -> Option<(String, Vec<(String, u64)>)> {
    let (mut pdev, mut id) = (None, None);
    let mut engines = Vec::new();
    for line in text.lines() {
        let Some((key, value)) = line.split_once(':') else { continue };
        let value = value.trim();
        match key {
            "drm-pdev" => pdev = Some(value),
            "drm-client-id" => id = Some(value),
            _ => {
                if let Some(engine) = key.strip_prefix("drm-engine-") {
                    // Skip `drm-engine-capacity-<engine>`; only `<n> ns` lines count.
                    let ns = value.strip_suffix("ns").and_then(|n| n.trim().parse::<u64>().ok());
                    if let (false, Some(ns)) = (engine.starts_with("capacity-"), ns) {
                        engines.push((engine.to_string(), ns));
                    }
                }
            }
        }
    }
    if engines.is_empty() {
        return None;
    }
    Some((format!("{}/{}", pdev.unwrap_or(""), id?), engines))
}

/// Utilisation of the busiest engine over `elapsed_ns`, clamped to 0..=100.
fn busiest_engine_percent(before: &HashMap<String, u64>, after: &HashMap<String, u64>, elapsed_ns: u64) -> f32 {
    if elapsed_ns == 0 {
        return 0.0;
    }
    after
        .iter()
        .map(|(engine, &now)| now.saturating_sub(before.get(engine).copied().unwrap_or(now)))
        .max()
        .map_or(0.0, |busy| (busy as f64 / elapsed_ns as f64 * 100.0).clamp(0.0, 100.0) as f32)
}

#[cfg(test)]
mod tests {
    use super::*;

    const AMDGPU: &str = "pos:\t0\nflags:\t02100002\ndrm-driver:\tamdgpu\ndrm-pdev:\t0000:03:00.0\n\
                          drm-client-id:\t7\ndrm-engine-gfx:\t1500 ns\ndrm-engine-compute:\t20 ns\n\
                          drm-memory-vram:\t100 KiB\n";

    #[test]
    fn fdinfo_gives_client_and_engine_times() {
        let (client, engines) = parse_drm_fdinfo(AMDGPU).unwrap();
        assert_eq!(client, "0000:03:00.0/7");
        assert_eq!(engines, vec![("gfx".to_string(), 1500), ("compute".to_string(), 20)]);
    }

    #[test]
    fn fdinfo_ignores_capacity_lines_and_non_drm_fds() {
        let text = "drm-client-id:\t1\ndrm-engine-render:\t5 ns\ndrm-engine-capacity-render:\t2\n";
        let (_, engines) = parse_drm_fdinfo(text).unwrap();
        assert_eq!(engines, vec![("render".to_string(), 5)]);
        assert_eq!(parse_drm_fdinfo("pos:\t0\nflags:\t02\n"), None);
    }

    #[test]
    fn engine_percent_is_the_busiest_engines_share_of_the_interval() {
        let before = HashMap::from([("gfx".to_string(), 1_000), ("compute".to_string(), 0)]);
        let after = HashMap::from([("gfx".to_string(), 251_000), ("compute".to_string(), 100_000)]);
        assert_eq!(busiest_engine_percent(&before, &after, 1_000_000), 25.0);
        assert_eq!(busiest_engine_percent(&before, &after, 0), 0.0);
        assert_eq!(busiest_engine_percent(&before, &after, 10), 100.0);
    }

    #[test]
    fn a_process_without_any_source_has_no_reading() {
        let mut meter = GpuMeter { nvml: None, nvml_last_seen: HashMap::new(), drm_previous: None };
        assert_eq!(meter.percent_of(u32::MAX), None);
    }
}
