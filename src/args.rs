//! Command line.

use crate::datatype::DataType;
use crate::freezer::{DEFAULT_INTERVAL_MS, MIN_INTERVAL_MS};
use clap::Parser;
use std::time::Duration;

/// scanmem-tui - a terminal frontend for scanmem
#[derive(Parser, Debug)]
#[command(
    version,
    after_help = "scanmem needs ptrace access to the target: run as root, \
                  or as the same user with kernel.yama.ptrace_scope=0."
)]
pub struct Args {
    /// Attach to this process on startup
    #[arg(short = 'p', long = "pid", value_name = "PID")]
    pid_flag: Option<u32>,

    /// Same as --pid
    #[arg(value_name = "PID", conflicts_with = "pid_flag")]
    pid_arg: Option<u32>,

    /// scanmem binary to run
    #[arg(long, value_name = "PATH", env = "SCANMEM", default_value = "scanmem")]
    pub scanmem: String,

    /// How often frozen values are re-written, in milliseconds
    #[arg(
        long,
        value_name = "MS",
        default_value_t = DEFAULT_INTERVAL_MS,
        value_parser = clap::value_parser!(u64).range(MIN_INTERVAL_MS..)
    )]
    freeze_ms: u64,

    /// Initial scan type: int8, int16, int32, int64, float32 or float64
    #[arg(long = "type", value_name = "TYPE", default_value = "int32")]
    pub scan_type: DataType,
}

impl Args {
    pub fn target_pid(&self) -> Option<u32> {
        self.pid_flag.or(self.pid_arg)
    }

    pub fn freeze_interval(&self) -> Duration {
        Duration::from_millis(self.freeze_ms)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(args: &[&str]) -> Result<Args, clap::Error> {
        Args::try_parse_from(std::iter::once("scanmem-tui").chain(args.iter().copied()))
    }

    #[test]
    fn pid_by_flag_or_position() {
        assert_eq!(parse(&["--pid", "42"]).unwrap().target_pid(), Some(42));
        assert_eq!(parse(&["-p", "42"]).unwrap().target_pid(), Some(42));
        assert_eq!(parse(&["42"]).unwrap().target_pid(), Some(42));
        assert_eq!(parse(&[]).unwrap().target_pid(), None);
    }

    #[test]
    fn pid_given_twice_is_rejected() {
        assert!(parse(&["--pid", "1", "2"]).is_err());
    }

    #[test]
    fn freeze_interval_has_a_floor() {
        assert!(parse(&["--freeze-ms", "9"]).is_err());
        let args = parse(&["--freeze-ms", "10"]).unwrap();
        assert_eq!(args.freeze_interval(), Duration::from_millis(10));
    }

    #[test]
    fn scan_type_accepts_aliases() {
        assert_eq!(parse(&["--type", "float"]).unwrap().scan_type, DataType::F32);
        assert_eq!(parse(&[]).unwrap().scan_type, DataType::I32);
        assert!(parse(&["--type", "banana"]).is_err());
    }
}
