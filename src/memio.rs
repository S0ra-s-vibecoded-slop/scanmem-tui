//! Direct access to a process's memory through `/proc/<pid>/mem`.
//!
//! Reads and writes here do NOT attach with ptrace (unlike scanmem's own
//! `write` command), so they don't stop the target. That is what makes
//! repeated "freeze" writes cheap enough to run many times per second.

use crate::datatype::DataType;
use std::fs::{File, OpenOptions};
use std::io;
use std::os::unix::fs::FileExt;

pub struct MemIo {
    file: File,
    writable: bool,
}

impl MemIo {
    pub fn open(pid: u32) -> io::Result<MemIo> {
        let path = format!("/proc/{pid}/mem");
        if let Ok(file) = OpenOptions::new().read(true).write(true).open(&path) {
            return Ok(MemIo { file, writable: true });
        }
        // Read-only still lets us display values.
        let file = File::open(&path)?;
        Ok(MemIo { file, writable: false })
    }

    pub fn read_into(&self, addr: u64, buf: &mut [u8]) -> io::Result<()> {
        self.file.read_exact_at(buf, addr)
    }

    /// The value at `addr` rendered as `ty`, or `None` when unreadable.
    pub fn read_as(&self, addr: u64, ty: DataType) -> Option<String> {
        let mut buf = [0u8; 8];
        let bytes = &mut buf[..ty.size()];
        self.read_into(addr, bytes).ok()?;
        Some(ty.format_bytes(bytes))
    }

    pub fn write(&self, addr: u64, data: &[u8]) -> io::Result<()> {
        if !self.writable {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "/proc/<pid>/mem is not writable for this user",
            ));
        }
        self.file.write_all_at(data, addr)
    }
}
