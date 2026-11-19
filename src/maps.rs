//! `/proc/<pid>/maps` parsing, shared by the code browser.
//!
//! The scanner has its own span merging logic (values can straddle adjacent
//! mappings), so it does not use these mappings directly. Here we keep every
//! mapping intact: permissions, file offsets and paths are what the code tab
//! displays and what module-relative addresses are computed from.

use std::fs;
use std::io;
use std::path::Path;

#[allow(clippy::struct_excessive_bools)] // it is /proc/<pid>/maps' four flags
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Perms {
    pub read: bool,
    pub write: bool,
    pub exec: bool,
    pub shared: bool,
}

impl Perms {
    fn parse(text: &str) -> Option<Perms> {
        if text.len() != 4 {
            return None;
        }
        let mut chars = text.chars();
        let read = match chars.next()? {
            'r' => true,
            '-' => false,
            _ => return None,
        };
        let write = match chars.next()? {
            'w' => true,
            '-' => false,
            _ => return None,
        };
        let exec = match chars.next()? {
            'x' => true,
            '-' => false,
            _ => return None,
        };
        let shared = match chars.next()? {
            's' => true,
            'p' => false,
            _ => return None,
        };
        Some(Perms {
            read,
            write,
            exec,
            shared,
        })
    }

    /// Compact `rwxp` form, with `-` for the missing permission.
    pub fn text(self) -> String {
        let mut text = String::with_capacity(4);
        text.push(if self.read { 'r' } else { '-' });
        text.push(if self.write { 'w' } else { '-' });
        text.push(if self.exec { 'x' } else { '-' });
        text.push(if self.shared { 's' } else { 'p' });
        text
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Mapping {
    pub start: u64,
    pub end: u64,
    pub perms: Perms,
    pub offset: u64,
    pub dev: String,
    pub inode: u64,
    /// File-backed path, or `[heap]`, `[stack]`, `[vdso]`, …; `None` for
    /// anonymous mappings.
    pub path: Option<String>,
}

impl Mapping {
    pub fn len(&self) -> u64 {
        self.end.saturating_sub(self.start)
    }

    pub fn is_empty(&self) -> bool {
        self.end <= self.start
    }

    pub fn contains(&self, addr: u64) -> bool {
        (self.start..self.end).contains(&addr)
    }

    pub fn executable(&self) -> bool {
        self.perms.exec && !self.is_empty()
    }

    pub fn file_path(&self) -> Option<&str> {
        self.path.as_deref().filter(|path| path.starts_with('/'))
    }

    /// What to show in the sidebar: the file name when there is one.
    pub fn display_name(&self) -> String {
        match self.path.as_deref() {
            Some(path) if path.starts_with('/') => Path::new(path).file_name().map_or_else(
                || path.to_string(),
                |name| name.to_string_lossy().into_owned(),
            ),
            Some(path) if !path.is_empty() => path.to_string(),
            _ => "anonymous".to_string(),
        }
    }
}

/// Every mapping of `pid`, in address order.
pub fn read_maps(pid: u32) -> io::Result<Vec<Mapping>> {
    let text = fs::read_to_string(format!("/proc/{pid}/maps"))?;
    Ok(parse_maps(&text))
}

pub fn parse_maps(text: &str) -> Vec<Mapping> {
    text.lines().filter_map(parse_line).collect()
}

/// One `start-end perms offset dev inode [path]` line. The path may contain
/// spaces, so only the first five fields are split.
fn parse_line(line: &str) -> Option<Mapping> {
    let mut fields = line.splitn(6, ' ');
    let range = fields.next()?;
    let perms = Perms::parse(fields.next()?)?;
    let offset = u64::from_str_radix(fields.next()?, 16).ok()?;
    let dev = fields.next()?.to_string();
    let inode = fields.next()?.parse().ok()?;
    let path = fields
        .next()
        .map(str::trim)
        .filter(|path| !path.is_empty())
        .map(str::to_string);
    let (start, end) = range.split_once('-')?;
    let start = u64::from_str_radix(start, 16).ok()?;
    let end = u64::from_str_radix(end, 16).ok()?;
    (end > start).then_some(Mapping {
        start,
        end,
        perms,
        offset,
        dev,
        inode,
        path,
    })
}

/// The mapping containing `addr`.
pub fn mapping_at(mappings: &[Mapping], addr: u64) -> Option<&Mapping> {
    mappings.iter().find(|mapping| mapping.contains(addr))
}

/// The lowest address mapped from the same file, used as the module base for
/// `module+offset` display. Pseudo-mappings (`[heap]`, anonymous) have none.
pub fn module_base(mappings: &[Mapping], mapping: &Mapping) -> Option<u64> {
    let path = mapping.file_path()?;
    mappings
        .iter()
        .filter(|other| other.file_path() == Some(path))
        .map(|other| other.start)
        .min()
}

/// `some_module.so+0x1234`, or `[heap]+0x20`, for status lines and titles.
pub fn module_and_offset(mappings: &[Mapping], addr: u64) -> Option<(String, u64)> {
    let mapping = mapping_at(mappings, addr)?;
    if let Some(base) = module_base(mappings, mapping) {
        return Some((mapping.display_name(), addr.saturating_sub(base)));
    }
    Some((mapping.display_name(), addr.saturating_sub(mapping.start)))
}

pub fn format_module_offset(mappings: &[Mapping], addr: u64) -> String {
    match module_and_offset(mappings, addr) {
        Some((name, offset)) => format!("{name}+0x{offset:x}"),
        None => format!("0x{addr:x}"),
    }
}

/// Resolves `module+0x1234` (file name or full path) to an address that is
/// actually mapped. `module` may also be `[heap]` / `[stack]`.
pub fn resolve_module_offset(mappings: &[Mapping], text: &str) -> Option<u64> {
    let (module, offset) = text.trim().rsplit_once('+')?;
    let offset = offset.trim();
    let offset = offset.strip_prefix("0x").unwrap_or(offset);
    let offset = u64::from_str_radix(offset, 16).ok()?;
    let matches = |mapping: &Mapping| {
        let Some(path) = mapping.path.as_deref() else {
            return false;
        };
        path == module
            || Path::new(path)
                .file_name()
                .is_some_and(|name| name.to_string_lossy() == module)
            || path.ends_with(module)
    };
    let base = mappings
        .iter()
        .filter(|mapping| matches(mapping))
        .map(|mapping| module_base(mappings, mapping).unwrap_or(mapping.start))
        .min()?;
    let addr = base.checked_add(offset)?;
    mappings
        .iter()
        .any(|mapping| mapping.contains(addr))
        .then_some(addr)
}

#[cfg(test)]
mod tests {
    use super::*;

    const MAPS: &str = "\
55db444ba000-55db444ca000 rw-p 00000000 00:00 0 
55db7605a000-55db760c4000 rw-p 00000000 00:00 0                          [heap]
7f32efd90000-7f32efda0000 r-xp 00002000 08:01 4242   /usr/bin/My Game.exe
7f32efda0000-7f32efdb0000 r--p 00012000 08:01 4242   /usr/bin/My Game.exe
7f32efdc0000-7f32efdd0000 r-xp 00000000 08:01 99     /usr/lib/libc.so.6
";

    #[test]
    fn lines_keep_permissions_paths_and_spaces() {
        let maps = parse_maps(MAPS);
        assert_eq!(maps.len(), 5);
        assert!(maps[0].path.is_none());
        assert!(maps[0].perms.write && !maps[0].perms.exec);
        assert_eq!(maps[1].path.as_deref(), Some("[heap]"));
        assert_eq!(maps[2].path.as_deref(), Some("/usr/bin/My Game.exe"));
        assert_eq!(maps[2].perms.text(), "r-xp");
        assert_eq!(maps[2].offset, 0x2000);
        assert_eq!(maps[2].inode, 4242);
    }

    #[test]
    fn malformed_lines_are_skipped() {
        let maps = parse_maps(
            "nonsense\n\
             0-0 r--p 00000000 00:00 0\n\
             1000-2000 nope 00000000 00:00 0\n\
             1000-2000 r--p 00000000 00:00 0\n",
        );
        assert_eq!(maps.len(), 1);
        assert!(maps[0].contains(0x1000));
        assert!(!maps[0].contains(0x2000));
    }

    #[test]
    fn modules_and_offsets_use_the_lowest_mapping() {
        let maps = parse_maps(MAPS);
        let (name, offset) = module_and_offset(&maps, 0x7f32_efd9_1234).unwrap();
        assert_eq!(name, "My Game.exe");
        assert_eq!(offset, 0x1234);
        assert_eq!(
            format_module_offset(&maps, 0x7f32_efd9_1234),
            "My Game.exe+0x1234"
        );
        assert_eq!(
            module_and_offset(&maps, 0x55db_7605_a010),
            Some(("[heap]".into(), 0x10))
        );
        assert!(module_and_offset(&maps, 0x1).is_none());
    }

    #[test]
    fn module_goto_matches_names_paths_and_validates_mapping() {
        let maps = parse_maps(MAPS);
        assert_eq!(
            resolve_module_offset(&maps, "libc.so.6+0x10"),
            Some(0x7f32_efdc_0010)
        );
        assert_eq!(
            resolve_module_offset(&maps, "/usr/lib/libc.so.6+0x10"),
            Some(0x7f32_efdc_0010)
        );
        assert_eq!(
            resolve_module_offset(&maps, "My Game.exe+0x10"),
            Some(0x7f32_efd9_0010)
        );
        assert_eq!(resolve_module_offset(&maps, "libc.so.6+0x50000"), None);
        assert_eq!(resolve_module_offset(&maps, "libc.so.6"), None);
        assert_eq!(resolve_module_offset(&maps, "nope+0x1"), None);
    }
}
