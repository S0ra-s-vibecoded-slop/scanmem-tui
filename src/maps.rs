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

    pub fn readable(&self) -> bool {
        self.perms.read && !self.is_empty()
    }

    pub fn writable(&self) -> bool {
        self.perms.write && !self.is_empty()
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

/// Coarse classification used by Analyze and the trace report. The order is
/// meaningful: module slots are the best static roots, so they sort first.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum RegionKind {
    Module,
    Heap,
    Stack,
    Anonymous,
    Other,
}

impl RegionKind {
    pub fn text(self) -> &'static str {
        match self {
            RegionKind::Module => "module",
            RegionKind::Heap => "heap",
            RegionKind::Stack => "stack",
            RegionKind::Anonymous => "anon",
            RegionKind::Other => "special",
        }
    }
}

/// What kind of region a mapping is. Executability is the caller's decision:
/// the trace only scans writable memory, but Analyze checks it first.
pub fn region_kind(mapping: &Mapping) -> RegionKind {
    match mapping.path.as_deref() {
        Some("[heap]") => RegionKind::Heap,
        Some("[stack]") => RegionKind::Stack,
        Some(path) if path.starts_with('/') => RegionKind::Module,
        Some(_) => RegionKind::Other,
        None => RegionKind::Anonymous,
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

/// Index to keep selected after the mapping list changes: the item with the
/// same start when it still exists, otherwise `fallback` clamped into range.
pub fn reselect_index(starts: &[u64], selected: Option<u64>, fallback: usize) -> usize {
    selected
        .and_then(|start| starts.iter().position(|other| *other == start))
        .unwrap_or(fallback)
        .min(starts.len().saturating_sub(1))
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

/// The load base implied by the module's executable segment. Some tools quote
/// offsets relative to this rather than the lowest mapping; for a normal ELF
/// or PE module the two are equal.
pub fn exec_base(mappings: &[Mapping], mapping: &Mapping) -> Option<u64> {
    let path = mapping.file_path()?;
    mappings
        .iter()
        .filter(|other| other.file_path() == Some(path) && other.executable())
        .map(|other| other.start.saturating_sub(other.offset))
        .min()
}

/// Which base a `module+offset` resolution used.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum OffsetBase {
    /// The module's lowest mapping, as every address in the UI is displayed.
    LowestMapping,
    /// The executable segment's load base, as debuggers usually quote it.
    ExecSegment,
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
/// Resolves `module+0x…` and says which base was used. The displayed
/// base is tried first, so every offset shown in the UI round-trips; an offset
/// quoted from the executable segment still resolves.
pub fn resolve_module_offset_with_base(
    mappings: &[Mapping],
    text: &str,
) -> Option<(u64, OffsetBase)> {
    let (module, offset) = text.trim().rsplit_once('+')?;
    let offset = offset.trim();
    let offset = offset.strip_prefix("0x").unwrap_or(offset);
    let offset = u64::from_str_radix(offset, 16).ok()?;
    let is_module = |mapping: &Mapping| {
        let Some(path) = mapping.path.as_deref() else {
            return false;
        };
        path == module
            || Path::new(path)
                .file_name()
                .is_some_and(|name| name.to_string_lossy() == module)
            || path.ends_with(module)
    };
    let matched: Vec<&Mapping> = mappings
        .iter()
        .filter(|mapping| is_module(mapping))
        .collect();
    let lowest = matched
        .iter()
        .map(|mapping| module_base(mappings, mapping).unwrap_or(mapping.start))
        .min()?;
    let exec = matched
        .iter()
        .filter_map(|mapping| exec_base(mappings, mapping))
        .min();
    let mapped = |addr: u64| mappings.iter().any(|mapping| mapping.contains(addr));
    let candidate = lowest.checked_add(offset).filter(|addr| mapped(*addr));
    if let Some(addr) = candidate {
        return Some((addr, OffsetBase::LowestMapping));
    }
    let addr = exec?.checked_add(offset).filter(|addr| mapped(*addr))?;
    Some((addr, OffsetBase::ExecSegment))
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
            resolve_module_offset_with_base(&maps, "libc.so.6+0x10").map(|(addr, _)| addr),
            Some(0x7f32_efdc_0010)
        );
        assert_eq!(
            resolve_module_offset_with_base(&maps, "/usr/lib/libc.so.6+0x10").map(|(addr, _)| addr),
            Some(0x7f32_efdc_0010)
        );
        assert_eq!(
            resolve_module_offset_with_base(&maps, "My Game.exe+0x10").map(|(addr, _)| addr),
            Some(0x7f32_efd9_0010)
        );
        assert_eq!(
            resolve_module_offset_with_base(&maps, "libc.so.6+0x50000"),
            None
        );
        assert_eq!(resolve_module_offset_with_base(&maps, "libc.so.6"), None);
        assert_eq!(resolve_module_offset_with_base(&maps, "nope+0x1"), None);
    }

    #[test]
    fn goto_accepts_the_executable_segments_base_too() {
        let maps = parse_maps(MAPS);
        // The exec mapping sits at 0x…d90000 with file offset 0x2000, so its
        // load base is 0x…d8e000. Offset 0x21000 is unmapped from the display
        // base but lands in the module from the exec base.
        assert_eq!(
            resolve_module_offset_with_base(&maps, "My Game.exe+0x21000"),
            Some((0x7f32_efda_f000, OffsetBase::ExecSegment))
        );
        assert_eq!(
            resolve_module_offset_with_base(&maps, "My Game.exe+0x2000"),
            Some((0x7f32_efd9_2000, OffsetBase::LowestMapping))
        );
        assert_eq!(
            resolve_module_offset_with_base(&maps, "My Game.exe+0x10"),
            Some((0x7f32_efd9_0010, OffsetBase::LowestMapping))
        );
        assert_eq!(exec_base(&maps, &maps[2]), Some(0x7f32_efd8_e000));
        assert_eq!(exec_base(&maps, &maps[0]), None);
    }

    #[test]
    fn reselect_keeps_the_start_and_clamps_a_missing_one() {
        let starts = [0x1000, 0x2000, 0x3000];
        assert_eq!(reselect_index(&starts, Some(0x2000), 0), 1);
        assert_eq!(reselect_index(&starts, Some(0x9000), 2), 2);
        assert_eq!(reselect_index(&starts, Some(0x9000), 99), 2);
        assert_eq!(reselect_index(&[], Some(0x1000), 4), 0);
    }

    #[test]
    fn region_kinds_separate_modules_heap_stack_and_anonymous() {
        let mut maps = parse_maps(MAPS);
        maps.push(Mapping {
            start: 0x7000,
            end: 0x8000,
            perms: Perms::parse("rw-p").unwrap(),
            offset: 0,
            dev: "00:00".to_string(),
            inode: 0,
            path: Some("[stack]".to_string()),
        });
        assert_eq!(region_kind(&maps[0]), RegionKind::Anonymous);
        assert_eq!(region_kind(&maps[1]), RegionKind::Heap);
        assert_eq!(region_kind(&maps[2]), RegionKind::Module);
        assert_eq!(region_kind(&maps[5]), RegionKind::Stack);
        assert!(RegionKind::Module < RegionKind::Heap);
    }
}
