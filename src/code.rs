//! x86-64 disassembly and the static cross-reference scan.
//!
//! Everything here works on plain readers so it can be tested without a
//! process. Unreadable pages are filled with `int3` (0xcc): it is a valid
//! one-byte instruction, so a linear decode crossing a hole stays in sync
//! instead of sliding into garbage.

use crate::datatype::DataType;
use crate::maps::Mapping;
use crate::memio::MemIo;
use crate::scanner::ScanControl;
use iced_x86::{
    Decoder, DecoderOptions, FlowControl, Formatter, Instruction, IntelFormatter, OpKind, Register,
};
use rayon::prelude::*;
use std::collections::{HashMap, HashSet};
use std::io;
use std::time::Instant;

/// Memory is read and decoded in page-sized pieces; a failed page becomes
/// `int3` bytes instead of aborting the window or the scan.
const PAGE: u64 = 4096;
/// Longest x86 instruction. A decode only starts when this many bytes remain,
/// unless the mapping ends there.
const INSTRUCTION_MAX: usize = 15;
/// Bytes read above the anchor when opening the disassembly pane.
const WINDOW_LOOKBACK: u64 = 4096;
/// Bytes read for the disassembly pane.
const WINDOW_BYTES: usize = 32 * 1024;
/// Instructions decoded for the pane; enough for any terminal.
const WINDOW_LINES: usize = 800;
/// Bytes read from the target per scan step.
const SCAN_CHUNK: usize = 1024 * 1024;
/// How many references the scan keeps.
pub const XREF_MAX_RESULTS: usize = 5000;
/// How far below the target a stored pointer may point and still be listed:
/// a pointer to a struct is usually the struct's base, while the labelled
/// address sits somewhere inside it.
pub const POINTER_WINDOW: u64 = 0x1000;
/// How many pointer slots the scan keeps.
pub const POINTER_MAX_RESULTS: usize = 5000;
/// Byte written for unreadable pages.
const UNREADABLE: u8 = 0xcc;

/// A byte source. `/proc/<pid>/mem` in the app; test buffers in unit tests.
pub trait ReadBytes: Sync {
    fn read_bytes(&self, addr: u64, buf: &mut [u8]) -> io::Result<()>;
}

impl ReadBytes for MemIo {
    fn read_bytes(&self, addr: u64, buf: &mut [u8]) -> io::Result<()> {
        self.read_into(addr, buf)
    }
}

/// Fills `buf` from `addr`. One read covers the whole range in the common
/// case; when it fails, pages are retried one by one and a page that still
/// fails is cut into small pieces so readable bytes next to a hole survive.
/// Whatever cannot be read is replaced with `int3` bytes.
pub fn read_filled(reader: &dyn ReadBytes, addr: u64, buf: &mut [u8]) {
    if reader.read_bytes(addr, buf).is_ok() {
        return;
    }
    let mut done = 0_usize;
    while done < buf.len() {
        let at = addr.saturating_add(u64::try_from(done).unwrap_or(u64::MAX));
        let page_left = PAGE - at % PAGE;
        let len = usize::try_from(page_left)
            .unwrap_or(buf.len() - done)
            .min(buf.len() - done);
        if reader.read_bytes(at, &mut buf[done..done + len]).is_err() {
            read_pieces(reader, at, &mut buf[done..done + len]);
        }
        done += len;
    }
}

/// Retries a failed page in 16-byte pieces; pieces that still fail become
/// `int3`. A whole bad page costs a few hundred cheap failed reads.
fn read_pieces(reader: &dyn ReadBytes, addr: u64, buf: &mut [u8]) {
    const PIECE: usize = 16;
    let mut done = 0_usize;
    while done < buf.len() {
        let len = PIECE.min(buf.len() - done);
        let at = addr.saturating_add(u64::try_from(done).unwrap_or(u64::MAX));
        if reader.read_bytes(at, &mut buf[done..done + len]).is_err() {
            buf[done..done + len].fill(UNREADABLE);
        }
        done += len;
    }
}

/// What an instruction does, for colouring and for keeping track of flow.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Flow {
    Normal,
    Call,
    Jump,
    Conditional,
    Return,
    Indirect,
    Interrupt,
    Invalid,
}

impl Flow {
    fn of(instr: &Instruction) -> Flow {
        if instr.is_invalid() {
            return Flow::Invalid;
        }
        match instr.flow_control() {
            FlowControl::Call => Flow::Call,
            FlowControl::UnconditionalBranch => Flow::Jump,
            FlowControl::ConditionalBranch => Flow::Conditional,
            FlowControl::Return => Flow::Return,
            FlowControl::IndirectBranch | FlowControl::IndirectCall => Flow::Indirect,
            FlowControl::Interrupt => Flow::Interrupt,
            FlowControl::Exception | FlowControl::XbeginXabortXend => Flow::Invalid,
            FlowControl::Next => Flow::Normal,
        }
    }
}

/// One decoded instruction, ready for the pane.
#[derive(Clone, Debug)]
pub struct DecodedLine {
    pub addr: u64,
    pub bytes: Vec<u8>,
    pub text: String,
    pub flow: Flow,
    /// Direct call/branch target, when Enter can follow it.
    pub target: Option<u64>,
    /// A memory operand whose address is encoded in the instruction.
    pub mention: Option<Mention>,
}

/// The absolute address of a memory operand. Laid out as a table base when
/// an index register is involved: `indexed` means the value is the table,
/// not the selected entry.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Mention {
    pub addr: u64,
    pub indexed: bool,
}

/// Instructions decoded around one anchor.
pub struct Window {
    pub start: u64,
    pub lines: Vec<DecodedLine>,
}

/// Reads and decodes the instructions visible around `anchor`.
///
/// `anchor` is assumed to be an instruction boundary (a branch target, a
/// mapping start, or a line the user already selected). Decoding starts up to
/// 15 bytes earlier so the pane has context; the earliest start that walks
/// exactly onto `anchor` wins.
pub fn decode_window(reader: &dyn ReadBytes, anchor: u64, lo: u64, hi: u64) -> Window {
    let start = anchor.saturating_sub(WINDOW_LOOKBACK).max(lo);
    let end = hi.min(start.saturating_add(u64::try_from(WINDOW_BYTES).unwrap_or(u64::MAX)));
    let Some(len) = usize::try_from(end.saturating_sub(start))
        .ok()
        .filter(|len| *len > 0)
    else {
        return Window {
            start: anchor,
            lines: Vec::new(),
        };
    };
    let mut bytes = vec![0_u8; len];
    read_filled(reader, start, &mut bytes);
    let aligned = aligned_start(&bytes, start, anchor);
    decode_lines(&bytes, start, aligned, hi)
}

/// Reads and decodes forward from an instruction boundary. Unlike
/// [`decode_window`] there is no lookback: scrolling down continues exactly
/// where the previous window ended.
pub fn decode_window_forward(reader: &dyn ReadBytes, start: u64, hi: u64) -> Window {
    let end = hi.min(start.saturating_add(u64::try_from(WINDOW_BYTES).unwrap_or(u64::MAX)));
    let Some(len) = usize::try_from(end.saturating_sub(start))
        .ok()
        .filter(|len| *len > 0)
    else {
        return Window {
            start,
            lines: Vec::new(),
        };
    };
    let mut bytes = vec![0_u8; len];
    read_filled(reader, start, &mut bytes);
    decode_lines(&bytes, start, start, hi)
}

/// The earliest address within 15 bytes of `anchor` from which decoding lands
/// exactly on `anchor` in at most four instructions.
fn aligned_start(bytes: &[u8], base: u64, anchor: u64) -> u64 {
    if anchor <= base {
        return anchor;
    }
    let max_back = (anchor - base).min(INSTRUCTION_MAX as u64);
    for back in (1..=max_back).rev() {
        let candidate = anchor - back;
        if decodes_onto(bytes, base, candidate, anchor) {
            return candidate;
        }
    }
    anchor
}

fn decodes_onto(bytes: &[u8], base: u64, start: u64, anchor: u64) -> bool {
    let Ok(offset) = usize::try_from(start - base) else {
        return false;
    };
    let Some(tail) = bytes.get(offset..) else {
        return false;
    };
    let mut decoder = Decoder::with_ip(64, tail, start, DecoderOptions::NONE);
    for _ in 0..4 {
        if !decoder.can_decode() {
            return false;
        }
        let instr = decoder.decode();
        if instr.is_invalid() {
            return false;
        }
        if instr.next_ip() == anchor {
            return true;
        }
        if instr.next_ip() > anchor {
            return false;
        }
    }
    false
}

fn decode_lines(bytes: &[u8], base: u64, start: u64, hi: u64) -> Window {
    let Ok(offset) = usize::try_from(start.saturating_sub(base)) else {
        return Window {
            start,
            lines: Vec::new(),
        };
    };
    let Some(tail) = bytes.get(offset..) else {
        return Window {
            start,
            lines: Vec::new(),
        };
    };
    let mut decoder = Decoder::with_ip(64, tail, start, DecoderOptions::NONE);
    let mut formatter = intel_formatter();
    let mut lines = Vec::new();
    while lines.len() < WINDOW_LINES && decoder.can_decode() && decoder.ip() < hi {
        let instr = decoder.decode();
        let addr = instr.ip();
        if addr >= hi {
            break;
        }
        let from = usize::try_from(addr.saturating_sub(base)).unwrap_or(usize::MAX);
        let Some(end) = from.checked_add(instr.len()) else {
            break;
        };
        let Some(slice) = bytes.get(from..end) else {
            break;
        };
        let mut text = String::new();
        formatter.format(&instr, &mut text);
        lines.push(DecodedLine {
            addr,
            bytes: slice.to_vec(),
            text,
            flow: Flow::of(&instr),
            target: branch_target(&instr),
            mention: memory_mention(&instr),
        });
    }
    Window {
        start: lines.first().map_or(start, |line| line.addr),
        lines,
    }
}

fn intel_formatter() -> IntelFormatter {
    let mut formatter = IntelFormatter::new();
    let options = formatter.options_mut();
    options.set_hex_prefix("0x");
    options.set_hex_suffix("");
    options.set_uppercase_hex(false);
    formatter
}

fn branch_target(instr: &Instruction) -> Option<u64> {
    if instr.is_invalid() {
        return None;
    }
    match instr.flow_control() {
        FlowControl::Call | FlowControl::UnconditionalBranch | FlowControl::ConditionalBranch => {
            match instr.op0_kind() {
                OpKind::NearBranch16 | OpKind::NearBranch32 | OpKind::NearBranch64 => {
                    Some(instr.near_branch_target())
                }
                _ => None,
            }
        }
        _ => None,
    }
}

/// The absolute address of a memory operand, when the instruction encodes it.
fn memory_mention(instr: &Instruction) -> Option<Mention> {
    if instr.is_ip_rel_memory_operand() {
        return Some(Mention {
            addr: instr.ip_rel_memory_address(),
            indexed: false,
        });
    }
    let has_memory = instr
        .op_kinds()
        .any(|kind| kind == OpKind::Memory && instr.memory_base() == Register::None);
    has_memory.then(|| Mention {
        addr: instr.memory_displacement64(),
        indexed: instr.memory_index() != Register::None,
    })
}

/// How a reference encodes the target address.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RefKind {
    RipRelative,
    Absolute,
    /// A base-less operand with an index register: the value is the table
    /// base, while the entry is chosen at runtime.
    Indexed,
    Immediate,
}

/// One address, or an inclusive span of addresses to look for.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct AddrRange {
    pub lo: u64,
    pub hi: u64,
}

impl AddrRange {
    pub const fn one(addr: u64) -> AddrRange {
        AddrRange { lo: addr, hi: addr }
    }

    /// Accepts the ends in either order.
    pub const fn span(lo: u64, hi: u64) -> AddrRange {
        if lo <= hi {
            AddrRange { lo, hi }
        } else {
            AddrRange { lo: hi, hi: lo }
        }
    }

    pub fn contains(self, value: u64) -> bool {
        self.lo <= value && value <= self.hi
    }

    pub fn is_single(self) -> bool {
        self.lo == self.hi
    }
}

impl Default for AddrRange {
    fn default() -> AddrRange {
        AddrRange::one(0)
    }
}

impl std::fmt::Display for AddrRange {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if self.is_single() {
            write!(f, "0x{:x}", self.lo)
        } else {
            write!(f, "0x{:x}..0x{:x}", self.lo, self.hi)
        }
    }
}

/// One instruction that mentions an address.
#[derive(Clone, Debug)]
pub struct Reference {
    pub addr: u64,
    /// The address the instruction actually mentioned.
    pub target: u64,
    pub text: String,
    pub kind: RefKind,
}

/// A memory slot holding a pointer into the scanned object.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Pointer {
    pub slot: u64,
    /// The address stored in the slot; `target - POINTER_WINDOW` to `target`.
    pub value: u64,
}

/// Budgets for one trace walk. The defaults are deliberately small enough to
/// finish on a large game while still finding ordinary two-to-four hop chains.
#[derive(Clone, Copy, Debug)]
pub struct TraceOptions {
    pub max_depth: usize,
    pub max_slots_per_level: usize,
    pub max_nodes: usize,
    pub max_paths: usize,
    pub align: usize,
    /// The extra reach below the target on the first edge, for a struct base.
    pub first_window: u64,
    pub include_stack: bool,
    /// Stop at a module slot (a static root). With `false`, dead ends in other
    /// regions are reported as roots too.
    pub require_static_root: bool,
}

impl Default for TraceOptions {
    fn default() -> TraceOptions {
        TraceOptions {
            max_depth: 4,
            max_slots_per_level: 2_000,
            max_nodes: 20_000,
            max_paths: 64,
            align: 8,
            first_window: POINTER_WINDOW,
            include_stack: false,
            require_static_root: true,
        }
    }
}

/// What one walk did, including whether a cap or cancellation made it partial.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct TraceStats {
    /// Levels that were actually scanned.
    pub levels: usize,
    /// Unique slots discovered (plus the target).
    pub nodes: usize,
    /// Slots found holding a frontier value.
    pub slots: usize,
    pub roots: usize,
    /// A cap dropped candidates, so the report is partial.
    pub truncated: bool,
    pub cancelled: bool,
    pub elapsed_ms: u128,
}

/// One edge from a slot to the value it holds.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Hop {
    pub slot: u64,
    pub value: u64,
    pub kind: crate::maps::RegionKind,
    /// Slot minus its mapping start.
    pub offset: u64,
}

/// The static end of a path: a slot in writable module memory.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TraceRoot {
    pub slot: u64,
    pub kind: crate::maps::RegionKind,
    pub offset: u64,
}

/// A candidate chain, ordered root → target. `code` is the instruction that
/// loads the root, when the static reference pass proved one.
#[derive(Clone, Debug)]
pub struct TracePath {
    pub hops: Vec<Hop>,
    pub root: Option<TraceRoot>,
    pub code: Option<Reference>,
    /// How far below `target` the closest hop's value is (0 for exact).
    pub offset: u64,
    /// All slots still held their traced values when re-read at the end.
    pub stable: bool,
}

/// Where a running trace is, for the status line.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TracePhase {
    Refs,
    Level(usize),
    Roots,
    Done,
}

/// The result of one Analyze/trace job.
#[derive(Clone, Debug)]
pub struct TraceReport {
    pub target: u64,
    pub target_label: String,
    pub target_kind: Option<crate::maps::RegionKind>,
    /// Direct static references to the target itself.
    pub refs: Vec<Reference>,
    pub paths: Vec<TracePath>,
    pub stats: TraceStats,
}

/// A saved address the annotation formatter can name and type.
#[derive(Clone, Copy)]
pub struct SavedRef<'a> {
    pub addr: u64,
    pub ty: DataType,
    pub label: &'a str,
}

/// One data row of the hex view.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HexRow {
    pub addr: u64,
    /// Hex bytes, `??` for unreadable ones, padded to the full row width.
    pub hex: String,
    /// Printable ASCII, `.` for other bytes, `?` for unreadable ones.
    pub ascii: String,
}

/// Bytes read for the data view, and which of them were readable.
pub struct ByteWindow {
    pub start: u64,
    pub bytes: Vec<u8>,
    pub readable: Vec<bool>,
}

impl ByteWindow {
    pub fn end(&self) -> u64 {
        self.start
            .saturating_add(u64::try_from(self.bytes.len()).unwrap_or(0))
    }
}

/// Reads `len` bytes without pretending: unreadable pieces are zeroed and
/// flagged. [`read_filled`] deliberately substitutes `int3`, which is right
/// for decoding and wrong for displaying data.
pub fn read_reporting(reader: &dyn ReadBytes, start: u64, len: usize) -> ByteWindow {
    const PIECE: usize = 16;
    let mut bytes = vec![0_u8; len];
    let mut readable = vec![false; len];
    if reader.read_bytes(start, &mut bytes).is_ok() {
        readable.fill(true);
        return ByteWindow {
            start,
            bytes,
            readable,
        };
    }
    let mut done = 0_usize;
    while done < len {
        let at = start.saturating_add(u64::try_from(done).unwrap_or(u64::MAX));
        let page_left = PAGE - at % PAGE;
        let chunk = usize::try_from(page_left)
            .unwrap_or(len - done)
            .min(len - done);
        if reader
            .read_bytes(at, &mut bytes[done..done + chunk])
            .is_ok()
        {
            readable[done..done + chunk].fill(true);
        } else {
            let mut piece = 0_usize;
            while piece < chunk {
                let n = PIECE.min(chunk - piece);
                let piece_at = at.saturating_add(u64::try_from(piece).unwrap_or(u64::MAX));
                if reader
                    .read_bytes(piece_at, &mut bytes[done + piece..done + piece + n])
                    .is_ok()
                {
                    readable[done + piece..done + piece + n].fill(true);
                }
                piece += n;
            }
        }
        done += chunk;
    }
    ByteWindow {
        start,
        bytes,
        readable,
    }
}

/// Splits a reported window into hex rows. `per_row` is 8, 16 or 32 in the UI.
pub fn hex_rows(window: &ByteWindow, per_row: usize) -> Vec<HexRow> {
    let per_row = per_row.max(1);
    let width = per_row * 3 - 1;
    let chunks = window.bytes.len().div_ceil(per_row);
    (0..chunks)
        .map(|row| {
            let from = row * per_row;
            let to = (from + per_row).min(window.bytes.len());
            let mut hex = String::new();
            let mut ascii = String::new();
            for index in from..to {
                if index > from {
                    hex.push(' ');
                }
                let ok = window.readable.get(index).copied().unwrap_or(false);
                let byte = window.bytes.get(index).copied().unwrap_or(0);
                if ok {
                    use std::fmt::Write;
                    let _ = write!(hex, "{byte:02x}");
                    ascii.push(if byte.is_ascii_graphic() || byte == b' ' {
                        char::from(byte)
                    } else {
                        '.'
                    });
                } else {
                    hex.push_str("??");
                    ascii.push('?');
                }
            }
            HexRow {
                addr: window
                    .start
                    .saturating_add(u64::try_from(row * per_row).unwrap_or(0)),
                hex: format!("{hex:<width$}"),
                ascii,
            }
        })
        .collect()
}

/// A short annotation for an encoded operand address: where it points, what
/// it currently holds (typed when a saved label says how), and -- when the
/// address is a live pointer slot -- the pointer it stores.
pub fn describe_mention(
    reader: &dyn ReadBytes,
    mappings: &[Mapping],
    saved: &[SavedRef<'_>],
    mention: Mention,
) -> String {
    let location = crate::maps::format_module_offset(mappings, mention.addr);
    let known = saved
        .iter()
        .find(|item| item.addr == mention.addr && !item.label.is_empty());
    let place = known.map_or_else(
        || location.clone(),
        |item| format!("{} ({location})", item.label),
    );
    if mention.indexed {
        return format!("{place} table");
    }
    let value = match known {
        Some(item) => read_typed(reader, mention.addr, item.ty),
        None => read_u64(reader, mention.addr).map(|value| format!("0x{value:x}")),
    };
    let mut text = value.map_or(place.clone(), |value| format!("{place} = {value}"));
    if let Some(pointer) = pointer_hint(reader, mappings, mention.addr) {
        use std::fmt::Write;
        let _ = write!(
            text,
            " → {}",
            crate::maps::format_module_offset(mappings, pointer)
        );
    }
    text
}

/// Reads `addr` as `ty` for display, `None` when the bytes are unreadable.
pub fn read_typed(reader: &dyn ReadBytes, addr: u64, ty: DataType) -> Option<String> {
    let mut buf = [0_u8; 8];
    reader.read_bytes(addr, &mut buf[..ty.size()]).ok()?;
    Some(ty.format_bytes(&buf[..ty.size()]))
}

fn read_u64(reader: &dyn ReadBytes, addr: u64) -> Option<u64> {
    let mut buf = [0_u8; 8];
    reader.read_bytes(addr, &mut buf).ok()?;
    Some(u64::from_le_bytes(buf))
}

/// What a writable operand slot currently points at, when it looks like a
/// pointer into this process.
fn pointer_hint(reader: &dyn ReadBytes, mappings: &[Mapping], slot: u64) -> Option<u64> {
    let mapping = crate::maps::mapping_at(mappings, slot)?;
    if !mapping.writable() {
        return None;
    }
    let value = read_u64(reader, slot)?;
    crate::maps::mapping_at(mappings, value).map(|_| value)
}

/// Scans every executable mapping for instructions encoding `targets`.
///
/// This is a *static* scan: it sees operands and immediates, so heap
/// addresses reached through pointers will usually have no hits. A span
/// catches accesses to a struct's base when the labelled address is a field.
pub fn scan(
    reader: &dyn ReadBytes,
    mappings: &[Mapping],
    targets: AddrRange,
    control: &ScanControl,
) -> Vec<Reference> {
    scan_targets(reader, mappings, TargetSet::Range(targets), control)
}

/// The same scan for an arbitrary set of addresses, used by the trace to
/// attach loading instructions to root slots.
pub fn scan_refs_many(
    reader: &dyn ReadBytes,
    mappings: &[Mapping],
    targets: &HashSet<u64>,
    control: &ScanControl,
) -> Vec<Reference> {
    scan_targets(reader, mappings, TargetSet::Many(targets), control)
}

fn scan_targets(
    reader: &dyn ReadBytes,
    mappings: &[Mapping],
    targets: TargetSet<'_>,
    control: &ScanControl,
) -> Vec<Reference> {
    let executable: Vec<&Mapping> = mappings
        .iter()
        .filter(|mapping| mapping.executable())
        .collect();
    let total = executable.iter().map(|mapping| mapping.len()).sum();
    control.set_total(total);
    let per_mapping: Vec<Vec<Reference>> = executable
        .par_iter()
        .map(|mapping| {
            if control.cancelled() {
                Vec::new()
            } else {
                scan_mapping(reader, mapping, targets, control)
            }
        })
        .collect();
    let mut found: Vec<Reference> = per_mapping.into_iter().flatten().collect();
    found.sort_by_key(|reference| reference.addr);
    found.dedup_by_key(|reference| reference.addr);
    found.truncate(XREF_MAX_RESULTS);
    found
}

/// Scans writable memory for 8-byte slots holding a pointer to the target,
/// or to up to `POINTER_WINDOW` bytes before it (a struct's base).
///
/// Pointers are stored data, not operands: this is the way to reach objects
/// whose address no instruction encodes. Read-only mappings are skipped:
/// a live pointer is written by the process, so it lives in writable memory.
/// A pointer that only exists in a register cannot be found this way.
pub fn scan_pointers(
    reader: &dyn ReadBytes,
    mappings: &[Mapping],
    target: u64,
    control: &ScanControl,
) -> Vec<Pointer> {
    let lo = target.saturating_sub(POINTER_WINDOW);
    let writable: Vec<&Mapping> = mappings
        .iter()
        .filter(|mapping| mapping.readable() && mapping.writable())
        .collect();
    let total = writable.iter().map(|mapping| mapping.len()).sum();
    control.set_total(total);
    let per_mapping: Vec<Vec<Pointer>> = writable
        .par_iter()
        .map(|mapping| {
            if control.cancelled() {
                Vec::new()
            } else {
                scan_mapping_pointers(
                    reader,
                    mapping,
                    PointerTarget::Window { lo, hi: target },
                    control,
                )
            }
        })
        .collect();
    let mut found: Vec<Pointer> = per_mapping.into_iter().flatten().collect();
    found.sort_by_key(|pointer| pointer.slot);
    found.dedup_by_key(|pointer| pointer.slot);
    // Exact pointers first, then the closest interior ones: anything else in
    // the window (a link_map, a stack copy of a module base) is noise.
    found.sort_by_key(|pointer| (target - pointer.value, pointer.slot));
    found.truncate(POINTER_MAX_RESULTS);
    found
}

/// One pass over writable memory for slots holding any value in `frontier`.
///
/// `window` additionally matches an inclusive range (used for the struct-base
/// edge at level 0). Slots are filtered to `align`-aligned addresses; the
/// manual pointer scan stays byte-granular.
pub fn scan_pointers_many(
    reader: &dyn ReadBytes,
    mappings: &[Mapping],
    frontier: &HashSet<u64>,
    window: Option<AddrRange>,
    align: usize,
    control: &ScanControl,
) -> Vec<Pointer> {
    let writable: Vec<&Mapping> = mappings
        .iter()
        .filter(|mapping| mapping.readable() && mapping.writable())
        .collect();
    let total = writable.iter().map(|mapping| mapping.len()).sum();
    control.set_total(total);
    let target = PointerTarget::Many {
        set: frontier,
        window,
        align: u64::try_from(align.max(1)).unwrap_or(1),
    };
    let per_mapping: Vec<Vec<Pointer>> = writable
        .par_iter()
        .map(|mapping| {
            if control.cancelled() {
                Vec::new()
            } else {
                scan_mapping_pointers(reader, mapping, target, control)
            }
        })
        .collect();
    let mut found: Vec<Pointer> = per_mapping.into_iter().flatten().collect();
    found.sort_by_key(|pointer| pointer.slot);
    found.dedup_by_key(|pointer| pointer.slot);
    found.sort_by_key(|pointer| (!frontier.contains(&pointer.value), pointer.slot));
    found.truncate(POINTER_MAX_RESULTS);
    found
}

#[derive(Clone, Copy)]
enum PointerTarget<'a> {
    /// The manual scan: any value in `[lo, hi]`, byte-granular.
    Window { lo: u64, hi: u64 },
    /// One trace level: exact set membership, plus an optional first-edge
    /// window, at aligned slots only.
    Many {
        set: &'a HashSet<u64>,
        window: Option<AddrRange>,
        align: u64,
    },
}

impl PointerTarget<'_> {
    fn matches(self, value: u64, slot: u64) -> bool {
        match self {
            PointerTarget::Window { lo, hi } => (lo..=hi).contains(&value),
            PointerTarget::Many { set, window, align } => {
                slot.is_multiple_of(align)
                    && (set.contains(&value) || window.is_some_and(|range| range.contains(value)))
            }
        }
    }
}

/// Walks backwards from `target` through stored pointers until it reaches a
/// writable module slot. This is a static candidate finder, not proof: it
/// reports what *could* load the address, with every cap and every changed
/// slot called out.
#[cfg(test)]
pub fn trace(
    reader: &dyn ReadBytes,
    mappings: &[Mapping],
    target: u64,
    label: Option<&str>,
    options: &TraceOptions,
    control: &ScanControl,
) -> TraceReport {
    trace_with_progress(reader, mappings, target, label, options, control, &|_| {})
}

/// [`trace`] with a phase callback, so the job's status line can say whether
/// it is still finding references, which level it is on, or collecting roots.
#[expect(clippy::too_many_lines, reason = "the walk has distinct phases")]
pub fn trace_with_progress(
    reader: &dyn ReadBytes,
    mappings: &[Mapping],
    target: u64,
    label: Option<&str>,
    options: &TraceOptions,
    control: &ScanControl,
    progress: &dyn Fn(TracePhase),
) -> TraceReport {
    let started = Instant::now();
    progress(TracePhase::Refs);
    let target_kind = crate::maps::mapping_at(mappings, target).map(crate::maps::region_kind);
    let refs = scan(reader, mappings, AddrRange::one(target), control);

    let mut incoming: HashMap<u64, Vec<Hop>> = HashMap::new();
    let mut roots: Vec<Hop> = Vec::new();
    let mut visited: HashSet<u64> = HashSet::new();
    visited.insert(target);
    let mut frontier = vec![target];
    let mut stats = TraceStats::default();
    let mut levels = 0_usize;

    for depth in 0..options.max_depth {
        if control.cancelled() || frontier.is_empty() {
            break;
        }
        progress(TracePhase::Level(depth));
        let set: HashSet<u64> = frontier.iter().copied().collect();
        let window = (depth == 0)
            .then(|| AddrRange::span(target.saturating_sub(options.first_window), target));
        let pointers = scan_pointers_many(reader, mappings, &set, window, options.align, control);
        levels += 1;
        let mut next: Vec<(Hop, bool)> = Vec::new();
        for pointer in pointers {
            if control.cancelled() {
                break;
            }
            let Some(mapping) = crate::maps::mapping_at(mappings, pointer.slot) else {
                continue;
            };
            if mapping.executable() {
                continue;
            }
            let kind = crate::maps::region_kind(mapping);
            if kind == crate::maps::RegionKind::Stack && !options.include_stack {
                continue;
            }
            if !visited.insert(pointer.slot) {
                continue;
            }
            let exact = set.contains(&pointer.value);
            // A window hit points at the struct base, so the chain logically
            // ends at the target; keep the actual value for the offset line.
            let child = if exact { pointer.value } else { target };
            let hop = Hop {
                slot: pointer.slot,
                value: pointer.value,
                kind,
                offset: pointer.slot.saturating_sub(mapping.start),
            };
            stats.slots += 1;
            incoming.entry(child).or_default().push(hop.clone());
            if kind == crate::maps::RegionKind::Module {
                roots.push(hop);
            } else {
                next.push((hop, exact));
            }
        }
        next.sort_by_key(|(hop, exact)| (hop.kind, !*exact, hop.offset, hop.slot));
        if next.len() > options.max_slots_per_level {
            stats.truncated = true;
            next.truncate(options.max_slots_per_level);
        }
        if stats.nodes + next.len() > options.max_nodes {
            stats.truncated = true;
            next.truncate(options.max_nodes.saturating_sub(stats.nodes));
        }
        stats.nodes += next.len();
        frontier = next.into_iter().map(|(hop, _)| hop.slot).collect();
        if stats.nodes >= options.max_nodes {
            stats.truncated = true;
            break;
        }
    }

    progress(TracePhase::Roots);
    let mut code_by_slot: HashMap<u64, Reference> = HashMap::new();
    if !roots.is_empty() && !control.cancelled() {
        let root_set: HashSet<u64> = roots.iter().map(|hop| hop.slot).collect();
        for reference in scan_refs_many(reader, mappings, &root_set, control) {
            code_by_slot.entry(reference.target).or_insert(reference);
        }
    }

    let mut chains: Vec<Vec<Hop>> = Vec::new();
    let mut budget = options.max_nodes.max(1024);
    let limit = options.max_paths.saturating_mul(8).max(1);
    walk_paths(
        &incoming,
        target,
        &mut Vec::new(),
        &mut chains,
        &mut budget,
        limit,
    );
    let paths_truncated = chains.len() >= limit;
    let mut paths: Vec<TracePath> = chains
        .into_iter()
        .map(|hops| {
            let first = hops.first();
            let root = first
                .filter(|hop| {
                    hop.kind == crate::maps::RegionKind::Module || !options.require_static_root
                })
                .map(|hop| TraceRoot {
                    slot: hop.slot,
                    kind: hop.kind,
                    offset: hop.offset,
                });
            let code = root
                .as_ref()
                .and_then(|root| code_by_slot.get(&root.slot).cloned());
            let offset = hops
                .last()
                .map_or(0, |hop| target.saturating_sub(hop.value));
            let stable = hops
                .iter()
                .all(|hop| read_u64(reader, hop.slot) == Some(hop.value));
            TracePath {
                hops,
                root,
                code,
                offset,
                stable,
            }
        })
        .collect();
    rank_paths(&mut paths);
    if paths.len() > options.max_paths {
        stats.truncated = true;
        paths.truncate(options.max_paths);
    }
    stats.truncated |= paths_truncated;
    stats.levels = levels;
    stats.roots = roots.len();
    stats.cancelled |= control.cancelled();
    stats.elapsed_ms = started.elapsed().as_millis();
    progress(TracePhase::Done);

    TraceReport {
        target,
        target_label: label.unwrap_or_default().to_string(),
        target_kind,
        refs,
        paths,
        stats,
    }
}

/// Orders candidates for the report: proven code refs first, then rooted
/// paths, then exact before offset, then shorter chains.
fn rank_paths(paths: &mut [TracePath]) {
    paths.sort_by_key(|path| {
        (
            path.code.is_none(),
            path.root.is_none(),
            path.offset != 0,
            path.hops.len(),
            path.root.as_ref().map_or(u64::MAX, |root| root.slot),
        )
    });
}

/// Collects root → target slot chains from the `child → slots` edge map.
fn walk_paths(
    incoming: &HashMap<u64, Vec<Hop>>,
    node: u64,
    suffix: &mut Vec<Hop>,
    out: &mut Vec<Vec<Hop>>,
    budget: &mut usize,
    limit: usize,
) {
    if *budget == 0 || out.len() >= limit {
        return;
    }
    let Some(edges) = incoming.get(&node) else {
        return;
    };
    for hop in edges {
        if *budget == 0 || out.len() >= limit {
            return;
        }
        if suffix.iter().any(|seen| seen.slot == hop.slot) {
            continue; // a cycle in heap pointers
        }
        *budget -= 1;
        suffix.push(hop.clone());
        let next = hop.slot;
        if hop.kind == crate::maps::RegionKind::Module || !incoming.contains_key(&next) {
            out.push(suffix.iter().rev().cloned().collect());
        } else {
            walk_paths(incoming, next, suffix, out, budget, limit);
        }
        suffix.pop();
    }
}

fn scan_mapping(
    reader: &dyn ReadBytes,
    mapping: &Mapping,
    targets: TargetSet<'_>,
    control: &ScanControl,
) -> Vec<Reference> {
    let mut found = Vec::new();
    let mut formatter = intel_formatter();
    let mut chunk = vec![0_u8; SCAN_CHUNK];
    let mut addr = mapping.start;
    // An instruction may straddle a chunk boundary; its bytes (and exact
    // address) are carried into the next chunk so decoding never desyncs.
    let mut carry: Vec<u8> = Vec::new();
    let mut carry_addr = mapping.start;
    while addr < mapping.end && !control.cancelled() {
        let len = usize::try_from((mapping.end - addr).min(SCAN_CHUNK as u64)).unwrap_or(0);
        if len == 0 {
            break;
        }
        read_filled(reader, addr, &mut chunk[..len]);
        control.add_done(u64::try_from(len).unwrap_or(0));
        let mut data = Vec::with_capacity(carry.len() + len);
        data.extend_from_slice(&carry);
        data.extend_from_slice(&chunk[..len]);
        let more_chunks = addr.saturating_add(u64::try_from(len).unwrap_or(0)) < mapping.end;
        let mut decoder = Decoder::with_ip(64, &data, carry_addr, DecoderOptions::NONE);
        while decoder.can_decode() {
            let offset = decoder.position();
            if more_chunks && data.len().saturating_sub(offset) < INSTRUCTION_MAX {
                break; // leave the tail for the next chunk
            }
            if control.cancelled() {
                return found;
            }
            let instr = decoder.decode();
            if let Some((target, kind)) = targets.target_of(&instr) {
                let mut text = String::new();
                formatter.format(&instr, &mut text);
                found.push(Reference {
                    addr: instr.ip(),
                    target,
                    text,
                    kind,
                });
            }
        }
        let next = decoder.ip();
        let Ok(tail) = usize::try_from(next.saturating_sub(carry_addr)) else {
            break;
        };
        carry = data.get(tail..).map(<[u8]>::to_vec).unwrap_or_default();
        carry_addr = next;
        addr = addr.saturating_add(u64::try_from(len).unwrap_or(0));
    }
    found
}

/// Pointer slots in one mapping. Like the xref scan, the last seven bytes
/// are carried into the next chunk so a slot on the boundary is not missed;
/// the overlap is deduplicated by slot address afterwards.
fn scan_mapping_pointers(
    reader: &dyn ReadBytes,
    mapping: &Mapping,
    target: PointerTarget<'_>,
    control: &ScanControl,
) -> Vec<Pointer> {
    let mut found = Vec::new();
    let mut chunk = vec![0_u8; SCAN_CHUNK];
    let mut carry: Vec<u8> = Vec::new();
    let mut carry_addr = mapping.start;
    let mut addr = mapping.start;
    while addr < mapping.end && !control.cancelled() {
        let len = usize::try_from((mapping.end - addr).min(SCAN_CHUNK as u64)).unwrap_or(0);
        if len == 0 {
            break;
        }
        read_filled(reader, addr, &mut chunk[..len]);
        control.add_done(u64::try_from(len).unwrap_or(0));
        let mut data = Vec::with_capacity(carry.len() + len);
        data.extend_from_slice(&carry);
        data.extend_from_slice(&chunk[..len]);
        for (offset, bytes) in data.windows(8).enumerate() {
            if control.cancelled() || found.len() >= POINTER_MAX_RESULTS {
                return found;
            }
            let value = u64::from_le_bytes(bytes.try_into().unwrap_or([0; 8]));
            let slot = carry_addr.saturating_add(u64::try_from(offset).unwrap_or(u64::MAX));
            if target.matches(value, slot) {
                found.push(Pointer { slot, value });
            }
        }
        let keep = data.len().min(7);
        carry = data.split_off(data.len() - keep);
        carry_addr = carry_addr.saturating_add(u64::try_from(data.len()).unwrap_or(0));
        addr = addr.saturating_add(u64::try_from(len).unwrap_or(0));
    }
    found
}

/// What an address is matched against during a scan.
#[derive(Clone, Copy)]
enum TargetSet<'a> {
    Range(AddrRange),
    Many(&'a HashSet<u64>),
}

impl TargetSet<'_> {
    fn contains(self, value: u64) -> bool {
        match self {
            TargetSet::Range(range) => range.contains(value),
            TargetSet::Many(set) => set.contains(&value),
        }
    }

    fn target_of(self, instr: &Instruction) -> Option<(u64, RefKind)> {
        if let Some((value, kind)) = reference_target(instr)
            && self.contains(value)
        {
            return Some((value, kind));
        }
        reference_targets(instr)
            .skip(1)
            .find(|(value, _)| self.contains(*value))
    }
}

/// Every address the instruction encodes as a possible reference, in decode
/// order: a RIP-relative operand, then base-less absolute/indexed operands,
/// then immediates. An instruction can name more than one (e.g. a store with
/// an address and an immediate), so scans check all of them.
fn reference_targets(instr: &Instruction) -> impl Iterator<Item = (u64, RefKind)> + '_ {
    let rip = instr
        .is_ip_rel_memory_operand()
        .then(|| (instr.ip_rel_memory_address(), RefKind::RipRelative));
    rip.into_iter().chain(
        instr
            .op_kinds()
            .filter_map(move |kind| operand_target(instr, kind)),
    )
}

/// The first address an instruction encodes, if any.
fn reference_target(instr: &Instruction) -> Option<(u64, RefKind)> {
    reference_targets(instr).next()
}

fn operand_target(instr: &Instruction, kind: OpKind) -> Option<(u64, RefKind)> {
    match kind {
        // A base-less absolute operand (`[0x1234]`, `[rax*4+0x404040]`).
        // With an index the displacement is the table base, not an entry.
        OpKind::Memory if instr.memory_base() == Register::None => {
            let indexed = instr.memory_index() != Register::None;
            Some((
                instr.memory_displacement64(),
                if indexed {
                    RefKind::Indexed
                } else {
                    RefKind::Absolute
                },
            ))
        }
        OpKind::Immediate8 => Some((u64::from(instr.immediate8()), RefKind::Immediate)),
        OpKind::Immediate16 => Some((u64::from(instr.immediate16()), RefKind::Immediate)),
        OpKind::Immediate32 => Some((u64::from(instr.immediate32()), RefKind::Immediate)),
        OpKind::Immediate64 => Some((instr.immediate64(), RefKind::Immediate)),
        OpKind::Immediate8to16 => Some((
            instr.immediate8to16().cast_unsigned().into(),
            RefKind::Immediate,
        )),
        OpKind::Immediate8to32 => Some((
            instr.immediate8to32().cast_unsigned().into(),
            RefKind::Immediate,
        )),
        OpKind::Immediate8to64 => {
            Some((instr.immediate8to64().cast_unsigned(), RefKind::Immediate))
        }
        OpKind::Immediate32to64 => {
            Some((instr.immediate32to64().cast_unsigned(), RefKind::Immediate))
        }
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A byte buffer mapped at `base`; reads outside it fail.
    struct Bytes {
        base: u64,
        data: Vec<u8>,
    }

    impl Bytes {
        fn at(base: u64, data: &[u8]) -> Bytes {
            Bytes {
                base,
                data: data.to_vec(),
            }
        }
    }

    impl ReadBytes for Bytes {
        fn read_bytes(&self, addr: u64, buf: &mut [u8]) -> io::Result<()> {
            let start = addr
                .checked_sub(self.base)
                .and_then(|offset| usize::try_from(offset).ok())
                .ok_or_else(|| io::Error::from(io::ErrorKind::UnexpectedEof))?;
            let end = start
                .checked_add(buf.len())
                .ok_or_else(|| io::Error::from(io::ErrorKind::UnexpectedEof))?;
            let slice = self
                .data
                .get(start..end)
                .ok_or_else(|| io::Error::from(io::ErrorKind::UnexpectedEof))?;
            buf.copy_from_slice(slice);
            Ok(())
        }
    }

    fn mapping(start: u64, len: u64) -> Mapping {
        Mapping {
            start,
            end: start + len,
            perms: crate::maps::Perms {
                read: true,
                write: false,
                exec: true,
                shared: false,
            },
            offset: 0,
            dev: "00:00".into(),
            inode: 0,
            path: Some("/bin/test".into()),
        }
    }

    /// Readable data, not code, for pointer tests.
    fn data_mapping(start: u64, len: u64) -> Mapping {
        Mapping {
            perms: crate::maps::Perms {
                read: true,
                write: true,
                exec: false,
                shared: false,
            },
            ..mapping(start, len)
        }
    }

    /// A writable region with an explicit maps path (`[heap]`, `[stack]`, …).
    fn region_mapping(start: u64, len: u64, path: &str) -> Mapping {
        Mapping {
            path: Some(path.to_string()),
            ..data_mapping(start, len)
        }
    }

    /// A sparse in-memory address space: only the listed regions are readable.
    struct Sparse {
        regions: Vec<(u64, Vec<u8>)>,
    }

    impl Sparse {
        fn new(regions: &[(u64, u64)]) -> Sparse {
            Sparse {
                regions: regions
                    .iter()
                    .map(|(base, len)| (*base, vec![0_u8; usize::try_from(*len).unwrap_or(0)]))
                    .collect(),
            }
        }

        fn write(&mut self, addr: u64, bytes: &[u8]) {
            for (base, data) in &mut self.regions {
                if addr < *base {
                    continue;
                }
                let Ok(offset) = usize::try_from(addr - *base) else {
                    continue;
                };
                if let Some(slice) = data.get_mut(offset..offset + bytes.len()) {
                    slice.copy_from_slice(bytes);
                    return;
                }
            }
            panic!("test write outside the sparse regions");
        }

        fn put_ptr(&mut self, slot: u64, value: u64) {
            self.write(slot, &value.to_le_bytes());
        }
    }

    impl ReadBytes for Sparse {
        fn read_bytes(&self, addr: u64, buf: &mut [u8]) -> io::Result<()> {
            for (base, data) in &self.regions {
                if addr < *base {
                    continue;
                }
                let Ok(offset) = usize::try_from(addr - *base) else {
                    continue;
                };
                if let Some(slice) = data.get(offset..offset + buf.len()) {
                    buf.copy_from_slice(slice);
                    return Ok(());
                }
            }
            Err(io::Error::from(io::ErrorKind::UnexpectedEof))
        }
    }

    /// target ← heap slot ← module slot, with code loading the module slot.
    fn chain_fixture() -> (Sparse, Vec<Mapping>) {
        let mut mem = Sparse::new(&[
            (0x10_0000, 0x100),
            (0x20_0000, 0x1000),
            (0x30_0000, 0x1000),
            (0x40_0000, 0x1000),
        ]);
        // mov rax,[rip+0x2ffff9] at 0x100000 -> 0x400000.
        mem.write(0x10_0000, &[0x48, 0x8b, 0x05, 0xf9, 0xff, 0x2f, 0x00]);
        mem.put_ptr(0x20_0010, 0x30_0000);
        mem.put_ptr(0x40_0000, 0x20_0010);
        let maps = vec![
            mapping(0x10_0000, 0x100),
            region_mapping(0x20_0000, 0x1000, "[heap]"),
            region_mapping(0x30_0000, 0x1000, "[heap]"),
            region_mapping(0x40_0000, 0x1000, "/tmp/game"),
        ];
        (mem, maps)
    }

    #[test]
    fn scan_refs_many_matches_a_one_address_range_scan() {
        let code = Bytes::at(0x1000, &[0x48, 0x8b, 0x05, 0x00, 0x10, 0x00, 0x00]);
        let map = mapping(0x1000, 7);
        let mut targets = HashSet::new();
        targets.insert(0x2007);
        let many = scan_refs_many(
            &code,
            std::slice::from_ref(&map),
            &targets,
            &ScanControl::new(),
        );
        let ranged = scan(
            &code,
            std::slice::from_ref(&map),
            AddrRange::one(0x2007),
            &ScanControl::new(),
        );
        assert_eq!(many.len(), ranged.len());
        assert_eq!(many[0].addr, ranged[0].addr);
        assert_eq!(many[0].kind, ranged[0].kind);
    }

    #[test]
    fn report_ranking_prefers_proven_rooted_exact_short_paths() {
        let hop = |slot: u64| Hop {
            slot,
            value: 0x30_0000,
            kind: crate::maps::RegionKind::Heap,
            offset: 0,
        };
        let root = |slot: u64| TraceRoot {
            slot,
            kind: crate::maps::RegionKind::Module,
            offset: 0,
        };
        let code = Reference {
            addr: 0x10_0000,
            target: 0x40_0000,
            text: "mov rax,[rip+0x2ffff9]".to_string(),
            kind: RefKind::RipRelative,
        };
        let path = |root: Option<TraceRoot>, code: Option<Reference>, offset: u64, hops: usize| {
            TracePath {
                hops: (0..hops)
                    .map(|index| hop(0x20_0000 + u64::try_from(index).unwrap_or(0) * 8))
                    .collect(),
                root,
                code,
                offset,
                stable: true,
            }
        };
        let mut paths = vec![
            path(None, None, 0, 1),
            path(Some(root(0x40_0000)), None, 0, 2),
            path(Some(root(0x50_0000)), Some(code), 0x10, 3),
        ];
        rank_paths(&mut paths);
        assert!(paths[0].code.is_some());
        assert_eq!(paths[1].root.map(|root| root.slot), Some(0x40_0000));
        assert!(paths[2].root.is_none());
    }

    #[test]
    fn trace_finds_a_rooted_chain_and_its_code_ref() {
        let (mem, maps) = chain_fixture();
        let report = trace(
            &mem,
            &maps,
            0x30_0000,
            Some("health"),
            &TraceOptions::default(),
            &ScanControl::new(),
        );
        assert_eq!(report.target_label, "health");
        assert_eq!(report.target_kind, Some(crate::maps::RegionKind::Heap));
        assert_eq!(report.paths.len(), 1);
        let path = &report.paths[0];
        assert_eq!(path.hops.len(), 2);
        assert_eq!(path.root.map(|root| root.slot), Some(0x40_0000));
        assert_eq!(path.code.as_ref().map(|code| code.addr), Some(0x10_0000));
        assert_eq!(path.offset, 0);
        assert!(path.stable);
        assert_eq!(report.stats.roots, 1);
        assert_eq!(report.stats.levels, 2);
        assert!(!report.stats.truncated);
    }

    #[test]
    fn trace_ignores_a_coincidental_integer() {
        let (mut mem, maps) = chain_fixture();
        // Replace the real chain with values that are neither the target nor
        // inside the first-edge window.
        mem.put_ptr(0x20_0010, 0x99_9999);
        mem.put_ptr(0x40_0000, 0x88_8888);
        let report = trace(
            &mem,
            &maps,
            0x30_0000,
            None,
            &TraceOptions::default(),
            &ScanControl::new(),
        );
        assert!(report.paths.is_empty());
        assert_eq!(report.stats.roots, 0);
    }

    #[test]
    fn trace_survives_a_pointer_cycle() {
        let mut mem = Sparse::new(&[(0x20_0000, 0x1000)]);
        mem.put_ptr(0x20_0010, 0x20_0020);
        mem.put_ptr(0x20_0020, 0x20_0010);
        let maps = vec![region_mapping(0x20_0000, 0x1000, "[heap]")];
        let report = trace(
            &mem,
            &maps,
            0x20_0020,
            None,
            &TraceOptions::default(),
            &ScanControl::new(),
        );
        assert_eq!(report.paths.len(), 1);
        assert!(report.paths[0].root.is_none());
    }

    #[test]
    fn trace_excludes_the_stack_by_default() {
        let mut mem = Sparse::new(&[(0x30_0000, 0x1000), (0x50_0000, 0x1000)]);
        mem.put_ptr(0x50_0010, 0x30_0000);
        let maps = vec![
            region_mapping(0x30_0000, 0x1000, "[heap]"),
            region_mapping(0x50_0000, 0x1000, "[stack]"),
        ];
        let report = trace(
            &mem,
            &maps,
            0x30_0000,
            None,
            &TraceOptions::default(),
            &ScanControl::new(),
        );
        assert!(report.paths.is_empty());
        assert_eq!(report.stats.slots, 0);

        let options = TraceOptions {
            include_stack: true,
            ..TraceOptions::default()
        };
        let report = trace(&mem, &maps, 0x30_0000, None, &options, &ScanControl::new());
        assert_eq!(report.paths.len(), 1);
        assert!(report.paths[0].root.is_none());
    }

    #[test]
    fn trace_reports_a_frontier_cap_as_truncated() {
        let mut mem = Sparse::new(&[(0x30_0000, 0x1000), (0x20_0000, 0x1000)]);
        for index in 0..32_u64 {
            mem.put_ptr(0x20_0000 + index * 8, 0x30_0000);
        }
        let maps = vec![
            region_mapping(0x20_0000, 0x1000, "[heap]"),
            region_mapping(0x30_0000, 0x1000, "[heap]"),
        ];
        let options = TraceOptions {
            max_slots_per_level: 2,
            ..TraceOptions::default()
        };
        let report = trace(&mem, &maps, 0x30_0000, None, &options, &ScanControl::new());
        assert!(report.stats.truncated);
        assert_eq!(report.stats.nodes, 2);
    }

    #[test]
    fn trace_marks_a_slot_that_changed_as_unstable() {
        struct Flaky {
            inner: Sparse,
            slot: u64,
            value: u64,
        }

        impl ReadBytes for Flaky {
            fn read_bytes(&self, addr: u64, buf: &mut [u8]) -> io::Result<()> {
                self.inner.read_bytes(addr, buf)?;
                if addr == self.slot && buf.len() == 8 {
                    buf.copy_from_slice(&self.value.to_le_bytes());
                }
                Ok(())
            }
        }

        let (mut inner, maps) = chain_fixture();
        inner.put_ptr(0x20_0010, 0x30_0000);
        let flaky = Flaky {
            inner,
            slot: 0x40_0000,
            value: 0x1234,
        };
        let report = trace(
            &flaky,
            &maps,
            0x30_0000,
            None,
            &TraceOptions::default(),
            &ScanControl::new(),
        );
        assert_eq!(report.paths.len(), 1);
        // The slot is still 0x200010 from the scan; stability re-read sees 0x1234.
        assert!(!report.paths[0].stable);
    }

    #[test]
    fn cancelled_trace_returns_a_partial_report() {
        let (mem, maps) = chain_fixture();
        let control = ScanControl::new();
        control.cancel();
        let report = trace(
            &mem,
            &maps,
            0x30_0000,
            Some("health"),
            &TraceOptions::default(),
            &control,
        );
        assert!(report.stats.cancelled);
        assert!(report.refs.is_empty());
        assert_eq!(report.target, 0x30_0000);
    }

    #[test]
    fn decodes_known_instructions() {
        // push rbp; mov rbp, rsp; ret
        let code = Bytes::at(0x1000, &[0x55, 0x48, 0x89, 0xe5, 0xc3]);
        let window = decode_window(&code, 0x1000, 0x1000, 0x1005);
        assert_eq!(window.start, 0x1000);
        let texts: Vec<&str> = window.lines.iter().map(|l| l.text.as_str()).collect();
        assert_eq!(texts, ["push rbp", "mov rbp,rsp", "ret"]);
        assert_eq!(window.lines[0].flow, Flow::Normal);
        assert_eq!(window.lines[2].flow, Flow::Return);
        assert_eq!(window.lines[1].bytes, [0x48, 0x89, 0xe5]);
    }

    #[test]
    fn a_window_finds_the_instruction_start_above_the_anchor() {
        let code = Bytes::at(0x1000, &[0x55, 0x48, 0x89, 0xe5, 0xc3]);
        let window = decode_window(&code, 0x1004, 0x1000, 0x1005);
        // Decoding from 0x1000 lands exactly on the anchor, so that start wins.
        assert_eq!(window.start, 0x1000);
        assert_eq!(window.lines.len(), 3);
        assert_eq!(window.lines[2].addr, 0x1004);
    }

    #[test]
    fn direct_branches_have_a_follow_target() {
        // call rel32 -> 0x1010; jne rel8 -> 0x1007
        let code = Bytes::at(0x1000, &[0xe8, 0x0b, 0x00, 0x00, 0x00, 0x75, 0x00]);
        let window = decode_window(&code, 0x1000, 0x1000, 0x1007);
        assert_eq!(window.lines[0].flow, Flow::Call);
        assert_eq!(window.lines[0].target, Some(0x1010));
        assert_eq!(window.lines[1].flow, Flow::Conditional);
        assert_eq!(window.lines[1].target, Some(0x1007));
    }

    #[test]
    fn unreadable_pages_do_not_stop_the_decode() {
        // 16 readable nops, then a hole that becomes int3 bytes.
        let code = Bytes::at(0x1000, &[0x90; 16]);
        let window = decode_window(&code, 0x1000, 0x1000, 0x1020);
        assert_eq!(window.lines.len(), 32);
        assert_eq!(window.lines[0].text, "nop");
        assert_eq!(window.lines[15].text, "nop");
        assert_eq!(window.lines[16].text, "int3");
        assert_eq!(window.lines[31].text, "int3");
    }

    #[test]
    fn scan_finds_rip_relative_operands() {
        // mov rax,[rip+0x1000] at 0x1000: next ip 0x1007 + 0x1000 = 0x2007.
        let code = Bytes::at(0x1000, &[0x48, 0x8b, 0x05, 0x00, 0x10, 0x00, 0x00]);
        let control = ScanControl::new();
        let found = scan(
            &code,
            &[mapping(0x1000, 7)],
            AddrRange::one(0x2007),
            &control,
        );
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].addr, 0x1000);
        assert_eq!(found[0].kind, RefKind::RipRelative);
        assert!(found[0].text.contains("mov"));
        assert_eq!(control.progress(), (7, 7));
    }

    #[test]
    fn scan_finds_immediates_and_absolute_operands() {
        // mov rax,0x1234; mov rax,[0x2000]
        let code = Bytes::at(
            0x1000,
            &[
                0x48, 0xb8, 0x34, 0x12, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x48, 0xa1, 0x00, 0x20,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            ],
        );
        let map = mapping(0x1000, 20);
        let control = ScanControl::new();
        let found = scan(
            &code,
            std::slice::from_ref(&map),
            AddrRange::one(0x1234),
            &control,
        );
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].kind, RefKind::Immediate);

        let control = ScanControl::new();
        let found = scan(
            &code,
            std::slice::from_ref(&map),
            AddrRange::one(0x2000),
            &control,
        );
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].kind, RefKind::Absolute);
        assert_eq!(found[0].addr, 0x100a);
    }

    #[test]
    fn instructions_crossing_a_chunk_boundary_are_decoded_once() {
        let len = SCAN_CHUNK + 64;
        let mut data = vec![0x90_u8; len]; // nops
        let at = SCAN_CHUNK - 3;
        // mov rax,[rip+0x42], straddling the chunk edge (7 bytes).
        data[at..at + 7].copy_from_slice(&[0x48, 0x8b, 0x05, 0x42, 0x00, 0x00, 0x00]);
        let instr_addr = 0x1_0000 + at as u64;
        let target = instr_addr + 7 + 0x42;
        let code = Bytes::at(0x1_0000, &data);
        let control = ScanControl::new();
        let found = scan(
            &code,
            &[mapping(0x1_0000, len as u64)],
            AddrRange::one(target),
            &control,
        );
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].addr, instr_addr);
    }

    #[test]
    fn cancelled_scans_return_what_they_have_and_keep_the_total() {
        let code = Bytes::at(0x1000, &[0x48, 0x8b, 0x05, 0x00, 0x10, 0x00, 0x00]);
        let control = ScanControl::new();
        control.cancel();
        let found = scan(
            &code,
            &[mapping(0x1000, 7)],
            AddrRange::one(0x2007),
            &control,
        );
        assert!(found.is_empty());
        assert_eq!(control.progress(), (0, 7));
    }

    #[test]
    fn our_own_code_mapping_decodes_through_memio() {
        // Reading our own /proc/self/mem needs no ptrace access.
        let pid = std::process::id();
        let Some(mapping) = crate::maps::read_maps(pid)
            .ok()
            .and_then(|maps| maps.into_iter().find(crate::maps::Mapping::executable))
        else {
            return; // no maps in this environment; nothing to prove
        };
        let Ok(memory) = MemIo::open(pid) else {
            return;
        };
        let window = decode_window(&memory, mapping.start, mapping.start, mapping.end);
        assert!(!window.lines.is_empty());
        assert!(window.lines.iter().all(|line| line.addr >= mapping.start));
        assert!(window.lines.iter().all(|line| !line.text.is_empty()));
    }

    #[test]
    fn scans_cap_results_in_address_order() {
        let count = XREF_MAX_RESULTS + 100;
        let base = 0x10_0000_u64;
        let target = 0x80_0000_u64;
        let mut data = Vec::with_capacity(count * 7);
        for i in 0..count {
            let at = base + u64::try_from(i).unwrap() * 7;
            let disp = i64::try_from(target).unwrap() - i64::try_from(at + 7).unwrap();
            data.extend_from_slice(&[0x48, 0x8b, 0x05]);
            data.extend_from_slice(&i32::try_from(disp).unwrap().to_le_bytes());
        }
        let code = Bytes::at(base, &data);
        let control = ScanControl::new();
        let found = scan(
            &code,
            &[mapping(base, u64::try_from(data.len()).unwrap())],
            AddrRange::one(target),
            &control,
        );
        assert_eq!(found.len(), XREF_MAX_RESULTS);
        assert!(found.windows(2).all(|pair| pair[0].addr < pair[1].addr));
    }

    #[test]
    fn only_executable_mappings_are_scanned() {
        let code = Bytes::at(0x1000, &[0x48, 0x8b, 0x05, 0x00, 0x10, 0x00, 0x00]);
        let mut data = mapping(0x1000, 7);
        data.perms.exec = false;
        let control = ScanControl::new();
        let found = scan(&code, &[data], AddrRange::one(0x2007), &control);
        assert!(found.is_empty());
        assert_eq!(control.progress(), (0, 0));
    }

    #[test]
    fn a_span_matches_several_addresses() {
        // mov rax,[rip+0xff9] at 0x1000 -> 0x2000; at 0x1007 -> 0x2008.
        let code = Bytes::at(
            0x1000,
            &[
                0x48, 0x8b, 0x05, 0xf9, 0x0f, 0x00, 0x00, 0x48, 0x8b, 0x05, 0xfa, 0x0f, 0x00, 0x00,
            ],
        );
        let map = mapping(0x1000, 14);
        let control = ScanControl::new();
        let found = scan(
            &code,
            std::slice::from_ref(&map),
            AddrRange::span(0x2000, 0x2008),
            &control,
        );
        assert_eq!(found.len(), 2);

        let control = ScanControl::new();
        let found = scan(
            &code,
            std::slice::from_ref(&map),
            AddrRange::one(0x2000),
            &control,
        );
        assert_eq!(found.len(), 1);
    }

    #[test]
    fn a_span_accepts_its_ends_in_either_order() {
        let range = AddrRange::span(0x3000, 0x2000);
        assert_eq!((range.lo, range.hi), (0x2000, 0x3000));
        assert!(range.contains(0x2800));
        assert!(!range.contains(0x1fff));
    }

    #[test]
    fn pointer_scan_lists_exact_pointers_first() {
        let target = 0x142a_2374c_u64;
        let mut data = vec![0_u8; 64];
        data[8..16].copy_from_slice(&(target - 0x18).to_le_bytes());
        data[16..24].copy_from_slice(&target.to_le_bytes());
        data[24..32].copy_from_slice(&(target - POINTER_WINDOW - 8).to_le_bytes());
        data[40..48].copy_from_slice(&0x1234_u64.to_le_bytes());
        let code = Bytes::at(0x1_0000, &data);
        let control = ScanControl::new();
        let found = scan_pointers(&code, &[data_mapping(0x1_0000, 64)], target, &control);
        assert_eq!(
            found,
            [
                Pointer {
                    slot: 0x1_0010,
                    value: target,
                },
                Pointer {
                    slot: 0x1_0008,
                    value: target - 0x18,
                },
            ]
        );
    }

    #[test]
    fn pointer_scan_skips_unreadable_mappings() {
        let target = 0x142a_2374c_u64;
        let mut data = vec![0_u8; 16];
        data[8..16].copy_from_slice(&target.to_le_bytes());
        let code = Bytes::at(0x1_0000, &data);
        let mut no_read = data_mapping(0x1_0000, 16);
        no_read.perms.read = false;
        let control = ScanControl::new();
        let found = scan_pointers(&code, &[no_read], target, &control);
        assert_eq!(found, []);
        assert_eq!(control.progress(), (0, 0));
    }

    #[test]
    fn pointer_scan_skips_read_only_mappings() {
        let target = 0x142a_2374c_u64;
        let mut data = vec![0_u8; 16];
        data[8..16].copy_from_slice(&target.to_le_bytes());
        let code = Bytes::at(0x1_0000, &data);
        let mut read_only = data_mapping(0x1_0000, 16);
        read_only.perms.write = false;
        let control = ScanControl::new();
        let found = scan_pointers(&code, &[read_only], target, &control);
        assert_eq!(found, []);
    }

    #[test]
    fn a_pointer_straddling_a_chunk_is_found_once() {
        let target = 0x142a_2374c_u64;
        let len = SCAN_CHUNK + 64;
        let mut data = vec![0x11_u8; len];
        let at = SCAN_CHUNK - 4;
        data[at..at + 8].copy_from_slice(&target.to_le_bytes());
        let code = Bytes::at(0x1_0000, &data);
        let control = ScanControl::new();
        let found = scan_pointers(
            &code,
            &[data_mapping(0x1_0000, u64::try_from(len).unwrap())],
            target,
            &control,
        );
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].slot, 0x1_0000 + u64::try_from(at).unwrap());
    }

    #[test]
    fn indexed_absolute_operands_match_the_table_base() {
        // mov eax,[rax*4+0x404040]
        let code = Bytes::at(0x1000, &[0x8b, 0x04, 0x85, 0x40, 0x40, 0x40, 0x00]);
        let map = mapping(0x1000, 7);
        let control = ScanControl::new();
        let found = scan(
            &code,
            std::slice::from_ref(&map),
            AddrRange::one(0x0040_4040),
            &control,
        );
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].kind, RefKind::Indexed);

        // The entry itself is chosen at runtime, so it is not a reference.
        let control = ScanControl::new();
        let found = scan(
            &code,
            std::slice::from_ref(&map),
            AddrRange::one(0x0040_4044),
            &control,
        );
        assert!(found.is_empty());

        // A base register plus an index is a runtime address, not a table.
        let code = Bytes::at(0x1000, &[0x8b, 0x04, 0x98]);
        let control = ScanControl::new();
        let found = scan(&code, &[mapping(0x1000, 3)], AddrRange::one(0), &control);
        assert!(found.is_empty());
    }

    #[test]
    fn decoded_lines_record_operand_addresses() {
        let code = Bytes::at(
            0x1000,
            &[
                0x48, 0x8b, 0x05, 0x00, 0x10, 0x00, 0x00, // mov rax,[rip+0x1000]
                0x8b, 0x04, 0x85, 0x40, 0x40, 0x40, 0x00, // mov eax,[rax*4+0x404040]
            ],
        );
        let window = decode_window(&code, 0x1000, 0x1000, 0x100e);
        assert_eq!(
            window.lines[0].mention,
            Some(Mention {
                addr: 0x2007,
                indexed: false
            })
        );
        assert_eq!(
            window.lines[1].mention,
            Some(Mention {
                addr: 0x0040_4040,
                indexed: true
            })
        );
    }

    #[test]
    fn a_forward_window_starts_at_the_boundary() {
        let code = Bytes::at(0x1000, &[0x90; 16]);
        let window = decode_window_forward(&code, 0x1004, 0x1008);
        assert_eq!(window.start, 0x1004);
        assert_eq!(window.lines.len(), 4);
        assert_eq!(window.lines[0].addr, 0x1004);
    }

    #[test]
    fn mention_notes_name_labels_and_type_their_values() {
        let mut data = vec![0_u8; 16];
        data[0..4].copy_from_slice(&42_i32.to_le_bytes());
        let reader = Bytes::at(0x2000, &data);
        let maps = [data_mapping(0x2000, 16), mapping(0x4000, 8)];
        let saved = [SavedRef {
            addr: 0x2000,
            ty: DataType::I32,
            label: "health",
        }];
        let note = describe_mention(
            &reader,
            &maps,
            &saved,
            Mention {
                addr: 0x2000,
                indexed: false,
            },
        );
        assert!(note.contains("health"), "{note}");
        assert!(note.contains("42"), "{note}");
    }

    #[test]
    fn mention_notes_follow_pointer_slots_and_skip_tables() {
        let mut slot = vec![0_u8; 8];
        slot.copy_from_slice(&0x4000_u64.to_le_bytes());
        let reader = Bytes::at(0x3000, &slot);
        let maps = [data_mapping(0x3000, 8), mapping(0x4000, 8)];
        let note = describe_mention(
            &reader,
            &maps,
            &[],
            Mention {
                addr: 0x3000,
                indexed: false,
            },
        );
        assert!(note.contains("→"), "{note}");
        assert!(note.contains("test"), "{note}");

        let table = describe_mention(
            &reader,
            &maps,
            &[],
            Mention {
                addr: 0x3000,
                indexed: true,
            },
        );
        assert!(table.ends_with("table"), "{table}");
    }

    #[test]
    fn read_reporting_flags_unreadable_bytes_instead_of_filling_int3() {
        let code = Bytes::at(0x1000, &[0x41; 16]);
        let window = read_reporting(&code, 0x1000, 32);
        assert_eq!(window.bytes.len(), 32);
        assert!(window.readable[..16].iter().all(|ok| *ok));
        assert!(window.readable[16..].iter().all(|ok| !*ok));
        assert_eq!(&window.bytes[16..], &[0_u8; 16]);
    }

    #[test]
    fn hex_rows_show_ascii_and_question_marks() {
        let window = ByteWindow {
            start: 0x1000,
            bytes: vec![0x41, 0x00, 0x7f, 0x20],
            readable: vec![true, true, false, true],
        };
        let rows = hex_rows(&window, 4);
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].addr, 0x1000);
        assert_eq!(rows[0].hex, "41 00 ?? 20");
        assert_eq!(rows[0].ascii, "A.? ");
    }
}
