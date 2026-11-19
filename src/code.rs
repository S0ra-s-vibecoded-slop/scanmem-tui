//! x86-64 disassembly and the static cross-reference scan.
//!
//! Everything here works on plain readers so it can be tested without a
//! process. Unreadable pages are filled with `int3` (0xcc): it is a valid
//! one-byte instruction, so a linear decode crossing a hole stays in sync
//! instead of sliding into garbage.

use crate::maps::Mapping;
use crate::memio::MemIo;
use crate::scanner::ScanControl;
use iced_x86::{
    Decoder, DecoderOptions, FlowControl, Formatter, Instruction, IntelFormatter, OpKind, Register,
};
use rayon::prelude::*;
use std::io;

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

/// How a reference encodes the target address.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RefKind {
    RipRelative,
    Absolute,
    Immediate,
}

/// One instruction that mentions an address.
#[derive(Clone, Debug)]
pub struct Reference {
    pub addr: u64,
    pub text: String,
    pub kind: RefKind,
}

/// Scans every executable mapping for instructions encoding `target`.
///
/// This is a *static* scan: it sees operands and immediates, so heap
/// addresses reached through pointers will usually have no hits.
pub fn scan(
    reader: &dyn ReadBytes,
    mappings: &[Mapping],
    target: u64,
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
                scan_mapping(reader, mapping, target, control)
            }
        })
        .collect();
    let mut found: Vec<Reference> = per_mapping.into_iter().flatten().collect();
    found.sort_by_key(|reference| reference.addr);
    found.dedup_by_key(|reference| reference.addr);
    found.truncate(XREF_MAX_RESULTS);
    found
}

fn scan_mapping(
    reader: &dyn ReadBytes,
    mapping: &Mapping,
    target: u64,
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
            if let Some(kind) = reference_kind(&instr, target) {
                let mut text = String::new();
                formatter.format(&instr, &mut text);
                found.push(Reference {
                    addr: instr.ip(),
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

/// Whether an instruction mentions `target`, and how.
fn reference_kind(instr: &Instruction, target: u64) -> Option<RefKind> {
    if instr.is_ip_rel_memory_operand() && instr.ip_rel_memory_address() == target {
        return Some(RefKind::RipRelative);
    }
    for kind in instr.op_kinds() {
        let (value, how) = match kind {
            // A plain absolute operand (`[0x1234]`): no base, no index.
            OpKind::Memory
                if instr.memory_base() == Register::None
                    && instr.memory_index() == Register::None =>
            {
                (Some(instr.memory_displacement64()), RefKind::Absolute)
            }
            OpKind::Immediate8 => (Some(u64::from(instr.immediate8())), RefKind::Immediate),
            OpKind::Immediate16 => (Some(u64::from(instr.immediate16())), RefKind::Immediate),
            OpKind::Immediate32 => (Some(u64::from(instr.immediate32())), RefKind::Immediate),
            OpKind::Immediate64 => (Some(instr.immediate64()), RefKind::Immediate),
            OpKind::Immediate8to16 => (
                Some(instr.immediate8to16().cast_unsigned().into()),
                RefKind::Immediate,
            ),
            OpKind::Immediate8to32 => (
                Some(instr.immediate8to32().cast_unsigned().into()),
                RefKind::Immediate,
            ),
            OpKind::Immediate8to64 => (
                Some(instr.immediate8to64().cast_unsigned()),
                RefKind::Immediate,
            ),
            OpKind::Immediate32to64 => (
                Some(instr.immediate32to64().cast_unsigned()),
                RefKind::Immediate,
            ),
            _ => (None, RefKind::Immediate),
        };
        if value == Some(target) {
            return Some(how);
        }
    }
    None
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
        let found = scan(&code, &[mapping(0x1000, 7)], 0x2007, &control);
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
        let found = scan(&code, std::slice::from_ref(&map), 0x1234, &control);
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].kind, RefKind::Immediate);

        let control = ScanControl::new();
        let found = scan(&code, std::slice::from_ref(&map), 0x2000, &control);
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
        let found = scan(&code, &[mapping(0x1_0000, len as u64)], target, &control);
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].addr, instr_addr);
    }

    #[test]
    fn cancelled_scans_return_what_they_have_and_keep_the_total() {
        let code = Bytes::at(0x1000, &[0x48, 0x8b, 0x05, 0x00, 0x10, 0x00, 0x00]);
        let control = ScanControl::new();
        control.cancel();
        let found = scan(&code, &[mapping(0x1000, 7)], 0x2007, &control);
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
            target,
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
        let found = scan(&code, &[data], 0x2007, &control);
        assert!(found.is_empty());
        assert_eq!(control.progress(), (0, 0));
    }
}
