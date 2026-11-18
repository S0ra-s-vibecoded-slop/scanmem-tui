//! The built-in scanner used while a range limit (`range`) is active.
//!
//! scanmem's CLI can only search whole memory regions, so a range that falls
//! inside a larger region would also match everything around it, and the
//! matches we want drown among them (`list` prints the lowest addresses
//! first). While a range is active this module scans exactly `[lo, hi]`
//! through `/proc/<pid>/mem` instead, mirroring the comparison semantics of
//! scanmem's routines: integers are tested in both their signed and unsigned
//! interpretation, and whichever branches match are remembered per address
//! (like scanmem's match flags) to gate the next step's comparisons.

// The comparison core in this module is intentionally cast-heavy: it reads
// raw process bytes and interprets them as every width/signedness a scan type
// allows. The casts are guarded by the type's own bounds, so the pedantic
// cast lints would be noise here.
#![allow(
    clippy::cast_lossless,
    clippy::cast_possible_truncation,
    clippy::cast_possible_wrap,
    clippy::cast_precision_loss,
    clippy::cast_sign_loss
)]

use crate::datatype::DataType;
use crate::memio::MemIo;
use rayon::prelude::*;
use std::cmp::Ordering;
use std::fs;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering::Relaxed};

/// How many matches a range scan stores before it stops storing (but keeps
/// counting) so the caller can report a truncated result.
pub const MAX_MATCHES: usize = 1_000_000;

/// Bytes fetched per read while sweeping; unreadable spans are retried page
/// by page, so holes between mappings are skipped.
const CHUNK: usize = 64 * 1024;
const PAGE: u64 = 4096;
/// Address range one parallel sweep task covers.
const SWEEP_CHUNK: u64 = 8 * 1024 * 1024;

/// Shared between the UI thread and the scan thread: asks the scan to stop
/// and reports how far it has got. `total == 0` means unknown.
#[derive(Default)]
pub struct ScanControl {
    cancel: AtomicBool,
    done: AtomicU64,
    total: AtomicU64,
}

impl ScanControl {
    pub fn new() -> ScanControl {
        ScanControl::default()
    }

    /// Ask the running scan to stop at its next check.
    pub fn cancel(&self) {
        self.cancel.store(true, Relaxed);
    }

    /// Whether a stop was requested.
    pub fn cancelled(&self) -> bool {
        self.cancel.load(Relaxed)
    }

    pub fn set_total(&self, total: u64) {
        self.total.store(total, Relaxed);
    }

    /// How much work is finished, and how much there is in total.
    pub fn progress(&self) -> (u64, u64) {
        (self.done.load(Relaxed), self.total.load(Relaxed))
    }

    fn add_done(&self, bytes: u64) {
        self.done.fetch_add(bytes, Relaxed);
    }
}

/// One contiguous readable span of the target's address space, already
/// clipped to the scan range. Adjacent mappings are merged, so bytes inside a
/// span can be read without a gap interrupting them.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Span {
    pub start: u64,
    /// Exclusive end of the matchable addresses.
    pub end: u64,
    /// True when `end` is the scan limit rather than the real end of the
    /// mapping: a value starting just below it reaches past `end`.
    pub padded: bool,
}

/// Every readable span of `pid` that intersects `[lo, hi]`. Falls back to one
/// pseudo-span covering the raw range when the maps file cannot be read, so
/// scanning then crawls page by page exactly like scanmem does.
pub fn clipped_spans(pid: u32, lo: u64, hi: u64) -> Vec<Span> {
    match fs::read_to_string(format!("/proc/{pid}/maps")) {
        Ok(text) => spans_from_maps(&text, lo, hi),
        Err(_) => vec![Span {
            start: lo,
            end: hi.saturating_add(1),
            padded: true,
        }],
    }
}

/// Turns `/proc/<pid>/maps` text into spans clipped to `[lo, hi]`. All
/// mappings count (unreadable pages are skipped at scan time), and mappings
/// that touch are merged so values straddling them are still matched.
fn spans_from_maps(text: &str, lo: u64, hi: u64) -> Vec<Span> {
    let limit = hi.saturating_add(1);
    let mut spans: Vec<Span> = Vec::new();
    for line in text.lines() {
        let Some((range, _)) = line.split_once(' ') else {
            continue;
        };
        let Some((start_text, end_text)) = range.split_once('-') else {
            continue;
        };
        let (Ok(start), Ok(end)) = (
            u64::from_str_radix(start_text, 16),
            u64::from_str_radix(end_text, 16),
        ) else {
            continue;
        };
        let (start, end) = (start.max(lo), end.min(limit));
        if start >= end {
            continue;
        }
        let padded = end == limit;
        match spans.last_mut() {
            // Touching mappings merge; the merged span reaches the clip only
            // if its last constituent does.
            Some(last) if last.end == start => {
                last.end = end;
                last.padded = padded;
            }
            _ => spans.push(Span { start, end, padded }),
        }
    }
    spans
}

/// One scan step, in the same syntax scanmem's prompt takes.
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum ScanStep {
    /// A value: the first search, or an equality narrowing later on.
    Equal(Operand),
    NotEqual(Operand),
    Greater(Operand),
    Less(Operand),
    /// `=` alone: the value has not changed since the last step.
    NotChanged,
    /// `!=` alone: the value has changed since the last step.
    Changed,
    Increased,
    Decreased,
    IncreasedBy(Operand),
    DecreasedBy(Operand),
    /// `A..B`: the value lies inside the range, inclusive.
    Within(Operand, Operand),
    /// Refresh the remembered values without narrowing.
    Update,
}

impl ScanStep {
    /// Steps that compare against a typed argument, and so can also run as
    /// the first search over a range. The rest need a previous step.
    pub fn takes_a_value(self) -> bool {
        matches!(
            self,
            ScanStep::Equal(_)
                | ScanStep::NotEqual(_)
                | ScanStep::Greater(_)
                | ScanStep::Less(_)
                | ScanStep::Within(..)
        )
    }
}

/// A numeric argument. Integers stay exact in `i128`; the interpretations
/// they get at a type's width are decided when comparing.
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum Operand {
    Int(i128),
    Float(f64),
}

/// Which integer interpretations a candidate is still live under. A branch
/// that matched a step saves itself, exactly like scanmem's match flags.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Interp {
    Signed,
    Unsigned,
    Both,
}

impl Interp {
    fn allows_signed(self) -> bool {
        !matches!(self, Interp::Unsigned)
    }

    fn allows_unsigned(self) -> bool {
        !matches!(self, Interp::Signed)
    }

    /// The union of the branches that matched a step; `None` drops the row.
    fn join(signed: bool, unsigned: bool) -> Option<Interp> {
        match (signed, unsigned) {
            (true, true) => Some(Interp::Both),
            (true, false) => Some(Interp::Signed),
            (false, true) => Some(Interp::Unsigned),
            (false, false) => None,
        }
    }
}

impl From<i128> for Operand {
    fn from(v: i128) -> Operand {
        Operand::Int(v)
    }
}

impl From<f64> for Operand {
    fn from(f: f64) -> Operand {
        Operand::Float(f)
    }
}

/// One address still in the running, remembering what matched last step.
#[derive(Clone, Debug, PartialEq)]
pub struct Candidate {
    pub addr: u64,
    /// The bytes read when the candidate last matched; the `old` value the
    /// next step compares against.
    pub old: Vec<u8>,
    pub interp: Interp,
}

/// Reads process memory; tests stand in for `/proc/<pid>/mem`.
pub trait ReadMemory {
    /// Fills `buf` from `addr`. Fewer bytes than asked for means the readable
    /// span ends there; zero means nothing is readable at `addr`.
    fn read(&self, addr: u64, buf: &mut [u8]) -> usize;
}

impl ReadMemory for MemIo {
    fn read(&self, addr: u64, buf: &mut [u8]) -> usize {
        match self.read_into(addr, buf) {
            Ok(()) => buf.len(),
            Err(_) => 0,
        }
    }
}

/// First search over every span: every address whose `ty`-sized value
/// matches `step` (which must take a value). Matches are stored up to
/// [`MAX_MATCHES`], but everything is counted. Returns the candidates and
/// the total number of matches. Progress goes to `control`, which also
/// stops the sweep when [`ScanControl::cancel`] was called.
pub fn sweep<R: ReadMemory + Sync>(
    reader: &R,
    spans: &[Span],
    ty: DataType,
    step: ScanStep,
    control: &ScanControl,
) -> (Vec<Candidate>, u64) {
    // Done counts every fetched byte, including page-granular retries in
    // unreadable spans, so this is an approximation — close enough for a
    // percentage.
    control.set_total(spans.iter().map(|span| span.end - span.start).sum());
    let mut candidates: Vec<Candidate> = Vec::new();
    let mut total: u64 = 0;
    for span in spans {
        if control.cancelled() {
            break;
        }
        let (span_candidates, span_total) =
            sweep_span(reader, span, ty, step, control, SWEEP_CHUNK);
        total += span_total;
        candidates.extend(span_candidates);
    }
    candidates.truncate(MAX_MATCHES);
    (candidates, total)
}

/// Sweeps one span, split into page-aligned chunks scanned in parallel. The
/// chunks cover the span in address order, so the collected results stay
/// ascending.
fn sweep_span<R: ReadMemory + Sync>(
    reader: &R,
    span: &Span,
    ty: DataType,
    step: ScanStep,
    control: &ScanControl,
    chunk: u64,
) -> (Vec<Candidate>, u64) {
    let width = ty.size() as u64;
    let starts = chunk_starts(span.start, span.end, chunk);
    let chunks: Vec<(u64, u64, u64)> = starts
        .iter()
        .enumerate()
        .map(|(i, &lo)| {
            let hi = starts.get(i + 1).copied().unwrap_or(span.end);
            // A chunk's last owned value reaches `width - 1` bytes past its
            // end, into the next chunk's territory; at the span's end only a
            // clipped (not real) end is padded.
            let read_hi = if i + 1 < starts.len() {
                hi + width - 1
            } else {
                hi + if span.padded { width - 1 } else { 0 }
            };
            (lo, hi, read_hi)
        })
        .collect();
    let results: Vec<(Vec<Candidate>, u64)> = chunks
        .par_iter()
        .map(|&(lo, hi, read_hi)| scan_region(reader, lo, hi, read_hi, ty, step, control))
        .collect();
    let mut candidates: Vec<Candidate> = Vec::new();
    let mut total: u64 = 0;
    for (chunk_candidates, chunk_total) in results {
        candidates.extend(chunk_candidates);
        total += chunk_total;
    }
    (candidates, total)
}

/// Start addresses of the chunks covering `[start, end)`: the first chunk
/// begins at `start`, later boundaries are page-aligned.
fn chunk_starts(start: u64, end: u64, chunk: u64) -> Vec<u64> {
    let mut starts = vec![start];
    let mut next = start.saturating_add(chunk);
    while next < end {
        let Some(ceiling) = next.checked_add(PAGE - 1) else {
            break;
        };
        let aligned = ceiling / PAGE * PAGE;
        if aligned >= end {
            break;
        }
        starts.push(aligned);
        next = aligned.saturating_add(chunk);
    }
    starts
}

/// Scans the byte range `[lo, read_hi)` of one chunk, comparing values that
/// start inside `[lo, hi)`. Bytes past `hi` only serve as tails of values
/// starting before it, so nothing is compared twice across chunks.
fn scan_region<R: ReadMemory>(
    reader: &R,
    lo: u64,
    hi: u64,
    read_hi: u64,
    ty: DataType,
    step: ScanStep,
    control: &ScanControl,
) -> (Vec<Candidate>, u64) {
    let width = ty.size();
    let mut candidates: Vec<Candidate> = Vec::new();
    let mut total: u64 = 0;

    // Bytes read but not yet compared, and the address of the first one.
    // The tail of each chunk waits here, so a value straddling a chunk edge
    // is still tested once, like scanmem's truncated `memlength` handles it.
    let mut pending: Vec<u8> = Vec::new();
    let mut pending_addr = lo;
    let mut buf = vec![0u8; CHUNK];

    let mut addr = lo;
    while addr < read_hi && pending_addr < hi {
        if control.cancelled() {
            break;
        }
        let mut want = CHUNK.min((read_hi - addr) as usize);
        let mut got = reader.read(addr, &mut buf[..want]);
        if got < width {
            // The read failed: either `addr` sits in an unreadable span or the
            // chunk crossed into one. Retry just to the end of this page so
            // everything readable before the hole is kept.
            want = (PAGE - (addr & (PAGE - 1))) as usize;
            got = reader.read(addr, &mut buf[..want]);
            if got < width {
                // Unreadable page: a value cannot combine across it, so drop
                // anything pending and continue at the next page.
                pending.clear();
                control.add_done(PAGE);
                addr = ((addr | (PAGE - 1)) + 1).min(read_hi);
                pending_addr = addr;
                continue;
            }
        }
        control.add_done(got as u64);
        pending.extend_from_slice(&buf[..got]);

        let comparable = pending.len() - (width - 1);
        for p in 0..comparable {
            let at = pending_addr + p as u64;
            if at >= hi {
                break; // the next chunk owns this one
            }
            let current = &pending[p..p + width];
            if let Some(interp) = step_matches(step, ty, current, None, None) {
                total += 1;
                candidates.push(Candidate {
                    addr: at,
                    old: current.to_vec(),
                    interp,
                });
            }
        }
        // Keep the last `width - 1` bytes so values straddling the next read
        // are still tested once.
        pending = pending.split_off(comparable);
        pending_addr += comparable as u64;
        addr = pending_addr + pending.len() as u64;
    }
    (candidates, total)
}

/// Narrows `candidates` to those whose current value still matches `step`,
/// reading each address in parallel. Candidates whose memory became
/// unreadable are dropped, like scanmem's failed peeks. `Update` keeps
/// everything but refreshes the old bytes. Progress and cancellation go
/// through `control`.
pub fn narrow<R: ReadMemory + Sync>(
    reader: &R,
    ty: DataType,
    step: ScanStep,
    candidates: &[Candidate],
    control: &ScanControl,
) -> Vec<Candidate> {
    let width = ty.size();
    control.set_total(candidates.len() as u64);
    candidates
        .par_iter()
        .map_init(
            || vec![0u8; width],
            |buf, candidate| {
                if control.cancelled() {
                    return None;
                }
                control.add_done(1);
                if reader.read(candidate.addr, buf) < width {
                    return None;
                }
                let current = buf[..width].to_vec();
                let interp = match step {
                    ScanStep::Update => candidate.interp,
                    _ => step_matches(
                        step,
                        ty,
                        &current,
                        Some(&candidate.old),
                        Some(candidate.interp),
                    )?,
                };
                Some(Candidate {
                    addr: candidate.addr,
                    old: current,
                    interp,
                })
            },
        )
        .filter_map(std::convert::identity)
        .collect()
}

/// Whether the bytes read at an address match `step`. `old` and `old_interp`
/// come from the previous step and are `None` during a first search; the
/// result says which interpretations matched, or `None` for no match.
fn step_matches(
    step: ScanStep,
    ty: DataType,
    current: &[u8],
    old: Option<&[u8]>,
    old_interp: Option<Interp>,
) -> Option<Interp> {
    if ty.is_float() {
        return float_step(step, ty, current, old, old_interp);
    }
    let (cur_signed, cur_unsigned) = int_views(current, ty);
    let old_signed = old_interp.is_some_and(Interp::allows_signed);
    let old_unsigned = old_interp.is_some_and(Interp::allows_unsigned);
    let old = old.map(|bytes| int_views(bytes, ty));

    let (signed, unsigned) = match step {
        ScanStep::Equal(op) => {
            let v = operand_views(op, ty);
            (
                v.signed.is_some() && Some(cur_signed) == v.signed,
                v.unsigned.is_some() && Some(cur_unsigned) == v.unsigned,
            )
        }
        ScanStep::NotEqual(op) => {
            let v = operand_views(op, ty);
            (
                v.signed.is_some() && Some(cur_signed) != v.signed,
                v.unsigned.is_some() && Some(cur_unsigned) != v.unsigned,
            )
        }
        ScanStep::Greater(op) => {
            let v = operand_views(op, ty);
            (
                v.signed.is_some() && cur_signed > v.signed.unwrap(),
                v.unsigned.is_some() && cur_unsigned > v.unsigned.unwrap(),
            )
        }
        ScanStep::Less(op) => {
            let v = operand_views(op, ty);
            (
                v.signed.is_some() && cur_signed < v.signed.unwrap(),
                v.unsigned.is_some() && cur_unsigned < v.unsigned.unwrap(),
            )
        }
        ScanStep::Within(lo, hi) => {
            let lo = operand_views(lo, ty);
            let hi = operand_views(hi, ty);
            (
                lo.signed.is_some()
                    && hi.signed.is_some()
                    && cur_signed >= lo.signed.unwrap()
                    && cur_signed <= hi.signed.unwrap(),
                lo.unsigned.is_some()
                    && hi.unsigned.is_some()
                    && cur_unsigned >= lo.unsigned.unwrap()
                    && cur_unsigned <= hi.unsigned.unwrap(),
            )
        }
        ScanStep::NotChanged | ScanStep::Changed | ScanStep::Increased | ScanStep::Decreased => {
            let old = old?;
            match step {
                ScanStep::NotChanged => (
                    old_signed && cur_signed == old.0,
                    old_unsigned && cur_unsigned == old.1,
                ),
                ScanStep::Changed => (
                    old_signed && cur_signed != old.0,
                    old_unsigned && cur_unsigned != old.1,
                ),
                ScanStep::Increased => (
                    old_signed && cur_signed > old.0,
                    old_unsigned && cur_unsigned > old.1,
                ),
                _ => (
                    old_signed && cur_signed < old.0,
                    old_unsigned && cur_unsigned < old.1,
                ),
            }
        }
        ScanStep::IncreasedBy(op) | ScanStep::DecreasedBy(op) => {
            let old = old?;
            let v = operand_views(op, ty);
            let decreased = matches!(step, ScanStep::DecreasedBy(_));
            (
                old_signed
                    && v.signed.is_some()
                    && cur_signed == signed_op(ty, old.0, v.signed.unwrap(), decreased),
                old_unsigned
                    && v.unsigned.is_some()
                    && cur_unsigned == unsigned_op(ty, old.1, v.unsigned.unwrap(), decreased),
            )
        }
        ScanStep::Update => return old_interp,
    };
    Interp::join(signed, unsigned)
}

/// A user operand's interpretations at `ty`'s width; `None` where the value
/// does not fit, which switches that branch off (scanmem leaves the
/// corresponding match flag unset in the same cases).
#[derive(Clone, Copy)]
struct Views {
    signed: Option<i64>,
    unsigned: Option<u64>,
}

fn operand_views(op: Operand, ty: DataType) -> Views {
    let Operand::Int(v) = op else {
        return Views {
            signed: None,
            unsigned: None,
        };
    };
    let (min, max, umax) = match ty {
        DataType::I8 => (i8::MIN as i128, i8::MAX as i128, u8::MAX as u128),
        DataType::I16 => (i16::MIN as i128, i16::MAX as i128, u16::MAX as u128),
        DataType::I32 => (i32::MIN as i128, i32::MAX as i128, u32::MAX as u128),
        DataType::I64 => (i64::MIN as i128, i64::MAX as i128, u64::MAX as u128),
        DataType::F32 | DataType::F64 => {
            return Views {
                signed: None,
                unsigned: None,
            };
        }
    };
    Views {
        signed: (min..=max).contains(&v).then_some(v as i64),
        unsigned: (v >= 0 && v as u128 <= umax).then_some(v as u64),
    }
}

/// The signed and unsigned readings of `ty`-sized little-endian `bytes`.
fn int_views(bytes: &[u8], ty: DataType) -> (i64, u64) {
    let mut le = [0u8; 8];
    le[..bytes.len()].copy_from_slice(bytes);
    match ty {
        DataType::I8 => (le[0] as i8 as i64, le[0] as u64),
        DataType::I16 => (
            i16::from_le_bytes(le[..2].try_into().unwrap()) as i64,
            u16::from_le_bytes(le[..2].try_into().unwrap()) as u64,
        ),
        DataType::I32 => (
            i32::from_le_bytes(le[..4].try_into().unwrap()) as i64,
            u32::from_le_bytes(le[..4].try_into().unwrap()) as u64,
        ),
        _ => (i64::from_le_bytes(le), u64::from_le_bytes(le)),
    }
}

/// `old +|- operand` in the type's own width, wrapping like C does.
fn signed_op(ty: DataType, old: i64, operand: i64, subtract: bool) -> i64 {
    match (ty, subtract) {
        (DataType::I8, false) => (old as i8).wrapping_add(operand as i8) as i64,
        (DataType::I8, true) => (old as i8).wrapping_sub(operand as i8) as i64,
        (DataType::I16, false) => (old as i16).wrapping_add(operand as i16) as i64,
        (DataType::I16, true) => (old as i16).wrapping_sub(operand as i16) as i64,
        (DataType::I32, false) => (old as i32).wrapping_add(operand as i32) as i64,
        (DataType::I32, true) => (old as i32).wrapping_sub(operand as i32) as i64,
        (_, false) => old.wrapping_add(operand),
        (_, true) => old.wrapping_sub(operand),
    }
}

fn unsigned_op(ty: DataType, old: u64, operand: u64, subtract: bool) -> u64 {
    match (ty, subtract) {
        (DataType::I8, false) => (old as u8).wrapping_add(operand as u8) as u64,
        (DataType::I8, true) => (old as u8).wrapping_sub(operand as u8) as u64,
        (DataType::I16, false) => (old as u16).wrapping_add(operand as u16) as u64,
        (DataType::I16, true) => (old as u16).wrapping_sub(operand as u16) as u64,
        (DataType::I32, false) => (old as u32).wrapping_add(operand as u32) as u64,
        (DataType::I32, true) => (old as u32).wrapping_sub(operand as u32) as u64,
        (_, false) => old.wrapping_add(operand),
        (_, true) => old.wrapping_sub(operand),
    }
}

/// A floating-point value in its own precision; comparisons and arithmetic
/// happen exactly as scanmem's float routines do them.
#[derive(Clone, Copy)]
enum Float {
    F32(f32),
    F64(f64),
}

impl Float {
    fn read(ty: DataType, bytes: &[u8]) -> Float {
        match ty {
            DataType::F32 => Float::F32(f32::from_le_bytes(bytes.try_into().unwrap())),
            _ => Float::F64(f64::from_le_bytes(bytes.try_into().unwrap())),
        }
    }

    /// The user operand in the type's precision; scanmem casts the parsed
    /// number to the scan type before comparing.
    fn operand(ty: DataType, op: Operand) -> Float {
        match (ty, op) {
            (DataType::F32, Operand::Float(f)) => Float::F32(f as f32),
            (DataType::F32, Operand::Int(v)) => Float::F32(v as f32),
            (DataType::F64, Operand::Float(f)) => Float::F64(f),
            (DataType::F64, Operand::Int(v)) => Float::F64(v as f64),
            // Never produced for float types; make every comparison fail.
            _ => Float::F64(f64::NAN),
        }
    }

    fn compare(self, other: Float) -> Option<Ordering> {
        match (self, other) {
            (Float::F32(a), Float::F32(b)) => a.partial_cmp(&b),
            (Float::F64(a), Float::F64(b)) => a.partial_cmp(&b),
            _ => None,
        }
    }

    fn add(self, other: Float) -> Float {
        match (self, other) {
            (Float::F32(a), Float::F32(b)) => Float::F32(a + b),
            (Float::F64(a), Float::F64(b)) => Float::F64(a + b),
            _ => Float::F64(f64::NAN),
        }
    }

    fn subtract(self, other: Float) -> Float {
        match (self, other) {
            (Float::F32(a), Float::F32(b)) => Float::F32(a - b),
            (Float::F64(a), Float::F64(b)) => Float::F64(a - b),
            _ => Float::F64(f64::NAN),
        }
    }
}

fn float_step(
    step: ScanStep,
    ty: DataType,
    current: &[u8],
    old: Option<&[u8]>,
    old_interp: Option<Interp>,
) -> Option<Interp> {
    let cur = Float::read(ty, current);
    let matched = match step {
        ScanStep::Equal(op) => cur.compare(Float::operand(ty, op)) == Some(Ordering::Equal),
        ScanStep::NotEqual(op) => cur.compare(Float::operand(ty, op)) != Some(Ordering::Equal),
        ScanStep::Greater(op) => cur.compare(Float::operand(ty, op)) == Some(Ordering::Greater),
        ScanStep::Less(op) => cur.compare(Float::operand(ty, op)) == Some(Ordering::Less),
        ScanStep::Within(lo, hi) => {
            let at_least_lo = matches!(
                cur.compare(Float::operand(ty, lo)),
                Some(Ordering::Greater | Ordering::Equal)
            );
            let at_most_hi = matches!(
                cur.compare(Float::operand(ty, hi)),
                Some(Ordering::Less | Ordering::Equal)
            );
            at_least_lo && at_most_hi
        }
        ScanStep::NotChanged | ScanStep::Changed | ScanStep::Increased | ScanStep::Decreased => {
            let was = Float::read(ty, old?);
            match step {
                ScanStep::NotChanged => cur.compare(was) == Some(Ordering::Equal),
                ScanStep::Changed => cur.compare(was) != Some(Ordering::Equal),
                ScanStep::Increased => cur.compare(was) == Some(Ordering::Greater),
                _ => cur.compare(was) == Some(Ordering::Less),
            }
        }
        ScanStep::IncreasedBy(op) | ScanStep::DecreasedBy(op) => {
            let was = Float::read(ty, old?);
            let expected = match step {
                ScanStep::IncreasedBy(_) => was.add(Float::operand(ty, op)),
                _ => was.subtract(Float::operand(ty, op)),
            };
            cur.compare(expected) == Some(Ordering::Equal)
        }
        ScanStep::Update => return old_interp,
    };
    matched.then_some(Interp::Both)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Contiguous fake memory starting at `base`; unreadable elsewhere.
    struct FakeMemory {
        base: u64,
        bytes: Vec<u8>,
    }

    impl ReadMemory for FakeMemory {
        fn read(&self, addr: u64, buf: &mut [u8]) -> usize {
            if addr < self.base {
                return 0;
            }
            let offset = (addr - self.base) as usize;
            let available = self.bytes.len().saturating_sub(offset);
            let n = buf.len().min(available);
            buf[..n].copy_from_slice(&self.bytes[offset..offset + n]);
            n
        }
    }

    fn memory(base: u64, bytes: &[u8]) -> FakeMemory {
        FakeMemory {
            base,
            bytes: bytes.to_vec(),
        }
    }

    fn int(value: i128) -> Operand {
        Operand::Int(value)
    }

    /// Sweeps one pseudo-span over `[lo, hi]`, like a scan without maps.
    fn sweep_range(
        mem: &FakeMemory,
        lo: u64,
        hi: u64,
        ty: DataType,
        step: ScanStep,
    ) -> (Vec<Candidate>, u64) {
        let control = ScanControl::new();
        sweep(
            mem,
            &[Span {
                start: lo,
                end: hi + 1,
                padded: true,
            }],
            ty,
            step,
            &control,
        )
    }

    fn step_of(step: ScanStep, ty: DataType, bytes: &[u8], old: Option<&[u8]>) -> Option<Interp> {
        step_matches(step, ty, bytes, old, old.map(|_| Interp::Both))
    }

    #[test]
    fn greater_than_tests_both_interpretations() {
        let i32_bytes = (-1i32).to_le_bytes(); // -1 signed, u32::MAX unsigned
        let step = step_of(ScanStep::Greater(int(1)), DataType::I32, &i32_bytes, None);
        // signed -1 > 1 is false, unsigned 0xffffffff > 1 is true
        assert_eq!(step, Some(Interp::Unsigned));

        let step = step_of(
            ScanStep::Greater(int(1)),
            DataType::I32,
            &50i32.to_le_bytes(),
            None,
        );
        assert_eq!(step, Some(Interp::Both));

        // negative operands switch the unsigned branch off entirely
        let step = step_of(
            ScanStep::Greater(int(-2)),
            DataType::I32,
            &(-1i32).to_le_bytes(),
            None,
        );
        assert_eq!(step, Some(Interp::Signed));
        let step = step_of(
            ScanStep::Greater(int(-2)),
            DataType::I32,
            &0i32.to_le_bytes(),
            None,
        );
        assert_eq!(step, Some(Interp::Signed)); // 0 > -2 only as signed
        let step = step_of(
            ScanStep::Greater(int(-2)),
            DataType::I32,
            &(-5i32).to_le_bytes(),
            None,
        );
        assert_eq!(step, None);
    }

    #[test]
    fn equal_narrows_by_bytes() {
        let step = step_of(
            ScanStep::Equal(int(50)),
            DataType::I32,
            &50i32.to_le_bytes(),
            None,
        );
        assert_eq!(step, Some(Interp::Both));
        let step = step_of(
            ScanStep::Equal(int(-5)),
            DataType::I32,
            &(-5i32).to_le_bytes(),
            None,
        );
        assert_eq!(step, Some(Interp::Signed)); // -5 only fits signed
        let step = step_of(
            ScanStep::Equal(int(4)),
            DataType::I32,
            &5i32.to_le_bytes(),
            None,
        );
        assert_eq!(step, None);
    }

    #[test]
    fn out_of_range_operands_match_nothing() {
        // 5_000_000_000 fits neither i32 nor u32
        let step = step_of(
            ScanStep::Equal(int(5_000_000_000)),
            DataType::I32,
            &[0; 4],
            None,
        );
        assert_eq!(step, None);
        // but it does fit i64 and u64 alike
        let step = step_of(
            ScanStep::Equal(int(5_000_000_000)),
            DataType::I64,
            &5_000_000_000u64.to_le_bytes(),
            None,
        );
        assert_eq!(step, Some(Interp::Both));
    }

    #[test]
    fn changed_steps_compare_against_the_previous_step() {
        let old = 10i32.to_le_bytes();
        let changed = 11i32.to_le_bytes();
        let same = 10i32.to_le_bytes();

        let step = step_of(ScanStep::NotChanged, DataType::I32, &same, Some(&old));
        assert_eq!(step, Some(Interp::Both));
        let step = step_of(ScanStep::NotChanged, DataType::I32, &changed, Some(&old));
        assert_eq!(step, None);
        let step = step_of(ScanStep::Changed, DataType::I32, &changed, Some(&old));
        assert_eq!(step, Some(Interp::Both));

        // a candidate saved as signed-only ignores its unsigned reading
        let signed_only = step_matches(
            ScanStep::Increased,
            DataType::I32,
            &(-1i32).to_le_bytes(),
            Some(&(-2i32).to_le_bytes()),
            Some(Interp::Signed),
        );
        assert_eq!(signed_only, Some(Interp::Signed));
        let unsigned_view = step_matches(
            ScanStep::Increased,
            DataType::I32,
            &(-1i32).to_le_bytes(),
            Some(&(-2i32).to_le_bytes()),
            Some(Interp::Both),
        );
        assert_eq!(unsigned_view, Some(Interp::Both));
    }

    #[test]
    fn increased_by_wraps_in_the_type_width() {
        let old = 127i8.to_le_bytes();
        // 127 + 1 wraps to -128 in an i8
        let step = step_of(
            ScanStep::IncreasedBy(int(1)),
            DataType::I8,
            &(-128i8).to_le_bytes(),
            Some(&old),
        );
        assert_eq!(step, Some(Interp::Both));
        let step = step_of(
            ScanStep::IncreasedBy(int(2)),
            DataType::I8,
            &(-128i8).to_le_bytes(),
            Some(&old),
        );
        assert_eq!(step, None);

        let old = (-1i32).to_le_bytes();
        // -5 == -1 - 4, and unsigned 0xfffffffb - 4 == 0xfffffffc too
        let step = step_of(
            ScanStep::DecreasedBy(int(4)),
            DataType::I32,
            &(-5i32).to_le_bytes(),
            Some(&old),
        );
        assert_eq!(step, Some(Interp::Both));
    }

    #[test]
    fn within_bounds_are_inclusive() {
        let step = step_of(
            ScanStep::Within(int(1), int(10)),
            DataType::I32,
            &1i32.to_le_bytes(),
            None,
        );
        assert_eq!(step, Some(Interp::Both));
        let step = step_of(
            ScanStep::Within(int(1), int(10)),
            DataType::I32,
            &10i32.to_le_bytes(),
            None,
        );
        assert_eq!(step, Some(Interp::Both));
        let step = step_of(
            ScanStep::Within(int(1), int(10)),
            DataType::I32,
            &11i32.to_le_bytes(),
            None,
        );
        assert_eq!(step, None);
    }

    #[test]
    fn floats_compare_at_their_own_precision() {
        let f = 0.1f32.to_le_bytes();
        // 0.1f32 > 0.1f64 is false, > 0.1f32 (scanmem's cast) is false too;
        // but 0.3f32 > 0.3f64 is false while both are equal at f32 precision
        let step = step_of(
            ScanStep::Equal(Operand::Float(0.1)),
            DataType::F32,
            &f,
            None,
        );
        assert_eq!(step, Some(Interp::Both));

        let step = step_of(
            ScanStep::Greater(Operand::Float(1.0)),
            DataType::F32,
            &1.5f32.to_le_bytes(),
            None,
        );
        assert_eq!(step, Some(Interp::Both));
        let step = step_of(
            ScanStep::Greater(Operand::Float(1.0)),
            DataType::F32,
            &1.0f32.to_le_bytes(),
            None,
        );
        assert_eq!(step, None);

        // integers are accepted for float scans, like scanmem does
        let step = step_of(
            ScanStep::Equal(Operand::Float(2.0)),
            DataType::F64,
            &2.0f64.to_le_bytes(),
            None,
        );
        assert_eq!(step, Some(Interp::Both));
        // NaN compares unequal to everything, which counts as changed
        let step = step_of(
            ScanStep::NotEqual(Operand::Float(1.0)),
            DataType::F32,
            &f32::NAN.to_le_bytes(),
            None,
        );
        assert_eq!(step, Some(Interp::Both));
    }

    #[test]
    fn first_scan_finds_matching_addresses() {
        let mem = memory(
            0x1000,
            &[
                50, 0, 0, 0, // 0x1000: 50
                49, 0, 0, 0, // 0x1004: 49
                50, 0, 0, 0, // 0x1008: 50
                0, 50, 0, 0, // 0x100c..: not 50 anywhere in range
            ],
        );
        let (candidates, total) = sweep_range(
            &mem,
            0x1000,
            0x100d,
            DataType::I32,
            ScanStep::Equal(int(50)),
        );
        assert_eq!(total, 2);
        let addrs: Vec<u64> = candidates.iter().map(|c| c.addr).collect();
        assert_eq!(addrs, vec![0x1000, 0x1008]);
        for candidate in &candidates {
            assert_eq!(candidate.old, 50i32.to_le_bytes());
            assert_eq!(candidate.interp, Interp::Both);
        }
    }

    #[test]
    fn narrowing_uses_live_memory_and_updates_the_old_bytes() {
        // one address holding 10 that becomes 11
        let mem = memory(0x2000, &11i32.to_le_bytes());
        let candidates = vec![Candidate {
            addr: 0x2000,
            old: 10i32.to_le_bytes().to_vec(),
            interp: Interp::Both,
        }];
        let survivors = narrow(
            &mem,
            DataType::I32,
            ScanStep::Increased,
            &candidates,
            &ScanControl::new(),
        );
        assert_eq!(survivors.len(), 1);
        assert_eq!(survivors[0].old, 11i32.to_le_bytes());

        // and disappears when it stops matching
        let candidates = vec![Candidate {
            addr: 0x2000,
            old: 10i32.to_le_bytes().to_vec(),
            interp: Interp::Both,
        }];
        let survivors = narrow(
            &mem,
            DataType::I32,
            ScanStep::Equal(int(10)),
            &candidates,
            &ScanControl::new(),
        );
        assert!(survivors.is_empty(), "no longer matching, so dropped");
    }

    #[test]
    fn unreadable_addresses_are_dropped_when_narrowing() {
        let mem = memory(0x3000, &7i32.to_le_bytes());
        let candidates = vec![
            Candidate {
                addr: 0x2000,
                old: 7i32.to_le_bytes().to_vec(),
                interp: Interp::Both,
            },
            Candidate {
                addr: 0x3000,
                old: 7i32.to_le_bytes().to_vec(),
                interp: Interp::Both,
            },
        ];
        let survivors = narrow(
            &mem,
            DataType::I32,
            ScanStep::Equal(int(7)),
            &candidates,
            &ScanControl::new(),
        );
        assert_eq!(survivors.len(), 1);
        assert_eq!(survivors[0].addr, 0x3000);
    }

    #[test]
    fn update_refreshes_without_narrowing() {
        let mem = memory(0x100, &99i32.to_le_bytes());
        let candidates = vec![Candidate {
            addr: 0x100,
            old: 1i32.to_le_bytes().to_vec(),
            interp: Interp::Signed,
        }];
        let survivors = narrow(
            &mem,
            DataType::I32,
            ScanStep::Update,
            &candidates,
            &ScanControl::new(),
        );
        assert_eq!(survivors.len(), 1);
        assert_eq!(survivors[0].old, 99i32.to_le_bytes());
        assert_eq!(survivors[0].interp, Interp::Signed);
    }

    #[test]
    fn holes_between_mappings_are_skipped() {
        // fake memory only readable from 0x2000 on; the range starts earlier
        let mem = memory(0x2000, &50i32.to_le_bytes());
        let (candidates, total) = sweep_range(
            &mem,
            0x1000,
            0x2003,
            DataType::I32,
            ScanStep::Equal(int(50)),
        );
        assert_eq!(total, 1);
        assert_eq!(candidates[0].addr, 0x2000);
    }

    #[test]
    fn values_straddling_a_chunk_edge_are_found_once() {
        // a value sitting right where the second chunk read begins
        let mut bytes = vec![0u8; CHUNK + 8];
        let at = CHUNK - 1;
        bytes[at..at + 4].copy_from_slice(&50i32.to_le_bytes());
        let mem = memory(0x1000, &bytes);
        let (candidates, total) = sweep_range(
            &mem,
            0x1000,
            0x1000 + (CHUNK - 1) as u64,
            DataType::I32,
            ScanStep::Equal(int(50)),
        );
        assert_eq!(total, 1);
        assert_eq!(candidates[0].addr, 0x1000 + at as u64);
        // and nothing is matched twice
        let (candidates, total) = sweep_range(
            &mem,
            0x1000,
            0x1000 + (CHUNK + 3) as u64,
            DataType::I32,
            ScanStep::Equal(int(50)),
        );
        assert_eq!(total, 1);
        assert_eq!(candidates[0].addr, 0x1000 + at as u64);
    }

    #[test]
    #[expect(clippy::unreadable_literal)]
    fn maps_text_becomes_merged_and_clipped_spans() {
        let maps = "400000-401000 r--p 00000000 08:01 123 /a\n\
                    401000-402000 rw-p 00000000 08:01 123 /a\n\
                    402000-403000 ---p 00000000 08:01 123 \n\
                    403000-405000 rw-p 00000000 08:01 123 /b\n\
                    500000-501000 r-xp 00000000 08:01 124 /c\n\
                    (garbage line)\n";
        // touching mappings merge; the gap at 0x405000 splits
        let spans = spans_from_maps(maps, 0x400000, 0x600000);
        assert_eq!(spans.len(), 2);
        assert_eq!(
            spans[0],
            Span {
                start: 0x400000,
                end: 0x405000,
                padded: false
            }
        );
        assert_eq!(
            spans[1],
            Span {
                start: 0x500000,
                end: 0x501000,
                padded: false
            }
        );

        // clipping to a window: entries outside drop, the rest lose their
        // unclipped parts, and a clipped end is padded
        let spans = spans_from_maps(maps, 0x400800, 0x404000);
        assert_eq!(spans.len(), 1);
        assert_eq!(
            spans[0],
            Span {
                start: 0x400800,
                end: 0x404001,
                padded: true
            }
        );

        // no maps available: one pseudo-span crawls the raw range
        assert_eq!(
            clipped_spans(u32::MAX, 5, 9),
            vec![Span {
                start: 5,
                end: 10,
                padded: true
            }]
        );
    }

    #[test]
    fn chunk_boundaries_are_page_aligned_and_inside_the_span() {
        // tiny spans stay whole
        assert_eq!(chunk_starts(0x1000, 0x1004, 8 * 1024 * 1024), vec![0x1000]);
        // boundaries land on pages
        assert_eq!(
            chunk_starts(0x1000, 0x1000 + 20 * 4096, 8 * 4096),
            vec![0x1000, 0x9000, 0x11000]
        );
        // a boundary past the end never appears
        assert_eq!(
            chunk_starts(0x1ff8, 0x3000, 4096),
            vec![0x1ff8] // next candidate boundary 0x3000 == end, so one chunk
        );
        assert_eq!(chunk_starts(0x1ff8, 0x4000, 4096), vec![0x1ff8, 0x3000]);
    }

    #[test]
    fn values_on_chunk_boundaries_are_found_exactly_once() {
        // 5 pages of memory with a value on each side of every boundary
        let mut bytes = vec![0u8; 5 * 4096];
        for &offset in &[4091u64, 4096, 8187, 8192] {
            bytes[offset as usize..offset as usize + 4].copy_from_slice(&7i32.to_le_bytes());
        }
        let mem = memory(0x10000, &bytes);
        let control = ScanControl::new();
        let span = Span {
            start: 0x10000,
            end: 0x10000 + 5 * 4096,
            padded: false,
        };
        let (candidates, total) = sweep_span(
            &mem,
            &span,
            DataType::I32,
            ScanStep::Equal(int(7)),
            &control,
            4096,
        );
        assert_eq!(total, 4);
        let addrs: Vec<u64> = candidates.iter().map(|c| c.addr).collect();
        assert_eq!(
            addrs,
            vec![
                0x10000 + 4091,
                0x10000 + 4096,
                0x10000 + 8187,
                0x10000 + 8192
            ]
        );
        // ascending order survived the parallel chunks
        assert!(addrs.windows(2).all(|w| w[0] < w[1]));
    }

    #[test]
    fn cancel_stops_the_sweep_and_narrowing() {
        let mem = memory(0x1000, &50i32.to_le_bytes());
        let control = ScanControl::new();
        control.cancel();
        let span = Span {
            start: 0x1000,
            end: 0x1010,
            padded: true,
        };
        let (candidates, total) = sweep(
            &mem,
            &[span],
            DataType::I32,
            ScanStep::Equal(int(50)),
            &control,
        );
        assert_eq!((candidates.len(), total), (0, 0));

        let candidates = vec![Candidate {
            addr: 0x1000,
            old: 50i32.to_le_bytes().to_vec(),
            interp: Interp::Both,
        }];
        let survivors = narrow(
            &mem,
            DataType::I32,
            ScanStep::Equal(int(50)),
            &candidates,
            &control,
        );
        assert_eq!(survivors.len(), 0);
    }

    #[test]
    fn sweep_reports_progress() {
        // 3 pages with the byte 7 on every even offset
        let mut bytes = vec![0u8; 3 * 4096];
        for chunk in bytes.chunks_mut(2) {
            chunk[0] = 7;
        }
        let mem = memory(0x10000, &bytes);
        let control = ScanControl::new();
        control.set_total(3 * 4096);
        let span = Span {
            start: 0x10000,
            end: 0x10000 + 3 * 4096,
            padded: false,
        };
        let (candidates, total) = sweep(
            &mem,
            &[span],
            DataType::I8,
            ScanStep::Equal(int(7)),
            &control,
        );
        assert_eq!(total, 3 * 4096 / 2);
        assert_eq!(candidates.len() as u64, total); // far below the cap, so all are stored
        let (done, reported_total) = control.progress();
        assert_eq!(reported_total, 3 * 4096);
        assert!(done > 0);
    }
}
