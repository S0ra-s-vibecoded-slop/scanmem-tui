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
use std::cmp::Ordering;

/// How many matches a range scan stores before it stops storing (but keeps
/// counting) so the caller can report a truncated result.
pub const MAX_MATCHES: usize = 1_000_000;

/// Bytes fetched per read while sweeping the range; unreadable spans are
/// retried page by page, so holes between mappings are skipped.
const CHUNK: usize = 64 * 1024;
const PAGE: u64 = 4096;

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

/// First search over `[lo, hi]`: every address whose `ty`-sized value
/// matches `step` (which must take a value). Both bounds are inclusive.
/// Matches are stored up to [`MAX_MATCHES`], but everything is counted.
/// Returns the candidates and the total number of matches.
pub fn scan_range(
    reader: &impl ReadMemory,
    lo: u64,
    hi: u64,
    ty: DataType,
    step: ScanStep,
) -> (Vec<Candidate>, u64) {
    let width = ty.size();
    // A value at `hi` spans past it, so read a type's worth further.
    let last_byte = hi.saturating_add(width as u64 - 1);
    let mut candidates: Vec<Candidate> = Vec::new();
    let mut total: u64 = 0;

    // Bytes read but not yet compared, and the address of the first one.
    // The tail of each chunk waits here, so a value straddling a chunk edge
    // is still tested once, like scanmem's truncated `memlength` handles it.
    let mut pending: Vec<u8> = Vec::new();
    let mut pending_addr = lo;
    let mut buf = vec![0u8; CHUNK];

    let mut addr = lo;
    // Values starting at `hi` reach `width - 1` bytes past it, so read on
    // until `last_byte`; every position that gets compared here is at most
    // `hi`, because reads are capped at `last_byte`.
    while addr <= last_byte {
        let mut want = CHUNK.min((last_byte - addr + 1) as usize);
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
                addr = ((addr | (PAGE - 1)) + 1).min(last_byte + 1);
                pending_addr = addr;
                continue;
            }
        }
        pending.extend_from_slice(&buf[..got]);

        let comparable = pending.len() - (width - 1);
        for p in 0..comparable {
            let current = &pending[p..p + width];
            if let Some(interp) = step_matches(step, ty, current, None, None) {
                total += 1;
                if candidates.len() < MAX_MATCHES {
                    candidates.push(Candidate {
                        addr: pending_addr + p as u64,
                        old: current.to_vec(),
                        interp,
                    });
                }
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

/// Narrows `candidates` to those whose current value still matches `step`.
/// Candidates whose memory became unreadable are dropped, like scanmem's
/// failed peeks. `Update` keeps everything but refreshes the old bytes.
pub fn narrow(
    reader: &impl ReadMemory,
    ty: DataType,
    step: ScanStep,
    candidates: Vec<Candidate>,
) -> Vec<Candidate> {
    let width = ty.size();
    let mut buf = vec![0u8; width];
    let mut survivors = Vec::new();
    for candidate in candidates {
        if reader.read(candidate.addr, &mut buf) < width {
            continue;
        }
        let current = buf[..width].to_vec();
        let interp = match step {
            ScanStep::Update => candidate.interp,
            _ => match step_matches(
                step,
                ty,
                &current,
                Some(&candidate.old),
                Some(candidate.interp),
            ) {
                Some(interp) => interp,
                None => continue,
            },
        };
        survivors.push(Candidate {
            addr: candidate.addr,
            old: current,
            interp,
        });
    }
    survivors
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
        let (candidates, total) = scan_range(
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
        let survivors = narrow(&mem, DataType::I32, ScanStep::Increased, candidates);
        assert_eq!(survivors.len(), 1);
        assert_eq!(survivors[0].old, 11i32.to_le_bytes());

        // and disappears when it stops matching
        let candidates = vec![Candidate {
            addr: 0x2000,
            old: 10i32.to_le_bytes().to_vec(),
            interp: Interp::Both,
        }];
        let survivors = narrow(&mem, DataType::I32, ScanStep::Equal(int(10)), candidates);
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
        let survivors = narrow(&mem, DataType::I32, ScanStep::Equal(int(7)), candidates);
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
        let survivors = narrow(&mem, DataType::I32, ScanStep::Update, candidates);
        assert_eq!(survivors.len(), 1);
        assert_eq!(survivors[0].old, 99i32.to_le_bytes());
        assert_eq!(survivors[0].interp, Interp::Signed);
    }

    #[test]
    fn holes_between_mappings_are_skipped() {
        // fake memory only readable from 0x2000 on; the range starts earlier
        let mem = memory(0x2000, &50i32.to_le_bytes());
        let (candidates, total) = scan_range(
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
        let (candidates, total) = scan_range(
            &mem,
            0x1000,
            0x1000 + (CHUNK - 1) as u64,
            DataType::I32,
            ScanStep::Equal(int(50)),
        );
        assert_eq!(total, 1);
        assert_eq!(candidates[0].addr, 0x1000 + at as u64);
        // and nothing is matched twice
        let (candidates, total) = scan_range(
            &mem,
            0x1000,
            0x1000 + (CHUNK + 3) as u64,
            DataType::I32,
            ScanStep::Equal(int(50)),
        );
        assert_eq!(total, 1);
        assert_eq!(candidates[0].addr, 0x1000 + at as u64);
    }
}
