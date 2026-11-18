//! The value types we can scan for, and how they map to bytes and to scanmem's spelling.

use std::str::FromStr;

/// Accepted type names, as shown in error messages.
pub const SUPPORTED: &str = "int8/16/32/64, float32/64";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DataType {
    I8,
    I16,
    I32,
    I64,
    F32,
    F64,
}

impl DataType {
    pub const ALL: [DataType; 6] = [
        DataType::I8,
        DataType::I16,
        DataType::I32,
        DataType::I64,
        DataType::F32,
        DataType::F64,
    ];

    pub fn size(self) -> usize {
        match self {
            DataType::I8 => 1,
            DataType::I16 => 2,
            DataType::I32 | DataType::F32 => 4,
            DataType::I64 | DataType::F64 => 8,
        }
    }

    /// Name understood by scanmem's `option scan_data_type`.
    pub fn scanmem_name(self) -> &'static str {
        match self {
            DataType::I8 => "int8",
            DataType::I16 => "int16",
            DataType::I32 => "int32",
            DataType::I64 => "int64",
            DataType::F32 => "float32",
            DataType::F64 => "float64",
        }
    }

    pub fn next(self) -> DataType {
        Self::ALL[(self as usize + 1) % Self::ALL.len()]
    }

    /// Whether values of this type are floating point rather than integer.
    pub fn is_float(self) -> bool {
        matches!(self, DataType::F32 | DataType::F64)
    }

    /// Parse a flag token from scanmem's `list` output (`I32`, `I32u`, `F64`...).
    pub fn from_flag(token: &str) -> Option<DataType> {
        match token.trim_end_matches(['u', 's']) {
            "I8" => Some(DataType::I8),
            "I16" => Some(DataType::I16),
            "I32" => Some(DataType::I32),
            "I64" => Some(DataType::I64),
            "F32" => Some(DataType::F32),
            "F64" => Some(DataType::F64),
            _ => None,
        }
    }

    /// Turn user text into little-endian bytes for this type.
    pub fn parse_value(self, text: &str) -> Result<Vec<u8>, String> {
        let text = text.trim();
        if text.is_empty() {
            return Err("empty value".into());
        }
        match self {
            DataType::F32 => text
                .parse::<f32>()
                .map(|v| v.to_le_bytes().to_vec())
                .map_err(|_| format!("`{text}` is not a valid float32")),
            DataType::F64 => text
                .parse::<f64>()
                .map(|v| v.to_le_bytes().to_vec())
                .map_err(|_| format!("`{text}` is not a valid float64")),
            _ => self.parse_integer(text),
        }
    }

    fn parse_integer(self, text: &str) -> Result<Vec<u8>, String> {
        let n = parse_int(text).ok_or_else(|| format!("`{text}` is not a valid integer"))?;
        self.encode_int(n)
    }

    /// Little-endian bytes for integer `n`, accepting the signed range plus the
    /// unsigned spelling (an i8 takes -128..=255, like the scan prompt).
    #[expect(clippy::cast_possible_truncation)]
    pub fn encode_int(self, n: i128) -> Result<Vec<u8>, String> {
        if self.is_float() {
            return Err(format!(
                "{} needs a floating point value",
                self.scanmem_name()
            ));
        }
        let bits = (self.size() * 8) as u32;
        let min_signed = -(1i128 << (bits - 1));
        let max_unsigned = (1i128 << bits) - 1;
        if n < min_signed || n > max_unsigned {
            return Err(format!("{n} does not fit in {}", self.scanmem_name()));
        }
        Ok((n as i64).to_le_bytes()[..self.size()].to_vec())
    }

    /// Render bytes read from memory as text.
    pub fn format_bytes(self, bytes: &[u8]) -> String {
        if bytes.len() != self.size() {
            return "??".into();
        }
        match self {
            DataType::I8 => i8::from_le_bytes(bytes.try_into().unwrap()).to_string(),
            DataType::I16 => i16::from_le_bytes(bytes.try_into().unwrap()).to_string(),
            DataType::I32 => i32::from_le_bytes(bytes.try_into().unwrap()).to_string(),
            DataType::I64 => i64::from_le_bytes(bytes.try_into().unwrap()).to_string(),
            DataType::F32 => f32::from_le_bytes(bytes.try_into().unwrap()).to_string(),
            DataType::F64 => f64::from_le_bytes(bytes.try_into().unwrap()).to_string(),
        }
    }
}

/// User-typed type names: `int32`, `i32`, `float`, ...
impl FromStr for DataType {
    type Err = String;

    fn from_str(name: &str) -> Result<DataType, String> {
        match name.to_ascii_lowercase().as_str() {
            "int8" | "i8" | "byte" => Ok(DataType::I8),
            "int16" | "i16" | "short" => Ok(DataType::I16),
            "int32" | "i32" | "int" => Ok(DataType::I32),
            "int64" | "i64" | "long" => Ok(DataType::I64),
            "float32" | "f32" | "float" => Ok(DataType::F32),
            "float64" | "f64" | "double" => Ok(DataType::F64),
            _ => Err(format!("unknown type `{name}` (supported: {SUPPORTED})")),
        }
    }
}

/// User-typed integers: `0x10` is hex, everything else decimal, sign allowed.
pub(crate) fn parse_int(text: &str) -> Option<i128> {
    let (negative, body) = match text.strip_prefix('-') {
        Some(rest) => (true, rest),
        None => (false, text.strip_prefix('+').unwrap_or(text)),
    };
    let magnitude = match body.strip_prefix("0x").or_else(|| body.strip_prefix("0X")) {
        Some(hex) => i128::from_str_radix(hex, 16).ok()?,
        None => body.parse::<i128>().ok()?,
    };
    Some(if negative { -magnitude } else { magnitude })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn int_roundtrip() {
        let bytes = DataType::I32.parse_value("-5").unwrap();
        assert_eq!(bytes, (-5i32).to_le_bytes());
        assert_eq!(DataType::I32.format_bytes(&bytes), "-5");
    }

    #[test]
    fn int_range_checks() {
        assert!(DataType::I8.parse_value("300").is_err());
        assert!(DataType::I8.parse_value("-129").is_err());
        assert!(DataType::I8.parse_value("255").is_ok()); // unsigned spelling
        assert_eq!(
            DataType::I16.parse_value("0xFFFF").unwrap(),
            vec![0xff, 0xff]
        );
        assert!(DataType::I64.parse_value("abc").is_err());
    }

    #[test]
    fn float_roundtrip() {
        let bytes = DataType::F32.parse_value("3.5").unwrap();
        assert_eq!(DataType::F32.format_bytes(&bytes), "3.5");
        let bytes = DataType::F64.parse_value("-0.25").unwrap();
        assert_eq!(DataType::F64.format_bytes(&bytes), "-0.25");
    }

    #[test]
    fn wrong_length_is_unknown() {
        assert_eq!(DataType::I32.format_bytes(&[1, 2]), "??");
    }

    #[test]
    fn flags_and_names() {
        assert_eq!(DataType::from_flag("I32u"), Some(DataType::I32));
        assert_eq!(DataType::from_flag("F64"), Some(DataType::F64));
        assert_eq!(DataType::from_flag("bytearray"), None);
        assert_eq!("Float".parse::<DataType>(), Ok(DataType::F32));
        assert!("banana".parse::<DataType>().is_err());
    }

    #[test]
    fn next_cycles_in_declaration_order() {
        assert_eq!(DataType::I64.next(), DataType::F32);
        assert_eq!(DataType::F64.next(), DataType::I8);
        for ty in DataType::ALL {
            assert_eq!(DataType::ALL[ty as usize], ty);
        }
    }
}
