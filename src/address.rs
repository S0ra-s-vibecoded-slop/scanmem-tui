//! Address expressions shared by the scan prompt and the Lua API.
//!
//! An expression is a base (a saved label or a hex address) followed by any
//! number of `+`/`-` offsets: `health`, `health+0x10`, `0x140902b8a-0x1140`.
//! Labels contain no operators, so every `+`/`-` separates two terms.

use crate::datatype::DataType;

/// A resolved address, remembering the base label's type when there was one.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Resolved {
    pub addr: u64,
    pub ty: Option<DataType>,
}

/// Resolves `expr`. `lookup` reports a saved label as its address and type;
/// anything it does not know is read as a hex address.
pub fn resolve_expression(
    expr: &str,
    lookup: impl Fn(&str) -> Option<(u64, Option<DataType>)>,
) -> Result<Resolved, String> {
    let mut total: i128 = 0;
    let mut resolved: Option<Resolved> = None;
    let mut positive = true;
    let mut start = 0;
    for (index, c) in expr.char_indices() {
        if c != '+' && c != '-' {
            continue;
        }
        add_term(
            &mut total,
            &mut resolved,
            positive,
            &expr[start..index],
            &lookup,
        )?;
        positive = c == '+';
        start = index + 1;
    }
    add_term(&mut total, &mut resolved, positive, &expr[start..], &lookup)?;
    if !(0..=i128::from(u64::MAX)).contains(&total) {
        return Err(format!("{expr} does not fit in an address"));
    }
    #[expect(clippy::cast_sign_loss, clippy::cast_possible_truncation)]
    let addr = total as u64;
    Ok(Resolved {
        addr,
        ty: resolved.and_then(|base| base.ty),
    })
}

/// Adds one term: the first must be a label or a hex address, the rest are
/// offsets applied with the sign before them.
fn add_term(
    total: &mut i128,
    resolved: &mut Option<Resolved>,
    positive: bool,
    token: &str,
    lookup: &impl Fn(&str) -> Option<(u64, Option<DataType>)>,
) -> Result<(), String> {
    if resolved.is_none() {
        if !positive {
            return Err(format!("`{token}` cannot start an address"));
        }
        let (addr, ty) = match lookup(token) {
            Some(found) => found,
            None => (parse_hex(token)?, None),
        };
        *total = i128::from(addr);
        *resolved = Some(Resolved { addr, ty });
        return Ok(());
    }
    let Some(offset) = crate::datatype::parse_int(token) else {
        return Err(format!("`{token}` is not a valid offset"));
    };
    *total += if positive { offset } else { -offset };
    Ok(())
}

/// A bare hex address like `140902b8a` or `0x140902b8a`.
fn parse_hex(term: &str) -> Result<u64, String> {
    let digits = term.trim_start_matches("0x").trim_start_matches("0X");
    u64::from_str_radix(digits, 16)
        .map_err(|_| format!("`{term}` is neither a saved label nor a hex address"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn label(name: &str) -> Option<(u64, Option<DataType>)> {
        (name.eq_ignore_ascii_case("health")).then_some((0x1_4090_2b8a, Some(DataType::I32)))
    }

    #[test]
    #[expect(clippy::unreadable_literal)]
    fn labels_and_offsets_resolve() {
        assert_eq!(
            resolve_expression("health", label),
            Ok(Resolved {
                addr: 0x140902b8a,
                ty: Some(DataType::I32)
            })
        );
        assert_eq!(
            resolve_expression("health+0x10", label),
            Ok(Resolved {
                addr: 0x140902b9a,
                ty: Some(DataType::I32)
            })
        );
        assert_eq!(
            resolve_expression("0x140902b8a-0x1140", label),
            Ok(Resolved {
                addr: 0x140901a4a,
                ty: None
            })
        );
        // hex defaults and several steps compose
        assert_eq!(
            resolve_expression("140902b8a+0x100-4", label),
            Ok(Resolved {
                addr: 0x140902c86,
                ty: None
            })
        );
    }

    #[test]
    fn bad_expressions_explain_themselves() {
        assert!(
            resolve_expression("zz", label)
                .unwrap_err()
                .contains("neither a saved label nor a hex address")
        );
        assert!(resolve_expression("0x10+", label).is_err());
        assert!(resolve_expression("-0x10", label).is_err());
        assert!(
            resolve_expression("0x10-0x20", label)
                .unwrap_err()
                .contains("does not fit")
        );
    }
}
