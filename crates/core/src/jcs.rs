//! RFC 8785 (JSON Canonicalization Scheme) serialization, hand-rolled on
//! purpose.
//!
//! The agent-event `prev_hash` chain (agent-passport SPEC §6.5) hashes "the
//! JCS canonical serialization of the event object with the prev_hash field
//! removed", so every emitter across the stack must produce byte-identical
//! canonical forms. Go uses `github.com/gowebpki/jcs` and Python uses the
//! `rfc8785` package; this crate cannot take a canonicalization dependency
//! (tokenfuse-core's allowed list is closed: thiserror, serde, serde_json,
//! regex, sha2), so the scheme is implemented here directly - and pinned, in
//! `agent_event`'s tests, against the SAME cross-language vectors the Go and
//! Python implementations pin (`agent-stack-go/event/testdata/
//! chain-vectors.json`), so the three cannot drift silently.
//!
//! What JCS requires, and where each rule lands below:
//! - object members sorted by the key's UTF-16 code units ([`canonicalize`]);
//! - minimal JSON string escaping, raw UTF-8 for everything printable
//!   (delegated to `serde_json`'s string serializer, which already emits
//!   exactly that form);
//! - numbers in ECMAScript `Number::toString` form ([`es_number`]): integers
//!   plain, fractions shortest-round-trip, exponent notation only at
//!   magnitude >= 1e21 or < 1e-6, exponent sign always written.
//!
//! Scope honesty: this operates on `serde_json::Value`, whose numbers are
//! i64/u64/f64 - the same value space every emitter in the stack uses.
//! Non-finite floats cannot occur (`serde_json::Number` refuses them).

use serde_json::Value;

/// Serialize `value` in RFC 8785 canonical form.
pub fn canonicalize(value: &Value) -> String {
    let mut out = String::new();
    write_value(&mut out, value);
    out
}

fn write_value(out: &mut String, value: &Value) {
    match value {
        Value::Null => out.push_str("null"),
        Value::Bool(true) => out.push_str("true"),
        Value::Bool(false) => out.push_str("false"),
        Value::Number(n) => {
            if let Some(i) = n.as_i64() {
                out.push_str(&i.to_string());
            } else if let Some(u) = n.as_u64() {
                out.push_str(&u.to_string());
            } else {
                // as_f64 is total for any serde_json::Number that is not an
                // integer, and non-finite values cannot be constructed.
                out.push_str(&es_number(n.as_f64().unwrap_or(0.0)));
            }
        }
        Value::String(s) => {
            // serde_json's string form IS the JCS string form: shorthand
            // escapes for the control set, no HTML escaping, no /-escaping,
            // raw UTF-8 for everything else. Serializing a bare &str cannot
            // fail.
            out.push_str(&serde_json::to_string(s).unwrap_or_default());
        }
        Value::Array(items) => {
            out.push('[');
            for (i, item) in items.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                write_value(out, item);
            }
            out.push(']');
        }
        Value::Object(map) => {
            // Sort keys by UTF-16 code units, as JCS requires. This differs
            // from plain byte order only for keys containing characters
            // beyond the BMP; sorting the encode_utf16 sequences is exact
            // either way.
            let mut keys: Vec<&String> = map.keys().collect();
            keys.sort_by(|a, b| {
                let a16: Vec<u16> = a.encode_utf16().collect();
                let b16: Vec<u16> = b.encode_utf16().collect();
                a16.cmp(&b16)
            });
            out.push('{');
            for (i, key) in keys.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                out.push_str(&serde_json::to_string(key).unwrap_or_default());
                out.push(':');
                write_value(out, &map[key.as_str()]);
            }
            out.push('}');
        }
    }
}

/// Format a finite f64 exactly as ECMAScript `Number::toString` does - the
/// number form RFC 8785 mandates.
///
/// serde_json already prints the shortest round-trip digits (ryu), which is
/// the hard half; what it does NOT do is ECMAScript's placement rules (it
/// prints `100.0`, `1e21`, `1e-6` where ES prints `100`, `1e+21`,
/// `0.000001`). So: take serde_json's digits, then re-place them by the
/// ECMA-262 `Number::toString` algorithm - with `s` the digit string, `k`
/// its length, and `n` the position of the decimal point (value =
/// 0.s x 10^n):
/// - `k <= n <= 21`: the digits followed by `n-k` zeros;
/// - `0 < n <= 21`: a point inside the digits;
/// - `-6 < n <= 0`: `0.` then `-n` zeros then the digits;
/// - otherwise: exponent form `d.ddd` `e` +/- `n-1`, sign always written.
fn es_number(f: f64) -> String {
    if f == 0.0 {
        // Positive and negative zero both print "0" in ES.
        return "0".to_string();
    }

    // serde_json's ryu output: one of D[.D+], D[.D+]eE, with an optional
    // leading '-'. Decompose into sign + significant digits + n.
    let ryu = serde_json::Number::from_f64(f)
        .map(|n| n.to_string())
        .unwrap_or_default();
    let (sign, body) = match ryu.strip_prefix('-') {
        Some(rest) => ("-", rest),
        None => ("", ryu.as_str()),
    };
    let (mantissa, exp10) = match body.split_once(['e', 'E']) {
        Some((m, e)) => (m, e.parse::<i64>().unwrap_or(0)),
        None => (body, 0),
    };
    let (int_part, frac_part) = match mantissa.split_once('.') {
        Some((i, fr)) => (i, fr),
        None => (mantissa, ""),
    };

    // Significant digits with the point removed, then stripped of leading
    // zeros (0.001 forms) and trailing zeros (100.0 forms), tracking how the
    // point position n shifts as we strip.
    let digits_raw: String = format!("{int_part}{frac_part}");
    let mut n = int_part.len() as i64 + exp10;
    let stripped_leading = digits_raw.len() - digits_raw.trim_start_matches('0').len();
    n -= stripped_leading as i64;
    let s = digits_raw.trim_matches('0');
    // f != 0 here, so at least one significant digit remains.
    let k = s.len() as i64;

    let placed = if k <= n && n <= 21 {
        format!("{s}{}", "0".repeat((n - k) as usize))
    } else if 0 < n && n <= 21 {
        format!("{}.{}", &s[..n as usize], &s[n as usize..])
    } else if -6 < n && n <= 0 {
        format!("0.{}{s}", "0".repeat((-n) as usize))
    } else {
        let e = n - 1;
        let exp = if e >= 0 {
            format!("e+{e}")
        } else {
            format!("e-{}", -e)
        };
        if k == 1 {
            format!("{s}{exp}")
        } else {
            format!("{}.{}{exp}", &s[..1], &s[1..])
        }
    };
    format!("{sign}{placed}")
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn objects_sort_keys_and_arrays_keep_order() {
        let v = json!({"b": 2, "a": 1, "arr": [3, 1, 2]});
        assert_eq!(canonicalize(&v), r#"{"a":1,"arr":[3,1,2],"b":2}"#);
    }

    #[test]
    fn strings_keep_raw_utf8_and_minimal_escapes() {
        let v = json!({"note": "обмеження діє", "esc": "a\"b\\c\nd", "html": "<&>"});
        assert_eq!(
            canonicalize(&v),
            "{\"esc\":\"a\\\"b\\\\c\\nd\",\"html\":\"<&>\",\"note\":\"обмеження діє\"}"
        );
    }

    #[test]
    fn integers_print_plain() {
        let v = json!({"i": 3, "neg": -7, "big": 9007199254740991i64});
        assert_eq!(
            canonicalize(&v),
            r#"{"big":9007199254740991,"i":3,"neg":-7}"#
        );
    }

    /// The ECMAScript number placements RFC 8785 requires - exactly the
    /// forms serde_json alone would get wrong.
    #[test]
    fn es_number_placement_rules() {
        let cases: &[(f64, &str)] = &[
            (12.5, "12.5"),
            (100.0, "100"), // serde_json alone: "100.0"
            (0.0, "0"),
            (-0.0, "0"),
            (-12.5, "-12.5"),
            (1e20, "100000000000000000000"),
            (1e21, "1e+21"), // serde_json alone: "1e21"
            (1.25e22, "1.25e+22"),
            (0.000001, "0.000001"), // serde_json alone: "1e-6"
            (1e-7, "1e-7"),
            (-2.5e-8, "-2.5e-8"),
            (0.001, "0.001"),
            (std::f64::consts::PI, "3.141592653589793"),
        ];
        for (input, want) in cases {
            assert_eq!(&es_number(*input), want, "for {input}");
        }
    }

    #[test]
    fn floats_inside_documents_use_es_form() {
        let v = json!({"budget_usd": 12.5, "whole": 100.0, "tiny": 0.000001});
        assert_eq!(
            canonicalize(&v),
            r#"{"budget_usd":12.5,"tiny":0.000001,"whole":100}"#
        );
    }
}
