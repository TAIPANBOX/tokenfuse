//! `TOKENFUSE_PRICE_BOOK`: an operator-maintained price-book file, read once
//! at startup, whose rows override the built-in book's (tokenfuse#313).
//!
//! The built-in rows (`crate::pricebook`) are true on the date somebody read
//! a vendor's page, and some prices cannot be read off a model id at all: a
//! Google Cloud dateless Claude id is the Claude API's id character for
//! character, while a regional Google endpoint bills 10 percent more. The
//! operator who knows which endpoint, which negotiated discount, or which
//! model the book has never heard of writes the rate here.
//!
//! The file is the published book's own row shape
//! (`contracts/tokenfuse-constants.json`, `price_book.models`), so a row can
//! be copied from there and its numbers changed:
//!
//! ```json
//! {"models": [{"model": "claude-sonnet-5",
//!              "input_per_mtok_microusd": 2200000,
//!              "output_per_mtok_microusd": 11000000,
//!              "cache_read_per_mtok_microusd": 220000,
//!              "cache_write_per_mtok_microusd": 2750000,
//!              "cache_write_1h_per_mtok_microusd": 4400000}]}
//! ```
//!
//! It is read as hostile input, because it decides what every call costs and
//! a typo in it is a wrong bill nobody sees: a set but unusable file stops the
//! process (exit 2, the field named) rather than running on the built-in book
//! while the operator believes their rates are live. Every field is required
//! and nothing else is accepted, so a misspelt key is an error rather than a
//! zero. Rates are whole micro-USD per million tokens: a negative number or a
//! fraction does not parse, and a rate above [`MAX_RATE_MICROUSD`] is refused.
//! The file is capped at [`MAX_FILE_BYTES`] and [`MAX_ROWS`] rows, a model id
//! must be 1 to [`MAX_MODEL_ID_BYTES`] visible ASCII characters, and an id may
//! appear once. The fallback rate is not settable here (ADR-8): an unknown
//! model is priced at the top of the range, and a file that could lower that
//! could make every unlisted model cheap.

use serde::Deserialize;
use std::collections::HashSet;
use std::io::Read;
use tokenfuse_core::{Microusd, ModelPrice, PriceBook};

/// The environment variable naming the file.
pub const ENV: &str = "TOKENFUSE_PRICE_BOOK";
/// 1 MiB: about 4,000 rows at the published shape, far past any real book.
pub const MAX_FILE_BYTES: u64 = 1024 * 1024;
/// More rows than any provider lists.
pub const MAX_ROWS: usize = 4096;
/// Longer than any provider id this repository has seen (the longest Bedrock
/// inference profile is under 60 bytes).
pub const MAX_MODEL_ID_BYTES: usize = 256;
/// USD 1,000 per million tokens: more than 13 times the dearest rate any
/// vendor lists for Claude (Opus 4.1's 75 output). A rate past it is a units
/// mistake (USD where micro-USD was meant multiplies by a million), not a
/// price.
pub const MAX_RATE_MICROUSD: u64 = 1_000_000_000;

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct File {
    models: Vec<Row>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Row {
    model: String,
    input_per_mtok_microusd: u64,
    output_per_mtok_microusd: u64,
    cache_read_per_mtok_microusd: u64,
    cache_write_per_mtok_microusd: u64,
    cache_write_1h_per_mtok_microusd: u64,
}

/// The validated rows of a price-book file, in file order.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PriceFile {
    pub rows: Vec<(String, ModelPrice)>,
}

/// What applying a file did to a book, for the startup line.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Applied {
    /// Rows that replaced a built-in row.
    pub overridden: usize,
    /// Rows for a model the built-in book had no row for.
    pub added: usize,
    /// The model ids of `overridden`, sorted (invariant 85: what
    /// `GET /v1/price-book` names).
    pub overridden_models: Vec<String>,
    /// The model ids of `added`, sorted.
    pub added_models: Vec<String>,
}

impl PriceFile {
    /// Parse and validate a file's bytes. Every refusal names what to fix.
    pub fn parse(bytes: &[u8]) -> Result<PriceFile, String> {
        if bytes.len() as u64 > MAX_FILE_BYTES {
            return Err(format!(
                "the file is {} bytes, over the {MAX_FILE_BYTES}-byte cap",
                bytes.len()
            ));
        }
        let file: File = serde_json::from_slice(bytes).map_err(|e| {
            format!(
                "not a price book: {e}; expected {{\"models\": [{{\"model\": ..., \
                 \"input_per_mtok_microusd\": ..., \"output_per_mtok_microusd\": ..., \
                 \"cache_read_per_mtok_microusd\": ..., \"cache_write_per_mtok_microusd\": ..., \
                 \"cache_write_1h_per_mtok_microusd\": ...}}]}} with whole, non-negative \
                 micro-USD rates and no other keys"
            )
        })?;
        if file.models.is_empty() {
            return Err(
                "`models` is empty: a price book that prices nothing is a mistake; \
                        unset the variable to run on the built-in book"
                    .to_string(),
            );
        }
        if file.models.len() > MAX_ROWS {
            return Err(format!(
                "{} rows, over the {MAX_ROWS}-row cap",
                file.models.len()
            ));
        }
        let mut seen = HashSet::new();
        let mut rows = Vec::with_capacity(file.models.len());
        for (n, row) in file.models.into_iter().enumerate() {
            let at = format!("models[{n}]");
            check_model_id(&row.model).map_err(|why| format!("{at}.model {why}"))?;
            if !seen.insert(row.model.clone()) {
                return Err(format!(
                    "{at}.model `{}` appears more than once; which rate is meant?",
                    row.model
                ));
            }
            let rates = [
                ("input_per_mtok_microusd", row.input_per_mtok_microusd),
                ("output_per_mtok_microusd", row.output_per_mtok_microusd),
                (
                    "cache_read_per_mtok_microusd",
                    row.cache_read_per_mtok_microusd,
                ),
                (
                    "cache_write_per_mtok_microusd",
                    row.cache_write_per_mtok_microusd,
                ),
                (
                    "cache_write_1h_per_mtok_microusd",
                    row.cache_write_1h_per_mtok_microusd,
                ),
            ];
            for (field, v) in rates {
                if v > MAX_RATE_MICROUSD {
                    return Err(format!(
                        "{at}.{field} is {v} micro-USD per million tokens, over the cap of \
                         {MAX_RATE_MICROUSD} (USD 1,000); rates are micro-USD, not USD"
                    ));
                }
            }
            // Within the cap, so every figure fits an i64.
            let m = |v: u64| Microusd(v as i64);
            rows.push((
                row.model,
                ModelPrice {
                    input_per_mtok: m(row.input_per_mtok_microusd),
                    output_per_mtok: m(row.output_per_mtok_microusd),
                    cache_read_per_mtok: m(row.cache_read_per_mtok_microusd),
                    cache_write_per_mtok: m(row.cache_write_per_mtok_microusd),
                    cache_write_1h_per_mtok: m(row.cache_write_1h_per_mtok_microusd),
                },
            ));
        }
        Ok(PriceFile { rows })
    }

    /// Read and validate the file at `path`, reading at most one byte past
    /// the cap so an enormous file is refused without being loaded.
    pub fn read(path: &str) -> Result<PriceFile, String> {
        let f = std::fs::File::open(path).map_err(|e| format!("cannot open {path}: {e}"))?;
        let mut bytes = Vec::new();
        f.take(MAX_FILE_BYTES + 1)
            .read_to_end(&mut bytes)
            .map_err(|e| format!("cannot read {path}: {e}"))?;
        PriceFile::parse(&bytes)
    }

    /// Put every row into `book`, replacing a built-in row of the same id.
    /// The fallback is left alone.
    pub fn apply(&self, book: &mut PriceBook) -> Applied {
        let mut applied = Applied {
            overridden: 0,
            added: 0,
            overridden_models: Vec::new(),
            added_models: Vec::new(),
        };
        for (model, price) in &self.rows {
            if book.is_known(model) {
                applied.overridden += 1;
                applied.overridden_models.push(model.clone());
            } else {
                applied.added += 1;
                applied.added_models.push(model.clone());
            }
            book.insert(model.clone(), *price);
        }
        applied.overridden_models.sort();
        applied.added_models.sort();
        applied
    }
}

fn check_model_id(id: &str) -> Result<(), String> {
    if id.is_empty() {
        return Err("is empty".to_string());
    }
    if id.len() > MAX_MODEL_ID_BYTES {
        return Err(format!(
            "is {} bytes, over the {MAX_MODEL_ID_BYTES}-byte cap",
            id.len()
        ));
    }
    if let Some(c) = id.chars().find(|c| !c.is_ascii_graphic()) {
        return Err(format!(
            "`{}` carries {c:?}: a model id is visible ASCII with no spaces",
            id.escape_debug()
        ));
    }
    Ok(())
}

/// The value of `TOKENFUSE_PRICE_BOOK`, decided: unset or blank is `None` (the
/// built-in book alone); anything else is a file that must read and validate.
pub fn from_value(value: Option<&str>) -> Result<Option<PriceFile>, String> {
    match value.map(str::trim) {
        None | Some("") => Ok(None),
        Some(path) => PriceFile::read(path)
            .map(Some)
            .map_err(|e| format!("{ENV}={path}: {e}; refusing to start")),
    }
}

/// [`from_value`] over the process environment.
pub fn from_env() -> Result<Option<PriceFile>, String> {
    from_value(std::env::var(ENV).ok().as_deref())
}

#[cfg(test)]
mod tests {
    use super::*;

    const ROW: &str = r#"{"model": "claude-sonnet-5",
        "input_per_mtok_microusd": 2200000,
        "output_per_mtok_microusd": 11000000,
        "cache_read_per_mtok_microusd": 220000,
        "cache_write_per_mtok_microusd": 2750000,
        "cache_write_1h_per_mtok_microusd": 4400000}"#;

    fn file(rows: &[&str]) -> String {
        format!(r#"{{"models": [{}]}}"#, rows.join(","))
    }

    fn row(model: &str) -> String {
        ROW.replace("claude-sonnet-5", model)
    }

    #[test]
    fn a_row_overrides_the_built_in_rate_and_a_new_id_is_added() {
        let mut book = crate::pricebook::default_price_book();
        let f = PriceFile::parse(file(&[ROW, &row("my-local-model")]).as_bytes()).unwrap();
        assert_eq!(
            f.apply(&mut book),
            Applied {
                overridden: 1,
                added: 1,
                overridden_models: vec!["claude-sonnet-5".to_string()],
                added_models: vec!["my-local-model".to_string()],
            }
        );
        let p = book.price("claude-sonnet-5").unwrap();
        assert_eq!(p.input_per_mtok, Microusd(2_200_000));
        assert_eq!(p.output_per_mtok, Microusd(11_000_000));
        assert_eq!(p.cache_read_per_mtok, Microusd(220_000));
        assert_eq!(p.cache_write_per_mtok, Microusd(2_750_000));
        assert_eq!(p.cache_write_1h_per_mtok, Microusd(4_400_000));
        assert!(book.is_known("my-local-model"));
        // Untouched rows and the fallback are as shipped.
        assert_eq!(
            book.price("claude-haiku-4-5").unwrap().input_per_mtok,
            Microusd(1_000_000)
        );
        assert_eq!(
            book.price("never-heard-of-it").unwrap().input_per_mtok,
            Microusd(15_000_000)
        );
    }

    #[test]
    fn a_published_row_can_be_copied_verbatim() {
        // The shape is the constants file's: a row taken from it parses.
        let constants: serde_json::Value =
            serde_json::from_str(include_str!("../../../contracts/tokenfuse-constants.json"))
                .unwrap();
        let models = &constants["price_book"]["models"];
        let f = PriceFile::parse(
            serde_json::json!({ "models": models })
                .to_string()
                .as_bytes(),
        )
        .unwrap();
        assert_eq!(f.rows.len(), models.as_array().unwrap().len());
    }

    #[test]
    fn a_zero_rate_is_a_price_for_a_local_model() {
        let z = r#"{"model": "llama-local", "input_per_mtok_microusd": 0,
            "output_per_mtok_microusd": 0, "cache_read_per_mtok_microusd": 0,
            "cache_write_per_mtok_microusd": 0, "cache_write_1h_per_mtok_microusd": 0}"#;
        assert!(PriceFile::parse(file(&[z]).as_bytes()).is_ok());
    }

    /// Each refusal, with the words that must be in it.
    #[test]
    fn hostile_files_are_refused_and_say_why() {
        let neg = ROW.replace("2200000,", "-1,");
        let frac = ROW.replace("2200000,", "2.5,");
        let absurd = ROW.replace("11000000", "1000000001");
        let at_cap = ROW.replace("11000000", "1000000000");
        let unknown_row_key = ROW.replace("\"model\"", "\"modle\"");
        let missing = ROW.replace(
            ",\n        \"cache_write_1h_per_mtok_microusd\": 4400000",
            "",
        );
        let huge_number = ROW.replace("2200000,", "99999999999999999999999,");
        let string_rate = ROW.replace("2200000,", "\"2200000\",");
        let long_id = row(&"m".repeat(MAX_MODEL_ID_BYTES + 1));
        let id_at_cap = row(&"m".repeat(MAX_MODEL_ID_BYTES));
        let cases: Vec<(String, &str)> = vec![
            (file(&[&neg]), "not a price book"),
            (file(&[&frac]), "not a price book"),
            (file(&[&absurd]), "output_per_mtok_microusd is 1000000001"),
            (file(&[&unknown_row_key]), "modle"),
            (file(&[&missing]), "cache_write_1h_per_mtok_microusd"),
            (file(&[&huge_number]), "not a price book"),
            (file(&[&string_rate]), "not a price book"),
            (file(&[ROW, ROW]), "appears more than once"),
            (file(&[]), "`models` is empty"),
            (file(&[&row("")]), "models[0].model is empty"),
            (file(&[&row("has space")]), "visible ASCII"),
            (file(&[&row("tab\\there")]), "visible ASCII"),
            (file(&[&row("caf\u{e9}")]), "visible ASCII"),
            (file(&[&long_id]), "over the 256-byte cap"),
            (
                format!(r#"{{"models": [{ROW}], "fallback": {ROW}}}"#),
                "fallback",
            ),
            ("[]".to_string(), "not a price book"),
            ("".to_string(), "not a price book"),
            ("null".to_string(), "not a price book"),
            ("{\"models\": null}".to_string(), "not a price book"),
        ];
        for (body, needle) in cases {
            let err = PriceFile::parse(body.as_bytes()).expect_err(&body);
            assert!(
                err.contains(needle),
                "for {body:?}: {err:?} lacks {needle:?}"
            );
        }
        // The boundaries themselves are accepted.
        assert!(PriceFile::parse(file(&[&at_cap]).as_bytes()).is_ok());
        assert!(PriceFile::parse(file(&[&id_at_cap]).as_bytes()).is_ok());
    }

    #[test]
    fn the_size_and_row_caps_hold() {
        // One byte over the cap, refused before parsing.
        let mut big = file(&[ROW]).into_bytes();
        big.resize(MAX_FILE_BYTES as usize + 1, b' ');
        assert!(PriceFile::parse(&big).unwrap_err().contains("byte cap"));
        // At the cap, still parsed (trailing whitespace is valid JSON).
        big.truncate(MAX_FILE_BYTES as usize);
        assert!(PriceFile::parse(&big).is_ok());
        // Rows: compact rows so the count, not the bytes, is what trips.
        let compact = |i: usize| {
            format!(
                r#"{{"model":"m{i}","input_per_mtok_microusd":1,"output_per_mtok_microusd":1,"cache_read_per_mtok_microusd":1,"cache_write_per_mtok_microusd":1,"cache_write_1h_per_mtok_microusd":1}}"#
            )
        };
        let rows = |n: usize| (0..n).map(compact).collect::<Vec<_>>().join(",");
        let at = format!(r#"{{"models":[{}]}}"#, rows(MAX_ROWS));
        assert!(PriceFile::parse(at.as_bytes()).is_ok());
        let over = format!(r#"{{"models":[{}]}}"#, rows(MAX_ROWS + 1));
        assert!(PriceFile::parse(over.as_bytes())
            .unwrap_err()
            .contains("row cap"));
    }

    /// 200 seeded rounds of mutated and random bytes: parsing never panics,
    /// and whatever it accepts honours every bound.
    #[test]
    fn hostile_bytes_never_panic_and_never_slip_a_bound() {
        let base = file(&[ROW, &row("x")]).into_bytes();
        let mut state: u64 = 0x5eed_1a7e_0000_0001;
        let mut next = || {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            state
        };
        let mut accepted = 0;
        for seed in 0..200u64 {
            let mut b = if seed % 4 == 0 {
                (0..(next() % 512)).map(|_| next() as u8).collect()
            } else {
                base.clone()
            };
            for _ in 0..(1 + next() % 6) {
                if b.is_empty() {
                    break;
                }
                let at = (next() as usize) % b.len();
                match next() % 3 {
                    0 => b[at] = next() as u8,
                    1 => {
                        b.remove(at);
                    }
                    _ => {
                        const SHARP: &[u8] = b"0-9.e\"{}[],: \x00";
                        b.insert(at, SHARP[(next() as usize) % SHARP.len()])
                    }
                }
            }
            if let Ok(f) = PriceFile::parse(&b) {
                accepted += 1;
                for (id, p) in &f.rows {
                    assert!(check_model_id(id).is_ok(), "seed {seed}: {id:?}");
                    for v in [
                        p.input_per_mtok,
                        p.output_per_mtok,
                        p.cache_read_per_mtok,
                        p.cache_write_per_mtok,
                        p.cache_write_1h_per_mtok,
                    ] {
                        assert!((0..=MAX_RATE_MICROUSD as i64).contains(&v.0), "seed {seed}");
                    }
                }
            }
        }
        // Some mutations land on a digit and leave valid JSON, so the
        // accepted branch is exercised, not only the refusals.
        assert!(
            accepted > 0,
            "no mutated file parsed; the sweep checked nothing"
        );
    }

    #[test]
    fn unset_or_blank_is_the_built_in_book_and_a_missing_file_refuses() {
        assert_eq!(from_value(None), Ok(None));
        assert_eq!(from_value(Some("  ")), Ok(None));
        let err = from_value(Some("/nonexistent/prices.json")).unwrap_err();
        assert!(
            err.contains("TOKENFUSE_PRICE_BOOK=/nonexistent/prices.json"),
            "{err}"
        );
        assert!(err.contains("refusing to start"), "{err}");
    }
}
