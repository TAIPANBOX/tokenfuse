//! `GET /v1/price-book`: which price book this gateway charges calls at
//! (invariant 85).
//!
//! WHY
//!
//! `TOKENFUSE_PRICE_BOOK` (invariant 79) replaces built-in rows or adds rows
//! at startup, and until this route the only record of what it did was one
//! `info` line in the startup log naming two counts. An operator who wants to
//! know whether their negotiated rate is live, or which model ids their
//! callers send that the book has no row for (and so are charged at the
//! fallback, up to five times a list price), had to find that line or read
//! `x-fuse-price` off individual answers.
//!
//! This answers both from the process itself: the merged book's size, the
//! built-in book's size, which model ids the operator's file replaced and
//! which it added, the fallback rates, and the model ids a call has been
//! priced at the fallback for since this process started.
//!
//! WHAT IT IS NOT
//!
//! It is not the rates of every row: those are published, per release, in
//! `contracts/tokenfuse-constants.json` (`price_book`), and an operator's own
//! rows are in the operator's own file. It carries no run, key or prompt.
//! The fallback list is caller-supplied model ids, so it sits behind the same
//! admin gate as `/v1/runs` (invariant 41) and is bounded (see
//! [`MAX_FALLBACK_MODELS_SHOWN`]).

use crate::state::AppState;
use axum::extract::State;
use axum::Json;
use serde::Serialize;
use tokenfuse_core::ModelPrice;

/// How many fallback-priced model ids the report lists. They are caller
/// chosen, so the list is bounded in count here and in length below; the
/// total beside it says how many there were.
pub const MAX_FALLBACK_MODELS_SHOWN: usize = 100;

/// The longest model id the report prints in full. A caller can send any
/// string as a model id; a longer one is cut at a character boundary and
/// marked.
pub const MAX_MODEL_ID_SHOWN: usize = 256;

/// What `TOKENFUSE_PRICE_BOOK` did to the built-in book, kept from startup.
/// Sorted model ids, so the report reads the same on every call.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct OperatorRows {
    pub overridden: Vec<String>,
    pub added: Vec<String>,
}

/// Where the book this process prices with came from, fixed at startup.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PriceBookSource {
    /// Rows in the built-in book before any operator file.
    pub built_in_rows: usize,
    /// `None` when `TOKENFUSE_PRICE_BOOK` was unset or blank.
    pub operator: Option<OperatorRows>,
}

/// One rate row in the published book's own column names.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct Rates {
    pub input_per_mtok_microusd: i64,
    pub output_per_mtok_microusd: i64,
    pub cache_read_per_mtok_microusd: i64,
    pub cache_write_per_mtok_microusd: i64,
    pub cache_write_1h_per_mtok_microusd: i64,
}

impl From<ModelPrice> for Rates {
    fn from(p: ModelPrice) -> Self {
        Rates {
            input_per_mtok_microusd: p.input_per_mtok.0,
            output_per_mtok_microusd: p.output_per_mtok.0,
            cache_read_per_mtok_microusd: p.cache_read_per_mtok.0,
            cache_write_per_mtok_microusd: p.cache_write_per_mtok.0,
            cache_write_1h_per_mtok_microusd: p.cache_write_1h_per_mtok.0,
        }
    }
}

/// The answer.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct PriceBookReport {
    /// Rows in the book calls are priced with: built-in plus the operator's.
    pub rows: usize,
    /// Rows the binary ships with.
    pub built_in_rows: usize,
    /// Whether `TOKENFUSE_PRICE_BOOK` named a file this process applied.
    pub operator_file: bool,
    /// Built-in rows the operator's file replaced.
    pub overridden: usize,
    /// Rows the operator's file added for ids the built-in book lacks.
    pub added: usize,
    pub overridden_models: Vec<String>,
    pub added_models: Vec<String>,
    /// The rate an id with no row is charged at; `null` for a book with no
    /// fallback (a test book; the shipped one always has one).
    pub fallback: Option<Rates>,
    /// Model ids a call has been charged at the fallback for since this
    /// process started, sorted, at most [`MAX_FALLBACK_MODELS_SHOWN`].
    pub fallback_models_seen: Vec<String>,
    /// How many there were in all. The set is the once-per-model warning's
    /// memory, which is emptied past 8,192 ids (`state::CLAMP_LOG_CAP`), so
    /// this counts since that last happened, never more than it can know.
    pub fallback_models_seen_total: usize,
    /// One sentence for an operator reading this by eye.
    pub detail: String,
}

/// Cut `id` to [`MAX_MODEL_ID_SHOWN`] bytes at a character boundary.
fn shown(id: &str) -> String {
    if id.len() <= MAX_MODEL_ID_SHOWN {
        return id.to_string();
    }
    let mut end = MAX_MODEL_ID_SHOWN;
    while !id.is_char_boundary(end) {
        end -= 1;
    }
    format!("{}... ({} bytes)", &id[..end], id.len())
}

/// Build the report. Pure, so a test can hand it any source and any set.
pub fn report(
    rows: usize,
    fallback: Option<ModelPrice>,
    source: &PriceBookSource,
    mut fallback_seen: Vec<String>,
) -> PriceBookReport {
    fallback_seen.sort();
    let total = fallback_seen.len();
    let seen: Vec<String> = fallback_seen
        .iter()
        .take(MAX_FALLBACK_MODELS_SHOWN)
        .map(|m| shown(m))
        .collect();
    let (overridden_models, added_models) = match &source.operator {
        Some(op) => (op.overridden.clone(), op.added.clone()),
        None => (Vec::new(), Vec::new()),
    };
    let detail = match &source.operator {
        None => format!(
            "the built-in book ({} rows) is the whole book; TOKENFUSE_PRICE_BOOK is not set",
            source.built_in_rows
        ),
        Some(op) => format!(
            "TOKENFUSE_PRICE_BOOK replaced {} built-in row(s) and added {}; {} rows in all",
            op.overridden.len(),
            op.added.len(),
            rows
        ),
    };
    let detail = if total == 0 {
        format!("{detail}. No call has been charged at the fallback since this process started.")
    } else {
        format!(
            "{detail}. {total} model id(s) with no row have been charged at the fallback; \
             add a row for each with TOKENFUSE_PRICE_BOOK."
        )
    };
    PriceBookReport {
        rows,
        built_in_rows: source.built_in_rows,
        operator_file: source.operator.is_some(),
        overridden: overridden_models.len(),
        added: added_models.len(),
        overridden_models,
        added_models,
        fallback: fallback.map(Rates::from),
        fallback_models_seen: seen,
        fallback_models_seen_total: total,
        detail,
    }
}

/// `GET /v1/price-book`.
pub async fn price_book(State(st): State<AppState>) -> Json<PriceBookReport> {
    Json(report(
        st.prices.entries().len(),
        st.prices.fallback(),
        &st.price_book_source,
        st.fallback_models_seen(),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A caller-chosen model id is bounded in the report, in count and in
    /// length, whatever the caller sent, and a multi-byte character at the
    /// cut never panics.
    #[test]
    fn caller_chosen_ids_are_bounded_in_count_and_length() {
        let mut ids: Vec<String> = (0..500).map(|i| format!("m-{i:03}")).collect();
        ids.push(format!("a{}", "é".repeat(300)));
        ids.push("x".repeat(1_000_000));
        let r = report(1, None, &PriceBookSource::default(), ids);
        assert_eq!(r.fallback_models_seen_total, 502);
        assert_eq!(r.fallback_models_seen.len(), MAX_FALLBACK_MODELS_SHOWN);
        for id in &r.fallback_models_seen {
            assert!(id.len() <= MAX_MODEL_ID_SHOWN + 32, "{} bytes", id.len());
        }
        let long = report(
            1,
            None,
            &PriceBookSource::default(),
            vec![format!("a{}", "é".repeat(300)), "x".repeat(1_000_000)],
        );
        // 601 bytes, and byte 256 falls inside an "é": the cut steps back.
        assert!(long.fallback_models_seen[0].ends_with("(601 bytes)"));
        assert!(long.fallback_models_seen[0].starts_with(&format!("a{}", "é".repeat(127))));
        assert!(long.fallback_models_seen[1].ends_with("(1000000 bytes)"));
    }
}
