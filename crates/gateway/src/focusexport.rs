//! `tokenfuse focus-export --traces <dir-or-glob> --out <file.csv> [--from RFC3339] [--to RFC3339]`
//!
//! Exports the Parquet call trace as a FOCUS 1.2-style CSV (FinOps Open Cost &
//! Usage Specification) — one row per LLM call — so a bank/FinOps team can load
//! LLM agent spend into the same tooling they already use for cloud spend.
//!
//! Read-only: this reads the already-written trace via the same DataFusion path
//! as `tokenfuse sql` ([`crate::sqlq`]). It never touches the enforcement hot
//! path (`proxy.rs` / `tokenfuse_core::breaker`).
//!
//! ## Column sourcing
//!
//! Every column is derived from the ACTUAL `calls` Parquet schema
//! ([`crate::sink::ParquetSink`]) — nothing is invented. A few FOCUS-shaped
//! columns have no matching source field today and are always emitted empty,
//! rather than synthesized:
//!   - `x_parent_run_id`: sourced from `CallRecord.parent_run_id` (P3,
//!     agent-passport SPEC.md §3.2) — the run's `X-Fuse-Parent-Run-Id`
//!     header, now written to the trace (see `crate::sink::CallRecord`).
//!     `COALESCE(parent_run_id, '')` in [`load_records`] keeps this `""` for
//!     rows from a pre-P3 trace file that lacks the column (schema
//!     evolution, same pattern as `agent_id` below) as well as for rows that
//!     genuinely had no parent.
//!   - `x_outcome`: sourced from `CallRecord.outcome` (P4, unit economics) —
//!     the raw, per-call `X-Fuse-Outcome` value. `""` for rows from a pre-P4
//!     trace file (schema evolution, same `COALESCE` pattern) as well as for
//!     calls that never set the header. This is the raw per-call capture, not
//!     the "last non-empty per run" aggregation `tokenfuse outcomes` computes
//!     — see `tokenfuse_core::outcomes`.
//!   - `x_unit`: sourced from `CallRecord.unit` (docs/20-identity-map.md
//!     section 4) - the business unit resolved server-side from the identity
//!     map. `""` for rows from a pre-unit trace file (schema evolution, same
//!     `COALESCE` pattern) as well as for calls the map did not match.
//!   - `x_tool_calls`: sourced from `CallRecord.tool_calls` (I1,
//!     docs/21-tool-runs.md) - the count of tool calls the model emitted in
//!     that call's response. Blank (not `"0"`) for rows from a pre-I1 trace
//!     file (schema evolution) as well as for a call whose response body
//!     never parsed; a real, observed zero renders as `"0"`, distinguishable
//!     from the blank "we don't know" case.
//!   - `x_key_id`: sourced from `CallRecord.key_id` (invariant 81) - the
//!     client credential the call was made with, resolved server-side from
//!     `x-fuse-key`, never written by the caller. `""` when client keys are
//!     off, and for a row from a trace file written before the column
//!     existed (schema evolution, same `COALESCE` pattern).
//!   - `x_block_reason`: the Breaker reason's wire string on a blocked row
//!     (invariant 81), so non-empty exactly when `x_blocked` is `true`;
//!     `""` on every other row, including a policy plane's own refusal
//!     (`wardryx_deny`/`wardryx_hold`), which is not a Breaker block.
//!   - `x_identity_reason`: the identity check's finding (invariant 87),
//!     `CallRecord.identity_reason`: on a row refused for identity, which
//!     check refused it (`x_block_reason` says only `identity_mismatch`); on
//!     a row `TOKENFUSE_IDENTITY_STRICT=warn` forwarded anyway, the reason it
//!     would have been refused. Such a forwarded row is still an admitted,
//!     spent call filed under the agent id it claimed, as warn mode records
//!     what it would do without doing it; this column is how a reader tells
//!     it from an honest one. `""` on every other row, and for a row from a
//!     trace file written before the column existed.
//!   - `x_price_basis`: `CallRecord.price_basis` (invariant 109), the word
//!     the call was charged at, `known` or `fallback` (the same word
//!     `x-fuse-price` and the Cloud wire use), on an admitted row; `""` on any
//!     other row and on a row written before the column existed. A FinOps tool
//!     reading only this export can tell a guess priced at the fallback from a
//!     list price with it.
//!   - `x_pii_findings`: `CallRecord.pii_findings` (invariant 106), the PII
//!     the scanner found and let through in shadow or mask, `kind=count` pairs
//!     joined by `,` (so the field is quoted); `""` when nothing was found or
//!     the row predates the column. Never a matched span.
//!   - `x_cache_read_tokens`, `x_cache_write_tokens`, `x_cache_write_1h_tokens`,
//!     `x_reasoning_tokens`: the trace's four columns of invariant 148, the
//!     cache and reasoning counts an admitted call was priced with. Blank on a
//!     row not priced from parsed counts and on a row written before the
//!     columns existed; a real zero renders as `0`. `x_tokens_in` stays the
//!     uncached input and `x_tokens_out` the whole billed output, reasoning
//!     included, exactly as before.
//!   - `ChargePeriodStart` / `ChargePeriodEnd`: the trace records exactly one
//!     timestamp per call (`ts_millis`, the settle time) — there is no
//!     separate call-start timestamp — so both columns get the SAME instant.
//!
//! `ProviderName` / `PublisherName` / `InvoiceIssuerName` also have no direct
//! source: the trace has no per-call upstream/provider field
//! (`TOKENFUSE_UPSTREAM` is a gateway-wide setting, not recorded per row), so
//! the provider is inferred from the `model` string via
//! [`provider_from_model`]. This is a derivation from real data, not an
//! invention, but it is a heuristic — an unrecognized model name falls back to
//! `"Unknown"`.
//!
//! ## Who a row is filed under
//!
//! `ResourceId`, `ResourceName` and `x_agent_id` carry the call's
//! `x-fuse-agent-id`, except on a row refused for identity
//! (`identity_mismatch`), where that id is the one the gateway refused as
//! unauthenticated: such a row is filed under `key:<key_id>` with an empty
//! `x_agent_id` (invariant 81, see [`filed_under`]).
//!
//! ## Cost basis and `x_blocked`
//!
//! A call's `decision` column already tells us whether the Breaker tripped
//! (the nine reasons in [`tokenfuse_core::BreakerReason`]) — see
//! [`is_blocked_decision`]. For a blocked row `cost_microusd` holds the
//! *reserved estimate* that was never actually charged (see `proxy.rs`), so
//! `BilledCost`/`EffectiveCost` are forced to `0` and `x_cost_basis` is
//! `"blocked"` — that zero-cost row, kept rather than dropped, IS the savings
//! story a bank's FinOps team wants to see.
//!
//! For an allowed call, `cost_microusd` is normally the real settled cost
//! (parsed usage × price). One edge case: a settlement with no priced token
//! count parsed settles on the *reserved fallback* — `SettleGuard`'s `Drop`
//! path (client cancel / upstream error mid-stream, see `settle.rs`), or any
//! 2xx whose body carried no usage block, which every `include_usage: false`
//! stream is (invariant 43) — recorded with `decision = "allow"` but
//! `input_tokens = output_tokens = 0`. We detect that shape
//! (zero tokens, non-zero cost) and mark it `x_cost_basis = "estimated"`;
//! everything else lands on `"settled"`. A settlement whose usage stopped short
//! of its final event is written in the same shape on purpose, because its
//! output side is the request's cap and not a figure (invariant 43).

use crate::sqlq::{query, str_at};
use datafusion::arrow::array::{Array, Int64Array};
use tokenfuse_core::timefmt::{days_from_civil, ts_millis_to_rfc3339};
use tokenfuse_core::{BreakerReason, Microusd};

/// Parsed `tokenfuse focus-export` flags.
#[derive(Debug, Clone, Default)]
pub struct Args {
    pub traces: Option<String>,
    pub out: Option<String>,
    pub from: Option<String>,
    pub to: Option<String>,
    /// `--spec <version>`: `None` (or `1.2`) is the default export, one row
    /// per call, unchanged; `1.5` is the FOCUS 1.5 release-candidate shape,
    /// one row per token kind (see [`HEADER_1_5`]). Anything else is refused.
    pub spec: Option<String>,
}

/// Parse `--traces <dir-or-glob>`, `--out <file.csv>`, `--from <rfc3339>`,
/// `--to <rfc3339>`, `--spec <version>`.
pub fn parse_args(args: &[String]) -> Args {
    let mut out = Args::default();
    let mut it = args.iter();
    while let Some(a) = it.next() {
        match a.as_str() {
            "--traces" => out.traces = it.next().cloned(),
            "--out" => out.out = it.next().cloned(),
            "--from" => out.from = it.next().cloned(),
            "--to" => out.to = it.next().cloned(),
            "--spec" => out.spec = it.next().cloned(),
            _ => {}
        }
    }
    out
}

/// Which shape `--spec` asked for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Spec {
    /// The default export: one row per call, [`HEADER`].
    Default,
    /// FOCUS 1.5 release-candidate names: one row per token kind,
    /// [`HEADER_1_5`].
    Focus15,
}

fn spec_of(arg: Option<&str>) -> Result<Spec, String> {
    match arg.map(str::trim) {
        None | Some("1.2") => Ok(Spec::Default),
        Some("1.5") => Ok(Spec::Focus15),
        Some(other) => Err(format!(
            "unknown --spec '{other}': this export writes the default shape (no --spec, or 1.2) \
             or FOCUS 1.5 release-candidate names (--spec 1.5)"
        )),
    }
}

/// One `calls` row as loaded from the trace, before FOCUS projection.
#[derive(Debug, Clone, PartialEq, Eq)]
struct FocusRecord {
    ts_millis: i64,
    run_id: String,
    model: String,
    decision: String,
    input_tokens: u64,
    output_tokens: u64,
    cost_microusd: i64,
    agent_id: String,
    parent_run_id: String,
    outcome: String,
    unit: String,
    /// I1 (docs/21-tool-runs.md): tool calls the model emitted in this
    /// call's response. `None` for a pre-I1 trace row or an unparseable
    /// response body - see `x_tool_calls`'s sourcing note above.
    tool_calls: Option<u32>,
    /// The client credential the call was made with (`CallRecord::key_id`,
    /// resolved server-side, never a header). `""` when client keys are off
    /// and for a row written before the trace carried the column.
    key_id: String,
    /// The identity check's finding (`CallRecord::identity_reason`,
    /// invariant 87); `""` when it found nothing or the row predates it.
    identity_reason: String,
    /// The price basis of an admitted call (`CallRecord::price_basis`,
    /// invariant 109): `known` or `fallback`; `""` on any other row and on a
    /// row that predates the column.
    price_basis: String,
    /// The PII the scanner let through (`CallRecord::pii_findings`,
    /// invariant 106): `kind=count` pairs; `""` when nothing was found.
    pii_findings: String,
    /// Invariant 148: the cache and reasoning counts the call was priced
    /// with, `None` on a row not priced from parsed counts and on a row
    /// written before the columns existed.
    cache_read_tokens: Option<u64>,
    cache_write_tokens: Option<u64>,
    cache_write_1h_tokens: Option<u64>,
    reasoning_tokens: Option<u64>,
}

/// The FOCUS 1.2-style column header, in the order the architect specified.
const HEADER: [&str; 35] = [
    "BilledCost",
    "EffectiveCost",
    "BillingCurrency",
    "ChargePeriodStart",
    "ChargePeriodEnd",
    "ChargeDescription",
    "ProviderName",
    "PublisherName",
    "InvoiceIssuerName",
    "ServiceName",
    "ServiceCategory",
    "ResourceId",
    "ResourceName",
    "SubAccountId",
    "SubAccountName",
    "x_run_id",
    "x_parent_run_id",
    "x_agent_id",
    "x_model",
    "x_tokens_in",
    "x_tokens_out",
    "x_blocked",
    "x_cost_basis",
    "x_outcome",
    "x_unit",
    "x_tool_calls",
    // Invariant 81: appended LAST, so a reader that addresses the 26
    // columns above by position keeps reading them.
    "x_key_id",
    "x_block_reason",
    // Invariant 87: appended after them, same rule.
    "x_identity_reason",
    // Invariant 109: appended after it, same rule, for a reader that sees
    // only this export (costcrew): the basis a call was charged at and the PII
    // the scanner let through.
    "x_price_basis",
    "x_pii_findings",
    // Invariant 148: appended after them, same rule: the cache and reasoning
    // counts the call was priced with, blank where the trace holds none.
    "x_cache_read_tokens",
    "x_cache_write_tokens",
    "x_cache_write_1h_tokens",
    "x_reasoning_tokens",
];

/// The `--spec 1.5` header: FOCUS 1.5 release-candidate names (release
/// candidate completed 2026-11-02, ratification set for 2026-12-03), one row
/// per token kind of a call. A name here follows the release candidate and
/// moves with the ratified text if that differs. The `x_` columns are this
/// gateway's own, as in the default export.
const HEADER_1_5: [&str; 36] = [
    "BilledCost",
    "EffectiveCost",
    "BillingCurrency",
    "ChargePeriodStart",
    "ChargePeriodEnd",
    "ChargeCategory",
    "ChargeDescription",
    "ProviderName",
    "PublisherName",
    "InvoiceIssuerName",
    "ServiceName",
    "ServiceCategory",
    "ResourceId",
    "ResourceName",
    "SubAccountId",
    "SubAccountName",
    "ConsumedQuantity",
    "ConsumedUnit",
    "SkuPriceDetails",
    "PrincipalId",
    "CredentialId",
    "RequesterDetails",
    "x_run_id",
    "x_parent_run_id",
    "x_model",
    "x_blocked",
    "x_cost_basis",
    "x_block_reason",
    "x_outcome",
    "x_unit",
    "x_tool_calls",
    "x_identity_reason",
    "x_price_basis",
    "x_pii_findings",
    "x_reasoning_tokens",
    "x_cache_write_1h_tokens",
];

/// The prefix a row refused for identity is filed under, ahead of the key id
/// (invariant 81). It cannot be mistaken for an agent id, so a key named like
/// an agent never lands in that agent's figures.
pub(crate) const KEY_RESOURCE_PREFIX: &str = "key:";

/// The header, for the constants contract (`crate::constants`), which
/// publishes it so a consumer reads the columns instead of retyping them.
pub(crate) fn columns() -> &'static [&'static str] {
    &HEADER
}

/// The `--spec 1.5` header, published beside the default one.
pub(crate) fn columns_1_5() -> &'static [&'static str] {
    &HEADER_1_5
}

/// Load, project, and write the FOCUS CSV. Returns `Err` with a clear message
/// on bad flags, a missing/unreadable trace, or an empty result set — the
/// caller (`main.rs`) turns that into a non-zero exit.
pub async fn run(args: &Args) -> Result<(), String> {
    let traces = args
        .traces
        .clone()
        .ok_or_else(|| "missing --traces <dir-or-glob>".to_string())?;
    let out_path = args
        .out
        .clone()
        .ok_or_else(|| "missing --out <file.csv>".to_string())?;
    let spec = spec_of(args.spec.as_deref())?;

    let from_ms = match &args.from {
        Some(s) => Some(parse_rfc3339_millis(s).map_err(|e| format!("bad --from: {e}"))?),
        None => None,
    };
    let to_ms = match &args.to {
        Some(s) => Some(parse_rfc3339_millis(s).map_err(|e| format!("bad --to: {e}"))?),
        None => None,
    };

    let records = load_records(&traces, from_ms, to_ms)
        .await
        .map_err(|e| format!("could not read traces at '{traces}': {e}"))?;

    if records.is_empty() {
        let window = if from_ms.is_some() || to_ms.is_some() {
            " in the given --from/--to window"
        } else {
            ""
        };
        return Err(format!(
            "no calls found in the trace at '{traces}'{window} — nothing to export"
        ));
    }

    let csv = match spec {
        Spec::Default => render_csv(&records),
        Spec::Focus15 => render_csv_1_5(&records, &export_price_book()?),
    };
    std::fs::write(&out_path, &csv).map_err(|e| format!("could not write '{out_path}': {e}"))?;

    println!(
        "tokenfuse focus-export: wrote {} row(s) to {out_path}",
        records.len()
    );
    Ok(())
}

/// Load the trace rows FOCUS needs, oldest first (ties broken by `run_id` —
/// the trace has no per-row sequence number to break ties further).
async fn load_records(
    dir: &str,
    from_ms: Option<i64>,
    to_ms: Option<i64>,
) -> Result<Vec<FocusRecord>, Box<dyn std::error::Error>> {
    let mut sql = String::from(
        "select ts_millis, run_id, model, decision, \
         cast(input_tokens as bigint) as input_tokens, \
         cast(output_tokens as bigint) as output_tokens, \
         cast(cost_microusd as bigint) as cost_microusd, \
         coalesce(agent_id, '') as agent_id, \
         coalesce(parent_run_id, '') as parent_run_id, \
         coalesce(outcome, '') as outcome, \
         coalesce(unit, '') as unit, \
         cast(tool_calls as bigint) as tool_calls, \
         coalesce(key_id, '') as key_id, \
         coalesce(identity_reason, '') as identity_reason, \
         coalesce(price_basis, '') as price_basis, \
         coalesce(pii_findings, '') as pii_findings, \
         cast(cache_read_tokens as bigint) as cache_read_tokens, \
         cast(cache_write_tokens as bigint) as cache_write_tokens, \
         cast(cache_write_1h_tokens as bigint) as cache_write_1h_tokens, \
         cast(reasoning_tokens as bigint) as reasoning_tokens \
         from calls",
    );
    let mut conds: Vec<String> = Vec::new();
    if let Some(f) = from_ms {
        conds.push(format!("ts_millis >= {f}"));
    }
    if let Some(t) = to_ms {
        conds.push(format!("ts_millis <= {t}"));
    }
    if !conds.is_empty() {
        sql.push_str(" where ");
        sql.push_str(&conds.join(" and "));
    }
    sql.push_str(" order by ts_millis, run_id");

    let batches = query(&sql, dir).await?;
    let mut out = Vec::new();
    for b in &batches {
        let ts = b
            .column(0)
            .as_any()
            .downcast_ref::<Int64Array>()
            .ok_or("ts_millis column type")?;
        let input_tokens = b
            .column(4)
            .as_any()
            .downcast_ref::<Int64Array>()
            .ok_or("input_tokens column type")?;
        let output_tokens = b
            .column(5)
            .as_any()
            .downcast_ref::<Int64Array>()
            .ok_or("output_tokens column type")?;
        let cost = b
            .column(6)
            .as_any()
            .downcast_ref::<Int64Array>()
            .ok_or("cost_microusd column type")?;
        let tool_calls = b
            .column(11)
            .as_any()
            .downcast_ref::<Int64Array>()
            .ok_or("tool_calls column type")?;
        // Invariant 148: genuinely nullable, like `tool_calls`.
        let counts: Vec<&Int64Array> = (16..20)
            .map(|c| {
                b.column(c)
                    .as_any()
                    .downcast_ref::<Int64Array>()
                    .ok_or("cache/reasoning column type")
            })
            .collect::<Result<_, _>>()?;
        let count_at = |c: usize, i: usize| -> Option<u64> {
            (!counts[c].is_null(i)).then(|| counts[c].value(i).max(0) as u64)
        };
        for i in 0..b.num_rows() {
            out.push(FocusRecord {
                ts_millis: ts.value(i),
                run_id: str_at(b.column(1).as_ref(), i),
                model: str_at(b.column(2).as_ref(), i),
                decision: str_at(b.column(3).as_ref(), i),
                input_tokens: input_tokens.value(i).max(0) as u64,
                output_tokens: output_tokens.value(i).max(0) as u64,
                cost_microusd: cost.value(i),
                agent_id: str_at(b.column(7).as_ref(), i),
                parent_run_id: str_at(b.column(8).as_ref(), i),
                outcome: str_at(b.column(9).as_ref(), i),
                unit: str_at(b.column(10).as_ref(), i),
                // Genuinely nullable (unlike the coalesced string columns
                // above): NULL means "pre-I1 file or unparseable response",
                // a real 0 means "observed, no tool calls" - see
                // `FocusRecord::tool_calls`'s doc.
                tool_calls: if tool_calls.is_null(i) {
                    None
                } else {
                    Some(tool_calls.value(i).max(0) as u32)
                },
                key_id: str_at(b.column(12).as_ref(), i),
                identity_reason: str_at(b.column(13).as_ref(), i),
                price_basis: str_at(b.column(14).as_ref(), i),
                pii_findings: str_at(b.column(15).as_ref(), i),
                cache_read_tokens: count_at(0, i),
                cache_write_tokens: count_at(1, i),
                cache_write_1h_tokens: count_at(2, i),
                reasoning_tokens: count_at(3, i),
            });
        }
    }
    Ok(out)
}

/// The Breaker block reasons, read off [`tokenfuse_core::BreakerReason`]
/// so this stays in sync with core's canonical list rather than duplicating
/// the wire strings by hand. Includes the identity-map pair (docs/20):
/// `unit_budget_exceeded` rows carry the avoided estimate and
/// `identity_mismatch` rows carry zero cost; both stay $0 `x_blocked` rows.
pub(crate) fn is_blocked_decision(decision: &str) -> bool {
    [
        BreakerReason::BudgetExceeded,
        BreakerReason::PolicyViolation,
        BreakerReason::LoopDetected,
        BreakerReason::Killed,
        BreakerReason::WasmPolicy,
        BreakerReason::TaintBlocked,
        BreakerReason::DlpBlocked,
        BreakerReason::UnitBudgetExceeded,
        BreakerReason::IdentityMismatch,
    ]
    .iter()
    .any(|r| r.as_wire_str() == decision)
}

/// Infer a provider display name from the model string. The trace has no
/// per-call upstream field, so this is the best real-data-driven signal
/// available; unrecognized names fall back to `"Unknown"` rather than
/// guessing further.
fn provider_from_model(model: &str) -> &'static str {
    let m = model.to_ascii_lowercase();
    if m.contains("claude") {
        "Anthropic"
    } else if m.contains("gpt")
        || m.contains("chatgpt")
        || m.starts_with("o1")
        || m.starts_with("o3")
        || m.starts_with("o4")
    {
        "OpenAI"
    } else if m.contains("gemini") {
        "Google"
    } else if m.contains("llama") {
        "Meta"
    } else if m.contains("mistral") {
        "Mistral AI"
    } else {
        "Unknown"
    }
}

/// Render `microusd` as a plain (no `$`) fixed-point USD string, matching the
/// microdollar precision the ledger stores.
fn usd_string(microusd: i64) -> String {
    format!("{:.6}", Microusd(microusd).as_usd())
}

/// Who a row is filed under: `(ResourceId and ResourceName, x_agent_id)`.
///
/// Invariant 81. `agent_id` is the `x-fuse-agent-id` header, which the caller
/// writes. On every row but one kind that is all the trace knows, and the
/// export reports it as it always has. The exception is a row refused for
/// identity (`identity_mismatch`): the gateway refused that call precisely
/// because the credential presented may not speak as that agent, so the
/// header names somebody who did NOT make the call. Filing it there put an
/// impersonation's refusals on its victim's figures (the R6 run, 2026-10-07).
///
/// Such a row is filed under the credential that did make it,
/// [`KEY_RESOURCE_PREFIX`] plus the key id, and reports no agent id, because
/// a consumer reads `x_agent_id` first and `ResourceId` second (CostCrew's
/// `tokenfuse-focus` reader does exactly that). With client keys off there is
/// no credential on the row and both are empty: filed under nobody, which a
/// reader can see, rather than under somebody, which it cannot tell from the
/// truth. The claimed id is still in the Parquet trace and in the
/// `identity_mismatch` agent event.
fn filed_under(rec: &FocusRecord) -> (String, String) {
    if rec.decision == BreakerReason::IdentityMismatch.as_wire_str() {
        let resource = if rec.key_id.is_empty() {
            String::new()
        } else {
            format!("{KEY_RESOURCE_PREFIX}{}", rec.key_id)
        };
        (resource, String::new())
    } else {
        (rec.agent_id.clone(), rec.agent_id.clone())
    }
}

/// A count as the export writes it: blank for `None`, the number otherwise.
fn count_field(n: Option<u64>) -> String {
    n.map(|n| n.to_string()).unwrap_or_default()
}

/// Project one trace row into the 35 FOCUS column values, in [`HEADER`] order.
fn to_row(rec: &FocusRecord) -> [String; 35] {
    let blocked = is_blocked_decision(&rec.decision);
    // Non-empty exactly when `x_blocked` is true: the Breaker reason's own
    // wire string, which is what `decision` holds on a blocked row.
    let block_reason = if blocked {
        rec.decision.clone()
    } else {
        String::new()
    };
    let (resource, agent) = filed_under(rec);
    let (cost_microusd, cost_basis) = if blocked {
        (0i64, "blocked")
    } else if rec.input_tokens == 0 && rec.output_tokens == 0 && rec.cost_microusd != 0 {
        (rec.cost_microusd, "estimated")
    } else {
        (rec.cost_microusd, "settled")
    };
    let billed = usd_string(cost_microusd);
    let ts = ts_millis_to_rfc3339(rec.ts_millis);
    let provider = provider_from_model(&rec.model).to_string();

    [
        billed.clone(),                                            // BilledCost
        billed,                                                    // EffectiveCost
        "USD".to_string(),                                         // BillingCurrency
        ts.clone(),                                                // ChargePeriodStart
        ts,                                                        // ChargePeriodEnd
        format!("LLM call model={}", rec.model),                   // ChargeDescription
        provider.clone(),                                          // ProviderName
        provider.clone(),                                          // PublisherName
        provider,                                                  // InvoiceIssuerName
        "LLM inference".to_string(),                               // ServiceName
        "AI and Machine Learning".to_string(),                     // ServiceCategory
        resource.clone(),                                          // ResourceId
        resource,                                                  // ResourceName
        rec.run_id.clone(),                                        // SubAccountId
        rec.run_id.clone(),                                        // SubAccountName
        rec.run_id.clone(),                                        // x_run_id
        rec.parent_run_id.clone(),                                 // x_parent_run_id
        agent,                                                     // x_agent_id
        rec.model.clone(),                                         // x_model
        rec.input_tokens.to_string(),                              // x_tokens_in
        rec.output_tokens.to_string(),                             // x_tokens_out
        blocked.to_string(),                                       // x_blocked
        cost_basis.to_string(),                                    // x_cost_basis
        rec.outcome.clone(),                                       // x_outcome
        rec.unit.clone(),                                          // x_unit
        rec.tool_calls.map(|n| n.to_string()).unwrap_or_default(), // x_tool_calls
        rec.key_id.clone(),                                        // x_key_id
        block_reason,                                              // x_block_reason
        rec.identity_reason.clone(),                               // x_identity_reason
        rec.price_basis.clone(),                                   // x_price_basis
        rec.pii_findings.clone(),                                  // x_pii_findings
        count_field(rec.cache_read_tokens),                        // x_cache_read_tokens
        count_field(rec.cache_write_tokens),                       // x_cache_write_tokens
        count_field(rec.cache_write_1h_tokens),                    // x_cache_write_1h_tokens
        count_field(rec.reasoning_tokens),                         // x_reasoning_tokens
    ]
}

/// RFC 4180 field quoting: quote (doubling embedded quotes) whenever the field
/// contains a comma, a double quote, or a line break; leave everything else
/// bare.
fn csv_quote(field: &str) -> String {
    if field.contains(',') || field.contains('"') || field.contains('\n') || field.contains('\r') {
        format!("\"{}\"", field.replace('"', "\"\""))
    } else {
        field.to_string()
    }
}

fn csv_row<S: AsRef<str>>(fields: &[S]) -> String {
    fields
        .iter()
        .map(|f| csv_quote(f.as_ref()))
        .collect::<Vec<_>>()
        .join(",")
}

fn render_csv(records: &[FocusRecord]) -> String {
    let mut out = String::new();
    out.push_str(&csv_row(&HEADER));
    out.push('\n');
    for rec in records {
        out.push_str(&csv_row(&to_row(rec)));
        out.push('\n');
    }
    out
}

// -- FOCUS 1.5 (release candidate): one row per token kind ---------------------

/// The price book the `--spec 1.5` split weighs a call's cost with: the built-in
/// book with `TOKENFUSE_PRICE_BOOK` applied, as `tokenfuse serve` builds it, so a
/// gateway and its export on one host weigh with the same rates. A set but
/// unusable file is an error here, as it is at the gateway's start.
fn export_price_book() -> Result<tokenfuse_core::PriceBook, String> {
    let mut book = crate::pricebook::default_price_book();
    if let Some(file) = crate::pricefile::from_env()? {
        let _ = file.apply(&mut book);
    }
    Ok(book)
}

/// One token kind of a call, as FOCUS 1.5 names it in `SkuPriceDetails`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TokenKind {
    /// Input the provider read fresh. On a row written before invariant 148
    /// the trace cannot say whether any of the call's input was cached, so the
    /// input row of such a call names no cache action at all (`Unknown`).
    InputUncached,
    InputRead,
    InputWrite,
    InputUnknown,
    Output,
}

impl TokenKind {
    fn direction(self) -> &'static str {
        match self {
            TokenKind::Output => "Output",
            _ => "Input",
        }
    }

    /// `TokenCacheAction`, or `None` where none applies: an output token is
    /// never read from or written to a prompt cache, and an input count from a
    /// row that predates the cache columns is of unknown cache state.
    fn cache_action(self) -> Option<&'static str> {
        match self {
            TokenKind::InputUncached => Some("Uncached"),
            TokenKind::InputRead => Some("Read"),
            TokenKind::InputWrite => Some("Write"),
            TokenKind::InputUnknown | TokenKind::Output => None,
        }
    }

    fn label(self) -> &'static str {
        match self {
            TokenKind::InputUncached | TokenKind::InputUnknown => "input",
            TokenKind::InputRead => "input cache read",
            TokenKind::InputWrite => "input cache write",
            TokenKind::Output => "output",
        }
    }
}

/// The token kinds of one call with their counts, zero counts left out, in a
/// fixed order: input uncached, cache read, cache write, output. A row written
/// before invariant 148 (cache columns NULL) gives an input row of unknown
/// cache state and an output row.
fn token_kinds(rec: &FocusRecord) -> Vec<(TokenKind, u64)> {
    let cached_known = rec.cache_read_tokens.is_some() || rec.cache_write_tokens.is_some();
    let input = if cached_known {
        TokenKind::InputUncached
    } else {
        TokenKind::InputUnknown
    };
    [
        (input, rec.input_tokens),
        (TokenKind::InputRead, rec.cache_read_tokens.unwrap_or(0)),
        (TokenKind::InputWrite, rec.cache_write_tokens.unwrap_or(0)),
        (TokenKind::Output, rec.output_tokens),
    ]
    .into_iter()
    .filter(|(_, n)| *n > 0)
    .collect()
}

/// What each kind costs at the book's rate for this call (the prompt-length
/// tier chosen exactly as settlement chooses it), in microdollar-tokens per
/// Mtok: only the ratios matter. A 1-hour write is weighed at its own rate.
fn kind_weights(
    rec: &FocusRecord,
    kinds: &[(TokenKind, u64)],
    book: &tokenfuse_core::PriceBook,
) -> Vec<u128> {
    let usage = tokenfuse_core::Usage {
        input_tokens: rec.input_tokens,
        output_tokens: rec.output_tokens,
        cache_read_tokens: rec.cache_read_tokens.unwrap_or(0),
        cache_write_tokens: rec.cache_write_tokens.unwrap_or(0),
        cache_write_1h_tokens: rec.cache_write_1h_tokens.unwrap_or(0),
        ..Default::default()
    };
    let Some(p) = book.price_for(&rec.model, &usage) else {
        return kinds.iter().map(|(_, n)| *n as u128).collect();
    };
    let rate = |m: Microusd| m.0.max(0) as u128;
    let weights: Vec<u128> = kinds
        .iter()
        .map(|(kind, n)| {
            let n = *n as u128;
            match kind {
                TokenKind::InputUncached | TokenKind::InputUnknown => n * rate(p.input_per_mtok),
                TokenKind::InputRead => n * rate(p.cache_read_per_mtok),
                TokenKind::InputWrite => {
                    let one_hour = (usage.cache_write_1h_tokens as u128).min(n);
                    (n - one_hour) * rate(p.cache_write_per_mtok)
                        + one_hour * rate(p.cache_write_1h_per_mtok)
                }
                TokenKind::Output => n * rate(p.output_per_mtok),
            }
        })
        .collect();
    if weights.iter().all(|w| *w == 0) {
        kinds.iter().map(|(_, n)| *n as u128).collect()
    } else {
        weights
    }
}

/// Split `cost` across `weights` in whole microdollars so the parts sum to
/// `cost` exactly: each part is its floored share, and what flooring left over
/// goes to the heaviest part (the first, on a tie). The recorded cost of a call
/// is what the ledger charged; the split only says where it went, and must
/// never add or lose a microdollar. All weights zero puts the whole cost on
/// the first part.
fn allocate(cost: i64, weights: &[u128]) -> Vec<i64> {
    if weights.is_empty() {
        return Vec::new();
    }
    let total: u128 = weights.iter().sum();
    let mut parts: Vec<i64> = if total == 0 {
        vec![0; weights.len()]
    } else {
        weights
            .iter()
            .map(|w| ((cost as i128) * (*w as i128) / (total as i128)) as i64)
            .collect()
    };
    let heaviest = weights
        .iter()
        .enumerate()
        .fold(0, |best, (i, w)| if *w > weights[best] { i } else { best });
    let rest = cost - parts.iter().sum::<i64>();
    parts[heaviest] += rest;
    parts
}

/// Developer, family and version of a model, when its id says them plainly;
/// each `None` otherwise, and the export then leaves the key out rather than
/// guess. A vendor prefix (`openai/gpt-4.1`, `google/gemini-2.5-flash`) is
/// read past. Recognised shapes: `claude-<tier>-<major>[-<minor>]` and the
/// older `claude-<major>[-<minor>]-<tier>` (a trailing date is ignored),
/// `gpt-<version>[-<variant>]`, `gemini-<version>-<tier>`.
fn model_meta(model: &str) -> (Option<&'static str>, Option<String>, Option<String>) {
    let id = model
        .rsplit('/')
        .next()
        .unwrap_or(model)
        .to_ascii_lowercase();
    let developer = match provider_from_model(&id) {
        "Unknown" => None,
        d => Some(d),
    };
    let parts: Vec<&str> = id.split('-').filter(|p| !p.is_empty()).collect();
    let is_short_number = |p: &&str| p.len() <= 2 && p.chars().all(|c| c.is_ascii_digit());
    let is_date = |p: &&str| p.len() == 8 && p.chars().all(|c| c.is_ascii_digit());
    let cap = |w: &str| {
        let mut c = w.chars();
        c.next()
            .map(|f| f.to_ascii_uppercase().to_string() + c.as_str())
            .unwrap_or_default()
    };
    let (family, version) = match parts.as_slice() {
        ["claude", rest @ ..] => {
            let tiers = ["haiku", "sonnet", "opus"];
            let rest: Vec<&str> = rest.iter().copied().filter(|p| !is_date(p)).collect();
            match rest.as_slice() {
                [tier, nums @ ..]
                    if tiers.contains(tier)
                        && !nums.is_empty()
                        && nums.iter().all(is_short_number) =>
                {
                    (Some(format!("Claude {}", cap(tier))), Some(nums.join(".")))
                }
                [nums @ .., tier]
                    if tiers.contains(tier)
                        && !nums.is_empty()
                        && nums.iter().all(is_short_number) =>
                {
                    (Some(format!("Claude {}", cap(tier))), Some(nums.join(".")))
                }
                _ => (None, None),
            }
        }
        ["gpt", version, variant @ ..]
            if version.starts_with(|c: char| c.is_ascii_digit())
                && variant
                    .iter()
                    .all(|v| v.chars().all(|c| c.is_ascii_lowercase())) =>
        {
            let mut v = (*version).to_string();
            for w in variant {
                v.push('-');
                v.push_str(w);
            }
            (Some("GPT".to_string()), Some(v))
        }
        ["gemini", version, tier @ ..]
            if version.starts_with(|c: char| c.is_ascii_digit())
                && !tier.is_empty()
                && tier
                    .iter()
                    .all(|t| ["flash", "pro", "lite", "ultra", "nano"].contains(t)) =>
        {
            let tier: Vec<String> = tier.iter().map(|t| cap(t)).collect();
            (
                Some(format!("Gemini {}", tier.join("-"))),
                Some((*version).to_string()),
            )
        }
        _ => (None, None),
    };
    (developer, family, version)
}

/// `SkuPriceDetails` for one row: `ModelId` always (the id as the trace holds
/// it, which is the id the call was billed under), `ModelDeveloper`,
/// `ModelFamily`, `ModelVersion` when [`model_meta`] can read them, and the
/// token kind when the row is one.
fn sku_price_details(model: &str, kind: Option<TokenKind>) -> String {
    let mut m = serde_json::Map::new();
    m.insert("ModelId".into(), serde_json::Value::from(model));
    let (developer, family, version) = model_meta(model);
    if let Some(d) = developer {
        m.insert("ModelDeveloper".into(), serde_json::Value::from(d));
    }
    if let Some(f) = family {
        m.insert("ModelFamily".into(), serde_json::Value::from(f));
    }
    if let Some(v) = version {
        m.insert("ModelVersion".into(), serde_json::Value::from(v));
    }
    if let Some(k) = kind {
        m.insert(
            "TokenDirection".into(),
            serde_json::Value::from(k.direction()),
        );
        if let Some(a) = k.cache_action() {
            m.insert("TokenCacheAction".into(), serde_json::Value::from(a));
        }
    }
    serde_json::Value::Object(m).to_string()
}

/// `RequesterDetails`: a JSON array of the attributes this gateway records for
/// the principal and the credential, `{"Name", "Value"}` pairs, empty when
/// neither is known. The names are this gateway's own: the release candidate
/// fixes the column and its JSON-array shape, not the keys inside it. The
/// credential is named by its key id, never by anything that authenticates.
fn requester_details(principal: &str, credential: &str, unit: &str) -> String {
    if principal.is_empty() && credential.is_empty() {
        return String::new();
    }
    let pair = |n: &str, v: &str| serde_json::json!({"Name": n, "Value": v});
    let mut out = Vec::new();
    if !principal.is_empty() {
        out.push(pair("PrincipalType", "Agent"));
        out.push(pair("AgentId", principal));
    }
    if !credential.is_empty() {
        out.push(pair("CredentialType", "ClientKey"));
        out.push(pair("KeyId", credential));
    }
    if !unit.is_empty() {
        out.push(pair("Unit", unit));
    }
    serde_json::Value::Array(out).to_string()
}

/// Project one trace row into its `--spec 1.5` rows, in [`HEADER_1_5`] order.
///
/// An admitted call with token counts becomes one row per token kind: input
/// uncached, input cache read, input cache write, output, each with its count
/// in `ConsumedQuantity` (`ConsumedUnit` `Token`) and its share of the call's
/// recorded cost, weighed at the book's rates for that kind ([`allocate`]: the
/// shares sum to the recorded cost exactly). Reasoning tokens are output and
/// stay inside the output row's count, as FOCUS 1.5 says separately metered
/// reasoning is `Output`; `x_reasoning_tokens` names them there. Per-call
/// figures that would double if summed (`x_tool_calls`, `x_reasoning_tokens`)
/// ride the output row alone, `x_cache_write_1h_tokens` the write row alone.
/// Any other row (a refusal, a cache hit, a call settled on the estimate with
/// no counts) is one row with no quantity.
fn to_rows_1_5(rec: &FocusRecord, book: &tokenfuse_core::PriceBook) -> Vec<[String; 36]> {
    let blocked = is_blocked_decision(&rec.decision);
    let block_reason = if blocked {
        rec.decision.clone()
    } else {
        String::new()
    };
    let (resource, agent) = filed_under(rec);
    let (cost_microusd, cost_basis) = if blocked {
        (0i64, "blocked")
    } else if rec.input_tokens == 0 && rec.output_tokens == 0 && rec.cost_microusd != 0 {
        (rec.cost_microusd, "estimated")
    } else {
        (rec.cost_microusd, "settled")
    };
    let ts = ts_millis_to_rfc3339(rec.ts_millis);
    let provider = provider_from_model(&rec.model).to_string();
    let requester = requester_details(&agent, &rec.key_id, &rec.unit);

    let kinds = if blocked {
        Vec::new()
    } else {
        token_kinds(rec)
    };
    let shares = allocate(cost_microusd, &kind_weights(rec, &kinds, book));
    let mut slots: Vec<(Option<TokenKind>, Option<u64>, i64)> = kinds
        .iter()
        .zip(shares)
        .map(|((k, n), c)| (Some(*k), Some(*n), c))
        .collect();
    if slots.is_empty() {
        slots.push((None, None, cost_microusd));
    }
    let single = slots.len() == 1 && slots[0].0.is_none();

    slots
        .into_iter()
        .map(|(kind, quantity, cost)| {
            let billed = usd_string(cost);
            let on_output = single || kind == Some(TokenKind::Output);
            let description = match kind {
                Some(k) => format!("LLM call model={} {}", rec.model, k.label()),
                None => format!("LLM call model={}", rec.model),
            };
            [
                billed.clone(),                                            // BilledCost
                billed,                                                    // EffectiveCost
                "USD".to_string(),                                         // BillingCurrency
                ts.clone(),                                                // ChargePeriodStart
                ts.clone(),                                                // ChargePeriodEnd
                "Usage".to_string(),                                       // ChargeCategory
                description,                                               // ChargeDescription
                provider.clone(),                                          // ProviderName
                provider.clone(),                                          // PublisherName
                provider.clone(),                                          // InvoiceIssuerName
                "LLM inference".to_string(),                               // ServiceName
                "AI and Machine Learning".to_string(),                     // ServiceCategory
                resource.clone(),                                          // ResourceId
                resource.clone(),                                          // ResourceName
                rec.run_id.clone(),                                        // SubAccountId
                rec.run_id.clone(),                                        // SubAccountName
                count_field(quantity),                                     // ConsumedQuantity
                quantity.map(|_| "Token".to_string()).unwrap_or_default(), // ConsumedUnit
                sku_price_details(&rec.model, kind),                       // SkuPriceDetails
                agent.clone(),                                             // PrincipalId
                rec.key_id.clone(),                                        // CredentialId
                requester.clone(),                                         // RequesterDetails
                rec.run_id.clone(),                                        // x_run_id
                rec.parent_run_id.clone(),                                 // x_parent_run_id
                rec.model.clone(),                                         // x_model
                blocked.to_string(),                                       // x_blocked
                cost_basis.to_string(),                                    // x_cost_basis
                block_reason.clone(),                                      // x_block_reason
                rec.outcome.clone(),                                       // x_outcome
                rec.unit.clone(),                                          // x_unit
                if on_output {
                    rec.tool_calls.map(|n| n.to_string()).unwrap_or_default()
                } else {
                    String::new()
                }, // x_tool_calls
                rec.identity_reason.clone(),                               // x_identity_reason
                rec.price_basis.clone(),                                   // x_price_basis
                rec.pii_findings.clone(),                                  // x_pii_findings
                if on_output {
                    count_field(rec.reasoning_tokens)
                } else {
                    String::new()
                }, // x_reasoning_tokens
                if kind == Some(TokenKind::InputWrite) {
                    count_field(rec.cache_write_1h_tokens)
                } else {
                    String::new()
                }, // x_cache_write_1h_tokens
            ]
        })
        .collect()
}

fn render_csv_1_5(records: &[FocusRecord], book: &tokenfuse_core::PriceBook) -> String {
    let mut out = String::new();
    out.push_str(&csv_row(&HEADER_1_5));
    out.push('\n');
    for rec in records {
        for row in to_rows_1_5(rec, book) {
            out.push_str(&csv_row(&row));
            out.push('\n');
        }
    }
    out
}

/// Parse a minimal RFC 3339 UTC timestamp (`YYYY-MM-DDTHH:MM:SS[.fff]Z`) into
/// epoch milliseconds, for `--from`/`--to`. Deliberately narrow — no
/// non-`Z` timezone offsets — good enough for CLI filter flags without a
/// date-parsing dependency.
///
/// `pub(crate)` so `tokenfuse outcomes` ([`crate::outcomescli`]) can reuse the
/// exact same `--from`/`--to` parsing instead of duplicating it.
pub(crate) fn parse_rfc3339_millis(s: &str) -> Result<i64, String> {
    let s = s.trim();
    let bad = || format!("expected RFC3339 like 2026-01-02T15:04:05Z, got '{s}'");
    let body = s.strip_suffix('Z').ok_or_else(bad)?;
    let (date, time) = body.split_once('T').ok_or_else(bad)?;

    let mut dp = date.split('-');
    let y: i64 = dp.next().ok_or_else(bad)?.parse().map_err(|_| bad())?;
    let m: u32 = dp.next().ok_or_else(bad)?.parse().map_err(|_| bad())?;
    let d: u32 = dp.next().ok_or_else(bad)?.parse().map_err(|_| bad())?;
    if dp.next().is_some() || !(1..=12).contains(&m) || !(1..=31).contains(&d) {
        return Err(bad());
    }

    // Fractional seconds (if any) aren't needed at second precision.
    let time = time.split('.').next().unwrap_or(time);
    let mut tp = time.split(':');
    let hh: i64 = tp.next().ok_or_else(bad)?.parse().map_err(|_| bad())?;
    let mm: i64 = tp.next().ok_or_else(bad)?.parse().map_err(|_| bad())?;
    let ss: i64 = tp.next().ok_or_else(bad)?.parse().map_err(|_| bad())?;
    if tp.next().is_some()
        || !(0..24).contains(&hh)
        || !(0..60).contains(&mm)
        || !(0..60).contains(&ss)
    {
        return Err(bad());
    }

    let days = days_from_civil(y, m, d);
    Ok(days * 86_400_000 + hh * 3_600_000 + mm * 60_000 + ss * 1000)
}

/// One exported row, keyed by header name. Test-only: a consumer reads the
/// CSV by name, so the tests do too, and a column that does not exist is a
/// test failure naming it rather than an index out of range.
#[cfg(test)]
pub(crate) type ExportRow = std::collections::BTreeMap<String, String>;

/// The value of column `name` in `row`, failing the test by name when the
/// export has no such column.
#[cfg(test)]
pub(crate) fn col<'a>(row: &'a ExportRow, name: &str) -> &'a str {
    row.get(name)
        .map(String::as_str)
        .unwrap_or_else(|| panic!("the export has no {name} column"))
}

/// Read an export back: RFC 4180, the exact dialect [`csv_quote`] writes
/// (a field is quoted when it holds a comma, a quote, CR or LF; a quote
/// inside is doubled; each record ends in LF). Written out rather than taken
/// from a crate so that the reader is independent of the writer it checks.
#[cfg(test)]
pub(crate) fn parse_export_csv(text: &str) -> Vec<ExportRow> {
    let mut records: Vec<Vec<String>> = Vec::new();
    let mut record: Vec<String> = Vec::new();
    let mut field = String::new();
    let mut quoted = false;
    let mut chars = text.chars().peekable();
    while let Some(c) = chars.next() {
        if quoted {
            if c == '"' {
                if chars.peek() == Some(&'"') {
                    chars.next();
                    field.push('"');
                } else {
                    quoted = false;
                }
            } else {
                field.push(c);
            }
            continue;
        }
        match c {
            '"' if field.is_empty() => quoted = true,
            ',' => record.push(std::mem::take(&mut field)),
            '\n' => {
                record.push(std::mem::take(&mut field));
                records.push(std::mem::take(&mut record));
            }
            _ => field.push(c),
        }
    }
    assert!(!quoted, "the export ends inside a quoted field");
    assert!(
        field.is_empty() && record.is_empty(),
        "the export's last record is not terminated by a newline"
    );
    let mut it = records.into_iter();
    let header = it.next().expect("the export has a header line");
    it.map(|values| {
        assert_eq!(
            values.len(),
            header.len(),
            "a record has {} fields and the header {}: {values:?}",
            values.len(),
            header.len()
        );
        header.iter().cloned().zip(values).collect()
    })
    .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sink::{CallRecord, EventSink, ParquetSink};

    // -- CSV quoting -----------------------------------------------------

    #[test]
    fn csv_quote_leaves_plain_fields_bare() {
        assert_eq!(csv_quote("claude-sonnet"), "claude-sonnet");
        assert_eq!(csv_quote(""), "");
    }

    #[test]
    fn csv_quote_wraps_and_escapes_commas_and_quotes() {
        assert_eq!(csv_quote("a,b"), "\"a,b\"");
        assert_eq!(csv_quote("say \"hi\""), "\"say \"\"hi\"\"\"");
        assert_eq!(csv_quote("a, \"b\""), "\"a, \"\"b\"\"\"");
    }

    #[test]
    fn csv_quote_wraps_newlines() {
        assert_eq!(csv_quote("a\nb"), "\"a\nb\"");
        assert_eq!(csv_quote("a\rb"), "\"a\rb\"");
    }

    // -- provider inference ------------------------------------------------

    #[test]
    fn provider_from_model_recognizes_known_families() {
        assert_eq!(provider_from_model("claude-sonnet"), "Anthropic");
        assert_eq!(provider_from_model("claude-3-5-haiku"), "Anthropic");
        assert_eq!(provider_from_model("gpt-4o"), "OpenAI");
        assert_eq!(provider_from_model("o3-mini"), "OpenAI");
        assert_eq!(provider_from_model("gemini-1.5-pro"), "Google");
        assert_eq!(provider_from_model("llama-3-70b"), "Meta");
        assert_eq!(provider_from_model("mistral-large"), "Mistral AI");
        assert_eq!(provider_from_model("some-custom-model"), "Unknown");
    }

    // -- blocked-decision set ------------------------------------------------

    #[test]
    fn is_blocked_decision_matches_the_seven_breaker_reasons() {
        for d in [
            "budget_exceeded",
            "policy_violation",
            "loop_detected",
            "killed",
            "wasm_policy",
            "taint_blocked",
            "dlp_blocked",
        ] {
            assert!(is_blocked_decision(d), "{d} should be blocked");
        }
        assert!(!is_blocked_decision("allow"));
        assert!(!is_blocked_decision("cache_hit"));
    }

    // -- RFC 3339 timestamp round-trip ------------------------------------

    #[test]
    fn ts_millis_to_rfc3339_known_values() {
        assert_eq!(ts_millis_to_rfc3339(0), "1970-01-01T00:00:00Z");
        assert_eq!(ts_millis_to_rfc3339(1_000), "1970-01-01T00:00:01Z");
        assert_eq!(ts_millis_to_rfc3339(86_400_000), "1970-01-02T00:00:00Z");
        assert_eq!(
            ts_millis_to_rfc3339(1_704_067_200_000),
            "2024-01-01T00:00:00Z"
        );
        // Leap day.
        assert_eq!(
            ts_millis_to_rfc3339(1_709_208_000_000),
            "2024-02-29T12:00:00Z"
        );
    }

    #[test]
    fn parse_rfc3339_millis_known_values() {
        assert_eq!(parse_rfc3339_millis("1970-01-01T00:00:00Z"), Ok(0));
        assert_eq!(
            parse_rfc3339_millis("2024-01-01T00:00:00Z"),
            Ok(1_704_067_200_000)
        );
        assert_eq!(
            parse_rfc3339_millis("2024-02-29T12:00:00Z"),
            Ok(1_709_208_000_000)
        );
        // Fractional seconds are accepted and truncated.
        assert_eq!(
            parse_rfc3339_millis("2024-01-01T00:00:00.999Z"),
            Ok(1_704_067_200_000)
        );
    }

    #[test]
    fn parse_rfc3339_millis_rejects_malformed_input() {
        assert!(parse_rfc3339_millis("not-a-date").is_err());
        assert!(parse_rfc3339_millis("2024-01-01 00:00:00").is_err()); // no 'T'/'Z'
        assert!(parse_rfc3339_millis("2024-13-01T00:00:00Z").is_err()); // bad month
        assert!(parse_rfc3339_millis("2024-01-01T25:00:00Z").is_err()); // bad hour
    }

    #[test]
    fn rfc3339_round_trips_over_a_range_of_days() {
        use tokenfuse_core::timefmt::civil_from_days;
        // civil_from_days / days_from_civil must be exact inverses across a
        // span that includes multiple leap years and century boundaries.
        for days in -1000..1000 {
            let (y, m, d) = civil_from_days(days);
            assert_eq!(days_from_civil(y, m, d), days, "{y:04}-{m:02}-{d:02}");
        }
    }

    // -- golden end-to-end export -----------------------------------------

    #[allow(clippy::too_many_arguments)]
    fn rec(
        ts_millis: i64,
        run_id: &str,
        model: &str,
        decision: &str,
        input_tokens: u64,
        output_tokens: u64,
        cost_microusd: i64,
        agent_id: &str,
    ) -> CallRecord {
        rec_with_parent_and_outcome(
            ts_millis,
            run_id,
            model,
            decision,
            input_tokens,
            output_tokens,
            cost_microusd,
            agent_id,
            "",
            "",
            "",
            None,
        )
    }

    /// Like [`rec`], but also sets `parent_run_id` (P3), `outcome` (P4),
    /// `unit` (docs/20-identity-map.md), and `tool_calls` (I1,
    /// docs/21-tool-runs.md) - exercises `x_parent_run_id`, `x_outcome`,
    /// `x_unit`, and `x_tool_calls` sourcing together (see
    /// `exports_a_fixture_trace_to_the_exact_expected_csv`).
    #[allow(clippy::too_many_arguments)]
    fn rec_with_parent_and_outcome(
        ts_millis: i64,
        run_id: &str,
        model: &str,
        decision: &str,
        input_tokens: u64,
        output_tokens: u64,
        cost_microusd: i64,
        agent_id: &str,
        parent_run_id: &str,
        outcome: &str,
        unit: &str,
        tool_calls: Option<u32>,
    ) -> CallRecord {
        CallRecord {
            ts_millis,
            run_id: run_id.into(),
            model: model.into(),
            decision: decision.into(),
            input_tokens,
            output_tokens,
            cost_microusd,
            step: 1,
            agent_id: agent_id.into(),
            saved_microusd: 0,
            parent_run_id: parent_run_id.into(),
            on_behalf_of: String::new(),
            outcome: outcome.into(),
            key_id: String::new(),
            unit: unit.into(),
            tool_calls,
            tools_offered: None,
            tools_would_prune: None,
            pruned_schema_tokens_est: None,
            identity_reason: None,
            pii_findings: None,
            price_basis: None,
            cache_read_tokens: None,
            cache_write_tokens: None,
            cache_write_1h_tokens: None,
            reasoning_tokens: None,
        }
    }

    #[tokio::test]
    async fn exports_a_fixture_trace_to_the_exact_expected_csv() {
        let dir = std::env::temp_dir().join(format!("tf-focus-export-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let out = dir.join("focus.csv");

        {
            let sink = ParquetSink::new(&dir, 1).unwrap();
            // A: a normal settled allow (real parsed usage), WITH a parent run,
            // an outcome tag, a resolved unit, AND two observed tool calls -
            // exercises P3's x_parent_run_id sourcing, P4's x_outcome
            // sourcing, unit identity's x_unit sourcing, and I1's
            // x_tool_calls sourcing together.
            sink.record(rec_with_parent_and_outcome(
                0,
                "run-a",
                "claude-sonnet",
                "allow",
                100,
                50,
                345_000,
                "agent-1",
                "run-parent-a",
                "case_resolved",
                "treasury",
                Some(2),
            ));
            // B: SettleGuard-drop-without-complete edge case — allow, zero
            // tokens, non-zero cost (the reserved fallback) -> "estimated".
            sink.record(rec(1_000, "run-a", "gpt-4o", "allow", 0, 0, 1_000_000, ""));
            // C: a genuine $0 cache hit -> "settled", not "estimated".
            sink.record(rec(
                2_000,
                "run-b",
                "claude-haiku",
                "cache_hit",
                0,
                0,
                0,
                "agent-2",
            ));
            // D: a Breaker block, with a comma AND a quote in the model name
            // and a comma in the agent id, to exercise RFC 4180 quoting.
            sink.record(rec(
                3_000,
                "run-b",
                "claude-sonnet, pro\"tier",
                "budget_exceeded",
                0,
                0,
                250_000,
                "agent://team,ops",
            ));
        }

        let args = Args {
            traces: Some(dir.to_str().unwrap().to_string()),
            out: Some(out.to_str().unwrap().to_string()),
            from: None,
            to: None,
            spec: None,
        };
        run(&args).await.expect("export should succeed");

        let got = std::fs::read_to_string(&out).unwrap();
        let want = concat!(
            "BilledCost,EffectiveCost,BillingCurrency,ChargePeriodStart,ChargePeriodEnd,",
            "ChargeDescription,ProviderName,PublisherName,InvoiceIssuerName,ServiceName,",
            "ServiceCategory,ResourceId,ResourceName,SubAccountId,SubAccountName,x_run_id,",
            "x_parent_run_id,x_agent_id,x_model,x_tokens_in,x_tokens_out,x_blocked,x_cost_basis,",
            "x_outcome,x_unit,x_tool_calls,x_key_id,x_block_reason,x_identity_reason,x_price_basis,",
            "x_pii_findings,x_cache_read_tokens,x_cache_write_tokens,x_cache_write_1h_tokens,",
            "x_reasoning_tokens\n",
            "0.345000,0.345000,USD,1970-01-01T00:00:00Z,1970-01-01T00:00:00Z,",
            "LLM call model=claude-sonnet,Anthropic,Anthropic,Anthropic,LLM inference,",
            "AI and Machine Learning,agent-1,agent-1,run-a,run-a,run-a,run-parent-a,agent-1,",
            "claude-sonnet,100,50,false,settled,case_resolved,treasury,2,,,,,,,,,\n",
            "1.000000,1.000000,USD,1970-01-01T00:00:01Z,1970-01-01T00:00:01Z,",
            "LLM call model=gpt-4o,OpenAI,OpenAI,OpenAI,LLM inference,AI and Machine Learning,",
            ",,run-a,run-a,run-a,,,gpt-4o,0,0,false,estimated,,,,,,,,,,,,\n",
            "0.000000,0.000000,USD,1970-01-01T00:00:02Z,1970-01-01T00:00:02Z,",
            "LLM call model=claude-haiku,Anthropic,Anthropic,Anthropic,LLM inference,",
            "AI and Machine Learning,agent-2,agent-2,run-b,run-b,run-b,,agent-2,claude-haiku,",
            "0,0,false,settled,,,,,,,,,,,,\n",
            "0.000000,0.000000,USD,1970-01-01T00:00:03Z,1970-01-01T00:00:03Z,",
            "\"LLM call model=claude-sonnet, pro\"\"tier\",Anthropic,Anthropic,Anthropic,",
            "LLM inference,AI and Machine Learning,\"agent://team,ops\",\"agent://team,ops\",",
            "run-b,run-b,run-b,,\"agent://team,ops\",\"claude-sonnet, pro\"\"tier\",0,0,true,",
            "blocked,,,,,budget_exceeded,,,,,,,\n",
        );
        assert_eq!(got, want);

        std::fs::remove_dir_all(&dir).ok();
    }

    #[tokio::test]
    async fn from_to_window_filters_rows() {
        let dir =
            std::env::temp_dir().join(format!("tf-focus-export-window-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let out = dir.join("focus.csv");

        {
            let sink = ParquetSink::new(&dir, 1).unwrap();
            sink.record(rec(0, "run-a", "m", "allow", 1, 1, 1_000, ""));
            sink.record(rec(10_000, "run-b", "m", "allow", 1, 1, 1_000, ""));
        }

        let args = Args {
            traces: Some(dir.to_str().unwrap().to_string()),
            out: Some(out.to_str().unwrap().to_string()),
            from: Some("1970-01-01T00:00:05Z".to_string()),
            to: None,
            spec: None,
        };
        run(&args).await.expect("export should succeed");
        let got = std::fs::read_to_string(&out).unwrap();
        assert_eq!(got.lines().count(), 2); // header + run-b only
        assert!(got.contains("run-b"));
        assert!(!got.contains("run-a"));

        std::fs::remove_dir_all(&dir).ok();
    }

    #[tokio::test]
    async fn missing_traces_dir_is_a_clear_error_not_a_panic() {
        let args = Args {
            traces: Some("/nonexistent/tf-focus-export-dir-xyz".to_string()),
            out: Some("/tmp/should-not-be-written.csv".to_string()),
            from: None,
            to: None,
            spec: None,
        };
        let err = run(&args).await.unwrap_err();
        assert!(err.contains("nonexistent"), "{err}");
    }

    // -- who a row is filed under (invariant 81) ------------------------------

    /// A trace row as the gateway writes it, with the credential it was made
    /// with. `step`, `saved_microusd` and the shadow-pruning columns do not
    /// reach the export and are left at their defaults.
    fn keyed(
        ts_millis: i64,
        run_id: &str,
        decision: &str,
        agent_id: &str,
        key_id: &str,
        unit: &str,
    ) -> CallRecord {
        let mut r = rec_with_parent_and_outcome(
            ts_millis,
            run_id,
            "gpt-4o-mini",
            decision,
            0,
            0,
            0,
            agent_id,
            "",
            "",
            unit,
            None,
        );
        r.key_id = key_id.into();
        r
    }

    /// Write `records` to a fresh trace directory, export it, and read the
    /// CSV back as rows keyed by header name, in export order.
    async fn export_rows(tag: &str, records: Vec<CallRecord>) -> Vec<ExportRow> {
        let dir =
            std::env::temp_dir().join(format!("tf-focus-export-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let out = dir.join("focus.csv");
        {
            let sink = ParquetSink::new(&dir, 1).unwrap();
            for r in records {
                sink.record(r);
            }
        }
        let args = Args {
            traces: Some(dir.to_str().unwrap().to_string()),
            out: Some(out.to_str().unwrap().to_string()),
            from: None,
            to: None,
            spec: None,
        };
        run(&args).await.expect("export should succeed");
        let text = std::fs::read_to_string(&out).unwrap();
        std::fs::remove_dir_all(&dir).ok();
        parse_export_csv(&text)
    }

    /// The R6 run of 2026-10-07, reduced to its two rows: a key bound to its
    /// own agent presents another agent's id, strict identity refuses it,
    /// and the trace row carries the CLAIMED id in `agent_id` (the header)
    /// beside the credential that really called in `key_id`. The export
    /// used to file the refusal under the claimed agent, so a downstream
    /// console showed the victim with blocked calls it never made.
    #[tokio::test]
    async fn an_identity_refused_row_is_filed_under_the_credential_not_the_claim() {
        let rows = export_rows(
            "identity-refused",
            vec![
                keyed(
                    0,
                    "run-flint",
                    "allow",
                    "agent://taipanbox.dev/routers/flint",
                    "flint-key",
                    "routers",
                ),
                keyed(
                    1_000,
                    "run-imposter",
                    "identity_mismatch",
                    "agent://taipanbox.dev/routers/flint",
                    "forge-imposter",
                    "forge",
                ),
            ],
        )
        .await;
        assert_eq!(rows.len(), 2);

        let refused = &rows[1];
        assert_eq!(col(refused, "x_run_id"), "run-imposter");
        assert_eq!(col(refused, "ResourceId"), "key:forge-imposter");
        assert_eq!(col(refused, "ResourceName"), "key:forge-imposter");
        assert_eq!(
            col(refused, "x_agent_id"),
            "",
            "an agent id the gateway refused as unauthenticated is not reported as the caller"
        );
        assert_eq!(col(refused, "x_key_id"), "forge-imposter");
        assert_eq!(col(refused, "x_block_reason"), "identity_mismatch");
        assert_eq!(col(refused, "x_blocked"), "true");
        assert_eq!(col(refused, "BilledCost"), "0.000000");
        for (name, value) in refused {
            assert!(
                !value.contains("routers/flint"),
                "the refused row still names the agent it claimed to be, in {name}: {value}"
            );
        }

        // The honest call by the real agent is untouched.
        let honest = &rows[0];
        assert_eq!(
            col(honest, "ResourceId"),
            "agent://taipanbox.dev/routers/flint"
        );
        assert_eq!(
            col(honest, "x_agent_id"),
            "agent://taipanbox.dev/routers/flint"
        );
        assert_eq!(col(honest, "x_key_id"), "flint-key");
        assert_eq!(col(honest, "x_block_reason"), "");
    }

    /// A gateway with no client keys has no credential to name: `key_id` is
    /// empty on every row. A refusal for identity there (a header that
    /// contradicts a proven delegation chain) is still not filed under the
    /// claimed agent; it is filed under nobody, which a consumer can see,
    /// rather than under somebody, which it cannot tell from the truth.
    #[tokio::test]
    async fn an_identity_refused_row_with_no_credential_names_no_resource() {
        let rows = export_rows(
            "identity-refused-keyless",
            vec![keyed(
                0,
                "run-x",
                "identity_mismatch",
                "agent://acme/victim",
                "",
                "",
            )],
        )
        .await;
        assert_eq!(rows.len(), 1);
        assert_eq!(col(&rows[0], "ResourceId"), "");
        assert_eq!(col(&rows[0], "ResourceName"), "");
        assert_eq!(col(&rows[0], "x_agent_id"), "");
        assert_eq!(col(&rows[0], "x_key_id"), "");
        assert_eq!(col(&rows[0], "x_block_reason"), "identity_mismatch");
    }

    #[tokio::test]
    async fn every_row_carries_the_key_it_was_made_with() {
        let rows = export_rows(
            "key-id",
            vec![
                keyed(0, "run-1", "allow", "agent://acme/a", "key-a", "u"),
                keyed(1_000, "run-2", "cache_hit", "agent://acme/b", "key-b", "u"),
                keyed(
                    2_000,
                    "run-3",
                    "budget_exceeded",
                    "agent://acme/c",
                    "key-c",
                    "u",
                ),
                keyed(3_000, "run-4", "allow", "agent://acme/d", "", ""),
            ],
        )
        .await;
        let keys: Vec<&str> = rows.iter().map(|r| col(r, "x_key_id")).collect();
        assert_eq!(keys, ["key-a", "key-b", "key-c", ""]);
        // Only an identity refusal moves the resource; a budget block by an
        // authenticated caller stays filed under its agent.
        assert_eq!(col(&rows[2], "ResourceId"), "agent://acme/c");
        assert_eq!(col(&rows[2], "x_agent_id"), "agent://acme/c");
    }

    /// Every one of the nine Breaker reasons is named on its row; an allowed
    /// call, a cache hit and a policy plane's own refusal (which is not a
    /// Breaker block, `x_blocked` false) name none, so the column is
    /// non-empty exactly when `x_blocked` is true.
    #[tokio::test]
    async fn a_blocked_row_names_its_reason_and_any_other_row_names_none() {
        let reasons = [
            "budget_exceeded",
            "policy_violation",
            "loop_detected",
            "killed",
            "wasm_policy",
            "taint_blocked",
            "dlp_blocked",
            "unit_budget_exceeded",
            "identity_mismatch",
        ];
        let others = ["allow", "cache_hit", "wardryx_deny", "wardryx_hold"];
        let mut records = Vec::new();
        for (i, d) in reasons.iter().chain(others.iter()).enumerate() {
            records.push(keyed(
                i as i64 * 1_000,
                &format!("run-{i:02}"),
                d,
                "agent://acme/a",
                "key-a",
                "u",
            ));
        }
        let rows = export_rows("block-reason", records).await;
        assert_eq!(rows.len(), reasons.len() + others.len());
        for (i, d) in reasons.iter().enumerate() {
            assert_eq!(col(&rows[i], "x_block_reason"), *d, "row for {d}");
            assert_eq!(col(&rows[i], "x_blocked"), "true", "row for {d}");
        }
        for (j, d) in others.iter().enumerate() {
            let row = &rows[reasons.len() + j];
            assert_eq!(col(row, "x_block_reason"), "", "row for {d}");
            assert_eq!(col(row, "x_blocked"), "false", "row for {d}");
        }
    }

    /// A control, not a red-first test: a trace segment written before the
    /// gateway recorded `key_id` (12 columns) still exports beside a current
    /// one, with the key empty and every row present. The column is read
    /// through `COALESCE`, the rule every appended column already follows
    /// (invariant 6).
    #[tokio::test]
    async fn a_trace_written_before_key_id_existed_still_exports() {
        use datafusion::arrow::array::{Int64Array, StringArray, UInt32Array, UInt64Array};
        use datafusion::arrow::datatypes::{DataType, Field, Schema};
        use datafusion::arrow::record_batch::RecordBatch;
        use datafusion::parquet::arrow::ArrowWriter;
        use std::sync::Arc;

        let dir =
            std::env::temp_dir().join(format!("tf-focus-export-pre-key-id-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let out = dir.join("focus.csv");

        let old = Arc::new(Schema::new(vec![
            Field::new("ts_millis", DataType::Int64, false),
            Field::new("run_id", DataType::Utf8, false),
            Field::new("model", DataType::Utf8, false),
            Field::new("decision", DataType::Utf8, false),
            Field::new("input_tokens", DataType::UInt64, false),
            Field::new("output_tokens", DataType::UInt64, false),
            Field::new("cost_microusd", DataType::Int64, false),
            Field::new("step", DataType::UInt32, false),
            Field::new("agent_id", DataType::Utf8, false),
            Field::new("saved_microusd", DataType::Int64, false),
            Field::new("parent_run_id", DataType::Utf8, false),
            Field::new("on_behalf_of", DataType::Utf8, false),
        ]));
        let batch = RecordBatch::try_new(
            old.clone(),
            vec![
                Arc::new(Int64Array::from(vec![0i64])),
                Arc::new(StringArray::from(vec!["run-old"])),
                Arc::new(StringArray::from(vec!["claude-sonnet"])),
                Arc::new(StringArray::from(vec!["allow"])),
                Arc::new(UInt64Array::from(vec![10u64])),
                Arc::new(UInt64Array::from(vec![5u64])),
                Arc::new(Int64Array::from(vec![105i64])),
                Arc::new(UInt32Array::from(vec![1u32])),
                Arc::new(StringArray::from(vec!["agent://acme/old"])),
                Arc::new(Int64Array::from(vec![0i64])),
                Arc::new(StringArray::from(vec![""])),
                Arc::new(StringArray::from(vec![""])),
            ],
        )
        .unwrap();
        {
            let file = std::fs::File::create(dir.join("calls-pre-key-id.parquet")).unwrap();
            let mut w = ArrowWriter::try_new(file, old, None).unwrap();
            w.write(&batch).unwrap();
            w.close().unwrap();
        }
        {
            let sink = ParquetSink::new(&dir, 1).unwrap();
            sink.record(keyed(
                1_000,
                "run-new",
                "allow",
                "agent://acme/new",
                "key-n",
                "u",
            ));
        }

        let args = Args {
            traces: Some(dir.to_str().unwrap().to_string()),
            out: Some(out.to_str().unwrap().to_string()),
            from: None,
            to: None,
            spec: None,
        };
        run(&args)
            .await
            .expect("a directory mixing pre-key_id and current segments must export");
        let rows = parse_export_csv(&std::fs::read_to_string(&out).unwrap());
        std::fs::remove_dir_all(&dir).ok();

        assert_eq!(rows.len(), 2);
        assert_eq!(col(&rows[0], "x_run_id"), "run-old");
        assert_eq!(col(&rows[0], "ResourceId"), "agent://acme/old");
        assert_eq!(
            rows[0].get("x_key_id").map(String::as_str).unwrap_or(""),
            ""
        );
        assert_eq!(col(&rows[1], "x_run_id"), "run-new");
    }

    /// 200 seeded rows refused for identity, each with a claimed agent id
    /// and a key id drawn from an alphabet of CSV-hostile characters (comma,
    /// quote, CR, LF, a non-ASCII letter). Every row must round-trip through
    /// the CSV, carry its own key in `x_key_id`, and never put the claim in
    /// `ResourceId`, `ResourceName` or `x_agent_id`.
    #[tokio::test]
    async fn hostile_claims_and_keys_never_reach_the_resource_columns() {
        const ALPHABET: &[&str] = &[
            "a", "Z", "0", ",", "\"", "\n", "\r", " ", "\u{e9}", "/", ":", "-",
        ];
        let mut state: u64 = 0x9e37_79b9_7f4a_7c15;
        let mut next = move || {
            state = state
                .wrapping_mul(6_364_136_223_846_793_005)
                .wrapping_add(1_442_695_040_888_963_407);
            state >> 33
        };
        let mut want = Vec::new();
        let mut records = Vec::new();
        for seed in 0..200usize {
            let claim_len = 1 + next() % 12;
            let claim_tail: String = (0..claim_len)
                .map(|_| ALPHABET[(next() as usize) % ALPHABET.len()])
                .collect();
            let claim = format!("agent://victim/{claim_tail}");
            // Every fourth row has no credential at all.
            let key = if seed % 4 == 0 {
                String::new()
            } else {
                let key_len = next() % 10;
                let tail: String = (0..key_len)
                    .map(|_| ALPHABET[(next() as usize) % ALPHABET.len()])
                    .collect();
                format!("k{tail}")
            };
            let run_id = format!("run-{seed:03}");
            records.push(keyed(
                seed as i64,
                &run_id,
                "identity_mismatch",
                &claim,
                &key,
                "",
            ));
            want.push((run_id, claim, key));
        }
        let rows = export_rows("hostile", records).await;
        assert_eq!(rows.len(), want.len());
        for (row, (run_id, claim, key)) in rows.iter().zip(&want) {
            assert_eq!(col(row, "x_run_id"), run_id.as_str());
            assert_eq!(col(row, "x_key_id"), key.as_str(), "{run_id}");
            let resource = if key.is_empty() {
                String::new()
            } else {
                format!("key:{key}")
            };
            assert_eq!(col(row, "ResourceId"), resource, "{run_id}");
            assert_eq!(col(row, "ResourceName"), resource, "{run_id}");
            assert_eq!(col(row, "x_agent_id"), "", "{run_id}");
            for name in ["ResourceId", "ResourceName", "x_agent_id"] {
                assert_ne!(col(row, name), claim.as_str(), "{run_id}: {name}");
            }
        }
    }

    // -- FOCUS 1.5 (invariant 148) ---------------------------------------------

    fn focus_record(model: &str, decision: &str) -> FocusRecord {
        FocusRecord {
            ts_millis: 0,
            run_id: "run-1".into(),
            model: model.into(),
            decision: decision.into(),
            input_tokens: 0,
            output_tokens: 0,
            cost_microusd: 0,
            agent_id: String::new(),
            parent_run_id: String::new(),
            outcome: String::new(),
            unit: String::new(),
            tool_calls: None,
            key_id: String::new(),
            identity_reason: String::new(),
            price_basis: String::new(),
            pii_findings: String::new(),
            cache_read_tokens: None,
            cache_write_tokens: None,
            cache_write_1h_tokens: None,
            reasoning_tokens: None,
        }
    }

    fn header_index(name: &str) -> usize {
        HEADER_1_5
            .iter()
            .position(|h| *h == name)
            .unwrap_or_else(|| panic!("no {name} in HEADER_1_5"))
    }

    /// The parts always sum to the whole, whatever the weights, over 200
    /// seeded draws: the split says where the cost went and never adds or
    /// loses a microdollar. The remainder goes to the heaviest part.
    #[test]
    fn the_split_always_sums_to_the_recorded_cost() {
        assert_eq!(allocate(1552, &[4_200_000, 1_547_500_000]), vec![4, 1548]);
        assert_eq!(allocate(10, &[1, 1, 1]), vec![4, 3, 3]);
        assert_eq!(allocate(7, &[0, 0]), vec![7, 0]);
        assert_eq!(allocate(0, &[5, 9]), vec![0, 0]);
        assert!(allocate(5, &[]).is_empty());
        let mut state: u64 = 0x2545_f491_4f6c_dd1d;
        let mut next = move || {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            state
        };
        for _ in 0..200 {
            let n = 1 + (next() % 4) as usize;
            let weights: Vec<u128> = (0..n).map(|_| (next() % 1_000_000_000) as u128).collect();
            let cost = (next() % 100_000_000) as i64;
            let parts = allocate(cost, &weights);
            assert_eq!(parts.iter().sum::<i64>(), cost, "{weights:?} {cost}");
            assert!(parts.iter().all(|p| *p >= 0), "{parts:?}");
        }
    }

    #[test]
    fn the_model_id_gives_developer_family_and_version_only_when_it_says_them() {
        let m = |id: &str| {
            let (d, f, v) = model_meta(id);
            (d, f.as_deref().map(str::to_string), v)
        };
        let some = |s: &str| Some(s.to_string());
        assert_eq!(
            m("claude-haiku-4-5"),
            (Some("Anthropic"), some("Claude Haiku"), some("4.5"))
        );
        assert_eq!(
            m("claude-haiku-4-5-20251001"),
            (Some("Anthropic"), some("Claude Haiku"), some("4.5"))
        );
        assert_eq!(
            m("claude-sonnet-5"),
            (Some("Anthropic"), some("Claude Sonnet"), some("5"))
        );
        assert_eq!(
            m("claude-3-5-sonnet-20241022"),
            (Some("Anthropic"), some("Claude Sonnet"), some("3.5"))
        );
        assert_eq!(m("gpt-4o"), (Some("OpenAI"), some("GPT"), some("4o")));
        assert_eq!(
            m("openai/gpt-4.1-mini"),
            (Some("OpenAI"), some("GPT"), some("4.1-mini"))
        );
        assert_eq!(
            m("google/gemini-2.5-flash-lite"),
            (Some("Google"), some("Gemini Flash-Lite"), some("2.5"))
        );
        // Recognised developer, unrecognised shape: the developer alone.
        assert_eq!(m("gemini-3.1-pro-preview"), (Some("Google"), None, None));
        assert_eq!(
            m("global.anthropic.claude-haiku-4-5-20251001-v1:0").0,
            Some("Anthropic")
        );
        // Nothing recognised: nothing guessed.
        assert_eq!(m("mystery-model-1"), (None, None, None));
    }

    /// A row refused for identity names its credential and no principal, and
    /// the credential is the key id the trace holds, never anything that
    /// authenticates. A blocked row is one row with no quantity.
    #[test]
    fn principal_and_credential_come_from_the_agent_and_the_key_id() {
        let book = crate::pricebook::default_price_book();
        let mut honest = focus_record("claude-haiku-4-5", "allow");
        honest.agent_id = "agent://acme/a".into();
        honest.key_id = "key-a".into();
        honest.unit = "treasury".into();
        honest.input_tokens = 10;
        honest.output_tokens = 20;
        honest.cost_microusd = 110;
        honest.cache_read_tokens = Some(0);
        honest.cache_write_tokens = Some(0);
        honest.cache_write_1h_tokens = Some(0);
        let rows = to_rows_1_5(&honest, &book);
        assert_eq!(
            rows.len(),
            2,
            "input and output; zero cache counts make no rows"
        );
        for r in &rows {
            assert_eq!(r[header_index("PrincipalId")], "agent://acme/a");
            assert_eq!(r[header_index("CredentialId")], "key-a");
            let details: serde_json::Value =
                serde_json::from_str(&r[header_index("RequesterDetails")]).unwrap();
            assert_eq!(
                details,
                serde_json::json!([
                    {"Name": "PrincipalType", "Value": "Agent"},
                    {"Name": "AgentId", "Value": "agent://acme/a"},
                    {"Name": "CredentialType", "Value": "ClientKey"},
                    {"Name": "KeyId", "Value": "key-a"},
                    {"Name": "Unit", "Value": "treasury"},
                ])
            );
        }

        let mut refused = focus_record("claude-haiku-4-5", "identity_mismatch");
        refused.agent_id = "agent://acme/victim".into();
        refused.key_id = "key-imposter".into();
        let rows = to_rows_1_5(&refused, &book);
        assert_eq!(rows.len(), 1);
        let r = &rows[0];
        assert_eq!(r[header_index("PrincipalId")], "");
        assert_eq!(r[header_index("CredentialId")], "key-imposter");
        assert_eq!(r[header_index("ConsumedQuantity")], "");
        assert_eq!(r[header_index("ConsumedUnit")], "");
        assert_eq!(r[header_index("BilledCost")], "0.000000");
        assert!(
            !r.iter().any(|v| v.contains("victim")),
            "the claimed agent appears nowhere: {r:?}"
        );

        let nobody = focus_record("claude-haiku-4-5", "allow");
        assert_eq!(
            to_rows_1_5(&nobody, &book)[0][header_index("RequesterDetails")],
            ""
        );
    }

    #[test]
    fn spec_names_the_two_shapes_and_refuses_anything_else() {
        assert_eq!(spec_of(None), Ok(Spec::Default));
        assert_eq!(spec_of(Some("1.2")), Ok(Spec::Default));
        assert_eq!(spec_of(Some("1.5")), Ok(Spec::Focus15));
        assert!(spec_of(Some("1.4")).unwrap_err().contains("--spec"));
        assert!(spec_of(Some("")).is_err());
        let a = parse_args(&["--spec".to_string(), "1.5".to_string()]);
        assert_eq!(a.spec.as_deref(), Some("1.5"));
    }

    #[test]
    fn parse_args_reads_all_flags() {
        let args = vec![
            "--traces".to_string(),
            "./data".to_string(),
            "--out".to_string(),
            "focus.csv".to_string(),
            "--from".to_string(),
            "2026-01-01T00:00:00Z".to_string(),
            "--to".to_string(),
            "2026-02-01T00:00:00Z".to_string(),
        ];
        let a = parse_args(&args);
        assert_eq!(a.traces.as_deref(), Some("./data"));
        assert_eq!(a.out.as_deref(), Some("focus.csv"));
        assert_eq!(a.from.as_deref(), Some("2026-01-01T00:00:00Z"));
        assert_eq!(a.to.as_deref(), Some("2026-02-01T00:00:00Z"));
    }
}
