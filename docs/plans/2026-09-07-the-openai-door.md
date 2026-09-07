# The OpenAI door: implementation plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Serve `POST /v1/chat/completions` from the same gateway and the same
enforcement pipeline as `/v1/messages`, against an upstream that speaks the
OpenAI wire.

**Architecture:** The wire shape becomes an explicit value (`Wire`) carried on
`AppState` and passed into one shared handler, so the enforcement path is
parameterised rather than copied. A process serves the door that matches its
upstream and refuses the other one loudly. No translation between shapes.

**Tech Stack:** Rust 2021, axum 0.8, serde_json, tokio. Tests are `#[test]` /
`#[tokio::test]` inside `crates/gateway/src/*.rs` plus integration tests in
`crates/gateway/tests/*.rs`.

**Design:** `docs/26-the-openai-door.md`. Read it first; it carries the
provider facts this plan assumes and the reasons for each decision.

## Global constraints

- **Tier T3.** Every new test is run against the unbuilt code first and must go
  red there. Mutation testing of the product code is required (Task 9).
- **Invariant 2 is untouched.** `breaker_error_response_matches_budget_error_byte_for_byte`
  (`crates/gateway/src/proxy.rs`) must never be modified, parameterised, moved
  or deleted. It is the proof the Anthropic door did not move.
- **No long em dashes** in any prose this plan adds (README, docs, comments are
  code and exempt, but the README is read by strangers: use a hyphen).
- **No competitor names** in README or any public copy.
- **`cargo fmt --all`, `cargo build`, `cargo test --all`, `cargo clippy
  --all-targets -- -D warnings`** before every commit. CI has a fmt gate.
- **One branch for the whole feature, one commit per task, one PR at the end.**
  `main` has nine required checks and direct pushes are blocked, so nine PRs
  would mean nine full CI runs for one feature. Each task still ends in its own
  commit and its own review, so the PR is readable commit by commit. Do not
  merge on red. (`@claude` 2026-09-07: this supersedes the earlier
  "one task, one PR" line, which collided with how this plan is executed.)
- Commit trailer: `Co-Authored-By: Claude Opus 5 <noreply@anthropic.com>`.
- Nothing metered is enabled anywhere in this work.

---

### Task 0: the money arithmetic stops wrapping

**Files:**
- Modify: `crates/core/src/pricing.rs` (`ModelPrice::cost`)
- Test: `crates/core/src/pricing.rs` (its own `#[cfg(test)] mod tests`)
- Test: `crates/gateway/tests/the_estimate_never_goes_negative.rs` (new)

**Interfaces:**
- Consumes: nothing.
- Produces: no signature change. `ModelPrice::cost(&self, usage: &Usage) -> Microusd` keeps its shape and stops returning a negative or panicking.

**Why this task exists, and it is not part of the OpenAI feature.** Found while
writing Task 2, and measured on commit `5413147`, whose only difference from
`main` is a module nothing calls:

`part()` multiplies in `i128` and then casts with `as i64`, which truncates
rather than saturating, and the four `part()` results are then added with a
plain `+`. Measured on a $15/Mtok model: correct to 1e17 output tokens,
**negative at 1e18** (`-3446744073709551616` micro-usd). Some magnitudes panic
instead, `attempt to add with overflow` at `pricing.rs:55`, which is a debug
build refusing to wrap; a release build wraps silently.

Measured through the live gateway, `$0.01` per-run budget, enforce mode:

| `max_tokens` | status | forwarded upstream |
|---|---|---|
| 1 000 | 402 | no |
| 1 000 000 | 402 | no |
| 1 000 000 000 000 | 402 | no |
| 18 446 744 073 709 551 615 | **200** | **yes** |

A larger ask passes where a smaller one is refused, on today's `/v1/messages`,
through an ordinary request-body field.

**Measured and NOT true, so nobody re-derives it:** this does not inflate the
budget for later calls. An honest 1M-token call is still refused after a
poisoned one has gone through. The bypass is one call, not a lasting credit.

**Why it blocks the feature.** Today the wrap needs an absurd `max_tokens` that
the provider would reject anyway. Once `n` multiplies the output estimate
(Task 2), the product `n * max_tokens` reaches the same zone from two
individually ordinary-looking numbers. The feature widens the reachable input,
so the arithmetic is fixed first.

- [ ] **Step 1: Write the failing unit tests**

Add to `crates/core/src/pricing.rs`'s `mod tests`:

```rust
#[test]
fn a_cost_is_never_negative_however_many_tokens_are_claimed() {
    let p = sonnet();
    for tokens in [1e17 as u64, 1e18 as u64, u64::MAX / 2, u64::MAX] {
        let usage = Usage { output_tokens: tokens, ..Default::default() };
        let c = p.cost(&usage);
        assert!(
            c.0 >= 0,
            "output_tokens={tokens} priced at {} micro-usd: a negative cost              passes every budget check there is",
            c.0
        );
    }
}

#[test]
fn an_unpayable_request_saturates_at_the_top_rather_than_wrapping_to_the_bottom() {
    let p = sonnet();
    let huge = Usage { output_tokens: u64::MAX, ..Default::default() };
    let ordinary = Usage { output_tokens: 1_000_000, ..Default::default() };
    assert!(
        p.cost(&huge).0 > p.cost(&ordinary).0,
        "the most expensive request must not be the cheapest"
    );
    assert_eq!(p.cost(&huge).0, i64::MAX, "saturating, not merely non-negative");
}

#[test]
fn every_token_field_saturates_and_the_sum_of_four_maxima_does_not_wrap() {
    let p = sonnet();
    let all = Usage {
        input_tokens: u64::MAX,
        output_tokens: u64::MAX,
        cache_read_tokens: u64::MAX,
        cache_write_tokens: u64::MAX,
    };
    assert_eq!(p.cost(&all).0, i64::MAX);
}

#[test]
fn ordinary_prices_are_exactly_what_they_always_were() {
    // The fix must not move a single real figure. These are the numbers the
    // existing tests in this module already assert, restated here so a future
    // saturating-arithmetic change cannot quietly round them.
    let p = sonnet();
    let u = Usage { input_tokens: 1_000_000, output_tokens: 1_000_000, ..Default::default() };
    assert_eq!(p.cost(&u).0, 3_000_000 + 15_000_000);
}
```

`sonnet()` and `Usage`'s field names already exist in that module; read them
rather than trusting the names above, and adjust only the spelling if they
differ.

- [ ] **Step 2: Run them and record the failures verbatim**

Run: `cargo test -p tokenfuse-core --lib pricing`
Expected: `a_cost_is_never_negative_...` fails on the 1e18 case, and
`an_unpayable_request_saturates...` fails or panics with
`attempt to add with overflow`. Paste exactly what the runner printed,
including which case failed first. Do not paraphrase.

- [ ] **Step 3: Write the failing end-to-end test**

Create `crates/gateway/tests/the_estimate_never_goes_negative.rs`. Copy the
harness shape from `crates/gateway/tests/require_run_id.rs`: its
`CountingProvider`, its `state()` builder and its `Request::post` pattern. Set
`budget_per_run: Some(Microusd(10_000))` (one cent) and `Mode::Enforce`.

```rust
/// A bigger ask must never pass where a smaller one is refused.
///
/// Measured before the fix, on this exact harness: max_tokens of 1e3, 1e6 and
/// 1e12 were all refused with 402 and never forwarded, and u64::MAX returned
/// 200 and WAS forwarded, because the estimate had wrapped negative.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_absurd_output_cap_is_refused_like_every_smaller_one() {
    for max_tokens in ["1000", "1000000", "1000000000000", "18446744073709551615"] {
        let provider = CountingProvider::default();
        let app = tokenfuse_gateway::app(state(provider.clone()));
        let resp = app
            .oneshot(
                Request::post("/v1/messages")
                    .header("x-fuse-run-id", format!("r-{max_tokens}"))
                    .body(Body::from(format!(
                        r#"{{"model":"test-model","max_tokens":{max_tokens},"messages":[{{"role":"user","content":"hi"}}]}}"#
                    )))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(
            resp.status(),
            StatusCode::PAYMENT_REQUIRED,
            "max_tokens={max_tokens} was not refused on a one-cent budget"
        );
        assert_eq!(
            provider.calls.load(Ordering::SeqCst),
            0,
            "max_tokens={max_tokens} reached the provider after a refusal was due"
        );
    }
}
```

- [ ] **Step 4: Run it and record the failure verbatim**

Run: `cargo test -p tokenfuse-gateway --test the_estimate_never_goes_negative`
Expected: FAIL on the `18446744073709551615` case, asserting 200 where 402 was
due. Paste what the runner printed.

- [ ] **Step 5: Fix the arithmetic**

In `crates/core/src/pricing.rs`, replace the body of `cost`:

```rust
    /// Price a usage record. Saturating throughout: an absurd token count
    /// prices at the ceiling, never at a negative or a wrapped-small figure.
    ///
    /// The direction matters and is not symmetric. Over-charging an impossible
    /// request refuses it, which is the safe answer for a request nobody can
    /// pay for. Under-charging it serves it, and a negative cost passes every
    /// budget check there is: measured on 2026-09-07, `output_tokens = 1e18`
    /// priced at -3446744073709551616 micro-usd and the gateway forwarded a
    /// call it should have refused. Same reasoning as ADR-8's fallback price.
    pub fn cost(&self, usage: &Usage) -> Microusd {
        let part = |tokens: u64, price: Microusd| -> i64 {
            let micros = (tokens as i128)
                .saturating_mul(price.0 as i128)
                / 1_000_000;
            micros.clamp(0, i64::MAX as i128) as i64
        };
        Microusd(
            part(usage.input_tokens, self.input_per_mtok)
                .saturating_add(part(usage.output_tokens, self.output_per_mtok))
                .saturating_add(part(usage.cache_read_tokens, self.cache_read_per_mtok))
                .saturating_add(part(usage.cache_write_tokens, self.cache_write_per_mtok)),
        )
    }
```

The `clamp(0, ..)` lower bound is deliberate and is not dead: a price is an
`i64` and a negative one is representable, so a misconfigured negative rate
would otherwise produce a negative cost by a second route. Say so in the
report, and add a test for it if the module's `ModelPrice` can be constructed
with a negative rate; if it cannot, say that instead.

- [ ] **Step 6: Run everything**

Run: `cargo test -p tokenfuse-core --lib pricing`, then
`cargo test -p tokenfuse-gateway --test the_estimate_never_goes_negative`,
then `cargo test --all`.
Expected: all green, and no existing test's expected figure changed. If any
pre-existing assertion had to move, stop and report it: this fix must not
alter one real price.

- [ ] **Step 7: Check the margin cast while you are here**

`crates/gateway/src/estimate.rs` finishes with
`Microusd((raw.0 as f64 * MARGIN).ceil() as i64)`. With `raw.0 == i64::MAX`
that product exceeds `i64`. Rust's float-to-int `as` saturates rather than
wrapping, so this is believed safe. Do not take that on faith: add one test to
`estimate.rs` asserting the estimate for a `u64::MAX` output cap is positive
and large, run it, and record the number it produced.

- [ ] **Step 8: Gates and commit**

```bash
cargo fmt --all && cargo clippy --all-targets -- -D warnings && cargo test --all
git add crates/core/src/pricing.rs crates/gateway/tests/the_estimate_never_goes_negative.rs crates/gateway/src/estimate.rs
git commit -m "fix(core): pricing saturates instead of wrapping negative"
```

---

### Task 1: `wire.rs`, the shape as a value

**Files:**
- Create: `crates/gateway/src/wire.rs`
- Modify: `crates/gateway/src/lib.rs` (add `mod wire;` beside the other module declarations)

**Interfaces:**
- Consumes: nothing.
- Produces: `pub enum Wire { Anthropic, OpenAi }` (derives `Clone, Copy, Debug, PartialEq, Eq`);
  `pub struct ParsedRequest { pub model: String, pub max_tokens: Option<u64>, pub stream: bool, pub completions: u64 }`;
  `impl Wire { pub fn parse_request(self, value: &serde_json::Value) -> ParsedRequest; pub fn route_path(self) -> &'static str; pub fn from_declaration(declared: Option<&str>, upstream: Option<&str>) -> Wire }`.

- [ ] **Step 1: Write the failing tests**

Create `crates/gateway/src/wire.rs` containing ONLY the tests below plus
`use serde_json::json;`. The types do not exist yet, which is the point.

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn the_anthropic_door_reads_max_tokens_and_never_asks_for_more_than_one_completion() {
        let v = json!({"model": "claude-haiku-4-5", "max_tokens": 64, "stream": true});
        let p = Wire::Anthropic.parse_request(&v);
        assert_eq!(p.model, "claude-haiku-4-5");
        assert_eq!(p.max_tokens, Some(64));
        assert!(p.stream);
        assert_eq!(p.completions, 1);
    }

    #[test]
    fn the_openai_door_prefers_max_completion_tokens_over_the_deprecated_name() {
        let v = json!({"model": "gpt-4o", "max_tokens": 16, "max_completion_tokens": 4096});
        assert_eq!(Wire::OpenAi.parse_request(&v).max_tokens, Some(4096));
    }

    #[test]
    fn the_openai_door_still_reads_the_deprecated_name_when_it_is_the_only_one() {
        let v = json!({"model": "gpt-4o", "max_tokens": 16});
        assert_eq!(Wire::OpenAi.parse_request(&v).max_tokens, Some(16));
    }

    #[test]
    fn a_request_asking_for_several_completions_says_so() {
        let v = json!({"model": "gpt-4o", "n": 4});
        assert_eq!(Wire::OpenAi.parse_request(&v).completions, 4);
    }

    #[test]
    fn a_nonsense_completion_count_is_one_and_never_zero() {
        for bad in [json!(0), json!(-3), json!("4"), json!(null), json!({})] {
            let v = json!({"model": "gpt-4o", "n": bad});
            assert_eq!(
                Wire::OpenAi.parse_request(&v).completions,
                1,
                "n={bad} must fall back to one completion, never zero"
            );
        }
    }

    #[test]
    fn an_output_limit_that_is_not_a_whole_number_is_absent_rather_than_guessed() {
        for bad in [json!("4096"), json!(1.5), json!(-1), json!(null)] {
            let v = json!({"model": "gpt-4o", "max_completion_tokens": bad});
            assert_eq!(Wire::OpenAi.parse_request(&v).max_tokens, None);
        }
    }

    #[test]
    fn a_body_that_is_not_an_object_still_parses_into_safe_defaults() {
        for v in [json!([]), json!("hello"), json!(7), json!(null)] {
            let p = Wire::OpenAi.parse_request(&v);
            assert_eq!(p.model, "unknown");
            assert_eq!(p.max_tokens, None);
            assert!(!p.stream);
            assert_eq!(p.completions, 1);
        }
    }

    #[test]
    fn each_door_knows_its_own_path() {
        assert_eq!(Wire::Anthropic.route_path(), "/v1/messages");
        assert_eq!(Wire::OpenAi.route_path(), "/v1/chat/completions");
    }

    #[test]
    fn a_declared_wire_wins_over_whatever_the_upstream_url_looks_like() {
        let w = Wire::from_declaration(Some("openai"), Some("https://api.anthropic.com/v1/messages"));
        assert_eq!(w, Wire::OpenAi);
    }

    #[test]
    fn an_undeclared_wire_is_read_off_the_upstream_path() {
        assert_eq!(
            Wire::from_declaration(None, Some("https://api.openai.com/v1/chat/completions")),
            Wire::OpenAi
        );
        assert_eq!(
            Wire::from_declaration(None, Some("https://api.anthropic.com/v1/messages")),
            Wire::Anthropic
        );
    }

    #[test]
    fn an_upstream_that_says_nothing_leaves_every_existing_deployment_where_it_was() {
        assert_eq!(Wire::from_declaration(None, None), Wire::Anthropic);
        assert_eq!(Wire::from_declaration(None, Some("http://localhost:9999/proxy")), Wire::Anthropic);
        assert_eq!(Wire::from_declaration(Some(""), Some("http://localhost:9999/proxy")), Wire::Anthropic);
    }

    #[test]
    fn an_unrecognised_declaration_falls_back_rather_than_inventing_a_third_shape() {
        assert_eq!(Wire::from_declaration(Some("gemini"), None), Wire::Anthropic);
    }
}
```

- [ ] **Step 2: Run the tests and watch them fail**

Run: `cargo test -p tokenfuse-gateway wire::`
Expected: compilation failure, `cannot find type Wire in this scope`. Record it.

- [ ] **Step 3: Write the module**

Put this ABOVE the test module in the same file:

```rust
//! Which wire shape a door speaks.
//!
//! The gateway serves two front doors and forwards to one upstream endpoint.
//! Everything whose answer depends on which shape a body is written in lives
//! here, so the enforcement path in `proxy.rs` is parameterised by a value
//! rather than copied per vendor. See `docs/26-the-openai-door.md`.

use serde_json::Value;

/// The request/response shape a door speaks.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Wire {
    Anthropic,
    OpenAi,
}

/// The handful of fields the enforcement path reads out of a request body,
/// whichever shape it arrived in.
#[derive(Debug, Clone)]
pub struct ParsedRequest {
    pub model: String,
    /// The caller's cap on generated tokens, if it gave one.
    pub max_tokens: Option<u64>,
    pub stream: bool,
    /// How many completions are being asked for and therefore billed. Always
    /// 1 on the Anthropic wire, which has no such parameter; `n` on OpenAI,
    /// where the provider's own reference says "you will be charged based on
    /// the number of generated tokens across all of the choices".
    pub completions: u64,
}

impl Wire {
    /// The path this door is served on.
    pub fn route_path(self) -> &'static str {
        match self {
            Wire::Anthropic => "/v1/messages",
            Wire::OpenAi => "/v1/chat/completions",
        }
    }

    /// Which shape this process serves: what the operator declared, else what
    /// the upstream URL's path implies, else Anthropic, which is what every
    /// deployment that predates this code already is.
    pub fn from_declaration(declared: Option<&str>, upstream: Option<&str>) -> Wire {
        match declared.map(str::trim).filter(|d| !d.is_empty()) {
            Some(d) if d.eq_ignore_ascii_case("openai") => return Wire::OpenAi,
            Some(d) if d.eq_ignore_ascii_case("anthropic") => return Wire::Anthropic,
            // An unrecognised value is not a third shape. main.rs warns about
            // it at startup; here it simply does not win.
            _ => {}
        }
        match upstream {
            Some(u) if u.contains("/chat/completions") => Wire::OpenAi,
            _ => Wire::Anthropic,
        }
    }

    /// Read the fields the enforcement path needs. Never fails: a body this
    /// cannot read yields defaults that are safe to price against, and the
    /// request goes on to be judged by everything downstream.
    pub fn parse_request(self, value: &Value) -> ParsedRequest {
        let model = value
            .get("model")
            .and_then(|m| m.as_str())
            .unwrap_or("unknown")
            .to_string();
        let stream = value
            .get("stream")
            .and_then(|s| s.as_bool())
            .unwrap_or(false);
        let max_tokens = match self {
            Wire::Anthropic => value.get("max_tokens").and_then(|m| m.as_u64()),
            // `max_tokens` is deprecated here and is refused outright by the
            // o-series, so the new name wins when both are present.
            Wire::OpenAi => value
                .get("max_completion_tokens")
                .and_then(|m| m.as_u64())
                .or_else(|| value.get("max_tokens").and_then(|m| m.as_u64())),
        };
        let completions = match self {
            Wire::Anthropic => 1,
            Wire::OpenAi => value
                .get("n")
                .and_then(|n| n.as_u64())
                .filter(|n| *n >= 1)
                .unwrap_or(1),
        };
        ParsedRequest {
            model,
            max_tokens,
            stream,
            completions,
        }
    }
}
```

- [ ] **Step 4: Add the module declaration**

In `crates/gateway/src/lib.rs`, beside the other `mod` lines, add:

```rust
pub mod wire;
```

- [ ] **Step 5: Run the tests and watch them pass**

Run: `cargo test -p tokenfuse-gateway wire::`
Expected: 12 passed.

- [ ] **Step 6: Gates and commit**

```bash
cargo fmt --all && cargo clippy --all-targets -- -D warnings && cargo test --all
git add crates/gateway/src/wire.rs crates/gateway/src/lib.rs
git commit -m "feat(gateway): the wire shape becomes a value"
```

---

### Task 2: the estimate learns that `n` multiplies

**Files:**
- Modify: `crates/gateway/src/estimate.rs` (the `estimate_cost` signature and body)
- Modify: `crates/gateway/src/proxy.rs` (**five** call sites: two on the request path, three in its own test module)
- Modify: `crates/gateway/src/router.rs` (one call site, line ~245)
- Modify: `crates/gateway/examples/bench.rs` (two call sites, lines ~79 and ~92)
- Test: `crates/gateway/src/estimate.rs` (its own `#[cfg(test)] mod tests`)

**The file list above is corrected.** An earlier version of this task said the
function had two call sites in `proxy.rs` and named no other file, and the
crate does not compile under that scope. `grep -rn estimate_cost crates/
--include='*.rs'` finds them all; run it rather than trusting any list,
including this one.

**Interfaces:**
- Consumes: nothing from Task 1 (deliberately: this lands on its own so the
  money change is reviewable without the refactor).
- Produces: `pub fn estimate_cost(prices: &PriceBook, model: &str, body_len: usize, max_tokens: Option<u64>, completions: u64) -> Option<Microusd>`.

- [ ] **Step 1: Write the failing tests**

Add to the existing `mod tests` in `crates/gateway/src/estimate.rs`:

```rust
#[test]
fn four_completions_cost_four_times_the_output_of_one() {
    let prices = crate::pricebook::default_price_book();
    let one = estimate_cost(&prices, "gpt-4o", 400, Some(1000), 1).unwrap();
    let four = estimate_cost(&prices, "gpt-4o", 400, Some(1000), 4).unwrap();
    // Input is charged once; only the output side multiplies, so four
    // completions cost strictly more than one and strictly less than four
    // whole calls.
    assert!(four.0 > one.0, "four completions must cost more than one");
    assert!(
        four.0 < one.0 * 4,
        "the input half is billed once, not four times"
    );
}

#[test]
fn a_completion_count_of_zero_is_treated_as_one_rather_than_as_free() {
    let prices = crate::pricebook::default_price_book();
    let zero = estimate_cost(&prices, "gpt-4o", 400, Some(1000), 0).unwrap();
    let one = estimate_cost(&prices, "gpt-4o", 400, Some(1000), 1).unwrap();
    assert_eq!(zero, one);
}

#[test]
fn an_absurd_completion_count_saturates_instead_of_wrapping_to_something_cheap() {
    let prices = crate::pricebook::default_price_book();
    let huge = estimate_cost(&prices, "gpt-4o", 400, Some(u64::MAX), u64::MAX).unwrap();
    let one = estimate_cost(&prices, "gpt-4o", 400, Some(1000), 1).unwrap();
    assert!(
        huge.0 > one.0,
        "a wrapped multiplication would make the most expensive request the cheapest"
    );
}
```

- [ ] **Step 2: Run them and watch them fail**

Run: `cargo test -p tokenfuse-gateway estimate::`
Expected: compilation failure, `this function takes 4 arguments but 5 arguments were supplied`. Record it.

- [ ] **Step 3: Change the signature and the arithmetic**

In `crates/gateway/src/estimate.rs`, replace the function's signature and the
`output_tokens` line:

```rust
/// Estimate the cost of a call from the request body length, the caller's
/// output cap, and how many completions are being asked for.
///
/// `completions` is 1 on the Anthropic wire, which has no such parameter. On
/// OpenAI it is `n`, and every one of those completions is generated and
/// billed, so the output half of the estimate multiplies. A count of zero is
/// read as one: no wire asks for nothing, and treating it as free is how a run
/// that should have been refused gets served.
pub fn estimate_cost(
    prices: &PriceBook,
    model: &str,
    body_len: usize,
    max_tokens: Option<u64>,
    completions: u64,
) -> Option<Microusd> {
    let input_tokens = (body_len as u64) / CHARS_PER_TOKEN;
    let output_tokens = max_tokens
        .unwrap_or(DEFAULT_MAX_TOKENS)
        .saturating_mul(completions.max(1));
    ...
```

Leave the rest of the body unchanged.

- [ ] **Step 4: Update both call sites**

In `crates/gateway/src/proxy.rs`, both existing calls gain a trailing `1`:

```rust
let estimate = estimate_cost(&st.prices, &parsed.model, body.len(), parsed.max_tokens, 1)
```

Task 5 replaces that `1` with the parsed count once the parser is wired in.
Leaving it literal here means this task changes no behaviour at all, which is
what makes it reviewable on its own.

- [ ] **Step 5: Run the tests and watch them pass**

Run: `cargo test -p tokenfuse-gateway`
Expected: everything green, including every pre-existing estimate test, whose
numbers must not move.

- [ ] **Step 6: Gates and commit**

```bash
cargo fmt --all && cargo clippy --all-targets -- -D warnings && cargo test --all
git add crates/gateway/src/estimate.rs crates/gateway/src/proxy.rs crates/gateway/src/router.rs crates/gateway/examples/bench.rs
git commit -m "feat(gateway): the estimate multiplies by the completions asked for"
```

---

### Task 3: one handler, parameterised by the door

**Files:**
- Modify: `crates/gateway/src/proxy.rs` (`messages`, `parse_request`, `ParsedRequest`)

`AppState` is NOT touched here. The `wire` field lands in Task 4, which is
what needs it; this task only moves the shape into the handler's signature.

**Interfaces:**
- Consumes: `Wire`, `ParsedRequest` from Task 1.
- Produces: `pub async fn messages(State(st): State<AppState>, headers: HeaderMap, body: Bytes) -> Response` (unchanged signature, now a thin wrapper) and `async fn handle(wire: Wire, st: AppState, headers: HeaderMap, body: Bytes) -> Response`.

- [ ] **Step 1: Write the failing test**

Add to `crates/gateway/src/proxy.rs`'s `mod tests`:

```rust
#[tokio::test]
async fn the_anthropic_door_is_served_through_the_shared_handler() {
    // The point of this test is not the 200: it is that `messages` reaches the
    // shared handler with Wire::Anthropic, so a later door cannot change what
    // this one does without failing here.
    let st = test_state();
    let resp = handle(
        Wire::Anthropic,
        st,
        HeaderMap::new(),
        Bytes::from(body(64)),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::OK);
}
```

Use the file's existing `test_state()` helper and its existing `body(u64)`
helper (both already defined in that module; do not write new ones).

- [ ] **Step 2: Run it and watch it fail**

Run: `cargo test -p tokenfuse-gateway the_anthropic_door_is_served`
Expected: `cannot find function handle in this scope`. Record it.

- [ ] **Step 3: Do the refactor**

Three edits, in this order:

1. Delete the local `struct ParsedRequest` and `fn parse_request` from
   `proxy.rs` (they move to `wire.rs`, done in Task 1) and add
   `use crate::wire::{ParsedRequest, Wire};` to the file's imports.

2. Rename `pub async fn messages(...)` to
   `async fn handle(wire: Wire, st: AppState, headers: HeaderMap, mut body: Bytes) -> Response`,
   changing only its first line of body from the axum extractor form. Inside
   it, replace the single call `parse_request(&request)` with
   `wire.parse_request(&request)`. Change nothing else in the 1,200 lines.

3. Add the thin door:

```rust
/// The Anthropic Messages door. Everything it does lives in [`handle`]; this
/// exists so the route table names a handler per door and the shape is chosen
/// in exactly one place.
pub async fn messages(State(st): State<AppState>, headers: HeaderMap, body: Bytes) -> Response {
    handle(Wire::Anthropic, st, headers, body).await
}
```

- [ ] **Step 4: Run the whole suite, and read the golden test's result specifically**

Run: `cargo test -p tokenfuse-gateway`
Expected: all green. Then run the invariant on its own and read its output:

Run: `cargo test -p tokenfuse-gateway breaker_error_response_matches_budget_error_byte_for_byte -- --nocapture`
Expected: PASS. If it fails, the refactor moved the Anthropic bytes. Do not
edit the test. Revert and find what moved.

- [ ] **Step 5: Gates and commit**

```bash
cargo fmt --all && cargo clippy --all-targets -- -D warnings && cargo test --all
git add crates/gateway/src/proxy.rs
git commit -m "refactor(gateway): one handler, and the door chooses the shape"
```

---

### Task 4: the process declares which door it serves

**Files:**
- Modify: `crates/gateway/src/state.rs` (`AppState.wire`)
- Modify: `crates/gateway/src/main.rs` (read `TOKENFUSE_WIRE` beside `TOKENFUSE_UPSTREAM`, around the provider construction)
- Modify: `crates/gateway/src/proxy.rs` (the mismatch refusal at the top of `handle`)
- Test: `crates/gateway/tests/wire_door.rs` (new integration test)

**Interfaces:**
- Consumes: `Wire::from_declaration` from Task 1.
- Produces: `AppState { pub wire: Wire, .. }`; a 400 refusal with `error.type == "wire_mismatch"`.

- [ ] **Step 1: Write the failing integration test**

Create `crates/gateway/tests/wire_door.rs`:

```rust
//! A process serves the door that matches its upstream, and says so about the
//! other one instead of reserving budget for a call the upstream will refuse.

use axum::body::Body;
use axum::http::{Request, StatusCode};
use tower::ServiceExt;

mod common;

#[tokio::test]
async fn a_gateway_pointed_at_anthropic_refuses_the_openai_door_before_it_reserves_anything() {
    let app = common::app_with_wire(tokenfuse_gateway::wire::Wire::Anthropic);
    let resp = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/chat/completions")
                .header("content-type", "application/json")
                .header("x-fuse-run-id", "r-wire-1")
                .body(Body::from(
                    r#"{"model":"gpt-4o","messages":[{"role":"user","content":"hi"}]}"#,
                ))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    let bytes = axum::body::to_bytes(resp.into_body(), 64 * 1024).await.unwrap();
    let v: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(v["error"]["type"], "wire_mismatch");
    assert!(
        v["error"]["message"].as_str().unwrap().contains("TOKENFUSE_WIRE"),
        "the refusal must name the variable that fixes it"
    );
}

#[tokio::test]
async fn a_gateway_pointed_at_openai_still_serves_its_own_door() {
    let app = common::app_with_wire(tokenfuse_gateway::wire::Wire::OpenAi);
    let resp = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/chat/completions")
                .header("content-type", "application/json")
                .header("x-fuse-run-id", "r-wire-2")
                .body(Body::from(
                    r#"{"model":"gpt-4o","messages":[{"role":"user","content":"hi"}]}"#,
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
}

#[tokio::test]
async fn the_anthropic_door_is_refused_on_a_gateway_pointed_at_openai() {
    let app = common::app_with_wire(tokenfuse_gateway::wire::Wire::OpenAi);
    let resp = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/messages")
                .header("content-type", "application/json")
                .header("x-fuse-run-id", "r-wire-3")
                .body(Body::from(
                    r#"{"model":"claude-haiku-4-5","max_tokens":16,"messages":[]}"#,
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}
```

Add `crates/gateway/tests/common/mod.rs` with an `app_with_wire` helper built
from whatever the existing integration tests use to construct state (copy the
construction from `crates/gateway/tests/require_run_id.rs` and set `wire`).

- [ ] **Step 2: Run and watch it fail**

Run: `cargo test -p tokenfuse-gateway --test wire_door`
Expected: compilation failure on `common::app_with_wire` / `AppState.wire`. Record it.

- [ ] **Step 3: Add the field and the startup read**

In `state.rs`, add to `AppState`:

```rust
/// Which front door this process serves, from `TOKENFUSE_WIRE` or inferred
/// from the upstream URL. The other door refuses rather than forwarding a
/// body the upstream cannot read.
pub wire: crate::wire::Wire,
```

In `main.rs`, immediately after the `provider` match, before `AppState` is
built:

```rust
let declared = std::env::var("TOKENFUSE_WIRE").ok();
let wire = Wire::from_declaration(declared.as_deref(), upstream_url.as_deref());
if let Some(d) = declared.as_deref().map(str::trim).filter(|d| !d.is_empty()) {
    if !d.eq_ignore_ascii_case("openai") && !d.eq_ignore_ascii_case("anthropic") {
        tracing::warn!(
            value = %d,
            "TOKENFUSE_WIRE is neither `anthropic` nor `openai`; falling back to the \
             shape implied by TOKENFUSE_UPSTREAM"
        );
    }
}
tracing::info!(?wire, path = %wire.route_path(), "serving one door");
```

`upstream_url` is the `Option<String>` the provider match already consumed:
clone it before the match rather than reconstructing it.

- [ ] **Step 4: Add the refusal at the top of `handle`**

The first thing `handle` does, before `resolve_client_key`, so nothing is
opened, reserved or recorded:

```rust
if wire != st.wire {
    return wire_mismatch(wire, st.wire);
}
```

and beside the other response builders in `proxy.rs`:

```rust
/// The door a caller used is not the one this process serves. Refused here,
/// before a run is opened or a cent reserved, because forwarding an OpenAI
/// body to an Anthropic endpoint turns a configuration mistake into a provider
/// error with a settled reservation behind it, and the operator reads the
/// upstream's complaint instead of ours.
fn wire_mismatch(asked: Wire, serving: Wire) -> Response {
    let body = serde_json::json!({
        "error": {
            "type": "wire_mismatch",
            "message": format!(
                "this gateway serves {} only. Set TOKENFUSE_WIRE={} and point \
                 TOKENFUSE_UPSTREAM at an endpoint that speaks it, or call {}.",
                serving.route_path(),
                match asked { Wire::OpenAi => "openai", Wire::Anthropic => "anthropic" },
                serving.route_path(),
            ),
            "retryable": false,
        }
    });
    (
        StatusCode::BAD_REQUEST,
        [("content-type", "application/json"), ("x-fuse", "blocked")],
        body.to_string(),
    )
        .into_response()
}
```

- [ ] **Step 5: Run and watch them pass**

Run: `cargo test -p tokenfuse-gateway --test wire_door`
Expected: 3 passed. Then `cargo test --all`: everything else still green,
because every existing `AppState` construction defaults `wire` to
`Wire::Anthropic`.

- [ ] **Step 6: Gates and commit**

```bash
cargo fmt --all && cargo clippy --all-targets -- -D warnings && cargo test --all
git add crates/gateway/src/state.rs crates/gateway/src/main.rs crates/gateway/src/proxy.rs crates/gateway/tests/
git commit -m "feat(gateway): a process declares which door it serves"
```

---

### Task 5: the door itself

**Files:**
- Modify: `crates/gateway/src/lib.rs` (register the route)
- Modify: `crates/gateway/src/proxy.rs` (the handler, and the estimate's completions argument)
- Test: `crates/gateway/tests/wire_door.rs` (extend)

**Interfaces:**
- Consumes: `handle`, `Wire`, `estimate_cost(.., completions)`.
- Produces: `pub async fn chat_completions(State(st): State<AppState>, headers: HeaderMap, body: Bytes) -> Response`.

- [ ] **Step 1: Write the failing test**

Add to `crates/gateway/tests/wire_door.rs`:

```rust
#[tokio::test]
async fn four_completions_are_reserved_for_before_the_call_is_forwarded() {
    // A budget that admits one completion of this size and not four. If the
    // estimate ignored `n`, this call would be served.
    let app = common::app_with_wire_and_budget(tokenfuse_gateway::wire::Wire::OpenAi, 0.02);
    let resp = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/chat/completions")
                .header("content-type", "application/json")
                .header("x-fuse-run-id", "r-n-1")
                .body(Body::from(
                    r#"{"model":"gpt-4o","n":4,"max_completion_tokens":4000,"messages":[{"role":"user","content":"hi"}]}"#,
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::PAYMENT_REQUIRED);
}
```

Add `app_with_wire_and_budget` to `tests/common/mod.rs`, setting
`policy.budget_per_run`. The 0.02 is a placeholder until you compute it: run

```
cargo test -p tokenfuse-gateway --lib estimate:: -- --nocapture
```

after adding a throwaway `println!` of
`estimate_cost(&default_price_book(), "gpt-4o", 220, Some(4000), 1)` and of the
same call with `4`, then set the budget strictly between the two figures and
write BOTH figures into a comment above the test. A test whose constant nobody
can re-derive is a test nobody can fix when the price book moves.

- [ ] **Step 2: Run and watch it fail**

Run: `cargo test -p tokenfuse-gateway --test wire_door four_completions`
Expected: FAIL, status 200 rather than 402, because the estimate still passes 1.

- [ ] **Step 3: Register the door and use the parsed count**

In `lib.rs`, beside the Anthropic route:

```rust
.route("/v1/chat/completions", post(proxy::chat_completions))
```

In `proxy.rs`, beside `messages`:

```rust
/// The OpenAI Chat Completions door. Same handler, same enforcement, a
/// different body shape. Requires an OpenAI-compatible upstream; see
/// `docs/26-the-openai-door.md`.
pub async fn chat_completions(
    State(st): State<AppState>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    handle(Wire::OpenAi, st, headers, body).await
}
```

And both `estimate_cost` call sites take the real count:

```rust
let estimate = estimate_cost(
    &st.prices,
    &parsed.model,
    body.len(),
    parsed.max_tokens,
    parsed.completions,
)
```

- [ ] **Step 4: Run and watch it pass**

Run: `cargo test -p tokenfuse-gateway --test wire_door`
Expected: all green.

- [ ] **Step 5: Gates and commit**

```bash
cargo fmt --all && cargo clippy --all-targets -- -D warnings && cargo test --all
git add crates/gateway/src/lib.rs crates/gateway/src/proxy.rs crates/gateway/tests/
git commit -m "feat(gateway): serve POST /v1/chat/completions"
```

---

### Task 6: the cache partition sees the system prompt on both doors

**Files:**
- Modify: `crates/gateway/src/wire.rs` (`system_text`)
- Modify: `crates/gateway/src/proxy.rs` (the cache partition call site, and delete the local `system_text`)
- Test: `crates/gateway/src/wire.rs`

**Interfaces:**
- Produces: `impl Wire { pub fn system_text(self, request: &serde_json::Value) -> String }`.

**Why this task exists.** `system_text` reads the top-level `system` field,
which is Anthropic's. OpenAI has no such field: its system prompt is a message
with role `system` (or `developer` on the o-series). So on the new door it
returns an empty string for every request, the semantic-cache partition key
loses the system prompt entirely, and two callers with different system prompts
and the same user message share a partition. The cache is Off by default, so
this is not live in most deployments, and it would ship silently in the ones
where it is on. Found by checking the plan against the design rather than by a
test, which is why the test comes first here.

- [ ] **Step 1: Write the failing tests**

In `wire.rs`'s test module:

```rust
#[test]
fn the_openai_door_finds_the_system_prompt_where_that_wire_keeps_it() {
    let v = json!({"model":"gpt-4o","messages":[
        {"role":"system","content":"You are terse."},
        {"role":"user","content":"hi"}
    ]});
    assert_eq!(Wire::OpenAi.system_text(&v), "You are terse.");
}

#[test]
fn the_o_series_developer_role_is_a_system_prompt_too() {
    let v = json!({"model":"o1","messages":[
        {"role":"developer","content":"Answer in one word."},
        {"role":"user","content":"hi"}
    ]});
    assert_eq!(Wire::OpenAi.system_text(&v), "Answer in one word.");
}

#[test]
fn two_openai_requests_with_different_system_prompts_do_not_share_a_partition() {
    let a = json!({"model":"gpt-4o","messages":[
        {"role":"system","content":"Answer in English."},
        {"role":"user","content":"hi"}]});
    let b = json!({"model":"gpt-4o","messages":[
        {"role":"system","content":"Answer in French."},
        {"role":"user","content":"hi"}]});
    assert_ne!(
        Wire::OpenAi.system_text(&a),
        Wire::OpenAi.system_text(&b),
        "an empty system text on both is how one caller gets the other's answer"
    );
}

#[test]
fn several_system_messages_are_read_in_order_and_joined() {
    let v = json!({"model":"gpt-4o","messages":[
        {"role":"system","content":"Be terse."},
        {"role":"user","content":"hi"},
        {"role":"system","content":"Be polite."}
    ]});
    assert_eq!(Wire::OpenAi.system_text(&v), "Be terse. Be polite.");
}

#[test]
fn an_openai_system_message_carrying_content_parts_is_read_as_text() {
    let v = json!({"model":"gpt-4o","messages":[
        {"role":"system","content":[{"type":"text","text":"Be terse."}]},
        {"role":"user","content":"hi"}
    ]});
    assert_eq!(Wire::OpenAi.system_text(&v), "Be terse.");
}

#[test]
fn the_anthropic_door_reads_the_field_it_always_read() {
    let v = json!({"model":"claude-haiku-4-5","system":"You are terse."});
    assert_eq!(Wire::Anthropic.system_text(&v), "You are terse.");
    let arr = json!({"model":"claude-haiku-4-5",
        "system":[{"type":"text","text":"You are terse."}]});
    assert_eq!(Wire::Anthropic.system_text(&arr), "You are terse.");
}

#[test]
fn a_messages_array_that_is_empty_or_full_of_nonsense_is_read_without_panicking() {
    for bad in [
        json!({"model":"gpt-4o","messages":[]}),
        json!({"model":"gpt-4o","messages":["hi", 3, null, []]}),
        json!({"model":"gpt-4o","messages":{"role":"system"}}),
        json!({"model":"gpt-4o"}),
    ] {
        assert_eq!(Wire::OpenAi.system_text(&bad), "");
    }
}

#[test]
fn a_body_with_no_system_prompt_anywhere_yields_an_empty_string_on_both_doors() {
    let v = json!({"model":"gpt-4o","messages":[{"role":"user","content":"hi"}]});
    assert_eq!(Wire::OpenAi.system_text(&v), "");
    assert_eq!(Wire::Anthropic.system_text(&json!({"model":"x"})), "");
}
```

- [ ] **Step 2: Run and watch them fail**

Run: `cargo test -p tokenfuse-gateway system_text`
Expected: `no method named system_text found for enum Wire`. Record it.

- [ ] **Step 3: Move the helper behind the shape**

Move `system_text` and `concat_text_blocks` from `proxy.rs` into `wire.rs`
(making `concat_text_blocks` a private free function there), and give the
Anthropic behaviour and the OpenAI behaviour one method:

```rust
    /// The system prompt, wherever this wire keeps it. Used for the semantic
    /// cache's partition key, so a wire whose system prompt this cannot see is
    /// a wire where two different callers share a partition.
    pub fn system_text(self, request: &Value) -> String {
        match self {
            Wire::Anthropic => match request.get("system") {
                Some(Value::String(s)) => s.clone(),
                Some(Value::Array(blocks)) => concat_text_blocks(blocks),
                _ => String::new(),
            },
            // OpenAI has no top-level system field: the prompt is one or more
            // messages, `developer` being the o-series spelling of `system`.
            Wire::OpenAi => {
                let Some(messages) = request.get("messages").and_then(|m| m.as_array()) else {
                    return String::new();
                };
                let mut buf = String::new();
                for m in messages {
                    let role = m.get("role").and_then(|r| r.as_str()).unwrap_or("");
                    if role != "system" && role != "developer" {
                        continue;
                    }
                    let text = match m.get("content") {
                        Some(Value::String(s)) => s.clone(),
                        Some(Value::Array(parts)) => concat_text_blocks(parts),
                        _ => String::new(),
                    };
                    if !text.is_empty() {
                        buf.push_str(&text);
                        buf.push(' ');
                    }
                }
                buf.trim().to_string()
            }
        }
    }
```

At the call site in `proxy.rs`, replace `&system_text(&request)` with
`&wire.system_text(&request)`.

- [ ] **Step 4: Run and watch them pass**

Run: `cargo test -p tokenfuse-gateway`
Expected: all green, including the pre-existing `system_text_extracts_*` tests,
which must be updated only in how they call the function, never in what they
assert.

- [ ] **Step 5: Gates and commit**

```bash
cargo fmt --all && cargo clippy --all-targets -- -D warnings && cargo test --all
git add crates/gateway/src/wire.rs crates/gateway/src/proxy.rs
git commit -m "fix(gateway): the cache partition sees the system prompt on both doors"
```

---

### Task 7: usage in a stream is asked for, and a null usage is not a zero

**Files:**
- Modify: `crates/gateway/src/wire.rs` (`prepare_upstream_body`)
- Modify: `crates/gateway/src/proxy.rs` (call it just before `st.provider.send`)
- Test: `crates/gateway/src/wire.rs` and `crates/gateway/src/provider.rs`

**Interfaces:**
- Produces: `impl Wire { pub fn prepare_upstream_body(self, body: &bytes::Bytes, stream: bool) -> Option<bytes::Bytes> }`, returning `None` when nothing needs changing.

- [ ] **Step 1: Write the failing tests**

In `wire.rs`'s test module:

```rust
#[test]
fn a_streamed_openai_request_is_asked_to_report_its_usage() {
    let body = bytes::Bytes::from(r#"{"model":"gpt-4o","stream":true}"#);
    let out = Wire::OpenAi.prepare_upstream_body(&body, true).unwrap();
    let v: serde_json::Value = serde_json::from_slice(&out).unwrap();
    assert_eq!(v["stream_options"]["include_usage"], json!(true));
}

#[test]
fn a_caller_that_already_answered_the_question_is_not_overruled() {
    for already in [json!(true), json!(false)] {
        let body = bytes::Bytes::from(
            serde_json::json!({"model":"gpt-4o","stream":true,
                "stream_options":{"include_usage": already}})
            .to_string(),
        );
        assert!(
            Wire::OpenAi.prepare_upstream_body(&body, true).is_none(),
            "include_usage={already} was the caller's choice and stays"
        );
    }
}

#[test]
fn a_stream_options_that_is_not_an_object_is_left_exactly_as_it_came() {
    for odd in [json!("yes"), json!(3), json!([]), json!(null)] {
        let body = bytes::Bytes::from(
            serde_json::json!({"model":"gpt-4o","stream":true,"stream_options": odd}).to_string(),
        );
        assert!(Wire::OpenAi.prepare_upstream_body(&body, true).is_none());
    }
}

#[test]
fn nothing_is_added_to_a_request_that_does_not_stream_or_to_the_other_door() {
    let body = bytes::Bytes::from(r#"{"model":"gpt-4o"}"#);
    assert!(Wire::OpenAi.prepare_upstream_body(&body, false).is_none());
    let anth = bytes::Bytes::from(r#"{"model":"claude-haiku-4-5","stream":true}"#);
    assert!(Wire::Anthropic.prepare_upstream_body(&anth, true).is_none());
}

#[test]
fn a_body_that_is_not_an_object_is_left_alone_rather_than_replaced() {
    let body = bytes::Bytes::from("[1,2,3]");
    assert!(Wire::OpenAi.prepare_upstream_body(&body, true).is_none());
}
```

In `provider.rs`'s test module, the two tests the design's section 6 asks for:

```rust
#[test]
fn a_null_usage_on_every_chunk_but_the_last_does_not_settle_the_run_at_zero() {
    // With include_usage set, the provider's own reference says "All other
    // chunks will also include a `usage` field, but with a null value."
    let mut p = UsageParser::default();
    p.feed(br#"data: {"choices":[{"delta":{"content":"hi"}}],"usage":null}

"#);
    p.feed(br#"data: {"choices":[],"usage":{"prompt_tokens":10,"completion_tokens":5}}

"#);
    let u = p.finish().expect("the final chunk carries the usage");
    assert_eq!(u.usage.input_tokens, 10);
    assert_eq!(u.usage.output_tokens, 5);
}

#[test]
fn the_final_usage_chunks_empty_choices_array_counts_no_tool_calls() {
    let mut p = UsageParser::default();
    p.feed(br#"data: {"choices":[],"usage":{"prompt_tokens":1,"completion_tokens":1}}

"#);
    let u = p.finish().unwrap();
    assert_eq!(u.tool_calls, 0);
}
```

Match the exact field names on `ParsedUsage` when you write these; read the
struct rather than trusting the names above.

- [ ] **Step 2: Run and watch them fail**

Run: `cargo test -p tokenfuse-gateway prepare_upstream_body`
Expected: `no method named prepare_upstream_body`. The two provider tests may
already pass, since the design established the parser survives a null `usage`
by construction; if they pass on first run, say so in the report rather than
claiming they were red.

- [ ] **Step 3: Implement**

In `wire.rs`:

```rust
    /// The body to forward, when it differs from the body that arrived.
    ///
    /// OpenAI sends no usage in a streamed response unless the request asked
    /// for it, and a run settled from an estimate rather than from measured
    /// usage is the failure this gateway exists to avoid. So a streamed
    /// request that did not answer the question gets `include_usage` added.
    ///
    /// Returns `None` when nothing needs changing, including when the body is
    /// not an object we can safely rewrite: the caller then forwards what it
    /// received, which is always safe.
    ///
    /// A caller who set `include_usage` themselves is never overruled, not
    /// even when they set it to `false`.
    pub fn prepare_upstream_body(
        self,
        body: &bytes::Bytes,
        stream: bool,
    ) -> Option<bytes::Bytes> {
        if self != Wire::OpenAi || !stream {
            return None;
        }
        let mut value: Value = serde_json::from_slice(body).ok()?;
        let obj = value.as_object_mut()?;
        match obj.get("stream_options") {
            Some(Value::Object(o)) if o.contains_key("include_usage") => return None,
            Some(Value::Object(_)) | None => {}
            // Present and not an object: the caller sent something we do not
            // understand, and rewriting it would change their request into one
            // they did not make.
            Some(_) => return None,
        }
        let entry = obj
            .entry("stream_options")
            .or_insert_with(|| Value::Object(Default::default()));
        entry
            .as_object_mut()?
            .insert("include_usage".to_string(), Value::Bool(true));
        serde_json::to_vec(&value).ok().map(bytes::Bytes::from)
    }
```

In `proxy.rs`, immediately before `st.provider.send(headers, body)`:

```rust
    // Ask for usage on a stream that would otherwise report none. Last, so it
    // sees the body every earlier stage produced (DLP masking, model rewrite).
    if let Some(prepared) = wire.prepare_upstream_body(&body, parsed.stream) {
        body = prepared;
    }
```

- [ ] **Step 4: Run and watch them pass**

Run: `cargo test -p tokenfuse-gateway`
Expected: all green.

- [ ] **Step 5: Gates and commit**

```bash
cargo fmt --all && cargo clippy --all-targets -- -D warnings && cargo test --all
git add crates/gateway/src/wire.rs crates/gateway/src/proxy.rs crates/gateway/src/provider.rs
git commit -m "feat(gateway): a streamed OpenAI call is asked to report its usage"
```

---

### Task 8: a refusal the OpenAI clients can read

**Files:**
- Modify: `crates/gateway/src/proxy.rs` (`breaker_error_response`, its call sites)
- Test: `crates/gateway/src/proxy.rs`

**Interfaces:**
- Produces: `fn breaker_error_response(wire: Wire, run_id: &str, verdict: &BreakerVerdict) -> Response`.

- [ ] **Step 1: Write the failing test**

```rust
#[test]
fn the_openai_door_refuses_in_the_envelope_its_clients_parse() {
    let verdict = budget_verdict(
        BreakerReason::BudgetExceeded,
        Some(5.0),
        Some(5.5),
        Some("p1"),
        "over budget",
    );
    let resp = breaker_error_response(Wire::OpenAi, "r1", &verdict);
    assert_eq!(resp.status(), StatusCode::PAYMENT_REQUIRED);
    let v = body_json(resp); // existing helper in this module
    assert_eq!(v["error"]["type"], "budget_exceeded");
    assert_eq!(v["error"]["code"], "budget_exceeded");
    assert!(v["error"]["param"].is_null());
    let msg = v["error"]["message"].as_str().unwrap();
    assert!(msg.contains("r1"), "the message names the run");
    // The fields the record already carries are still there.
    assert_eq!(v["error"]["run_id"], "r1");
    assert_eq!(v["error"]["retryable"], serde_json::json!(false));
}

#[test]
fn the_anthropic_door_still_refuses_in_exactly_the_bytes_it_always_did() {
    let verdict = budget_verdict(
        BreakerReason::BudgetExceeded,
        Some(5.0),
        Some(5.5),
        Some("p1"),
        "over budget",
    );
    let v = body_json(breaker_error_response(Wire::Anthropic, "r1", &verdict));
    assert!(v["error"].get("message").is_none(), "no message on this door");
    assert!(v["error"].get("code").is_none());
    assert!(v["error"].get("param").is_none());
}
```

- [ ] **Step 2: Run and watch them fail**

Run: `cargo test -p tokenfuse-gateway refuses_in_the_envelope`
Expected: `this function takes 2 arguments but 3 were supplied`. Record it.

- [ ] **Step 3: Implement**

Give `breaker_error_response` the `wire` parameter, keep the Anthropic branch
building exactly what it builds today, and add for OpenAI only:

```rust
    let mut value = verdict.to_error_json(run_id);
    if wire == Wire::OpenAi {
        if let Some(err) = value.get_mut("error").and_then(|e| e.as_object_mut()) {
            let kind = verdict
                .reason
                .map(|r| r.as_wire_str().to_string())
                .unwrap_or_else(|| "blocked".to_string());
            err.insert(
                "message".to_string(),
                serde_json::Value::String(format!(
                    "run {run_id} was stopped by the gateway: {}",
                    verdict.detail
                )),
            );
            err.insert("code".to_string(), serde_json::Value::String(kind));
            err.insert("param".to_string(), serde_json::Value::Null);
        }
    }
```

Read `BreakerVerdict`'s real field names in `crates/core/src/breaker.rs` before
writing this; `detail` and `reason` are the names as of 2026-09-07 but check.

Update the five call sites to pass `wire`.

- [ ] **Step 4: Run, and read the golden test's result specifically**

Run: `cargo test -p tokenfuse-gateway breaker_error_response_matches_budget_error_byte_for_byte -- --nocapture`
Expected: PASS, unmodified. This is the whole point of the task: the new
parameter must not have moved the old bytes.

Then `cargo test --all`.

- [ ] **Step 5: Gates and commit**

```bash
cargo fmt --all && cargo clippy --all-targets -- -D warnings && cargo test --all
git add crates/gateway/src/proxy.rs
git commit -m "feat(gateway): the OpenAI door refuses in the OpenAI envelope"
```

---

### Task 9: the scenarios, the teeth, the mutants, and the docs

**Files:**
- Create: `features/the-openai-door.feature`
- Modify: `scripts/gates-have-teeth.sh`
- Modify: `README.md` (three places), `docs/02-architecture.md` (the route list and the pipeline line), `docs/26-the-openai-door.md` (status)

**Interfaces:** none; this task ships the evidence and the copy.

- [ ] **Step 1: Write the feature file**

Create `features/the-openai-door.feature`, one scenario per behaviour, each
with a `# @test:<exact rust test name>` comment above it, in the shape of
`features/the-delegation-door.feature`. Bind, at minimum:
`the_openai_door_prefers_max_completion_tokens_over_the_deprecated_name`,
`a_nonsense_completion_count_is_one_and_never_zero`,
`four_completions_are_reserved_for_before_the_call_is_forwarded`,
`a_gateway_pointed_at_anthropic_refuses_the_openai_door_before_it_reserves_anything`,
`a_streamed_openai_request_is_asked_to_report_its_usage`,
`a_caller_that_already_answered_the_question_is_not_overruled`,
`a_null_usage_on_every_chunk_but_the_last_does_not_settle_the_run_at_zero`,
`the_openai_door_refuses_in_the_envelope_its_clients_parse`.

- [ ] **Step 2: Run the binding gate**

Run: `./scripts/features-are-bound.sh`
Expected: green, both directions. A red here means a name in the feature file
does not match a test.

- [ ] **Step 3: Run the mutation round by hand and record it**

For each mutant in the table below: apply it to the product code, run the
named test, confirm RED, revert. Record the failure line in the report.

| mutant | apply | must go red |
|---|---|---|
| drop the `n` multiplier | in `estimate.rs`, remove `.saturating_mul(completions.max(1))` | `four_completions_are_reserved_for_before_the_call_is_forwarded` |
| read the deprecated name first | in `wire.rs`, swap the `or_else` order for `Wire::OpenAi` | `the_openai_door_prefers_max_completion_tokens_over_the_deprecated_name` |
| skip the injection | in `proxy.rs`, delete the `prepare_upstream_body` call | `a_streamed_openai_request_is_asked_to_report_its_usage` (add an integration assertion if the unit test alone still passes) |
| overrule the caller | in `wire.rs`, remove the `contains_key("include_usage")` early return | `a_caller_that_already_answered_the_question_is_not_overruled` |
| serve the mismatched door | in `proxy.rs`, delete the `wire != st.wire` guard | `a_gateway_pointed_at_anthropic_refuses_the_openai_door_before_it_reserves_anything` |
| lose the system prompt on the new door | in `wire.rs`, make `Wire::OpenAi`'s `system_text` return `String::new()` | `two_openai_requests_with_different_system_prompts_do_not_share_a_partition` |
| treat a null usage as parsed | in `provider.rs`, drop `.filter(\|u\| u.is_object())` | `a_null_usage_on_every_chunk_but_the_last_does_not_settle_the_run_at_zero` |

Any mutant that does NOT go red is a missing test, not a passing mutant: write
the test before continuing.

- [ ] **Step 4: Add the teeth case**

In `scripts/gates-have-teeth.sh`, add a case in the shape the file already
uses, planting the "serve the mismatched door" fault and requiring the failure.
Run `./scripts/gates-have-teeth.sh` and confirm the new case reports `ok`.

- [ ] **Step 5: Correct the copy**

Three README lines currently say the endpoint is planned and not implemented
(the "Drop-in, fail-open, and fast" paragraph, the note under the FAQ area, and
the v0.4.0 status paragraph). Rewrite them to say what is now true, including
that the door requires an OpenAI-compatible upstream, that `TOKENFUSE_WIRE`
picks it, and that a streamed request gets `include_usage` added. Update
`docs/02-architecture.md`'s route list and its pipeline line. No em dashes, no
competitor names.

- [ ] **Step 6: Gates and commit**

```bash
./scripts/features-are-bound.sh && ./scripts/gates-have-teeth.sh
cargo fmt --all && cargo clippy --all-targets -- -D warnings && cargo test --all
git add features/ scripts/ README.md docs/
git commit -m "test+docs(gateway): the OpenAI door's scenarios, teeth and copy"
```

- [ ] **Step 7: Write the report**

The deliverable is the report, in the fixed shape: tier and why, scenarios and
their bindings, the red-first evidence per test, tests added and total, the
gate and its teeth case, `fmt`/`clippy`/coverage with the delta and the
uncovered paths that matter, what was actually run and what it printed, and a
`NOT proven` line that is never empty. Candidates for that last line, unless
the work disproves them: no run against a real OpenAI endpoint; no measurement
of the injection's effect on a real stream; the response-side firewall
judgement still absent from the streaming path.
