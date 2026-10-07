//! Default price book shipped with the gateway binary.
//!
//! Pulled out of `main.rs` so it's unit-testable: the goal is to catch a
//! units mistake (a 1e6 error turns a milli-dollar estimate into a
//! multi-thousand-dollar one) before it ships, and to pin which models
//! resolve via an exact price-book entry vs. the conservative fallback
//! (`x-fuse-price: known` vs `fallback`, see `proxy.rs`).
//!
//! Every Anthropic row below names the page its rate was read from and the
//! date it was read. A rate in this file is a claim about somebody else's
//! price list, true on that date: when a vendor moves a price, the row is
//! wrong until somebody reads the page again. An operator who cannot wait
//! for a release overrides any row with `TOKENFUSE_PRICE_BOOK`
//! (`crate::pricefile`).

use tokenfuse_core::{Microusd, ModelPrice, PriceBook};

/// A Claude model's list rate (USD per Mtok: input, output, cache read,
/// 5-minute cache write; the 1-hour write is the derived 1.6x, which is
/// Anthropic's ratio for every model below) and every id it is sold under.
struct Claude {
    rate: (f64, f64, f64, f64),
    /// Ids priced at the list rate: the Claude API, Google Cloud's dateless
    /// ids (identical to the Claude API's), a Bedrock `global.` profile,
    /// and OpenRouter.
    list: &'static [&'static str],
    /// Ids whose endpoint may be regional: list plus 10 percent.
    regional: &'static [&'static str],
}

/// Anthropic's model lineup on 2026-10-07 and the ids each model answers to.
///
/// Rates: <https://platform.claude.com/docs/en/about-claude/pricing>, "Model
/// pricing", read 2026-10-07. Claude API ids:
/// <https://platform.claude.com/docs/en/about-claude/models/overview>, read
/// 2026-10-07. Bedrock ids: <https://platform.claude.com/docs/en/build-with-claude/claude-in-amazon-bedrock>
/// ("Supported models") and, for the InvokeModel base ids and which
/// inference-profile prefixes each model has,
/// <https://platform.claude.com/docs/en/build-with-claude/claude-on-amazon-bedrock-legacy>
/// ("API model IDs"), both read 2026-10-07. Google Cloud ids:
/// <https://platform.claude.com/docs/en/build-with-claude/claude-on-vertex-ai>
/// ("API model IDs"), read 2026-10-07.
///
/// **Bedrock and Google Cloud.** Both clouds invoice Claude themselves.
/// Anthropic's pages above state the rule for Sonnet 4.5 and every later
/// model on both: a global endpoint is priced at the Claude API's list, a
/// regional or (Google) multi-region endpoint at a 10 percent premium. The
/// clouds' own price pages (<https://aws.amazon.com/bedrock/pricing/>,
/// <https://cloud.google.com/vertex-ai/generative-ai/pricing>) could not be
/// opened from the machine that wrote this on 2026-10-07; Google's page, as
/// its search listing showed it that day, prices Sonnet 5 at 2.20 / 11.00,
/// which is list plus 10 percent. So an id that names its endpoint is priced
/// for it: a Bedrock `global.` profile at list, a `us.`/`eu.`/`jp.`/`apac.`
/// profile at the premium. An id that does not (a bare Bedrock
/// `anthropic.*` id, whose endpoint is chosen by the URL; a Google `@`-dated
/// id) is priced at the premium, the over-charging side (ADR-8). A Google
/// dateless id is the Claude API's id character for character, so it is
/// priced at list and a regional Google call is under-priced by 10 percent:
/// that operator sets the rate in `TOKENFUSE_PRICE_BOOK`.
///
/// **OpenRouter.** Rates from each model's page on openrouter.ai
/// (`https://openrouter.ai/<id>`), read 2026-10-07 through the search index
/// because the site could not be fetched directly from this machine. Only
/// the ids whose page showed all five rates are here; each matched the list.
const CLAUDE: &[Claude] = &[
    // Claude Fable 5.1: 10 / 50, cache hits 0.25 (0.025x), writes 12.50 / 20.
    Claude {
        rate: (10.00, 50.00, 0.25, 12.50),
        list: &["claude-fable-5-1"],
        regional: &["anthropic.claude-fable-5-1"],
    },
    // Claude Fable 5: 10 / 50, cache hits 1, writes 12.50 / 20.
    Claude {
        rate: (10.00, 50.00, 1.00, 12.50),
        list: &["claude-fable-5"],
        regional: &["anthropic.claude-fable-5"],
    },
    // Claude Opus 5.5: 4 / 20, cache hits 0.20 (0.05x), writes 5 / 8.
    Claude {
        rate: (4.00, 20.00, 0.20, 5.00),
        list: &["claude-opus-5-5", "anthropic/claude-opus-5.5"],
        regional: &["anthropic.claude-opus-5-5"],
    },
    // Claude Opus 5: 5 / 25, cache hits 0.50, writes 6.25 / 10.
    Claude {
        rate: (5.00, 25.00, 0.50, 6.25),
        list: &["claude-opus-5", "anthropic/claude-opus-5"],
        regional: &["anthropic.claude-opus-5"],
    },
    // Claude Opus 4.8: as Opus 5.
    Claude {
        rate: (5.00, 25.00, 0.50, 6.25),
        list: &["claude-opus-4-8", "anthropic/claude-opus-4.8"],
        regional: &["anthropic.claude-opus-4-8"],
    },
    // Claude Opus 4.7: as Opus 5.
    Claude {
        rate: (5.00, 25.00, 0.50, 6.25),
        list: &["claude-opus-4-7"],
        regional: &["anthropic.claude-opus-4-7"],
    },
    // Claude Opus 4.6: as Opus 5. Bedrock profiles: global, us, eu, jp, apac.
    Claude {
        rate: (5.00, 25.00, 0.50, 6.25),
        list: &["claude-opus-4-6", "global.anthropic.claude-opus-4-6-v1"],
        regional: &[
            "anthropic.claude-opus-4-6-v1",
            "us.anthropic.claude-opus-4-6-v1",
            "eu.anthropic.claude-opus-4-6-v1",
            "jp.anthropic.claude-opus-4-6-v1",
            "apac.anthropic.claude-opus-4-6-v1",
        ],
    },
    // Claude Opus 4.5: as Opus 5 (a 67 percent cut from Opus 4.1's 15 / 75).
    // `claude-opus-4-5` is the Claude API alias of the dated snapshot; the
    // book has no alias mechanism, so both are rows. Bedrock: global, us, eu.
    Claude {
        rate: (5.00, 25.00, 0.50, 6.25),
        list: &[
            "claude-opus-4-5",
            "claude-opus-4-5-20251101",
            "global.anthropic.claude-opus-4-5-20251101-v1:0",
        ],
        regional: &[
            "claude-opus-4-5@20251101",
            "anthropic.claude-opus-4-5-20251101-v1:0",
            "us.anthropic.claude-opus-4-5-20251101-v1:0",
            "eu.anthropic.claude-opus-4-5-20251101-v1:0",
        ],
    },
    // Claude Sonnet 5.5: 2 / 10, cache hits 0.20, writes 2.50 / 4.
    Claude {
        rate: (2.00, 10.00, 0.20, 2.50),
        list: &["claude-sonnet-5-5", "anthropic/claude-sonnet-5.5"],
        regional: &["anthropic.claude-sonnet-5-5"],
    },
    // Claude Sonnet 5: 2 / 10, as Sonnet 5.5. The page's footnote: the 2 / 10
    // launch price "is now the standard price" and the increase to 3 / 15
    // scheduled for 2026-09-01 "will not occur". tokenfuse#305 assumed 3 / 15.
    Claude {
        rate: (2.00, 10.00, 0.20, 2.50),
        list: &["claude-sonnet-5", "anthropic/claude-sonnet-5"],
        regional: &["anthropic.claude-sonnet-5"],
    },
    // Claude Sonnet 4.6: 3 / 15, cache hits 0.30, writes 3.75 / 6. Bedrock:
    // global, us, eu, jp.
    Claude {
        rate: (3.00, 15.00, 0.30, 3.75),
        list: &[
            "claude-sonnet-4-6",
            "global.anthropic.claude-sonnet-4-6",
            "anthropic/claude-sonnet-4.6",
        ],
        regional: &[
            "anthropic.claude-sonnet-4-6",
            "us.anthropic.claude-sonnet-4-6",
            "eu.anthropic.claude-sonnet-4-6",
            "jp.anthropic.claude-sonnet-4-6",
        ],
    },
    // Claude Sonnet 4.5 (deprecated): as Sonnet 4.6. Bedrock: global, us, eu, jp.
    Claude {
        rate: (3.00, 15.00, 0.30, 3.75),
        list: &[
            "claude-sonnet-4-5",
            "claude-sonnet-4-5-20250929",
            "global.anthropic.claude-sonnet-4-5-20250929-v1:0",
        ],
        regional: &[
            "claude-sonnet-4-5@20250929",
            "anthropic.claude-sonnet-4-5-20250929-v1:0",
            "us.anthropic.claude-sonnet-4-5-20250929-v1:0",
            "eu.anthropic.claude-sonnet-4-5-20250929-v1:0",
            "jp.anthropic.claude-sonnet-4-5-20250929-v1:0",
        ],
    },
    // Claude Haiku 4.5: 1 / 5, cache hits 0.10, writes 1.25 / 2. Bedrock
    // Messages-API id `anthropic.claude-haiku-4-5`; InvokeModel profiles:
    // global, us, eu.
    Claude {
        rate: (1.00, 5.00, 0.10, 1.25),
        list: &[
            "claude-haiku-4-5",
            "claude-haiku-4-5-20251001",
            "global.anthropic.claude-haiku-4-5-20251001-v1:0",
        ],
        regional: &[
            "claude-haiku-4-5@20251001",
            "anthropic.claude-haiku-4-5",
            "anthropic.claude-haiku-4-5-20251001-v1:0",
            "us.anthropic.claude-haiku-4-5-20251001-v1:0",
            "eu.anthropic.claude-haiku-4-5-20251001-v1:0",
        ],
    },
];

/// A regional or multi-region endpoint's rate: list plus 10 percent, in
/// integer micro-USD. Every list rate above is a whole multiple of 10
/// micro-USD, so `* 11 / 10` is exact; the test that writes each figure out
/// by hand is what holds that.
fn regional(p: ModelPrice) -> ModelPrice {
    let up = |m: Microusd| Microusd(m.0 * 11 / 10);
    ModelPrice {
        input_per_mtok: up(p.input_per_mtok),
        output_per_mtok: up(p.output_per_mtok),
        cache_read_per_mtok: up(p.cache_read_per_mtok),
        cache_write_per_mtok: up(p.cache_write_per_mtok),
        cache_write_1h_per_mtok: up(p.cache_write_1h_per_mtok),
    }
}

/// The price book used by `tokenfuse serve`, before any `TOKENFUSE_PRICE_BOOK`
/// override. Illustrative generic entries, every Claude id in [`CLAUDE`],
/// and exact entries for three OpenAI models, so common calls price exactly
/// instead of falling back to the conservative generic rate.
pub fn default_price_book() -> PriceBook {
    let mut book = PriceBook::new()
        // --- Illustrative generic entries (pre-existing; kept for callers that
        // pass a bare family name rather than a real provider model string). ---
        .with(
            "claude-sonnet",
            ModelPrice::per_mtok_usd(3.0, 15.0, 0.30, 3.75),
        )
        .with(
            "claude-haiku",
            ModelPrice::per_mtok_usd(0.80, 4.0, 0.08, 1.0),
        )
        .with(
            "gpt",
            ModelPrice::per_mtok_usd(2.5, 10.0, 0.25, 3.125).with_cache_write_1h_usd(3.125),
        )
        //
        // --- OpenAI. Prices as of 2026-07, verify against
        // https://developers.openai.com/api/docs/pricing (not re-read for the
        // 2026-10-07 change, which touched Anthropic rows only). OpenAI's prompt
        // caching has no separate "cache write" fee (the first pass through
        // is billed as ordinary input) — cache_write_per_mtok is set equal to
        // input_per_mtok so writing to cache never appears artificially free
        // or artificially expensive if the caller ever tags tokens that way.
        // Cached-read discount is a flat 50% off input across these models. ---
        //
        // gpt-4o: $2.50 / $10.00 per Mtok, cached input $1.25.
        // OpenAI has no 1-hour cache tier either, so the derived 1.6x column
        // is set back to the single write rate on each of these three: the
        // published book must not show a rate no provider charges, and no
        // OpenAI usage object reports a 1-hour subset for it to price.
        .with(
            "gpt-4o",
            ModelPrice::per_mtok_usd(2.50, 10.00, 1.25, 2.50).with_cache_write_1h_usd(2.50),
        )
        // gpt-4o-mini: $0.15 / $0.60 per Mtok, cached input $0.075.
        .with(
            "gpt-4o-mini",
            ModelPrice::per_mtok_usd(0.15, 0.60, 0.075, 0.15).with_cache_write_1h_usd(0.15),
        )
        // o1: $15.00 / $60.00 per Mtok, cached input $7.50.
        .with(
            "o1",
            ModelPrice::per_mtok_usd(15.00, 60.00, 7.50, 15.00).with_cache_write_1h_usd(15.00),
        )
        //
        // --- Conservative fallback for anything not listed (ADR-8): priced at
        // (a margin above) the most expensive known model, so an unrecognized
        // model never under-reserves. Opus 4.1's 15 / 75 is still sold on the
        // clouds; nothing in the book is dearer in input or output. ---
        .with_fallback(ModelPrice::per_mtok_usd(15.0, 75.0, 1.5, 18.75));
    // Anthropic. The 1M-token context window of the 4.6 generation and later
    // is priced at the standard rate (the pricing page, "Long context
    // pricing"); Sonnet 4.5's >200K tier is still not modeled here.
    for m in CLAUDE {
        let (i, o, r, w) = m.rate;
        let list = ModelPrice::per_mtok_usd(i, o, r, w);
        for id in m.list {
            book.insert(*id, list);
        }
        for id in m.regional {
            book.insert(*id, regional(list));
        }
    }
    book
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokenfuse_core::{Microusd, Usage};

    /// A 1000-input/500-output claude-haiku-4-5 call should land in the
    /// single-digit-to-low-tens-of-milli-dollars range. This is the guard
    /// against a units error: get the Microusd/per-Mtok conversion wrong by
    /// 1e6 and this would report either sub-micro-dollar or multi-dollar
    /// costs instead.
    #[test]
    fn haiku_4_5_sample_estimate_is_in_sane_milli_dollar_range() {
        let book = default_price_book();
        let usage = Usage {
            input_tokens: 1000,
            output_tokens: 500,
            ..Default::default()
        };
        let cost = book.cost("claude-haiku-4-5", &usage).unwrap();
        // input: 1000 * $1.00/1e6 = $0.001; output: 500 * $5.00/1e6 = $0.0025
        // total = $0.0035 = 3.5 milli-dollars.
        assert_eq!(cost, Microusd::from_usd(0.0035));
        // Sane-range guard, independent of the exact arithmetic above: not
        // sub-micro-dollar, not dollars.
        assert!(
            cost > Microusd::from_usd(0.0001) && cost < Microusd::from_usd(1.0),
            "cost {cost} is outside the sane milli-dollar range for a small haiku call"
        );
    }

    #[test]
    fn new_2026_models_resolve_by_exact_match_not_fallback() {
        let book = default_price_book();
        for model in [
            "claude-haiku-4-5",
            "claude-haiku-4-5-20251001",
            "claude-sonnet-4-5",
            "claude-sonnet-4-5-20250929",
            "claude-opus-4-5",
            "claude-opus-4-5-20251101",
            "gpt-4o",
            "gpt-4o-mini",
            "o1",
        ] {
            assert!(book.is_known(model), "{model} should be an exact entry");
        }
        // Still no exact entry for a genuinely unknown model — it must fall
        // back rather than silently gaining a made-up price.
        assert!(!book.is_known("some-future-model-nobody-has-priced-yet"));
        assert!(
            book.price("some-future-model-nobody-has-priced-yet")
                .is_some(),
            "unknown models must still resolve via the conservative fallback"
        );
    }

    /// (input, output, cache read, 5-minute cache write, 1-hour cache write),
    /// micro-USD per million tokens, written out by hand from the vendor
    /// pages cited in `default_price_book` (read 2026-10-07). Deliberately
    /// NOT computed from the table under test: an expectation taken from the
    /// thing it checks cannot fail (invariant 14).
    type Rates = (i64, i64, i64, i64, i64);
    const FABLE_5_1: Rates = (10_000_000, 50_000_000, 250_000, 12_500_000, 20_000_000);
    const FABLE_5: Rates = (10_000_000, 50_000_000, 1_000_000, 12_500_000, 20_000_000);
    const OPUS_5_5: Rates = (4_000_000, 20_000_000, 200_000, 5_000_000, 8_000_000);
    const OPUS_5: Rates = (5_000_000, 25_000_000, 500_000, 6_250_000, 10_000_000);
    const SONNET_5: Rates = (2_000_000, 10_000_000, 200_000, 2_500_000, 4_000_000);
    const SONNET_4_6: Rates = (3_000_000, 15_000_000, 300_000, 3_750_000, 6_000_000);
    const HAIKU_4_5: Rates = (1_000_000, 5_000_000, 100_000, 1_250_000, 2_000_000);
    // Regional / multi-region endpoint: list plus 10 percent, by hand.
    const FABLE_5_1_R: Rates = (11_000_000, 55_000_000, 275_000, 13_750_000, 22_000_000);
    const FABLE_5_R: Rates = (11_000_000, 55_000_000, 1_100_000, 13_750_000, 22_000_000);
    const OPUS_5_5_R: Rates = (4_400_000, 22_000_000, 220_000, 5_500_000, 8_800_000);
    const OPUS_5_R: Rates = (5_500_000, 27_500_000, 550_000, 6_875_000, 11_000_000);
    const SONNET_5_R: Rates = (2_200_000, 11_000_000, 220_000, 2_750_000, 4_400_000);
    const SONNET_4_6_R: Rates = (3_300_000, 16_500_000, 330_000, 4_125_000, 6_600_000);
    const HAIKU_4_5_R: Rates = (1_100_000, 5_500_000, 110_000, 1_375_000, 2_200_000);

    fn expected_rows() -> Vec<(&'static str, Rates)> {
        vec![
            // Claude API ids (also the Google Cloud and Foundry id for the
            // dateless models).
            ("claude-fable-5-1", FABLE_5_1),
            ("claude-fable-5", FABLE_5),
            ("claude-opus-5-5", OPUS_5_5),
            ("claude-opus-5", OPUS_5),
            ("claude-opus-4-8", OPUS_5),
            ("claude-opus-4-7", OPUS_5),
            ("claude-opus-4-6", OPUS_5),
            ("claude-opus-4-5", OPUS_5),
            ("claude-opus-4-5-20251101", OPUS_5),
            ("claude-sonnet-5-5", SONNET_5),
            ("claude-sonnet-5", SONNET_5),
            ("claude-sonnet-4-6", SONNET_4_6),
            ("claude-sonnet-4-5", SONNET_4_6),
            ("claude-sonnet-4-5-20250929", SONNET_4_6),
            ("claude-haiku-4-5", HAIKU_4_5),
            ("claude-haiku-4-5-20251001", HAIKU_4_5),
            // Google Cloud dated ids: endpoint not visible in the id, so the
            // regional / multi-region rate.
            ("claude-opus-4-5@20251101", OPUS_5_R),
            ("claude-sonnet-4-5@20250929", SONNET_4_6_R),
            ("claude-haiku-4-5@20251001", HAIKU_4_5_R),
            // Amazon Bedrock Messages-API ids: endpoint not visible in the id.
            ("anthropic.claude-fable-5-1", FABLE_5_1_R),
            ("anthropic.claude-fable-5", FABLE_5_R),
            ("anthropic.claude-opus-5-5", OPUS_5_5_R),
            ("anthropic.claude-opus-5", OPUS_5_R),
            ("anthropic.claude-opus-4-8", OPUS_5_R),
            ("anthropic.claude-opus-4-7", OPUS_5_R),
            ("anthropic.claude-sonnet-5-5", SONNET_5_R),
            ("anthropic.claude-sonnet-5", SONNET_5_R),
            ("anthropic.claude-haiku-4-5", HAIKU_4_5_R),
            // Amazon Bedrock InvokeModel base ids and inference profiles.
            ("anthropic.claude-opus-4-6-v1", OPUS_5_R),
            ("global.anthropic.claude-opus-4-6-v1", OPUS_5),
            ("us.anthropic.claude-opus-4-6-v1", OPUS_5_R),
            ("eu.anthropic.claude-opus-4-6-v1", OPUS_5_R),
            ("jp.anthropic.claude-opus-4-6-v1", OPUS_5_R),
            ("apac.anthropic.claude-opus-4-6-v1", OPUS_5_R),
            ("anthropic.claude-opus-4-5-20251101-v1:0", OPUS_5_R),
            ("global.anthropic.claude-opus-4-5-20251101-v1:0", OPUS_5),
            ("us.anthropic.claude-opus-4-5-20251101-v1:0", OPUS_5_R),
            ("eu.anthropic.claude-opus-4-5-20251101-v1:0", OPUS_5_R),
            ("anthropic.claude-sonnet-4-6", SONNET_4_6_R),
            ("global.anthropic.claude-sonnet-4-6", SONNET_4_6),
            ("us.anthropic.claude-sonnet-4-6", SONNET_4_6_R),
            ("eu.anthropic.claude-sonnet-4-6", SONNET_4_6_R),
            ("jp.anthropic.claude-sonnet-4-6", SONNET_4_6_R),
            ("anthropic.claude-sonnet-4-5-20250929-v1:0", SONNET_4_6_R),
            (
                "global.anthropic.claude-sonnet-4-5-20250929-v1:0",
                SONNET_4_6,
            ),
            ("us.anthropic.claude-sonnet-4-5-20250929-v1:0", SONNET_4_6_R),
            ("eu.anthropic.claude-sonnet-4-5-20250929-v1:0", SONNET_4_6_R),
            ("jp.anthropic.claude-sonnet-4-5-20250929-v1:0", SONNET_4_6_R),
            ("anthropic.claude-haiku-4-5-20251001-v1:0", HAIKU_4_5_R),
            ("global.anthropic.claude-haiku-4-5-20251001-v1:0", HAIKU_4_5),
            ("us.anthropic.claude-haiku-4-5-20251001-v1:0", HAIKU_4_5_R),
            ("eu.anthropic.claude-haiku-4-5-20251001-v1:0", HAIKU_4_5_R),
            // OpenRouter ids.
            ("anthropic/claude-sonnet-5", SONNET_5),
            ("anthropic/claude-sonnet-5.5", SONNET_5),
            ("anthropic/claude-opus-5.5", OPUS_5_5),
            ("anthropic/claude-opus-5", OPUS_5),
            ("anthropic/claude-opus-4.8", OPUS_5),
            ("anthropic/claude-sonnet-4.6", SONNET_4_6),
        ]
    }

    /// Every id the vendors list resolves by an exact row, at the vendor's
    /// rate, never at the fallback (tokenfuse#305, #313).
    #[test]
    fn every_vendor_listed_id_prices_at_its_list_rate() {
        let book = default_price_book();
        let mut wrong = Vec::new();
        for (id, (i, o, r, w, w1h)) in expected_rows() {
            if !book.is_known(id) {
                wrong.push(format!("{id}: no row, priced at the fallback"));
                continue;
            }
            let p = book.price(id).unwrap();
            let got = (
                p.input_per_mtok.0,
                p.output_per_mtok.0,
                p.cache_read_per_mtok.0,
                p.cache_write_per_mtok.0,
                p.cache_write_1h_per_mtok.0,
            );
            if got != (i, o, r, w, w1h) {
                wrong.push(format!(
                    "{id}: got {got:?}, list is {:?}",
                    (i, o, r, w, w1h)
                ));
            }
        }
        assert!(
            wrong.is_empty(),
            "{} ids wrong:\n{}",
            wrong.len(),
            wrong.join("\n")
        );
    }

    /// The call #305 measured: 2874 input and 200 output tokens on
    /// claude-sonnet-5 settled at 0.05811 (the 15/75 fallback). At the list
    /// rate (2/10) it is 5748 + 2000 = 7748 micro-USD.
    #[test]
    fn the_measured_sonnet_5_call_settles_at_list_not_the_fallback() {
        let usage = Usage {
            input_tokens: 2874,
            output_tokens: 200,
            ..Default::default()
        };
        let book = default_price_book();
        assert_eq!(book.cost("claude-sonnet-5", &usage), Some(Microusd(7748)));
        assert_eq!(
            book.cost("anthropic/claude-sonnet-5", &usage),
            Some(Microusd(7748))
        );
    }

    /// A model nobody has priced still says so: no invented row, the
    /// conservative fallback, and `is_known` false (which is what makes the
    /// gateway answer `x-fuse-price: fallback`).
    #[test]
    fn a_truly_unknown_id_still_falls_back() {
        let book = default_price_book();
        for id in [
            "claude-sonnet-6",
            "anthropic.claude-sonnet-5-v9",
            "openrouter/auto",
            "",
        ] {
            assert!(!book.is_known(id), "{id} must not have a row");
            assert_eq!(
                book.price(id)
                    .map(|p| (p.input_per_mtok.0, p.output_per_mtok.0)),
                Some((15_000_000, 75_000_000)),
                "{id} must price at the fallback"
            );
        }
    }

    /// ADR-8 over the whole book: no row is dearer than the fallback in any
    /// column, so an unknown model is never priced below a known one.
    ///
    /// One exception, and it predates this test: `o1`'s cached input (7.50)
    /// is above the fallback's cache read (1.50). Written down rather than
    /// fixed here, because raising the fallback moves the price of every
    /// unknown model; it is named so that no new row can join it silently.
    #[test]
    fn the_fallback_is_at_least_every_row_in_every_column() {
        let book = default_price_book();
        let f = book.fallback().unwrap();
        for (id, p) in book.entries() {
            assert!(p.input_per_mtok <= f.input_per_mtok, "{id} input");
            assert!(p.output_per_mtok <= f.output_per_mtok, "{id} output");
            assert!(
                id == "o1" || p.cache_read_per_mtok <= f.cache_read_per_mtok,
                "{id} read"
            );
            assert!(
                p.cache_write_per_mtok <= f.cache_write_per_mtok,
                "{id} write"
            );
            assert!(
                p.cache_write_1h_per_mtok <= f.cache_write_1h_per_mtok,
                "{id} write 1h"
            );
        }
    }

    #[test]
    fn opus_4_5_is_the_most_expensive_entry_the_fallback_stays_conservative() {
        // ADR-8: the fallback should remain at least as expensive as any
        // known model, so an unrecognized model is never under-reserved
        // relative to what we do know how to price.
        let book = default_price_book();
        let usage = Usage {
            input_tokens: 1_000_000,
            output_tokens: 1_000_000,
            ..Default::default()
        };
        let opus_cost = book.cost("claude-opus-4-5", &usage).unwrap();
        let fallback_cost = book.cost("truly-unknown-model", &usage).unwrap();
        assert!(fallback_cost >= opus_cost);
    }
}
