//! Default price book shipped with the gateway binary.
//!
//! Pulled out of `main.rs` so it's unit-testable: the goal is to catch a
//! units mistake (a 1e6 error turns a milli-dollar estimate into a
//! multi-thousand-dollar one) before it ships, and to pin which models
//! resolve via an exact price-book entry vs. the conservative fallback
//! (`x-fuse-price: known` vs `fallback`, see `proxy.rs`).
//!
//! Every row below names the page its rate was read from and the date it was
//! read. A rate in this file is a claim about somebody else's
//! price list, true on that date: when a vendor moves a price, the row is
//! wrong until somebody reads the page again. An operator who cannot wait
//! for a release overrides any row with `TOKENFUSE_PRICE_BOOK`
//! (`crate::pricefile`).
//!
//! **A model may carry one long-prompt rate (invariant 99).** Where a vendor
//! sells a model at two rates by prompt length (Claude Haiku 5.5 above
//! 100,000 prompt tokens, OpenAI's tiered models above 272K, Gemini 2.5 Pro
//! and 3.1 Pro Preview above 200K), the row is the short rate and the tier is
//! the long one; a call whose prompt (input, cache reads and cache writes) is
//! above the threshold is priced whole, output included, at the long rate
//! (`PriceBook::cost`). Until 2026-10-13 the book held one rate per model and
//! the only safe row for a tiered model was the dearer tier, which over-charged
//! every short call.
//!
//! **Dated prices.** The book has no effective date. Where a vendor publishes
//! two dated rates for one id (an introductory or promotional price beside the
//! standard one), the row is the dearer, so passing the date can never leave a
//! row under-charging. DeepSeek bills by time of day; the row is the peak rate.

use tokenfuse_core::{LongContext, Microusd, ModelPrice, PriceBook};

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
    /// The long-prompt rate and the prompt length it starts ABOVE, same
    /// columns as `rate`; a regional id's tier is list plus 10 percent too.
    long: Option<(u64, (f64, f64, f64, f64))>,
}

/// Anthropic's model lineup on 2026-10-13 and the ids each model answers to.
///
/// Rates: <https://platform.claude.com/docs/en/about-claude/pricing>, "Model
/// pricing" and "Long context pricing", read 2026-10-07 and again 2026-10-13
/// (Sonnet 5.5's cache hits, Haiku 5.5 and its prompt-length tier; every
/// other rate re-confirmed). Haiku 5.5's ids:
/// <https://platform.claude.com/docs/en/about-claude/models/overview>, read
/// 2026-10-13; its OpenRouter id `anthropic/claude-haiku-5.5` at the list
/// rate as every global endpoint on its OpenRouter endpoints page listed it. Claude API ids:
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
        long: None,
    },
    // Claude Fable 5: 10 / 50, cache hits 1, writes 12.50 / 20.
    Claude {
        rate: (10.00, 50.00, 1.00, 12.50),
        list: &["claude-fable-5"],
        regional: &["anthropic.claude-fable-5"],
        long: None,
    },
    // Claude Opus 5.5: 4 / 20, cache hits 0.20 (0.05x), writes 5 / 8.
    Claude {
        rate: (4.00, 20.00, 0.20, 5.00),
        list: &["claude-opus-5-5", "anthropic/claude-opus-5.5"],
        regional: &["anthropic.claude-opus-5-5"],
        long: None,
    },
    // Claude Opus 5: 5 / 25, cache hits 0.50, writes 6.25 / 10.
    Claude {
        rate: (5.00, 25.00, 0.50, 6.25),
        list: &["claude-opus-5", "anthropic/claude-opus-5"],
        regional: &["anthropic.claude-opus-5"],
        long: None,
    },
    // Claude Opus 4.8: as Opus 5.
    Claude {
        rate: (5.00, 25.00, 0.50, 6.25),
        list: &["claude-opus-4-8", "anthropic/claude-opus-4.8"],
        regional: &["anthropic.claude-opus-4-8"],
        long: None,
    },
    // Claude Opus 4.7: as Opus 5.
    Claude {
        rate: (5.00, 25.00, 0.50, 6.25),
        list: &["claude-opus-4-7"],
        regional: &["anthropic.claude-opus-4-7"],
        long: None,
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
        long: None,
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
        long: None,
    },
    // Claude Sonnet 5.5: 2 / 10, cache hits 0.10 (footnote 2: "Cache hits and
    // refreshes on Claude Opus 5.5 and Claude Sonnet 5.5 are priced at 0.05x
    // the base input price"), writes 2.50 / 4. Read 2026-10-13; until then this
    // row shared Sonnet 5's 0.20.
    Claude {
        rate: (2.00, 10.00, 0.10, 2.50),
        list: &["claude-sonnet-5-5", "anthropic/claude-sonnet-5.5"],
        regional: &["anthropic.claude-sonnet-5-5"],
        long: None,
    },
    // Claude Sonnet 5: 2 / 10, cache hits 0.20, writes 2.50 / 4. The page's footnote: the 2 / 10
    // launch price "is now the standard price" and the increase to 3 / 15
    // scheduled for 2026-09-01 "will not occur". tokenfuse#305 assumed 3 / 15.
    Claude {
        rate: (2.00, 10.00, 0.20, 2.50),
        list: &["claude-sonnet-5", "anthropic/claude-sonnet-5"],
        regional: &["anthropic.claude-sonnet-5"],
        long: None,
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
        long: None,
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
        long: None,
    },
    // Claude Haiku 5.5, priced by prompt length: up to 100,000 tokens 0.10 /
    // 0.50, cache hits 0.01, writes 0.125 / 0.20; over 100,000, 0.50 / 2.50,
    // 0.05, 0.625 / 1. "A request's prompt length counts all of its input
    // tokens, including cache reads and cache writes. Each request is priced
    // on its own: a request over the threshold pays the higher prices". The
    // same id on the Claude API, Google Cloud and Foundry; Bedrock
    // `anthropic.claude-haiku-5-5` (endpoint not in the id: list plus 10
    // percent on both tiers).
    Claude {
        rate: (0.10, 0.50, 0.01, 0.125),
        list: &["claude-haiku-5-5", "anthropic/claude-haiku-5.5"],
        regional: &["anthropic.claude-haiku-5-5"],
        long: Some((100_000, (0.50, 2.50, 0.05, 0.625))),
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
        long: None,
    },
];

/// A Gemini rate: input, output, cached input, micro-USD per Mtok.
type GeminiRate = (i64, i64, i64);

/// Gemini on Vertex AI, by the id Vertex AI's OpenAI-compatible endpoint
/// takes (`model: "google/<model id>"` on `.../endpoints/openapi/chat/completions`):
/// micro-USD per Mtok, `(id, base, long-prompt tier)`, each `(input, output,
/// cached input)`.
///
/// Rates: <https://cloud.google.com/vertex-ai/generative-ai/pricing>, which
/// redirects to
/// <https://cloud.google.com/gemini-enterprise-agent-platform/generative-ai/pricing>,
/// tables "Gemini 3" and "Gemini 2.5", the Standard tab, read 2026-10-08.
/// Which models are current: the "Model versions" page
/// (<https://cloud.google.com/vertex-ai/generative-ai/docs/learn/model-versions>,
/// read 2026-10-08), its stable and shorter-term tables; the `google/` id
/// form: "Access Gemini models using OpenAI libraries"
/// (<https://cloud.google.com/vertex-ai/generative-ai/docs/start/openai>),
/// read the same day. Gemini 2.5 Flash at 0.30 / 2.50 / 0.03 agrees with the
/// reading of 2026-10-07 that invariant 80 measured against.
///
/// How each row was chosen, all on the over-charging side (ADR-8):
/// - **Output** is the page's "Text output (response and reasoning)": Google
///   bills a thinking model's reasoning at the output rate (invariant 80).
/// - **Context-length tier.** Gemini 2.5 Pro and 3.1 Pro Preview have one
///   (2.5 Pro: 1.25 / 10.00 / 0.125 up to 200K input tokens, 2.50 / 15.00 /
///   0.25 above; the page says a query over 200K bills every token, output
///   included, at the higher rate). Since 2026-10-13 the row is the short rate
///   and the long one is the model's tier (invariant 99); until then the book
///   held one rate per model and the row was the higher tier.
/// - **Global and non-global.** The Gemini 3 rows list a "Global" rate and a
///   "Non-global" one 10 percent above it, in effect since 2026-07-01. The id
///   does not say which served the call (the location is in the URL), so the
///   row is the non-global rate, the rule invariant 79 applies to Claude on
///   the clouds. The Gemini 2.5 tables list one rate.
/// - **Introductory pricing.** Gemini 3.6, 3.7 and 3.8 Flash are "offered with
///   introductory pricing" of 0.75 / 3.75 through 2026-12-31, "provided
///   through 50% credits back on net spend"; the standard 1.50 / 7.50 (1.65 /
///   8.25 non-global) is the rate billed before the credit and the only one
///   from 2027-01-01. The row is the standard rate, so until the year ends it
///   is twice what the credit leaves.
/// - **Modality.** Rows price text input. Where a model lists audio input
///   above text (2.5 Flash 1.00, 2.5 Flash-Lite 0.30, 3.1 Flash-Lite 0.55
///   non-global) an audio prompt is under-charged; that operator sets the rate
///   in `TOKENFUSE_PRICE_BOOK`.
/// - **Cache.** Google charges no cache-write fee (a cache is created at the
///   input rate, then stored by the hour, which the book cannot price), so
///   both write columns are the input rate, as the OpenAI rows do.
///
/// Not here: Gemini 3 Flash Preview, whose output rate the page does not
/// show, the Live, image, text-to-speech and embedding models, the
/// retired Gemini 2.0 and 1.x models, and the bare ids the Gemini API takes,
/// whose own price list was not read.
const GEMINI: &[(&str, GeminiRate, Option<GeminiRate>)] = &[
    // Gemini 3.8 Flash: standard 1.50 / 7.50, cached 0.15 global;
    // 1.65 / 8.25, cached 0.165 non-global.
    (
        "google/gemini-3.8-flash",
        (1_650_000, 8_250_000, 165_000),
        None,
    ),
    // Gemini 3.8 Flash Cyber: as 3.8 Flash's standard rate.
    (
        "google/gemini-3.8-flash-cyber",
        (1_650_000, 8_250_000, 165_000),
        None,
    ),
    // Gemini 3.7 Flash, 3.6 Flash: as 3.8 Flash.
    (
        "google/gemini-3.7-flash",
        (1_650_000, 8_250_000, 165_000),
        None,
    ),
    (
        "google/gemini-3.6-flash",
        (1_650_000, 8_250_000, 165_000),
        None,
    ),
    // Gemini 3.5 Flash: 1.50 / 9.00, cached 0.15 global; 1.65 / 9.90 / 0.165.
    (
        "google/gemini-3.5-flash",
        (1_650_000, 9_900_000, 165_000),
        None,
    ),
    // Gemini 3.5 Flash-Lite: 0.30 / 2.50 / 0.03 global; 0.33 / 2.75 / 0.033.
    (
        "google/gemini-3.5-flash-lite",
        (330_000, 2_750_000, 33_000),
        None,
    ),
    // Gemini 3.1 Flash-Lite, text input: 0.25 / 1.50 / 0.025 global;
    // 0.275 / 1.65 / 0.0275 non-global.
    (
        "google/gemini-3.1-flash-lite",
        (275_000, 1_650_000, 27_500),
        None,
    ),
    // Gemini 3.1 Pro Preview (model id `gemini-3.1-pro-preview`, its page
    // <https://cloud.google.com/vertex-ai/generative-ai/docs/models/gemini/3-1-pro>),
    // read 2026-10-13. The page lists a Global row only, so that is the row:
    // <= 200K 2.00 / 12.00, cached 0.20; > 200K 4.00 / 18.00, cached 0.40.
    (
        "google/gemini-3.1-pro-preview",
        (2_000_000, 12_000_000, 200_000),
        Some((4_000_000, 18_000_000, 400_000)),
    ),
    // Gemini 2.5 Pro: <= 200K 1.25 / 10.00, cached 0.125; > 200K 2.50 /
    // 15.00, cached 0.25 (until 2026-10-13 the row was the > 200K rate alone).
    (
        "google/gemini-2.5-pro",
        (1_250_000, 10_000_000, 125_000),
        Some((2_500_000, 15_000_000, 250_000)),
    ),
    // Gemini 2.5 Flash, text input: 0.30 / 2.50, cached 0.03 (one tier).
    (
        "google/gemini-2.5-flash",
        (300_000, 2_500_000, 30_000),
        None,
    ),
    // Gemini 2.5 Flash-Lite, text input: 0.10 / 0.40, cached 0.01.
    (
        "google/gemini-2.5-flash-lite",
        (100_000, 400_000, 10_000),
        None,
    ),
];

/// Google's prompt-length threshold: "If a query input context is longer than
/// 200K tokens, all tokens (input and output) are charged at long context
/// rates." K read as 1000.
const GEMINI_LONG_ABOVE: u64 = 200_000;

/// Five columns in micro-USD per Mtok: input, output, cache read, 5-minute
/// cache write, 1-hour cache write.
type Rates = (i64, i64, i64, i64, i64);

/// OpenAI, Standard tier: `(id, short context, long context)`, the long rate
/// for a prompt above [`OPENAI_LONG_ABOVE`] input tokens.
///
/// Rates: <https://developers.openai.com/api/docs/pricing> (its markdown twin
/// at `.md`), read 2026-10-13; cache writes:
/// <https://developers.openai.com/api/docs/guides/prompt-caching> ("cache
/// writes on GPT-5.6 and later cost 1.25x input"). OpenAI has no 1-hour cache
/// tier, so the 1-hour column is the write rate; where the page shows "-" for
/// cache writes there is no write fee and the write rate is the input rate.
/// The page's regional-processing (data residency) uplift, +10 percent for
/// models released on or after 2026-03-05, is opt-in and not in the id, so it
/// is the operator file's job. "GPT-5.6 Sol's promotional pricing is available
/// at least through November 21, 2026" names no rate; the row is the table's
/// 4 / 20 (the dearer, and the only one written down).
const OPENAI: &[(&str, Rates, Option<Rates>)] = &[
    (
        "gpt-6-astra",
        (10_000_000, 50_000_000, 1_000_000, 12_500_000, 12_500_000),
        Some((20_000_000, 75_000_000, 2_000_000, 25_000_000, 25_000_000)),
    ),
    (
        "gpt-6.1-sol",
        (2_000_000, 10_000_000, 100_000, 2_500_000, 2_500_000),
        Some((4_000_000, 15_000_000, 200_000, 5_000_000, 5_000_000)),
    ),
    // Read 2026-10-28: 1.00 / 5.00, cached 0.05, 30m write 1.25; over 272K
    // 2.00 / 7.50, cached 0.10, 30m write 2.50. The page's "12h write" column
    // (2.50, and 5.00 over 272K) is not the 1-hour column here, as for every
    // row above: see the note on this table.
    (
        "gpt-6.1-terra",
        (1_000_000, 5_000_000, 50_000, 1_250_000, 1_250_000),
        Some((2_000_000, 7_500_000, 100_000, 2_500_000, 2_500_000)),
    ),
    (
        "gpt-6-sol",
        (2_000_000, 10_000_000, 200_000, 2_500_000, 2_500_000),
        Some((4_000_000, 15_000_000, 400_000, 5_000_000, 5_000_000)),
    ),
    (
        "gpt-6-luna",
        (100_000, 500_000, 10_000, 125_000, 125_000),
        Some((200_000, 750_000, 20_000, 250_000, 250_000)),
    ),
    (
        "gpt-5.6-sol",
        (4_000_000, 20_000_000, 400_000, 5_000_000, 5_000_000),
        Some((8_000_000, 30_000_000, 800_000, 10_000_000, 10_000_000)),
    ),
    (
        "gpt-5.6-terra",
        (2_000_000, 12_000_000, 200_000, 2_500_000, 2_500_000),
        Some((4_000_000, 18_000_000, 400_000, 5_000_000, 5_000_000)),
    ),
    (
        "gpt-5.6-luna",
        (200_000, 1_200_000, 20_000, 250_000, 250_000),
        Some((400_000, 1_800_000, 40_000, 500_000, 500_000)),
    ),
    (
        "gpt-5.5",
        (5_000_000, 30_000_000, 500_000, 5_000_000, 5_000_000),
        Some((10_000_000, 45_000_000, 1_000_000, 10_000_000, 10_000_000)),
    ),
    (
        "gpt-5.4",
        (2_500_000, 15_000_000, 250_000, 2_500_000, 2_500_000),
        Some((5_000_000, 22_500_000, 500_000, 5_000_000, 5_000_000)),
    ),
    // No long tier listed.
    (
        "gpt-5.4-mini",
        (750_000, 4_500_000, 75_000, 750_000, 750_000),
        None,
    ),
    // Re-confirmed unchanged on 2026-10-13: 2.50 / 10.00, cached 1.25.
    (
        "gpt-4o",
        (2_500_000, 10_000_000, 1_250_000, 2_500_000, 2_500_000),
        None,
    ),
    // 0.15 / 0.60, cached 0.075.
    (
        "gpt-4o-mini",
        (150_000, 600_000, 75_000, 150_000, 150_000),
        None,
    ),
    // The GPT-4.1 family, read 2026-10-14 from the same page: 2.00 / 8.00,
    // cached 0.50; mini 0.40 / 1.60, cached 0.10; nano 0.10 / 0.40, cached
    // 0.025. Cache writes "-", so the write columns are the input rate. No
    // long tier listed. Invariant 107.
    (
        "gpt-4.1",
        (2_000_000, 8_000_000, 500_000, 2_000_000, 2_000_000),
        None,
    ),
    (
        "gpt-4.1-mini",
        (400_000, 1_600_000, 100_000, 400_000, 400_000),
        None,
    ),
    (
        "gpt-4.1-nano",
        (100_000, 400_000, 25_000, 100_000, 100_000),
        None,
    ),
    // 15.00 / 60.00, cached 7.50.
    (
        "o1",
        (15_000_000, 60_000_000, 7_500_000, 15_000_000, 15_000_000),
        None,
    ),
];

/// OpenAI's prompt-length threshold, "long context (>272K input tokens)", K
/// read as 1000.
const OPENAI_LONG_ABOVE: u64 = 272_000;

/// The prefix OpenRouter names OpenAI's models with (`openai/gpt-4.1-mini`).
/// Every [`OPENAI`] id is also priced under it (invariant 107).
const OPENROUTER_OPENAI: &str = "openai/";

/// First-party APIs priced at their default (global) endpoint, one rate per
/// id, no write fee unless a column says so.
///
/// DeepSeek: <https://api-docs.deepseek.com/quick_start/pricing>, read
/// 2026-10-13. Off-peak is half of peak ("Peak hours are 01:00 - 04:00 and
/// 06:00 - 10:00 UTC, Monday through Friday, excluding Chinese public
/// holidays"); the book does not price by the clock, so the row is the PEAK
/// rate, the dearer. A cache miss is input, a hit is the cache read, and there
/// is no write fee. The legacy names `deepseek-v4-flash` and
/// `deepseek-v4-flash-vision-exp` "are still accepted ... billed at the Flash
/// price".
///
/// Moonshot: <https://platform.kimi.ai/docs/pricing/chat> (platform.moonshot.ai
/// redirects there), read 2026-10-13: cache write 3.00 for the 5-minute TTL and
/// 6.00 for the 1-hour.
///
/// Z.ai: <https://docs.z.ai/guides/overview/pricing>, ids from
/// <https://docs.z.ai/guides/llm/glm-5.3> and `.../glm-5.1`, read 2026-10-13.
/// No write fee is shown, and cached-input storage is "Limited-time Free".
///
/// Not here: OpenRouter's `moonshotai/kimi-k3` and `z-ai/glm-5.3`, which
/// dozens of providers serve at rates up to six times apart; the book cannot
/// see which one answered, so those ids keep the fallback.
const FIRST_PARTY: &[(&str, Rates)] = &[
    // DeepSeek-V4.1-Flash, peak: miss 0.30, hit 0.006, output 1.20.
    (
        "deepseek-flash",
        (300_000, 1_200_000, 6_000, 300_000, 300_000),
    ),
    (
        "deepseek-v4-flash",
        (300_000, 1_200_000, 6_000, 300_000, 300_000),
    ),
    (
        "deepseek-v4-flash-vision-exp",
        (300_000, 1_200_000, 6_000, 300_000, 300_000),
    ),
    // DeepSeek-V4-Pro, peak: miss 1.32, hit 0.044, output 3.96.
    (
        "deepseek-v4-pro",
        (1_320_000, 3_960_000, 44_000, 1_320_000, 1_320_000),
    ),
    // Kimi K3: 3.00 / 15.00, cached 0.30, writes 3.00 / 6.00.
    (
        "kimi-k3",
        (3_000_000, 15_000_000, 300_000, 3_000_000, 6_000_000),
    ),
    // GLM-5.3 and GLM-5.1: 1.40 / 4.40, cached 0.26.
    (
        "glm-5.3",
        (1_400_000, 4_400_000, 260_000, 1_400_000, 1_400_000),
    ),
    (
        "glm-5.1",
        (1_400_000, 4_400_000, 260_000, 1_400_000, 1_400_000),
    ),
];

/// A row from five integer columns.
fn rates(r: Rates) -> ModelPrice {
    ModelPrice {
        input_per_mtok: Microusd(r.0),
        output_per_mtok: Microusd(r.1),
        cache_read_per_mtok: Microusd(r.2),
        cache_write_per_mtok: Microusd(r.3),
        cache_write_1h_per_mtok: Microusd(r.4),
    }
}

/// A Gemini row: the two cache-write columns are the input rate (no write fee).
fn gemini(input: i64, output: i64, cached: i64) -> ModelPrice {
    ModelPrice {
        input_per_mtok: Microusd(input),
        output_per_mtok: Microusd(output),
        cache_read_per_mtok: Microusd(cached),
        cache_write_per_mtok: Microusd(input),
        cache_write_1h_per_mtok: Microusd(input),
    }
}

/// A regional or multi-region endpoint's rate: list plus 10 percent, in
/// integer micro-USD. Every list rate above, long-prompt tiers included
/// (Haiku 5.5's 0.01 and 0.125 are 10,000 and 125,000), is a whole multiple of
/// 10 micro-USD, so `* 11 / 10` is exact; the tests that write each figure out
/// by hand are what hold that.
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
/// every Gemini id in [`GEMINI`], every OpenAI id in [`OPENAI`] and every id
/// in [`FIRST_PARTY`], each with its long-prompt tier where the vendor lists
/// one, so common calls price exactly instead of falling back to the
/// conservative generic rate.
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
        // --- Conservative fallback for anything not listed (ADR-8): priced at
        // (a margin above) the most expensive known model, so an unrecognized
        // model never under-reserves. Opus 4.1's 15 / 75 is still sold on the
        // clouds; no base row is dearer in input or output. Two columns of two
        // rows exceed it (o1's cache read, gpt-6-astra's long tier), named in
        // `the_fallback_is_at_least_every_row_in_every_column`. ---
        .with_fallback(ModelPrice::per_mtok_usd(15.0, 75.0, 1.5, 18.75));
    // Anthropic. The 1M-token context window of the 4.6 generation and later
    // is priced at the standard rate except Haiku 5.5 (the pricing page, "Long
    // context pricing"); Sonnet 4.5's >200K tier is still not modeled here.
    for m in CLAUDE {
        let (i, o, r, w) = m.rate;
        let list = ModelPrice::per_mtok_usd(i, o, r, w);
        let long = m.long.map(|(above, (i, o, r, w))| LongContext {
            above_prompt_tokens: above,
            price: ModelPrice::per_mtok_usd(i, o, r, w),
        });
        for id in m.list {
            book.insert(*id, list);
            if let Some(t) = long {
                book.insert_long_context(id, t);
            }
        }
        for id in m.regional {
            book.insert(*id, regional(list));
            if let Some(t) = long {
                book.insert_long_context(
                    id,
                    LongContext {
                        above_prompt_tokens: t.above_prompt_tokens,
                        price: regional(t.price),
                    },
                );
            }
        }
    }
    // Google, on Vertex AI's OpenAI-compatible endpoint (see `GEMINI`).
    for (id, (i, o, r), long) in GEMINI {
        book.insert(*id, gemini(*i, *o, *r));
        if let Some((i, o, r)) = long {
            book.insert_long_context(
                id,
                LongContext {
                    above_prompt_tokens: GEMINI_LONG_ABOVE,
                    price: gemini(*i, *o, *r),
                },
            );
        }
    }
    // OpenAI (see `OPENAI`), each id also under its OpenRouter name,
    // `openai/<id>` (invariant 107). Unlike `moonshotai/kimi-k3` and
    // `z-ai/glm-5.3`, which dozens of providers serve at rates up to six
    // times apart, an `openai/` id names OpenAI's own model sold at OpenAI's
    // list, so the vendor's row is the honest price. `@claude` 2026-10-14. An
    // `openai/` id with no bare row stays at the fallback: nothing here maps a
    // name the book does not know.
    for (id, base, long) in OPENAI {
        for name in [id.to_string(), format!("{OPENROUTER_OPENAI}{id}")] {
            book.insert(name.as_str(), rates(*base));
            if let Some(l) = long {
                book.insert_long_context(
                    name.as_str(),
                    LongContext {
                        above_prompt_tokens: OPENAI_LONG_ABOVE,
                        price: rates(*l),
                    },
                );
            }
        }
    }
    // DeepSeek, Moonshot, Z.ai (see `FIRST_PARTY`).
    for (id, r) in FIRST_PARTY {
        book.insert(*id, rates(*r));
    }
    book
}

/// The word a call's price basis is named by, `known` when `book` has a row
/// for `model` and `fallback` when it was charged at the fallback rate.
/// The one definition behind the answer's `x-fuse-price` (invariant 79) and
/// the `price_basis` the Cloud is told (invariant 86), so the two cannot
/// disagree about the same call.
pub fn basis(book: &PriceBook, model: &str) -> &'static str {
    if book.is_known(model) {
        "known"
    } else {
        "fallback"
    }
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
    const FABLE_5_1: Rates = (10_000_000, 50_000_000, 250_000, 12_500_000, 20_000_000);
    const FABLE_5: Rates = (10_000_000, 50_000_000, 1_000_000, 12_500_000, 20_000_000);
    const OPUS_5_5: Rates = (4_000_000, 20_000_000, 200_000, 5_000_000, 8_000_000);
    const OPUS_5: Rates = (5_000_000, 25_000_000, 500_000, 6_250_000, 10_000_000);
    const SONNET_5_5: Rates = (2_000_000, 10_000_000, 100_000, 2_500_000, 4_000_000);
    const SONNET_5: Rates = (2_000_000, 10_000_000, 200_000, 2_500_000, 4_000_000);
    const SONNET_4_6: Rates = (3_000_000, 15_000_000, 300_000, 3_750_000, 6_000_000);
    const HAIKU_4_5: Rates = (1_000_000, 5_000_000, 100_000, 1_250_000, 2_000_000);
    // Haiku 5.5's base rate, prompts up to 100,000 tokens (read 2026-10-13).
    const HAIKU_5_5: Rates = (100_000, 500_000, 10_000, 125_000, 200_000);
    // Regional / multi-region endpoint: list plus 10 percent, by hand.
    const FABLE_5_1_R: Rates = (11_000_000, 55_000_000, 275_000, 13_750_000, 22_000_000);
    const FABLE_5_R: Rates = (11_000_000, 55_000_000, 1_100_000, 13_750_000, 22_000_000);
    const OPUS_5_5_R: Rates = (4_400_000, 22_000_000, 220_000, 5_500_000, 8_800_000);
    const OPUS_5_R: Rates = (5_500_000, 27_500_000, 550_000, 6_875_000, 11_000_000);
    const SONNET_5_5_R: Rates = (2_200_000, 11_000_000, 110_000, 2_750_000, 4_400_000);
    const SONNET_5_R: Rates = (2_200_000, 11_000_000, 220_000, 2_750_000, 4_400_000);
    const SONNET_4_6_R: Rates = (3_300_000, 16_500_000, 330_000, 4_125_000, 6_600_000);
    const HAIKU_4_5_R: Rates = (1_100_000, 5_500_000, 110_000, 1_375_000, 2_200_000);
    const HAIKU_5_5_R: Rates = (110_000, 550_000, 11_000, 137_500, 220_000);

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
            ("claude-sonnet-5-5", SONNET_5_5),
            ("claude-sonnet-5", SONNET_5),
            ("claude-sonnet-4-6", SONNET_4_6),
            ("claude-sonnet-4-5", SONNET_4_6),
            ("claude-sonnet-4-5-20250929", SONNET_4_6),
            ("claude-haiku-4-5", HAIKU_4_5),
            ("claude-haiku-4-5-20251001", HAIKU_4_5),
            ("claude-haiku-5-5", HAIKU_5_5),
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
            ("anthropic.claude-sonnet-5-5", SONNET_5_5_R),
            ("anthropic.claude-sonnet-5", SONNET_5_R),
            ("anthropic.claude-haiku-4-5", HAIKU_4_5_R),
            ("anthropic.claude-haiku-5-5", HAIKU_5_5_R),
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
            ("anthropic/claude-sonnet-5.5", SONNET_5_5),
            ("anthropic/claude-haiku-5.5", HAIKU_5_5),
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

    /// Gemini on Vertex AI's OpenAI-compatible endpoint, by the ids that
    /// endpoint takes (`google/<model id>`), micro-USD per Mtok, written out
    /// by hand from <https://cloud.google.com/vertex-ai/generative-ai/pricing>
    /// (which redirected to `.../gemini-enterprise-agent-platform/generative-ai/pricing`),
    /// read 2026-10-08. Google has no cache-write fee (a cache is created at
    /// the input rate and stored by the hour), so both write columns are the
    /// input rate. The Gemini 3 family is priced at its "Non-global" rate,
    /// because the id does not say which endpoint served it (the location is
    /// in the URL); Gemini 2.5 Pro's base rate is its "<= 200K" one, the
    /// "> 200K" one being its long-prompt tier (invariant 99); Gemini 3.6, 3.7 and 3.8 Flash at the standard rate, not
    /// the introductory one paid back as a credit.
    fn expected_gemini_rows() -> Vec<(&'static str, Rates)> {
        // (input, output, cached input, cache write, 1-hour cache write)
        let flash_3_8: Rates = (1_650_000, 8_250_000, 165_000, 1_650_000, 1_650_000);
        vec![
            ("google/gemini-3.8-flash", flash_3_8),
            ("google/gemini-3.8-flash-cyber", flash_3_8),
            ("google/gemini-3.7-flash", flash_3_8),
            ("google/gemini-3.6-flash", flash_3_8),
            (
                "google/gemini-3.5-flash",
                (1_650_000, 9_900_000, 165_000, 1_650_000, 1_650_000),
            ),
            (
                "google/gemini-3.5-flash-lite",
                (330_000, 2_750_000, 33_000, 330_000, 330_000),
            ),
            (
                "google/gemini-3.1-flash-lite",
                (275_000, 1_650_000, 27_500, 275_000, 275_000),
            ),
            (
                "google/gemini-2.5-pro",
                (1_250_000, 10_000_000, 125_000, 1_250_000, 1_250_000),
            ),
            (
                "google/gemini-2.5-flash",
                (300_000, 2_500_000, 30_000, 300_000, 300_000),
            ),
            (
                "google/gemini-2.5-flash-lite",
                (100_000, 400_000, 10_000, 100_000, 100_000),
            ),
        ]
    }

    /// Every current Gemini text model sold on Vertex AI resolves by an exact
    /// row at its rate. Before this, each one settled at the 15 / 75
    /// fallback unless an operator file named it (invariant 80's note).
    #[test]
    fn every_gemini_id_on_vertex_prices_at_its_list_rate() {
        let book = default_price_book();
        let mut wrong = Vec::new();
        for (id, want) in expected_gemini_rows() {
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
            if got != want {
                wrong.push(format!("{id}: got {got:?}, list is {want:?}"));
            }
        }
        assert!(
            wrong.is_empty(),
            "{} ids wrong:\n{}",
            wrong.len(),
            wrong.join("\n")
        );
    }

    /// The call invariant 80 measured on 2026-10-07 through Vertex AI's
    /// OpenAI-compatible endpoint: google/gemini-2.5-flash, 14 input tokens
    /// and 619 output (59 visible, 560 reasoning). At 0.30 / 2.50 per Mtok
    /// that is 4.2 + 1547.5 = 1551.7 micro-USD, rounded up once to 1552
    /// (invariant 67). At the 15 / 75 fallback it was 210 + 46425 = 46635.
    #[test]
    fn the_measured_vertex_gemini_call_settles_at_list_not_the_fallback() {
        let usage = Usage {
            input_tokens: 14,
            output_tokens: 619,
            ..Default::default()
        };
        let book = default_price_book();
        assert_eq!(
            book.cost("google/gemini-2.5-flash", &usage),
            Some(Microusd(1552))
        );
    }

    /// Gemini 2.5 Pro is listed at 1.25 / 10.00, cached 0.125, up to 200K
    /// input tokens and 2.50 / 15.00, cached 0.25, above, where every token of
    /// the query is billed at the higher rate. Until invariant 99 the book held
    /// the higher tier alone; now a short call pays the short rate. 10000 input
    /// and 1000 output: 12500 + 10000 = 22500 micro-USD (40000 at the long
    /// rate). 250000 input and 1000 output: 625000 + 15000 = 640000.
    #[test]
    fn gemini_2_5_pro_is_priced_by_its_prompt_length() {
        let book = default_price_book();
        let short = Usage {
            input_tokens: 10_000,
            output_tokens: 1_000,
            ..Default::default()
        };
        let long = Usage {
            input_tokens: 250_000,
            output_tokens: 1_000,
            ..Default::default()
        };
        assert_eq!(
            book.cost("google/gemini-2.5-pro", &short),
            Some(Microusd(22_500))
        );
        assert_eq!(
            book.cost("google/gemini-2.5-pro", &long),
            Some(Microusd(640_000))
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

    /// Every id invariant 99 added, at its BASE rate, written out by hand from
    /// the vendors' pages read 2026-10-13 (see the tables above for each URL).
    /// (input, output, cache read, cache write, 1-hour cache write).
    fn expected_new_rows() -> Vec<(&'static str, Rates)> {
        vec![
            // OpenAI, Standard tier, short context (<= 272K input tokens). No
            // 1-hour tier: the 1-hour column is the write rate. "-" for cache
            // writes means no write fee, so the write rate is the input rate.
            (
                "gpt-6-astra",
                (10_000_000, 50_000_000, 1_000_000, 12_500_000, 12_500_000),
            ),
            (
                "gpt-6.1-sol",
                (2_000_000, 10_000_000, 100_000, 2_500_000, 2_500_000),
            ),
            // Read 2026-10-28: 1.00 / 5.00, cached 0.05, 30m write 1.25.
            (
                "gpt-6.1-terra",
                (1_000_000, 5_000_000, 50_000, 1_250_000, 1_250_000),
            ),
            (
                "gpt-6-sol",
                (2_000_000, 10_000_000, 200_000, 2_500_000, 2_500_000),
            ),
            ("gpt-6-luna", (100_000, 500_000, 10_000, 125_000, 125_000)),
            (
                "gpt-5.6-sol",
                (4_000_000, 20_000_000, 400_000, 5_000_000, 5_000_000),
            ),
            (
                "gpt-5.6-terra",
                (2_000_000, 12_000_000, 200_000, 2_500_000, 2_500_000),
            ),
            (
                "gpt-5.6-luna",
                (200_000, 1_200_000, 20_000, 250_000, 250_000),
            ),
            (
                "gpt-5.5",
                (5_000_000, 30_000_000, 500_000, 5_000_000, 5_000_000),
            ),
            (
                "gpt-5.4",
                (2_500_000, 15_000_000, 250_000, 2_500_000, 2_500_000),
            ),
            (
                "gpt-5.4-mini",
                (750_000, 4_500_000, 75_000, 750_000, 750_000),
            ),
            // Re-confirmed, unchanged.
            (
                "gpt-4o",
                (2_500_000, 10_000_000, 1_250_000, 2_500_000, 2_500_000),
            ),
            ("gpt-4o-mini", (150_000, 600_000, 75_000, 150_000, 150_000)),
            (
                "o1",
                (15_000_000, 60_000_000, 7_500_000, 15_000_000, 15_000_000),
            ),
            // DeepSeek, the PEAK rate (cache miss = input, hit = cache read,
            // no write fee).
            (
                "deepseek-flash",
                (300_000, 1_200_000, 6_000, 300_000, 300_000),
            ),
            (
                "deepseek-v4-flash",
                (300_000, 1_200_000, 6_000, 300_000, 300_000),
            ),
            (
                "deepseek-v4-flash-vision-exp",
                (300_000, 1_200_000, 6_000, 300_000, 300_000),
            ),
            (
                "deepseek-v4-pro",
                (1_320_000, 3_960_000, 44_000, 1_320_000, 1_320_000),
            ),
            // Moonshot: cache write 5-minute 3.00, 1-hour 6.00.
            (
                "kimi-k3",
                (3_000_000, 15_000_000, 300_000, 3_000_000, 6_000_000),
            ),
            // Z.ai: no write fee shown.
            (
                "glm-5.3",
                (1_400_000, 4_400_000, 260_000, 1_400_000, 1_400_000),
            ),
            (
                "glm-5.1",
                (1_400_000, 4_400_000, 260_000, 1_400_000, 1_400_000),
            ),
            // Gemini 3.1 Pro Preview, <= 200K, the Global row (the only one listed).
            (
                "google/gemini-3.1-pro-preview",
                (2_000_000, 12_000_000, 200_000, 2_000_000, 2_000_000),
            ),
        ]
    }

    /// Every id added on 2026-10-13 has a row at the vendor's base rate. On
    /// the book before it each one settled at the 15 / 75 fallback.
    /// Invariant 107: every OpenAI row is also the price of its OpenRouter
    /// name, the long tier included, and the prefix maps nothing the book does
    /// not know.
    #[test]
    fn every_openai_id_is_priced_under_its_openrouter_name_too() {
        let book = default_price_book();
        let long = Usage {
            input_tokens: 300_000,
            output_tokens: 1_000,
            ..Default::default()
        };
        let short = Usage {
            input_tokens: 14,
            output_tokens: 2,
            ..Default::default()
        };
        for (id, _, _) in OPENAI {
            let alias = format!("openai/{id}");
            assert!(book.is_known(&alias), "{alias}");
            assert_eq!(book.price(&alias), book.price(id), "{alias}");
            assert_eq!(book.cost(&alias, &long), book.cost(id, &long), "{alias}");
            assert_eq!(book.cost(&alias, &short), book.cost(id, &short), "{alias}");
        }
        assert!(!book.is_known("openai/gpt-9-turbo"));
        assert!(!book.is_known("openai/"));
        assert!(
            !book.is_known("moonshotai/kimi-k3"),
            "a many-seller id keeps the fallback"
        );
    }

    /// Invariant 107: the GPT-4.1 family at OpenAI's list, read 2026-10-14,
    /// and the forge call (14 in, 2 out on `openai/gpt-4.1-mini`) at 9
    /// micro-USD where the fallback charged 360.
    #[test]
    fn the_gpt_4_1_family_is_priced_at_its_list_rate() {
        let book = default_price_book();
        let rate = |id: &str| {
            let p = book.price(id).unwrap();
            (
                p.input_per_mtok.0,
                p.output_per_mtok.0,
                p.cache_read_per_mtok.0,
                p.cache_write_per_mtok.0,
            )
        };
        assert_eq!(rate("gpt-4.1"), (2_000_000, 8_000_000, 500_000, 2_000_000));
        assert_eq!(rate("gpt-4.1-mini"), (400_000, 1_600_000, 100_000, 400_000));
        assert_eq!(rate("gpt-4.1-nano"), (100_000, 400_000, 25_000, 100_000));
        let forge = Usage {
            input_tokens: 14,
            output_tokens: 2,
            ..Default::default()
        };
        assert_eq!(book.cost("openai/gpt-4.1-mini", &forge), Some(Microusd(9)));
    }

    #[test]
    fn every_new_vendor_id_prices_at_its_list_rate_never_the_fallback() {
        let book = default_price_book();
        let mut wrong = Vec::new();
        for (id, want) in expected_new_rows() {
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
            if got != want {
                wrong.push(format!("{id}: got {got:?}, list is {want:?}"));
            }
        }
        assert!(
            wrong.is_empty(),
            "{} ids wrong:\n{}",
            wrong.len(),
            wrong.join("\n")
        );
    }

    /// Anthropic's footnote: cache hits on Opus 5.5 and Sonnet 5.5 are 0.05x
    /// base input, so Sonnet 5.5's is 0.10, not the 0.20 Sonnet 5 pays. The
    /// regional endpoint is 0.11.
    #[test]
    fn sonnet_5_5_cache_hits_are_five_percent_of_input() {
        let book = default_price_book();
        let read = |id: &str| book.price(id).unwrap().cache_read_per_mtok;
        assert_eq!(read("claude-sonnet-5-5"), Microusd(100_000));
        assert_eq!(read("anthropic/claude-sonnet-5.5"), Microusd(100_000));
        assert_eq!(read("anthropic.claude-sonnet-5-5"), Microusd(110_000));
        assert_eq!(
            read("claude-sonnet-5"),
            Microusd(200_000),
            "Sonnet 5 is unchanged"
        );
    }

    /// claude-haiku-5-5, 1000 input and 500 output, a short prompt: 1000 x
    /// 0.10 + 500 x 0.50 = 100 + 250 = 350 micro-USD. At the 15 / 75 fallback
    /// it was 15000 + 37500 = 52500.
    #[test]
    fn a_haiku_5_5_short_call_is_priced_at_its_base_rate() {
        let book = default_price_book();
        let usage = Usage {
            input_tokens: 1000,
            output_tokens: 500,
            ..Default::default()
        };
        assert_eq!(book.cost("claude-haiku-5-5", &usage), Some(Microusd(350)));
        assert_eq!(
            book.cost("anthropic/claude-haiku-5.5", &usage),
            Some(Microusd(350))
        );
        // Bedrock's bare id, the regional rate: 110 + 275 = 385.
        assert_eq!(
            book.cost("anthropic.claude-haiku-5-5", &usage),
            Some(Microusd(385))
        );
    }

    /// claude-haiku-5-5, 150000 input and 1000 output: over 100,000, so every
    /// token at 0.50 / 2.50: 75000 + 2500 = 77500 micro-USD (not 15500 at the
    /// base rate). Bedrock's bare id: list plus 10 percent on the long tier
    /// too, 82500 + 2750 = 85250.
    #[test]
    fn a_haiku_5_5_long_call_is_priced_at_its_long_rate() {
        let book = default_price_book();
        let usage = Usage {
            input_tokens: 150_000,
            output_tokens: 1_000,
            ..Default::default()
        };
        assert_eq!(
            book.cost("claude-haiku-5-5", &usage),
            Some(Microusd(77_500))
        );
        assert_eq!(
            book.cost("anthropic.claude-haiku-5-5", &usage),
            Some(Microusd(85_250))
        );
    }

    /// gpt-6.1-sol, 300000 input and 1000 output: over 272K, so 4 / 15:
    /// 1,200,000 + 15,000 = 1,215,000 micro-USD.
    #[test]
    fn a_gpt_6_1_sol_long_call_is_priced_at_its_long_rate() {
        let book = default_price_book();
        let usage = Usage {
            input_tokens: 300_000,
            output_tokens: 1_000,
            ..Default::default()
        };
        assert_eq!(book.cost("gpt-6.1-sol", &usage), Some(Microusd(1_215_000)));
    }

    /// gpt-6.1-terra is a current OpenAI model (its page lists it, read
    /// 2026-10-28), so it is priced at its own row and not at the fallback's
    /// 15 / 75. Short call, 100000 input and 10000 output at 1 / 5:
    /// 100,000 + 50,000 = 150,000 micro-USD. Long call, 300000 input and 1000
    /// output, over 272K, at 2 / 7.5: 600,000 + 7,500 = 607,500 micro-USD. The
    /// OpenRouter name is the same price.
    #[test]
    fn gpt_6_1_terra_is_priced_at_its_own_row_not_the_fallback() {
        let book = default_price_book();
        let short = Usage {
            input_tokens: 100_000,
            output_tokens: 10_000,
            ..Default::default()
        };
        let long = Usage {
            input_tokens: 300_000,
            output_tokens: 1_000,
            ..Default::default()
        };
        for id in ["gpt-6.1-terra", "openai/gpt-6.1-terra"] {
            assert!(book.is_known(id), "{id}");
            assert_eq!(book.cost(id, &short), Some(Microusd(150_000)), "{id}");
            assert_eq!(book.cost(id, &long), Some(Microusd(607_500)), "{id}");
        }
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

    /// ADR-8 over the whole book, long-prompt tiers included: no row and no
    /// tier is dearer than the fallback in any column, so an unknown model is
    /// never priced below a known one.
    ///
    /// Named exceptions, each written down rather than fixed by raising the
    /// fallback, because that moves the price of every unknown model: `o1`'s
    /// cached input (7.50 against 1.50), which predates this test, and
    /// gpt-6-astra's long tier (input 20, cache read 2.00, cache write 25
    /// against 15 / 1.50 / 18.75), added 2026-10-13. Every other cell is
    /// checked, so no new row or tier can join them silently.
    #[test]
    fn the_fallback_is_at_least_every_row_in_every_column() {
        let book = default_price_book();
        let f = book.fallback().unwrap();
        // Invariant 107: an `openai/` row is the OpenAI row it copies, so it
        // carries the same exceptions.
        let exception = |id: &str, column: &str| {
            let id = id.strip_prefix(OPENROUTER_OPENAI).unwrap_or(id);
            matches!(
                (id, column),
                ("o1", "read")
                    | ("gpt-6-astra long", "input")
                    | ("gpt-6-astra long", "read")
                    | ("gpt-6-astra long", "write")
            )
        };
        let mut rows: Vec<(String, ModelPrice)> = book
            .entries()
            .into_iter()
            .map(|(id, p)| (id.to_string(), p))
            .collect();
        rows.extend(
            book.long_context_entries()
                .into_iter()
                .map(|(id, t)| (format!("{id} long"), t.price)),
        );
        let mut over = Vec::new();
        for (id, p) in &rows {
            for (column, got, cap) in [
                ("input", p.input_per_mtok, f.input_per_mtok),
                ("output", p.output_per_mtok, f.output_per_mtok),
                ("read", p.cache_read_per_mtok, f.cache_read_per_mtok),
                ("write", p.cache_write_per_mtok, f.cache_write_per_mtok),
                (
                    "write 1h",
                    p.cache_write_1h_per_mtok,
                    f.cache_write_1h_per_mtok,
                ),
            ] {
                if got > cap && !exception(id, column) {
                    over.push(format!("{id} {column}: {} > {}", got.0, cap.0));
                }
            }
        }
        assert!(over.is_empty(), "above the fallback:\n{}", over.join("\n"));
        // The exceptions are real, so a stale entry does not sit here forever.
        let astra = book.long_context("gpt-6-astra").unwrap().price;
        assert!(astra.input_per_mtok > f.input_per_mtok);
        assert!(book.price("o1").unwrap().cache_read_per_mtok > f.cache_read_per_mtok);
    }

    /// Every long-prompt tier in the shipped book, written out by hand from
    /// the vendors' pages read 2026-10-13: (id, the prompt length it starts
    /// ABOVE, the long rate). The set of tiered ids is exactly this list, so a
    /// tier cannot be added or dropped without this test changing.
    #[test]
    fn every_long_prompt_tier_is_the_vendors_written_out_by_hand() {
        let haiku: Rates = (500_000, 2_500_000, 50_000, 625_000, 1_000_000);
        let haiku_r: Rates = (550_000, 2_750_000, 55_000, 687_500, 1_100_000);
        let want: Vec<(&str, u64, Rates)> = vec![
            ("anthropic.claude-haiku-5-5", 100_000, haiku_r),
            ("anthropic/claude-haiku-5.5", 100_000, haiku),
            ("claude-haiku-5-5", 100_000, haiku),
            (
                "google/gemini-2.5-pro",
                200_000,
                (2_500_000, 15_000_000, 250_000, 2_500_000, 2_500_000),
            ),
            (
                "google/gemini-3.1-pro-preview",
                200_000,
                (4_000_000, 18_000_000, 400_000, 4_000_000, 4_000_000),
            ),
            (
                "gpt-5.4",
                272_000,
                (5_000_000, 22_500_000, 500_000, 5_000_000, 5_000_000),
            ),
            (
                "gpt-5.5",
                272_000,
                (10_000_000, 45_000_000, 1_000_000, 10_000_000, 10_000_000),
            ),
            (
                "gpt-5.6-luna",
                272_000,
                (400_000, 1_800_000, 40_000, 500_000, 500_000),
            ),
            (
                "gpt-5.6-sol",
                272_000,
                (8_000_000, 30_000_000, 800_000, 10_000_000, 10_000_000),
            ),
            (
                "gpt-5.6-terra",
                272_000,
                (4_000_000, 18_000_000, 400_000, 5_000_000, 5_000_000),
            ),
            (
                "gpt-6-astra",
                272_000,
                (20_000_000, 75_000_000, 2_000_000, 25_000_000, 25_000_000),
            ),
            (
                "gpt-6-luna",
                272_000,
                (200_000, 750_000, 20_000, 250_000, 250_000),
            ),
            (
                "gpt-6-sol",
                272_000,
                (4_000_000, 15_000_000, 400_000, 5_000_000, 5_000_000),
            ),
            (
                "gpt-6.1-sol",
                272_000,
                (4_000_000, 15_000_000, 200_000, 5_000_000, 5_000_000),
            ),
            (
                "gpt-6.1-terra",
                272_000,
                (2_000_000, 7_500_000, 100_000, 2_500_000, 2_500_000),
            ),
        ];
        let book = default_price_book();
        let got: Vec<(String, u64, Rates)> = book
            .long_context_entries()
            .into_iter()
            .map(|(id, t)| {
                let p = t.price;
                (
                    id.to_string(),
                    t.above_prompt_tokens,
                    (
                        p.input_per_mtok.0,
                        p.output_per_mtok.0,
                        p.cache_read_per_mtok.0,
                        p.cache_write_per_mtok.0,
                        p.cache_write_1h_per_mtok.0,
                    ),
                )
            })
            .collect();
        let mut want: Vec<(String, u64, Rates)> = want
            .into_iter()
            .map(|(id, a, r)| (id.to_string(), a, r))
            .collect();
        // Invariant 107: every OpenAI tier above is also OpenRouter's
        // `openai/` id, at the same rates.
        let openrouter: Vec<(String, u64, Rates)> = want
            .iter()
            .filter(|(id, _, _)| id.starts_with("gpt-"))
            .map(|(id, a, r)| (format!("{OPENROUTER_OPENAI}{id}"), *a, *r))
            .collect();
        want.extend(openrouter);
        assert_eq!(got, want);
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
