// @codex 2026-09-17: review-only probes, written against 80e0d42 without product changes. Moved into the suite by the ledger PR (invariant 49); codex_f02's setup is the one change, see its own comment.
// The seed literal below is the review's own, kept verbatim; clippy's digit-grouping
// style lint on it is silenced at the file level rather than by editing the literal.
#![allow(clippy::unusual_byte_groupings)]
use std::sync::{Arc, Barrier};
use tokenfuse_core::{Ledger, Microusd, ModelPrice, Usage};

#[test]
fn codex_f01_every_ancestor_budget_includes_the_65th_run() {
    let l = Ledger::new();
    l.open_run("r0", Microusd(0), None).expect("opens");
    for i in 1..=64 {
        l.open_run(
            format!("r{i}"),
            Microusd(1_000_000),
            Some(&format!("r{}", i - 1)),
        )
        .expect("opens");
    }
    let got = l.reserve("r64", Microusd(100_000));
    println!(
        "root={:?}; leaf={:?}; reservation={got:?}",
        l.snapshot("r0"),
        l.snapshot("r64")
    );
    assert!(
        got.is_err(),
        "ADR-2: reserve must check every ancestor, including the root beyond the walk cap"
    );
}

#[test]
fn codex_f02_late_parent_does_not_release_another_calls_reservation() {
    // As written by the review, the child's admission was `reserve`. Under D1 (invariant 49)
    // the checked reserve refuses a child whose parent this ledger has not opened, so the shape
    // the review measured (parent absent at the child's reserve, present at its settle with a
    // reservation of its own in flight) is reachable only through shadow and warn, which admit
    // with `reserve_unchecked` on the walkable prefix. That is the deployed shape: an
    // orchestrator whose workers call first. The assertion is the review's, unchanged.
    let l = Ledger::new();
    l.open_run("child", Microusd(1_000_000), Some("parent"))
        .expect("opens");
    let child = l.reserve_unchecked("child", Microusd(800_000));
    l.open_run("parent", Microusd(1_000_000), None)
        .expect("opens");
    let parent = l.reserve("parent", Microusd(800_000)).unwrap();
    l.settle(&child, Microusd(100_000));
    let p = l.snapshot("parent").unwrap();
    let extra = l.reserve("parent", Microusd(800_000));
    println!("after child settle={p:?}; additional reservation={extra:?}");
    assert_eq!(
        p.reserved,
        Microusd(800_000),
        "ADR-2: settle may only release what this call reserved on that ancestor"
    );
    assert_eq!(
        p.spent,
        Microusd(0),
        "and charges only what this call spent there: nothing"
    );
    assert!(
        extra.is_err(),
        "the parent's own reservation is still outstanding, so 800000 more does not fit"
    );
    l.settle(&parent, Microusd(800_000));
    let after = l.snapshot("parent").unwrap();
    assert_eq!(
        (after.reserved, after.spent),
        (Microusd(0), Microusd(800_000))
    );
    let c = l.snapshot("child").unwrap();
    assert_eq!((c.reserved, c.spent), (Microusd(0), Microusd(100_000)));
}

#[test]
fn codex_f09_saturated_budget_cannot_grant_past_its_ceiling() {
    let l = Ledger::new();
    l.open_run("r", Microusd(i64::MAX), None).expect("opens");
    let first = l.reserve("r", Microusd(i64::MAX)).unwrap();
    l.settle(&first, Microusd(i64::MAX));
    let next = l.reserve("r", Microusd(1));
    println!("snapshot={:?}; next={next:?}", l.snapshot("r"));
    assert!(next.is_err(), "ADR-2 and money.rs: no headroom remains at i64::MAX; saturation must not turn overflow into an allowed equality");
}

#[test]
fn codex_f10_settlement_replay_does_not_charge_twice_or_release_a_sibling() {
    let l = Ledger::new();
    l.open_run("r", Microusd(1_000_000), None).expect("opens");
    let first = l.reserve("r", Microusd(400_000)).unwrap();
    let _other = l.reserve("r", Microusd(400_000)).unwrap();
    l.settle(&first, Microusd(100_000));
    let before = l.snapshot("r").unwrap();
    l.settle(&first, Microusd(100_000));
    let after = l.snapshot("r").unwrap();
    println!("before={before:?}; after={after:?}");
    assert_eq!(after, before, "review requirement: a reservation cannot settle twice; library API probe, not an HTTP replay");
}

#[test]
fn codex_held_children_race_against_one_parent_with_exact_accounting() {
    for (budget, unit, count) in [(17, 3, 32), (0, 1, 8), (100, 7, 48)] {
        let l = Arc::new(Ledger::new());
        l.open_run("parent", Microusd(budget), None).expect("opens");
        let barrier = Arc::new(Barrier::new(count));
        let mut tasks = vec![];
        for i in 0..count {
            let id = format!("child{i}");
            l.open_run(&id, Microusd(1000), Some("parent"))
                .expect("opens");
            let l = l.clone();
            let barrier = barrier.clone();
            tasks.push(std::thread::spawn(move || {
                barrier.wait();
                l.reserve(&id, Microusd(unit)).ok()
            }));
        }
        let reservations: Vec<_> = tasks
            .into_iter()
            .filter_map(|t| t.join().unwrap())
            .collect();
        assert_eq!(reservations.len(), (budget / unit) as usize);
        assert_eq!(
            l.snapshot("parent").unwrap().reserved,
            Microusd(unit * reservations.len() as i64)
        );
        for r in &reservations {
            l.settle(r, Microusd(unit));
        }
        let p = l.snapshot("parent").unwrap();
        assert_eq!(p.reserved, Microusd(0));
        assert_eq!(p.spent, Microusd(unit * reservations.len() as i64));
        println!(
            "budget={budget} unit={unit} racers={count} grants={} settled={p:?}",
            reservations.len()
        );
    }
}

#[test]
fn codex_held_seeded_integer_arithmetic_matches_i128_oracle() {
    let mut seed = 0x18_09_2026_u64;
    let p = ModelPrice::per_mtok_usd(3.0, 15.0, 0.30, 3.75);
    for case in 0..10_000 {
        seed = seed.wrapping_mul(6364136223846793005).wrapping_add(1);
        let n = if case < 64 {
            (1u64 << case).saturating_sub(1)
        } else {
            seed
        };
        let u = Usage {
            input_tokens: n,
            output_tokens: n / 3,
            cache_read_tokens: n / 7,
            cache_write_tokens: n / 5,
            cache_write_1h_tokens: n / 11,
            ..Default::default()
        };
        let oracle = [
            (u.input_tokens, 3_000_000i128),
            (u.output_tokens, 15_000_000),
            (u.cache_read_tokens, 300_000),
            (u.cache_write_tokens - u.cache_write_1h_tokens, 3_750_000),
            (u.cache_write_1h_tokens, 6_000_000),
        ]
        .into_iter()
        .map(|(n, p)| i128::from(n) * p / 1_000_000)
        .sum::<i128>()
        .min(i64::MAX as i128) as i64;
        assert_eq!(p.cost(&u), Microusd(oracle), "pricing oracle case {case}");
        let a = seed as i64;
        let b = seed.rotate_left(17) as i64;
        assert_eq!(
            (Microusd(a) + Microusd(b)).0,
            (a as i128 + b as i128).clamp(i64::MIN as i128, i64::MAX as i128) as i64
        );
        assert_eq!(
            (Microusd(a) - Microusd(b)).0,
            (a as i128 - b as i128).clamp(i64::MIN as i128, i64::MAX as i128) as i64
        );
    }
    println!("10000 deterministic pricing/Add/Sub oracle cases held; seed=0x18092026");
}
