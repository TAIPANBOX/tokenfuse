// @claude 2026-09-17: probes for the items the second-model pass said the first review missed, written against 80e0d42. Moved into the suite by the ledger PR (invariant 49).
use tokenfuse_core::{Ledger, Microusd};

/// Missed 1: a child that names a parent this ledger never opened is checked
/// against nothing above itself, silently.
#[test]
fn missed1_a_child_naming_an_unopened_parent_is_checked_against_nothing() {
    let l = Ledger::new();
    l.open_run("c", Microusd(1_000_000), Some("p"))
        .expect("opens");
    let got = l.reserve("c", Microusd(999_999));
    println!("parent snapshot={:?}; reservation={got:?}", l.snapshot("p"));
    assert!(
        got.is_err(),
        "a parent that was never opened must not admit the child's spend unchecked"
    );
}

/// Missed 2: a parent declared after the run's first call is ignored for the
/// run's life (open_run sets the parent in or_insert only).
#[test]
fn missed2_a_parent_declared_after_the_first_call_is_ignored() {
    let l = Ledger::new();
    l.open_run("c", Microusd(1_000_000), None).expect("opens");
    l.open_run("p", Microusd(0), None).expect("opens");
    l.open_run("c", Microusd(1_000_000), Some("p"))
        .expect("opens");
    let got = l.reserve("c", Microusd(100_000));
    println!("parent snapshot={:?}; reservation={got:?}", l.snapshot("p"));
    assert!(
        got.is_err(),
        "a zero-budget parent declared on the second call must refuse the child"
    );
}

/// Missed 6: settle after close_run is a silent no-op that leaves every
/// ancestor's reserved counter inflated for good.
#[test]
fn missed6_settle_after_close_run_leaves_the_parent_reserved() {
    let l = Ledger::new();
    l.open_run("p", Microusd(1_000_000), None).expect("opens");
    l.open_run("c", Microusd(1_000_000), Some("p"))
        .expect("opens");
    let r = l.reserve("c", Microusd(100_000)).expect("reserve");
    l.close_run("c");
    l.settle(&r, Microusd(50_000));
    let p = l.snapshot("p").expect("parent");
    println!("parent after settle={p:?}");
    // Both counters, not one: a fix that only zeroes `reserved` and loses the
    // actual spend would pass a reserved-only assertion (Codex, 2026-09-17).
    assert_eq!(
        p.reserved,
        Microusd(0),
        "the parent's reservation must be released even though the leaf is gone"
    );
    assert_eq!(
        p.spent,
        Microusd(50_000),
        "the parent must still be charged the actual spend"
    );
    // And a second settlement of the same reservation must not charge twice.
    l.settle(&r, Microusd(50_000));
    let p2 = l.snapshot("p").expect("parent");
    assert_eq!(
        p2.spent,
        Microusd(50_000),
        "a repeated settlement must not charge the parent twice, got {p2:?}"
    );
}
