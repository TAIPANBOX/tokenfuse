//! Point this crate's revocation consumer at a REAL `vouchryx`.
//!
//! Ignored by default, because it needs a service running and CI has none. It
//! is here rather than in a scratch directory for the reason the estate keeps
//! relearning: a suite that agrees with the code it was written beside is the
//! weakest evidence there is, and the only cure is running the thing. The
//! fixture in `revocations.rs` claims to be a body `vouchryx` serves; this is
//! what checks that claim against `vouchryx` rather than against the person who
//! typed the fixture.
//!
//! Run it:
//!
//! ```sh
//! VOUCHRYX_BASE=http://127.0.0.1:4399 \
//! VOUCHRYX_REVOKED_JTI=<a jti you just revoked> \
//!   cargo test -p tokenfuse-delegation --test live_vouchryx -- --ignored --nocapture
//! ```
//!
//! The fetch is a hand-written HTTP/1.1 GET over `std::net::TcpStream`, which
//! is not a general HTTP client and is not trying to be. It is here because
//! this crate has no client and must not grow one (CLAUDE.md invariant 29): the
//! transport belongs to whatever polls, and in production that is the gateway's
//! `reqwest`. Twenty lines of `std` in a test is the honest way to reach a live
//! service without contradicting the crate's own claim about itself.

use std::io::{Read, Write};
use std::net::TcpStream;
use std::time::Duration;

use tokenfuse_delegation::revocations::{Basis, Install, Revocations, Snapshot};

#[test]
#[ignore = "needs a vouchryx running; see the module docs"]
fn the_body_a_live_vouchryx_serves_is_read_by_this_consumer() {
    let base =
        std::env::var("VOUCHRYX_BASE").expect("VOUCHRYX_BASE, for example http://127.0.0.1:4399");
    let revoked = std::env::var("VOUCHRYX_REVOKED_JTI")
        .expect("VOUCHRYX_REVOKED_JTI: revoke one first, or this proves nothing");

    let body = get(&base, "/v1/revocations");
    println!("live body: {body}");

    let snapshot = Snapshot::from_json(&body).expect("vouchryx's own body must parse");
    assert!(
        snapshot.as_of > 0,
        "no cursor, so a poller could not tell this from a failed fetch"
    );
    assert!(
        !snapshot.revocations.is_empty(),
        "the list is empty, so this run would prove nothing: revoke a token first"
    );

    let now = snapshot.as_of;
    let mut revs = Revocations::with_defaults();
    assert_eq!(revs.install(snapshot, now), Install::Applied);

    let answer = revs.check(&revoked, "user://acme/alice", now - 60, now);
    assert!(
        answer.revoked,
        "a live vouchryx says {revoked} is revoked and this consumer answered {answer:?}"
    );
    assert_eq!(answer.basis, Basis::Listed { age_secs: 0 });

    // The negative control, and it is the half that makes the line above mean
    // something: a consumer that refused everything would pass it.
    let other = revs.check("no-such-token-anywhere", "user://acme/alice", now - 60, now);
    assert!(!other.revoked, "a token nobody revoked: {other:?}");
    assert_eq!(other.basis, Basis::Absent { age_secs: 0 });

    // And the same list, four minutes later with no successful poll.
    let late = now + 240;
    assert!(
        revs.check(&revoked, "user://acme/alice", now - 60, late)
            .revoked,
        "a stale list must still refuse what it names"
    );
    assert_eq!(
        revs.check(
            "no-such-token-anywhere",
            "user://acme/alice",
            now - 60,
            late
        )
        .basis,
        Basis::Stale { age_secs: 240 },
        "and a MISS on it is where the fail mode answers"
    );

    println!("live vouchryx: {revoked} refused, an unrevoked token allowed, and a stale miss handed to the fail mode");
}

/// The smallest GET that works, deliberately.
fn get(base: &str, path: &str) -> String {
    let authority = base
        .trim_start_matches("http://")
        .trim_end_matches('/')
        .to_string();
    let mut stream = TcpStream::connect(&authority).expect("connect to vouchryx");
    stream
        .set_read_timeout(Some(Duration::from_secs(5)))
        .expect("a read timeout, so a hung service fails the test rather than the run");
    write!(
        stream,
        "GET {path} HTTP/1.1\r\nHost: {authority}\r\nAccept: application/json\r\nConnection: close\r\n\r\n"
    )
    .expect("write the request");
    let mut raw = String::new();
    stream.read_to_string(&mut raw).expect("read the response");
    let (head, body) = raw
        .split_once("\r\n\r\n")
        .expect("a response with headers and a body");
    assert!(
        head.starts_with("HTTP/1.1 200"),
        "vouchryx answered: {}",
        head.lines().next().unwrap_or_default()
    );
    body.to_string()
}
