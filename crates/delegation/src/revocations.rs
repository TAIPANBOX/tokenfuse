//! The revocation list, held locally, that [`crate::verify_delegation`]'s
//! `revoked` argument is meant to be filled from.
//!
//! # What was wrong before this file
//!
//! `vouchryx` has served `GET /v1/revocations` since the day it was written and
//! nothing in the estate has ever polled it. Both doors in this repository pass
//! `|_, _, _| false`, and no Go enforcement point sets `Options.Revoked` either.
//! Meanwhile four documents said, in the present tense, that every enforcement
//! point consults the list. So the sentence "revoking ends the right to act at
//! every enforcement point at once" described nothing that ran.
//!
//! # Still offline, and that is not a loophole
//!
//! This crate reaches out for nothing, which is CLAUDE.md invariant 29, and a
//! revocation cache does not change that: the FETCH is out of band and the
//! CHECK is local. [`Revocations::check`] takes a clock and returns an
//! [`Answer`]; it cannot block, cannot fail, and has nowhere to send a request.
//! Whatever polls `vouchryx` calls [`Revocations::install`] on its own schedule,
//! and a poll that never returns costs the request path nothing but age.
//!
//! Transport is therefore deliberately absent from this crate rather than
//! forgotten. The gateway already holds an HTTP client and a shipping loop
//! (`CloudSink`); adding a second one here would put a client inside the crate
//! whose whole claim is that it has none.
//!
//! # Age is the third state, and it is the useful one
//!
//! The estate has answered "what happens when a dependency is unreachable"
//! twice, the same way both times: an operator-chosen [`FailMode`], `open` or
//! `closed`, defaulting to open. `wardryx::FailMode` and
//! `TOKENFUSE_MCP_TAINT_FAILMODE` are the two. This takes the same vocabulary
//! and the OPPOSITE default, which is a difference stated rather than hidden.
//!
//! A revocation list has a state those two do not have. A PDP you cannot reach
//! tells you nothing at all; a revocation list from four minutes ago still
//! holds every revocation older than four minutes. So age is its own axis, with
//! a maximum, and the fail mode is what answers past the maximum rather than
//! what answers to an outage.
//!
//! That same difference is why the default differs. Opening on an unreachable
//! PDP decides a question no answer was coming for; opening on an unreachable
//! revocation list throws away one specific fact the operator asked to be told,
//! which is that this authority can no longer be confirmed to exist. See
//! [`FailMode::Closed`] for the whole argument and for what bounds the damage.
//!
//! # The rule the maximum governs, which is narrower than it looks
//!
//! **Age decides what a MISS means. It never decides what a HIT means.**
//!
//! A hit is data: this list said this token was revoked, and nothing un-revokes
//! a token, so the answer does not rot. Discarding a revocation we hold because
//! the list got old would take a token we KNOW is dead and call it live, which
//! is worse than the outage it was reacting to.
//!
//! A miss is not data. It is an inference from the list being COMPLETE, and
//! completeness is exactly the property that expires. So a miss on a fresh list
//! means "not revoked", a miss on a stale list means "I do not know", and that
//! is the question the fail mode is asked.
//!
//! # Never fetched is not stale
//!
//! Both fall back to the fail mode and they are different facts, so [`Basis`]
//! keeps them apart. Nothing fetched means the poller was never wired or has
//! never once succeeded, which is a configuration fault: it does not clear
//! itself and nothing else in the estate will mention it. Stale means a poller
//! that was working stopped, which usually clears. That is CLAUDE.md invariant
//! 13's boundary, and a caller that cannot tell the two apart cannot apply it.

use serde::{Deserialize, Serialize};

/// The default maximum age of a list that may still answer a miss.
///
/// # Why sixty seconds, which is the number that decides whether the estate's own sentence is true
///
/// This is the window in which a revoked token still works, once the poller has
/// stopped. It is not the window in the healthy case: there the window is the
/// poll interval, and the maximum only says how long a consumer may go on
/// trusting an unrefreshed list before it stops answering misses from it.
///
/// The bound that matters comes from the token, not from taste. `vouchryx`
/// mints with `DefaultTTL` of five minutes and refuses a TTL over `MaxTTL` of
/// one hour. If a list may be older than a token's whole life, then a token
/// minted after the last successful poll can be revoked and still work until it
/// expires on its own, and revocation never bit at all: the control would be
/// decorative for a whole generation of tokens. Sixty seconds is a fifth of the
/// default TTL, so in the worst case a fifth of one token's life is spent
/// answering misses from a list that stopped moving, and the operator's own
/// fail mode governs after that.
///
/// It is a default and not a law. A deployment that polls every five seconds
/// can lower it; one that has decided a revocation is advisory can raise it.
/// What it must not be is unstated, because the number IS the claim.
pub const DEFAULT_MAX_AGE_SECS: i64 = 60;

/// One revocation, in the shape `vouchryx` serves it.
///
/// Field names match `internal/revoke.Entry`'s JSON exactly, because this is a
/// wire type and a rename here is a consumer that silently stops matching.
#[derive(Debug, Clone, PartialEq, Eq, Default, Deserialize, Serialize)]
pub struct Revocation {
    /// Revokes exactly one token. Empty when this is a subject entry.
    #[serde(default)]
    pub jti: String,
    /// Revokes every token issued for this subject at or before
    /// [`Revocation::issued_before`].
    #[serde(default)]
    pub subject: String,
    /// A Unix second. Only meaningful with [`Revocation::subject`].
    #[serde(default)]
    pub issued_before: i64,
    /// When this entry stops being load-bearing: the last moment a token it
    /// could match might still be valid.
    ///
    /// Zero means the producer stated none, and an entry with no stated expiry
    /// is kept rather than dropped. The two mistakes are not the same size:
    /// dropping an entry too early makes a revoked token work, and keeping one
    /// too long only outlives a token that has expired anyway.
    #[serde(default)]
    pub expires: i64,
}

impl Revocation {
    /// Whether this entry covers a given token.
    ///
    /// An entry naming neither a token nor a subject matches nothing. That is
    /// not defensive programming for its own sake: `jti == self.jti` with both
    /// empty matches every token with no `jti`, and a producer other than
    /// `vouchryx` is not bound by `vouchryx`'s own refusal to record one.
    fn covers(&self, jti: &str, subject: &str, issued_at: i64) -> bool {
        if !self.jti.is_empty() && self.jti == jti {
            return true;
        }
        // At or before, never strictly before: the second a revocation happens
        // in is the second an incident happens in, and `vouchryx` records the
        // cursor with the same rule at the other end.
        !self.subject.is_empty() && self.subject == subject && issued_at <= self.issued_before
    }

    /// Whether this entry is still worth checking at `now`.
    fn live_at(&self, now: i64) -> bool {
        self.expires == 0 || self.expires > now
    }
}

/// One fetched list, with the cursor saying which moment it describes.
///
/// `as_of` is why this is a struct rather than a `Vec`. An empty list and a
/// fetch that failed are the same bytes without it, and one of those two means
/// every revoked token in the estate is live again.
#[derive(Debug, Clone, PartialEq, Eq, Default, Deserialize)]
pub struct Snapshot {
    #[serde(default)]
    pub revocations: Vec<Revocation>,
    #[serde(default)]
    pub as_of: i64,
}

impl Snapshot {
    /// Parse the body of `GET /v1/revocations`.
    ///
    /// Here rather than at the caller so a poller does not have to know the
    /// wire shape to feed this type, and so the shape is described in one place
    /// when `vouchryx` changes it.
    ///
    /// # Why it goes through `Value` rather than straight into the struct
    ///
    /// A derived `Deserialize` for a struct also accepts a SEQUENCE, positional
    /// field by field, so `[]` parses cleanly into `Snapshot { revocations: [],
    /// as_of: 0 }`. Found by this crate's own hostile-input test before it
    /// shipped, and it is the shape a proxy in the way, a wrong route, or a
    /// second service on the port produces. It would have been caught one layer
    /// down, since [`Install::NoCursor`] refuses a cursor of zero, but a parser
    /// that turns an unrelated body into an empty list is a defence resting on
    /// a defence, and this one is at poll rate rather than on the request path.
    ///
    /// Unknown MEMBERS are still accepted on purpose: entries carry `actor` and
    /// `reason` that this consumer has no use for, and refusing a member
    /// `vouchryx` adds later would make every consumer a release blocker.
    pub fn from_json(raw: &str) -> Result<Self, serde_json::Error> {
        let value: serde_json::Value = serde_json::from_str(raw)?;
        if !value.is_object() {
            return Err(serde::de::Error::custom(
                "a revocations body is a JSON object with `revocations` and `as_of`",
            ));
        }
        serde_json::from_value(value)
    }
}

/// What an unanswerable miss means, chosen by the operator.
///
/// Deliberately the same vocabulary as `wardryx::FailMode` and
/// `TOKENFUSE_MCP_TAINT_FAILMODE`, and deliberately NOT the same default. A
/// third spelling of one question is how an estate ends up answering it three
/// ways; a shared default across three questions that are not the same question
/// is how it answers the wrong one twice.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum FailMode {
    /// A list too old to answer a miss refuses. The default.
    ///
    /// The other two answer "the PDP is unreachable", and an unreachable PDP
    /// says NOTHING, so letting the call through decides a question no answer
    /// was coming for. An unreachable revocation list says one narrow thing:
    /// this authority can no longer be confirmed to exist. Opening there does
    /// not preserve availability in the absence of information, it throws away
    /// information the operator asked for.
    ///
    /// It is an attack primitive and not only an outage. Open makes "revoking
    /// ends the right to act" conditional on one service being reachable, so
    /// whoever can drop it, or partition a single door from it, buys a window
    /// in which revoked tokens work again, and every call in that window
    /// succeeds silently.
    ///
    /// Three things bound the damage, none of which a general fail-closed
    /// default would have: the check is off entirely unless a deployment wires
    /// a poller, a working poller refuses nothing at all, and vouchryx mints at
    /// a five-minute TTL, so the outage is bounded by the same clock the
    /// control is.
    #[default]
    Closed,
    /// A list too old to answer a miss lets the call through. For a deployment
    /// that has decided an unverifiable delegation is one it will honour rather
    /// than lose the traffic. A deliberate choice, which is why it is not what
    /// an operator who chose nothing gets.
    Open,
}

impl FailMode {
    /// What this mode answers when the list cannot say.
    fn refuses(self) -> bool {
        matches!(self, FailMode::Closed)
    }
}

/// Where an [`Answer`] came from. The verdict alone is not enough for a caller
/// to log honestly: `false` from a fresh list and `false` from a fail mode are
/// the same bit and different facts, which is `dependency_failed`'s
/// `allowed_ungoverned` distinction one plane over.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Basis {
    /// An entry matched, in a list this many seconds old. Age is reported and
    /// is NOT part of the decision: see the module docs.
    Listed { age_secs: i64 },
    /// Nothing matched, and the list is young enough for that to mean
    /// something.
    Absent { age_secs: i64 },
    /// Nothing matched, and the list is older than the maximum, so the fail
    /// mode answered instead.
    Stale { age_secs: i64 },
    /// No list has ever been installed, so the fail mode answered. A different
    /// fact from [`Basis::Stale`] and worth a different log line: a poller that
    /// has never once succeeded does not fix itself.
    Never,
}

impl Basis {
    /// Whether the fail mode answered rather than the list. The member a caller
    /// must not skip when it decides whether to record something.
    pub fn is_fallback(self) -> bool {
        matches!(self, Basis::Stale { .. } | Basis::Never)
    }

    /// The age of the list this answer came from, when there was one.
    pub fn age_secs(self) -> Option<i64> {
        match self {
            Basis::Listed { age_secs } | Basis::Absent { age_secs } | Basis::Stale { age_secs } => {
                Some(age_secs)
            }
            Basis::Never => None,
        }
    }
}

/// One revocation answer and where it came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Answer {
    pub revoked: bool,
    pub basis: Basis,
}

/// What [`Revocations::install`] did with an offered snapshot.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Install {
    /// Installed, and this is now the last-known-good list.
    Applied,
    /// Refused: the snapshot describes an EARLIER moment than the one already
    /// held.
    ///
    /// Two things make this worth refusing rather than taking. Installing it
    /// moves what this process knows backwards, and worse, it would reset the
    /// age, so a view that had genuinely stopped moving would start reading as
    /// fresh. The age is the whole of the staleness design; a snapshot that
    /// lies about it is the one input that can turn every other rule here off.
    ///
    /// Equal cursors ARE accepted. `as_of` is a Unix second, so two polls
    /// inside one second legitimately carry the same value, and refusing that
    /// would break any poller faster than 1 Hz.
    Backwards { held: i64, offered: i64 },
    /// Refused: the snapshot carries no cursor at all, so it cannot be compared
    /// with the one held and cannot be aged.
    NoCursor,
}

/// The last-known-good revocation list, plus the policy for what its age means.
///
/// Not `Sync`-wrapped here on purpose. A caller holds this behind whatever it
/// already uses (the gateway has `RwLock` and `Arc` in the request path
/// already), and a lock chosen in here would be a second one for that caller to
/// reason about.
#[derive(Debug)]
pub struct Revocations {
    max_age_secs: i64,
    fail_mode: FailMode,
    /// The last snapshot installed, and OUR clock when it was installed.
    ///
    /// Age is measured from our own clock rather than from `as_of` because what
    /// this bounds is the interval since this process last synchronised, which
    /// is a fact about us. `as_of` is kept beside it, for the ordering rule and
    /// for an operator who wants to see the skew.
    held: Option<(Snapshot, i64)>,
    rejected_backwards: u64,
}

impl Revocations {
    /// A cache with the estate's defaults: [`DEFAULT_MAX_AGE_SECS`] and
    /// [`FailMode::Closed`].
    pub fn with_defaults() -> Self {
        Self::new(DEFAULT_MAX_AGE_SECS, FailMode::default())
    }

    /// A cache with an operator's own policy.
    ///
    /// A `max_age_secs` of zero or less means every list is stale the instant
    /// it lands, which is a real configuration (it says "only a hit counts")
    /// and is not corrected here into something nobody asked for.
    pub fn new(max_age_secs: i64, fail_mode: FailMode) -> Self {
        Self {
            max_age_secs,
            fail_mode,
            held: None,
            rejected_backwards: 0,
        }
    }

    /// Offer a freshly fetched snapshot. See [`Install`] for what is refused.
    pub fn install(&mut self, snapshot: Snapshot, now: i64) -> Install {
        if snapshot.as_of <= 0 {
            return Install::NoCursor;
        }
        if let Some((held, _)) = &self.held {
            if snapshot.as_of < held.as_of {
                let refused = Install::Backwards {
                    held: held.as_of,
                    offered: snapshot.as_of,
                };
                self.rejected_backwards += 1;
                return refused;
            }
        }
        self.held = Some((snapshot, now));
        Install::Applied
    }

    /// Is this token revoked, and on what basis.
    ///
    /// Local, total, and infallible by construction: no clock of its own, no
    /// client, no error. That shape is the invariant rather than a
    /// convenience, because it is what makes a revocation check something a
    /// request path can afford to do on every call.
    pub fn check(&self, jti: &str, subject: &str, issued_at: i64, now: i64) -> Answer {
        let Some((held, fetched_at)) = &self.held else {
            return Answer {
                revoked: self.fail_mode.refuses(),
                basis: Basis::Never,
            };
        };
        let age_secs = now - fetched_at;

        if held
            .revocations
            .iter()
            .any(|e| e.live_at(now) && e.covers(jti, subject, issued_at))
        {
            // A hit, whatever the age. See the module docs: nothing un-revokes
            // a token, so this answer does not rot, and dropping it because the
            // list got old would call a token we know is dead a live one.
            return Answer {
                revoked: true,
                basis: Basis::Listed { age_secs },
            };
        }

        if age_secs <= self.max_age_secs {
            return Answer {
                revoked: false,
                basis: Basis::Absent { age_secs },
            };
        }
        Answer {
            revoked: self.fail_mode.refuses(),
            basis: Basis::Stale { age_secs },
        }
    }

    /// The closure [`crate::verify_delegation`] takes, bound to one request's
    /// clock.
    ///
    /// `observe` is not optional and takes the whole [`Answer`], so the site
    /// that wires this up has to decide what it does with a fallback rather
    /// than never being shown one. Pass `|_| {}` to decide on nothing, which is
    /// then visible in the diff as a decision.
    pub fn hook<'a>(
        &'a self,
        now: i64,
        observe: impl Fn(&Answer) + 'a,
    ) -> impl Fn(&str, &str, i64) -> bool + 'a {
        move |jti, subject, issued_at| {
            let answer = self.check(jti, subject, issued_at, now);
            observe(&answer);
            answer.revoked
        }
    }

    /// The age of the held list, or `None` when nothing has ever been
    /// installed.
    pub fn age_secs(&self, now: i64) -> Option<i64> {
        self.held.as_ref().map(|(_, at)| now - at)
    }

    /// The cursor of the held list.
    pub fn as_of(&self) -> Option<i64> {
        self.held.as_ref().map(|(s, _)| s.as_of)
    }

    /// How many snapshots were refused for describing an earlier moment than
    /// the one held. Not zero means something is serving from behind: a
    /// restarted instance, a second one behind a load balancer, or a clock.
    pub fn rejected_backwards(&self) -> u64 {
        self.rejected_backwards
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const AS_OF: i64 = 1_800_000_000;

    fn jti(id: &str, expires: i64) -> Revocation {
        Revocation {
            jti: id.into(),
            expires,
            ..Default::default()
        }
    }

    fn snapshot(as_of: i64, revocations: Vec<Revocation>) -> Snapshot {
        Snapshot { revocations, as_of }
    }

    /// A list with one revoked token in it, installed at `AS_OF`.
    fn holding_one() -> Revocations {
        let mut r = Revocations::with_defaults();
        assert_eq!(
            r.install(snapshot(AS_OF, vec![jti("tok-1", AS_OF + 3600)]), AS_OF),
            Install::Applied
        );
        r
    }

    /// THE ONE THE WHOLE THING IS FOR. Every door in this repository passes
    /// `|_, _, _| false` today, so this is the answer that has never once been
    /// given anywhere in the estate.
    #[test]
    fn a_revoked_token_is_refused_by_something_that_actually_read_the_list() {
        let r = holding_one();
        let answer = r.check("tok-1", "user://acme/alice", AS_OF - 10, AS_OF);
        assert!(
            answer.revoked,
            "the list names tok-1 and this answered {answer:?}"
        );
        assert_eq!(answer.basis, Basis::Listed { age_secs: 0 });
    }

    #[test]
    fn a_token_the_list_does_not_name_is_not_refused() {
        // The negative control. A cache that refused everything would pass the
        // test above and be worth nothing.
        let r = holding_one();
        let answer = r.check("tok-2", "user://acme/alice", AS_OF - 10, AS_OF);
        assert!(!answer.revoked);
        assert_eq!(answer.basis, Basis::Absent { age_secs: 0 });
    }

    #[test]
    fn a_subject_revocation_covers_what_was_issued_at_or_before_its_moment() {
        let mut r = Revocations::with_defaults();
        r.install(
            snapshot(
                AS_OF,
                vec![Revocation {
                    subject: "agent://acme/triage".into(),
                    issued_before: AS_OF,
                    expires: AS_OF + 3600,
                    ..Default::default()
                }],
            ),
            AS_OF,
        );
        for (issued_at, want, why) in [
            (AS_OF - 60, true, "issued before the revocation"),
            (AS_OF, true, "issued in the very second of it"),
            (AS_OF + 1, false, "issued after it: revoking is not banning"),
        ] {
            let answer = r.check("tok-9", "agent://acme/triage", issued_at, AS_OF);
            assert_eq!(answer.revoked, want, "{why}");
        }
    }

    /// The substance. A list from four minutes ago still holds every revocation
    /// older than four minutes, and answering `false` here would take a token
    /// this process KNOWS is dead and call it live.
    #[test]
    fn a_stale_list_still_refuses_what_it_names() {
        let r = holding_one();
        let late = AS_OF + DEFAULT_MAX_AGE_SECS * 4;
        let answer = r.check("tok-1", "user://acme/alice", AS_OF - 10, late);
        assert!(
            answer.revoked,
            "age decides what a MISS means and never what a HIT means: {answer:?}"
        );
        assert_eq!(
            answer.basis,
            Basis::Listed {
                age_secs: DEFAULT_MAX_AGE_SECS * 4
            },
            "and it says how old the list it matched in was"
        );
    }

    /// The case a naive implementation gets wrong by serving forever.
    #[test]
    fn a_miss_on_a_stale_list_falls_back_to_the_fail_mode() {
        for (mode, want) in [(FailMode::Open, false), (FailMode::Closed, true)] {
            let mut r = Revocations::new(DEFAULT_MAX_AGE_SECS, mode);
            r.install(snapshot(AS_OF, vec![jti("tok-1", AS_OF + 3600)]), AS_OF);
            let late = AS_OF + DEFAULT_MAX_AGE_SECS + 1;
            let answer = r.check("tok-2", "user://acme/alice", AS_OF - 10, late);
            assert_eq!(
                answer.revoked, want,
                "{mode:?} past the maximum age: {answer:?}"
            );
            assert_eq!(
                answer.basis,
                Basis::Stale {
                    age_secs: DEFAULT_MAX_AGE_SECS + 1
                }
            );
        }
    }

    #[test]
    fn a_list_exactly_at_the_maximum_age_is_still_trusted_for_a_miss() {
        // The boundary in the other direction, so "stale" cannot quietly become
        // "anything that is not this instant".
        let r = holding_one();
        let answer = r.check(
            "tok-2",
            "user://acme/alice",
            AS_OF - 10,
            AS_OF + DEFAULT_MAX_AGE_SECS,
        );
        assert_eq!(
            answer.basis,
            Basis::Absent {
                age_secs: DEFAULT_MAX_AGE_SECS
            }
        );
        assert!(!answer.revoked);
    }

    /// Never fetched is not stale. Both defer to the fail mode and they are
    /// different faults: one is an outage, the other is a poller nobody wired.
    #[test]
    fn a_list_nobody_ever_fetched_says_so_rather_than_reading_as_empty() {
        for (mode, want) in [(FailMode::Open, false), (FailMode::Closed, true)] {
            let r = Revocations::new(DEFAULT_MAX_AGE_SECS, mode);
            let answer = r.check("tok-1", "user://acme/alice", AS_OF - 10, AS_OF);
            assert_eq!(answer.revoked, want);
            assert_eq!(answer.basis, Basis::Never);
            assert_eq!(answer.basis.age_secs(), None);
            assert!(answer.basis.is_fallback());
        }
    }

    #[test]
    fn an_answer_from_the_list_is_never_reported_as_a_fallback() {
        let r = holding_one();
        for id in ["tok-1", "tok-2"] {
            let answer = r.check(id, "user://acme/alice", AS_OF - 10, AS_OF);
            assert!(
                !answer.basis.is_fallback(),
                "{id} was answered from the list: {answer:?}"
            );
        }
    }

    /// An older snapshot never replaces a newer one, and the reason is the age
    /// rather than the entries: installing it would reset the clock and a view
    /// that had stopped moving would start reading as fresh.
    #[test]
    fn a_cursor_that_moved_backwards_is_refused_and_does_not_reset_the_age() {
        let mut r = holding_one();
        let later = AS_OF + 30;
        let got = r.install(snapshot(AS_OF - 5, vec![]), later);
        assert_eq!(
            got,
            Install::Backwards {
                held: AS_OF,
                offered: AS_OF - 5
            }
        );
        assert_eq!(r.rejected_backwards(), 1);
        assert_eq!(r.as_of(), Some(AS_OF), "the newer list is still held");
        assert_eq!(
            r.age_secs(later),
            Some(30),
            "and it is still 30 seconds old, not 0"
        );
        assert!(
            r.check("tok-1", "user://acme/alice", AS_OF - 10, later)
                .revoked,
            "the refused snapshot was empty, and it must not have emptied this"
        );
    }

    #[test]
    fn a_cursor_that_did_not_move_is_accepted_because_a_second_is_a_coarse_clock() {
        let mut r = holding_one();
        assert_eq!(
            r.install(snapshot(AS_OF, vec![]), AS_OF + 1),
            Install::Applied
        );
        assert_eq!(r.rejected_backwards(), 0);
        assert!(
            !r.check("tok-1", "user://acme/alice", AS_OF - 10, AS_OF + 1)
                .revoked,
            "the same cursor with an empty list is a list that emptied, and it applies"
        );
    }

    #[test]
    fn a_snapshot_with_no_cursor_is_refused_rather_than_aged_from_nothing() {
        let mut r = Revocations::with_defaults();
        assert_eq!(
            r.install(snapshot(0, vec![jti("tok-1", AS_OF + 3600)]), AS_OF),
            Install::NoCursor
        );
        assert_eq!(
            r.check("tok-1", "user://acme/alice", AS_OF - 10, AS_OF)
                .basis,
            Basis::Never,
            "a refused snapshot leaves this having never fetched anything"
        );
    }

    #[test]
    fn an_entry_naming_neither_a_token_nor_a_subject_matches_nothing() {
        // Hostile shape: `jti == self.jti` with both empty matches every token
        // that carries no id, and this list comes off somebody else's wire.
        let mut r = Revocations::with_defaults();
        r.install(
            snapshot(
                AS_OF,
                vec![Revocation {
                    expires: AS_OF + 3600,
                    ..Default::default()
                }],
            ),
            AS_OF,
        );
        assert!(!r.check("", "", 0, AS_OF).revoked);
        assert!(
            !r.check("tok-1", "user://acme/alice", AS_OF - 10, AS_OF)
                .revoked
        );
    }

    #[test]
    fn an_entry_past_its_own_expiry_stops_matching() {
        let mut r = Revocations::with_defaults();
        r.install(snapshot(AS_OF, vec![jti("tok-1", AS_OF + 10)]), AS_OF);
        assert!(r.check("tok-1", "s", 0, AS_OF + 9).revoked);
        assert!(
            !r.check("tok-1", "s", 0, AS_OF + 10).revoked,
            "an entry only outlives the last token it could match"
        );
    }

    #[test]
    fn an_entry_with_no_stated_expiry_is_kept_rather_than_dropped() {
        // The two mistakes are different sizes. Dropping early makes a revoked
        // token work; keeping late outlives a token that has expired anyway.
        let mut r = Revocations::with_defaults();
        r.install(snapshot(AS_OF, vec![jti("tok-1", 0)]), AS_OF);
        assert!(r.check("tok-1", "s", 0, AS_OF + 86_400).revoked);
    }

    #[test]
    fn the_hook_is_the_shape_verify_delegation_takes_and_shows_the_caller_the_basis() {
        use std::cell::RefCell;
        let r = holding_one();
        let seen: RefCell<Vec<Basis>> = RefCell::new(Vec::new());
        let hook = r.hook(AS_OF, |a| seen.borrow_mut().push(a.basis));
        assert!(hook("tok-1", "user://acme/alice", AS_OF - 10));
        assert!(!hook("tok-2", "user://acme/alice", AS_OF - 10));
        assert_eq!(
            *seen.borrow(),
            vec![Basis::Listed { age_secs: 0 }, Basis::Absent { age_secs: 0 }]
        );
    }

    #[test]
    fn the_body_vouchryx_serves_parses_into_this() {
        // Copied from a live `GET /v1/revocations`, not written from the struct:
        // a fixture derived from the reader cannot catch the reader misreading.
        let raw = r#"{"as_of":1800000000,"revocations":[
            {"jti":"tok-1","expires":1800003600,"actor":"user://acme/ops","reason":"key leaked"},
            {"subject":"agent://acme/triage","issued_before":1800000000,
             "expires":1800003600,"actor":"user://acme/ops","reason":"compromised"}]}"#;
        let snap = Snapshot::from_json(raw).expect("vouchryx's own body");
        assert_eq!(snap.as_of, 1_800_000_000);
        assert_eq!(snap.revocations.len(), 2);
        assert_eq!(snap.revocations[0].jti, "tok-1");
        assert_eq!(snap.revocations[1].subject, "agent://acme/triage");
        assert_eq!(snap.revocations[1].issued_before, 1_800_000_000);
    }

    #[test]
    fn an_empty_list_is_a_list_and_not_a_failure() {
        // The distinction `as_of` exists for. An empty answer is knowledge.
        let mut r = Revocations::with_defaults();
        let snap = Snapshot::from_json(r#"{"as_of":1800000000,"revocations":[]}"#).expect("a body");
        assert_eq!(r.install(snap, AS_OF), Install::Applied);
        assert_eq!(
            r.check("tok-1", "s", 0, AS_OF).basis,
            Basis::Absent { age_secs: 0 },
            "an empty list answers a miss; it is not the same as never having fetched"
        );
    }

    #[test]
    fn a_body_that_is_not_a_list_at_all_is_an_error_rather_than_an_empty_list() {
        for raw in ["", "null", "[]", "{\"revocations\": 7}", "not json"] {
            assert!(
                Snapshot::from_json(raw).is_err(),
                "{raw:?} parsed as a revocation list"
            );
        }
    }

    /// Pins the DEFAULT, which is what a deployment that never names a mode
    /// gets. Every other test here passes a mode explicitly, so before this one
    /// the default was the most-used setting in the module and the only one
    /// nothing asserted.
    #[test]
    fn the_default_fail_mode_refuses() {
        assert_eq!(
            FailMode::default(),
            FailMode::Closed,
            "an operator who never chose gets this one"
        );
        // A cache nobody ever fetched into, built without naming a mode. This
        // is the shape a half-wired door has.
        let a = Revocations::with_defaults().check("tok-1", "user://acme/alice", AS_OF - 10, AS_OF);
        assert!(a.revoked, "a list nobody fetched let the call through");
        assert_eq!(a.basis, Basis::Never);
    }
}
