//! Per-key rate and concurrency limits on the LLM doors.
//!
//! The gateway had no bound on how fast or how much at once one caller may
//! call it: only the request body size was capped (`DefaultBodyLimit`). One
//! client key, or one agent token, could take every upstream connection and
//! every reservation slot the gateway has. This module bounds each principal
//! the door verified (`key:<id>`, `tok:<agent>`; one shared bucket when nothing
//! authenticates):
//!
//! - **Rate**: a token bucket of `TOKENFUSE_KEY_RPS` calls per second, holding
//!   at most `TOKENFUSE_KEY_BURST` (default: the rate, at least 1).
//! - **Concurrency**: at most `TOKENFUSE_KEY_CONCURRENCY` calls in flight, a
//!   call counted from admission until its answer, streamed or not, has been
//!   sent or the client went away.
//!
//! A call over either is answered `429` with `Retry-After`, before anything is
//! reserved, opened or forwarded. Both are off unless set, so a deployment that
//! sets nothing is unchanged. A value that cannot be read refuses to start
//! (`defaults::exit_on_refusal`), as a security switch does (invariant 98).

use std::collections::HashMap;
use std::sync::{Arc, Mutex, PoisonError};
use std::time::{Duration, Instant};

/// The variable for calls per second per principal.
pub const RPS_VAR: &str = "TOKENFUSE_KEY_RPS";
/// The variable for the most calls a bucket may hold at once.
pub const BURST_VAR: &str = "TOKENFUSE_KEY_BURST";
/// The variable for calls in flight per principal.
pub const CONCURRENCY_VAR: &str = "TOKENFUSE_KEY_CONCURRENCY";

/// The most principals whose buckets are remembered. Past it, buckets idle for
/// a minute are forgotten (a forgotten bucket is full again, which only ever
/// admits more); a principal needs a credential the door verified, so the set
/// is bounded by the credentials the operator issued.
const MAX_TRACKED: usize = 65_536;

/// What was configured. `None` is off.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Limits {
    pub rps: Option<f64>,
    pub burst: f64,
    pub concurrency: Option<u32>,
}

impl Limits {
    /// Whether anything is limited.
    pub fn is_on(&self) -> bool {
        self.rps.is_some() || self.concurrency.is_some()
    }
}

/// Which limit refused a call.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Limit {
    Rate,
    Concurrency,
}

impl Limit {
    pub fn as_str(self) -> &'static str {
        match self {
            Limit::Rate => "rate",
            Limit::Concurrency => "concurrency",
        }
    }
}

/// A refusal: which limit, and when a retry can succeed, in whole seconds.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Refusal {
    pub limit: Limit,
    pub retry_after_secs: u64,
}

#[derive(Debug)]
struct Bucket {
    tokens: f64,
    at: Instant,
}

/// The limiter one gateway holds.
#[derive(Debug)]
pub struct KeyLimiter {
    limits: Limits,
    buckets: Mutex<HashMap<String, Bucket>>,
    inflight: Mutex<HashMap<String, u32>>,
}

/// One admitted call's place in its principal's concurrency count, given back
/// when dropped.
#[derive(Debug)]
pub struct Permit {
    limiter: Arc<KeyLimiter>,
    principal: String,
    counted: bool,
}

impl Drop for Permit {
    fn drop(&mut self) {
        if !self.counted {
            return;
        }
        let mut inflight = self
            .limiter
            .inflight
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        if let Some(n) = inflight.get_mut(&self.principal) {
            *n = n.saturating_sub(1);
            if *n == 0 {
                inflight.remove(&self.principal);
            }
        }
    }
}

impl KeyLimiter {
    pub fn new(limits: Limits) -> Arc<Self> {
        Arc::new(Self {
            limits,
            buckets: Mutex::new(HashMap::new()),
            inflight: Mutex::new(HashMap::new()),
        })
    }

    pub fn limits(&self) -> Limits {
        self.limits
    }

    /// Admit one call for `principal` at `now`, or say which limit refuses it.
    /// Concurrency is checked first and takes nothing from the bucket when it
    /// refuses; a call the bucket refuses is not counted in flight.
    pub fn admit(self: &Arc<Self>, principal: &str, now: Instant) -> Result<Permit, Refusal> {
        let mut counted = false;
        if let Some(max) = self.limits.concurrency {
            let mut inflight = self.inflight.lock().unwrap_or_else(PoisonError::into_inner);
            let n = inflight.entry(principal.to_string()).or_insert(0);
            if *n >= max {
                return Err(Refusal {
                    limit: Limit::Concurrency,
                    retry_after_secs: 1,
                });
            }
            *n += 1;
            counted = true;
        }
        let permit = Permit {
            limiter: Arc::clone(self),
            principal: principal.to_string(),
            counted,
        };
        if let Some(rps) = self.limits.rps {
            let burst = self.limits.burst;
            let mut buckets = self.buckets.lock().unwrap_or_else(PoisonError::into_inner);
            if buckets.len() >= MAX_TRACKED && !buckets.contains_key(principal) {
                buckets
                    .retain(|_, b| now.saturating_duration_since(b.at) < Duration::from_secs(60));
                if buckets.len() >= MAX_TRACKED {
                    buckets.clear();
                }
            }
            let b = buckets.entry(principal.to_string()).or_insert(Bucket {
                tokens: burst,
                at: now,
            });
            let elapsed = now.saturating_duration_since(b.at).as_secs_f64();
            b.tokens = (b.tokens + elapsed * rps).min(burst);
            b.at = now;
            if b.tokens < 1.0 {
                let wait = (1.0 - b.tokens) / rps;
                return Err(Refusal {
                    limit: Limit::Rate,
                    retry_after_secs: (wait.ceil() as u64).max(1),
                });
            }
            b.tokens -= 1.0;
        }
        Ok(permit)
    }
}

/// Read the three variables. Unset or blank is off; a set value that is not a
/// positive number (rate, burst) or a positive integer (concurrency) is an
/// error naming the variable, and so is a burst with no rate or a burst below 1.
pub fn limits_from(
    rps: Option<&str>,
    burst: Option<&str>,
    concurrency: Option<&str>,
) -> Result<Limits, String> {
    let set = |v: Option<&str>| v.map(str::trim).filter(|v| !v.is_empty());
    let rps = match set(rps) {
        None => None,
        Some(v) => match v.parse::<f64>() {
            Ok(n) if n.is_finite() && n > 0.0 && n <= 1_000_000.0 => Some(n),
            _ => {
                return Err(format!(
                    "tokenfuse: {RPS_VAR}={v:?} is not a number of calls per second above 0 \
                     and at most 1000000"
                ))
            }
        },
    };
    let burst = match set(burst) {
        None => rps.map_or(1.0, |r| r.max(1.0)),
        Some(v) => {
            if rps.is_none() {
                return Err(format!(
                    "tokenfuse: {BURST_VAR} is set and {RPS_VAR} is not; a burst bounds a rate"
                ));
            }
            match v.parse::<f64>() {
                Ok(n) if n.is_finite() && (1.0..=1_000_000.0).contains(&n) => n,
                _ => {
                    return Err(format!(
                        "tokenfuse: {BURST_VAR}={v:?} is not a number from 1 to 1000000"
                    ))
                }
            }
        }
    };
    let concurrency = match set(concurrency) {
        None => None,
        Some(v) => match v.parse::<u32>() {
            Ok(n) if n >= 1 => Some(n),
            _ => {
                return Err(format!(
                    "tokenfuse: {CONCURRENCY_VAR}={v:?} is not a whole number of calls above 0"
                ))
            }
        },
    };
    Ok(Limits {
        rps,
        burst,
        concurrency,
    })
}

/// [`limits_from`] against the process environment.
pub fn limits_from_env() -> Result<Limits, String> {
    let get = |k: &str| std::env::var(k).ok();
    limits_from(
        get(RPS_VAR).as_deref(),
        get(BURST_VAR).as_deref(),
        get(CONCURRENCY_VAR).as_deref(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn lim(rps: Option<f64>, burst: f64, concurrency: Option<u32>) -> Arc<KeyLimiter> {
        KeyLimiter::new(Limits {
            rps,
            burst,
            concurrency,
        })
    }

    #[test]
    fn nothing_set_is_off_and_admits_everything() {
        let l = limits_from(None, Some(" "), Some("")).unwrap();
        assert!(!l.is_on());
        let k = KeyLimiter::new(l);
        let t = Instant::now();
        let held: Vec<_> = (0..1000).map(|_| k.admit("key:a", t).unwrap()).collect();
        assert_eq!(held.len(), 1000);
    }

    #[test]
    fn the_bucket_holds_the_burst_and_refills_at_the_rate() {
        let k = lim(Some(2.0), 3.0, None);
        let t0 = Instant::now();
        for _ in 0..3 {
            k.admit("key:a", t0).unwrap();
        }
        let r = k.admit("key:a", t0).unwrap_err();
        assert_eq!(
            r,
            Refusal {
                limit: Limit::Rate,
                retry_after_secs: 1
            }
        );
        // Half a second at 2 per second is exactly one call, not two.
        let t1 = t0 + Duration::from_millis(500);
        k.admit("key:a", t1).unwrap();
        assert_eq!(k.admit("key:a", t1).unwrap_err().limit, Limit::Rate);
        // Another principal has its own bucket.
        k.admit("key:b", t1).unwrap();
    }

    #[test]
    fn a_slow_rate_names_the_wait_in_whole_seconds() {
        let k = lim(Some(0.1), 1.0, None);
        let t0 = Instant::now();
        k.admit("key:a", t0).unwrap();
        assert_eq!(k.admit("key:a", t0).unwrap_err().retry_after_secs, 10);
    }

    #[test]
    fn concurrency_counts_until_the_permit_is_dropped() {
        let k = lim(None, 1.0, Some(2));
        let t = Instant::now();
        let a = k.admit("tok:agent://x/y", t).unwrap();
        let _b = k.admit("tok:agent://x/y", t).unwrap();
        assert_eq!(
            k.admit("tok:agent://x/y", t).unwrap_err().limit,
            Limit::Concurrency
        );
        k.admit("key:other", t).unwrap();
        drop(a);
        k.admit("tok:agent://x/y", t).unwrap();
    }

    #[test]
    fn a_concurrency_refusal_takes_nothing_from_the_bucket() {
        let k = lim(Some(1.0), 1.0, Some(1));
        let t = Instant::now();
        let held = k.admit("key:a", t).unwrap();
        assert_eq!(k.admit("key:a", t).unwrap_err().limit, Limit::Concurrency);
        drop(held);
        // The bucket was spent by the first call only; one second refills it.
        k.admit("key:a", t + Duration::from_secs(1)).unwrap();
    }

    #[test]
    fn a_rate_refusal_is_not_counted_in_flight() {
        let k = lim(Some(1.0), 1.0, Some(1));
        let t = Instant::now();
        let held = k.admit("key:a", t).unwrap();
        drop(held);
        assert_eq!(k.admit("key:a", t).unwrap_err().limit, Limit::Rate);
        // Nothing is left in flight: the next second admits.
        k.admit("key:a", t + Duration::from_secs(1)).unwrap();
    }

    #[test]
    fn unusable_values_refuse_to_start_naming_the_variable() {
        for (r, b, c, var) in [
            (Some("0"), None, None, RPS_VAR),
            (Some("-1"), None, None, RPS_VAR),
            (Some("lots"), None, None, RPS_VAR),
            (Some("inf"), None, None, RPS_VAR),
            (Some("5"), Some("0.5"), None, BURST_VAR),
            (None, Some("5"), None, BURST_VAR),
            (None, None, Some("0"), CONCURRENCY_VAR),
            (None, None, Some("2.5"), CONCURRENCY_VAR),
        ] {
            let e = limits_from(r, b, c).unwrap_err();
            assert!(e.contains(var), "{r:?} {b:?} {c:?}: {e}");
        }
        let l = limits_from(Some("0.5"), None, Some("8")).unwrap();
        assert_eq!(
            l,
            Limits {
                rps: Some(0.5),
                burst: 1.0,
                concurrency: Some(8)
            }
        );
    }
}
