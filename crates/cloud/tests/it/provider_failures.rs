//! Invariant 144: a provider's failed calls become ONE `dependency_failed`
//! incident per provider, in the console and the API, once a provider has
//! failed `TOKENFUSE_CLOUD_INCIDENT_PROVIDER_FAILURES` calls within ten
//! minutes. The route that carries the report is held to a hostile caller: a
//! role, a body size, an entry count, a label that is sanitised and bounded,
//! and a count that cannot overflow.

use std::collections::HashMap;
use std::sync::Arc;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use http_body_util::BodyExt;
use tower::ServiceExt;

use tokenfuse_cloud::keys::digest;
use tokenfuse_cloud::store::{
    provider_label, MAX_INCIDENTS_PER_ORG, MAX_PROVIDERS_PER_ORG, MAX_PROVIDER_FAILURES_PER_REPORT,
    MAX_PROVIDER_INCIDENTS_PER_ORG, PROVIDER_LABEL_MAX_CHARS, PROVIDER_OVERFLOW_BUCKET,
};
use tokenfuse_cloud::{app, AppState, FindingInput, IncidentConfig, Principal, Store};

const T0: i64 = 1_800_000_000_000;
const MINUTE: i64 = 60_000;
const PROVIDER: &str = "api.example.test";

fn store(threshold: u64) -> Store {
    Store::with_incident_config(IncidentConfig {
        provider_failures: threshold,
        ..Default::default()
    })
}

fn severity_of(inc: &tokenfuse_cloud::Incident) -> String {
    serde_json::to_value(inc).unwrap()["severity"]
        .as_str()
        .unwrap()
        .to_string()
}

// --- the detector -----------------------------------------------------------

#[test]
fn a_provider_under_the_threshold_opens_nothing() {
    let s = store(3);
    assert!(s
        .note_provider_failures_at("acme", PROVIDER, 1, "", T0)
        .is_none());
    assert!(s
        .note_provider_failures_at("acme", PROVIDER, 1, "", T0 + 1_000)
        .is_none());
    assert!(s.incidents("acme").is_empty());
}

#[test]
fn the_failure_that_reaches_the_threshold_opens_one_incident_for_that_provider() {
    let s = store(3);
    s.note_provider_failures_at("acme", PROVIDER, 1, "", T0);
    s.note_provider_failures_at("acme", PROVIDER, 1, "", T0 + 1_000);
    let inc = s
        .note_provider_failures_at("acme", PROVIDER, 1, "HTTP 503", T0 + 2_000)
        .expect("the third failure reaches the threshold");
    assert_eq!(inc.id, "dependency_failed:provider:api.example.test");
    assert_eq!(inc.kind, "dependency_failed");
    assert_eq!(severity_of(&inc), "high");
    assert_eq!(inc.occurrences, 3);
    assert!(
        inc.agent_id.is_none() && inc.run_id.is_none(),
        "a provider is not an agent or a run, which is why this incident stays off the agent-event bus"
    );
    assert!(inc.source.is_none(), "this plane measured it itself");
    assert!(!inc.acknowledged);
    assert_eq!(s.incidents("acme").len(), 1);
}

#[test]
fn a_storm_of_failures_is_one_incident_whose_count_is_the_storm() {
    let s = store(3);
    for i in 0..500 {
        s.note_provider_failures_at("acme", PROVIDER, 1, "HTTP 503", T0 + i * 100);
    }
    let incidents = s.incidents("acme");
    assert_eq!(incidents.len(), 1, "five hundred failures, one row");
    assert_eq!(incidents[0].occurrences, 500);
}

#[test]
fn a_report_that_carries_a_count_counts_every_failure_in_it() {
    let s = store(3);
    let inc = s
        .note_provider_failures_at("acme", PROVIDER, 7, "", T0)
        .expect("seven failures in one report is over the threshold of three");
    assert_eq!(inc.occurrences, 7);
}

#[test]
fn later_failures_add_to_the_incident_that_is_already_open() {
    let s = store(3);
    s.note_provider_failures_at("acme", PROVIDER, 3, "", T0);
    let inc = s
        .note_provider_failures_at("acme", PROVIDER, 5, "", T0 + 20_000)
        .unwrap();
    assert_eq!(inc.occurrences, 8);
    assert_eq!(s.incidents("acme").len(), 1);
}

#[test]
fn two_providers_are_two_incidents() {
    let s = store(3);
    s.note_provider_failures_at("acme", "one.example.test", 3, "", T0);
    s.note_provider_failures_at("acme", "two.example.test", 3, "", T0);
    let mut ids: Vec<String> = s.incidents("acme").into_iter().map(|i| i.id).collect();
    ids.sort();
    assert_eq!(
        ids,
        vec![
            "dependency_failed:provider:one.example.test".to_string(),
            "dependency_failed:provider:two.example.test".to_string()
        ]
    );
}

#[test]
fn a_provider_failing_in_one_org_is_not_counted_in_another() {
    let s = store(3);
    s.note_provider_failures_at("acme", PROVIDER, 2, "", T0);
    s.note_provider_failures_at("globex", PROVIDER, 2, "", T0 + 1_000);
    assert!(s.incidents("acme").is_empty());
    assert!(s.incidents("globex").is_empty());
}

#[test]
fn failures_older_than_the_window_do_not_count() {
    let s = store(3);
    s.note_provider_failures_at("acme", PROVIDER, 2, "", T0);
    let late = s.note_provider_failures_at("acme", PROVIDER, 1, "", T0 + 10 * MINUTE + 1_000);
    assert!(
        late.is_none(),
        "two failures eleven minutes ago and one now are not three in ten minutes"
    );
    assert!(s.incidents("acme").is_empty());
}

#[test]
fn failures_inside_the_window_do_count() {
    let s = store(3);
    s.note_provider_failures_at("acme", PROVIDER, 2, "", T0);
    let inc = s.note_provider_failures_at("acme", PROVIDER, 1, "", T0 + 9 * MINUTE);
    assert!(inc.is_some(), "three failures within nine minutes");
}

#[test]
fn the_window_slides_rather_than_resetting() {
    let s = store(3);
    s.note_provider_failures_at("acme", PROVIDER, 2, "", T0);
    // Eleven minutes on, the first two are out of the window.
    let now = T0 + 11 * MINUTE;
    assert!(s
        .note_provider_failures_at("acme", PROVIDER, 2, "", now)
        .is_none());
    assert!(s
        .note_provider_failures_at("acme", PROVIDER, 1, "", now + 1_000)
        .is_some());
}

#[test]
fn a_zero_count_and_a_blank_provider_open_nothing() {
    let s = store(1);
    assert!(s
        .note_provider_failures_at("acme", PROVIDER, 0, "", T0)
        .is_none());
    assert!(s.note_provider_failures_at("acme", "", 5, "", T0).is_none());
    assert!(s
        .note_provider_failures_at("acme", "   \t\n", 5, "", T0)
        .is_none());
    assert!(s.incidents("acme").is_empty());
}

#[test]
fn the_threshold_is_the_configured_one() {
    let one = store(1);
    assert!(one
        .note_provider_failures_at("acme", PROVIDER, 1, "", T0)
        .is_some());
    let five = store(5);
    assert!(five
        .note_provider_failures_at("acme", PROVIDER, 4, "", T0)
        .is_none());
    assert!(five
        .note_provider_failures_at("acme", PROVIDER, 1, "", T0 + 1)
        .is_some());
    assert_eq!(IncidentConfig::default().provider_failures, 3);
}

#[test]
fn a_hostile_label_is_sanitised_and_bounded() {
    let long = "a".repeat(10_000);
    let hostile = [
        "<script>alert(1)</script>",
        "api.example.test\r\nx-injected: 1",
        "../../etc/passwd",
        "p\u{0}\u{1b}[31mred",
        "ключ.example.test",
        "emoji\u{1f4a5}host",
        long.as_str(),
    ];
    for raw in hostile {
        let label = provider_label(raw).expect("a non-blank label names a provider");
        assert!(label.chars().count() <= PROVIDER_LABEL_MAX_CHARS, "{raw:?}");
        assert!(
            label
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | ':' | '-')),
            "{raw:?} became {label:?}"
        );
        let s = store(1);
        let inc = s.note_provider_failures_at("acme", raw, 1, "", T0).unwrap();
        assert_eq!(inc.id, format!("dependency_failed:provider:{label}"));
    }
    assert_eq!(provider_label("  api.example.test  ").unwrap(), PROVIDER);
}

#[test]
fn hostile_labels_cannot_open_an_incident_apiece() {
    let s = store(3);
    for i in 0..(MAX_PROVIDERS_PER_ORG * 3) {
        s.note_provider_failures_at("acme", &format!("p{i}.example.test"), 3, "", T0);
    }
    let incidents = s.incidents("acme");
    assert!(
        incidents.len() <= MAX_PROVIDERS_PER_ORG + 1,
        "{} incidents for {} labels",
        incidents.len(),
        MAX_PROVIDERS_PER_ORG * 3
    );
    assert!(
        incidents
            .iter()
            .any(|i| i.id == format!("dependency_failed:provider:{PROVIDER_OVERFLOW_BUCKET}")),
        "the providers past the cap are still counted, in one visible bucket"
    );
}

#[test]
fn a_provider_already_tracked_keeps_its_own_incident_when_the_cap_is_full() {
    let s = store(3);
    s.note_provider_failures_at("acme", PROVIDER, 1, "", T0);
    for i in 0..(MAX_PROVIDERS_PER_ORG * 2) {
        s.note_provider_failures_at("acme", &format!("p{i}.example.test"), 1, "", T0);
    }
    let inc = s.note_provider_failures_at("acme", PROVIDER, 2, "", T0 + 1_000);
    assert_eq!(
        inc.expect("the first provider was tracked before the cap filled")
            .id,
        "dependency_failed:provider:api.example.test"
    );
}

#[test]
fn a_provider_that_stopped_failing_gives_its_slot_back() {
    // The cap is on providers being counted, not on every label ever seen:
    // sixty-four old labels whose windows have emptied must not push a real
    // provider into the shared bucket, where its incident would carry a name
    // nobody recognises.
    let s = store(3);
    for i in 0..MAX_PROVIDERS_PER_ORG {
        s.note_provider_failures_at("acme", &format!("old{i}.example.test"), 1, "", T0);
    }
    let later = T0 + 11 * MINUTE;
    let inc = s
        .note_provider_failures_at("acme", "real.example.test", 3, "", later)
        .expect("three failures of a real provider reach the threshold");
    assert_eq!(inc.id, "dependency_failed:provider:real.example.test");
    assert!(
        s.incidents("acme")
            .iter()
            .all(|i| !i.id.ends_with(&format!(":{PROVIDER_OVERFLOW_BUCKET}"))),
        "the real provider was counted in the shared bucket"
    );
}

#[test]
fn an_absurd_count_is_clamped_and_cannot_overflow() {
    let s = store(3);
    let first = s
        .note_provider_failures_at("acme", PROVIDER, u64::MAX, "", T0)
        .unwrap();
    assert_eq!(first.occurrences, MAX_PROVIDER_FAILURES_PER_REPORT);
    let second = s
        .note_provider_failures_at("acme", PROVIDER, u64::MAX, "", T0 + 1)
        .unwrap();
    assert_eq!(second.occurrences, 2 * MAX_PROVIDER_FAILURES_PER_REPORT);
}

#[test]
fn the_summary_names_the_provider_and_is_bounded_and_clean() {
    let s = store(1);
    let hostile = format!("HTTP 503\r\n\u{0}\u{1b}[31m{}", "z".repeat(10_000));
    let inc = s
        .note_provider_failures_at("acme", PROVIDER, 1, &hostile, T0)
        .unwrap();
    let summary = inc
        .summary
        .expect("an incident of this kind says what it is");
    assert!(summary.starts_with("api.example.test failed 1 calls in the last 10 min"));
    assert!(!summary.chars().any(char::is_control), "{summary:?}");
    assert!(summary.chars().count() < 300, "{}", summary.chars().count());
    assert!(summary.contains("HTTP 503"));
}

#[test]
fn a_summary_with_no_detail_still_reads() {
    let s = store(1);
    let inc = s
        .note_provider_failures_at("acme", PROVIDER, 1, "", T0)
        .unwrap();
    assert_eq!(
        inc.summary.unwrap(),
        "api.example.test failed 1 calls in the last 10 min"
    );
}

// --- the number of provider incidents is bounded, and they evict nothing else ---

const PROVIDER_ID_PREFIX: &str = "dependency_failed:provider:";

fn provider_incidents(s: &Store, org: &str) -> usize {
    s.incidents(org)
        .iter()
        .filter(|i| i.id.starts_with(PROVIDER_ID_PREFIX))
        .count()
}

/// `n` incidents of another kind, filed the way a service in the stack files
/// them.
fn fill_with_other_incidents(s: &Store, n: usize) {
    for i in 0..n {
        let subject = format!("agent://acme.example/a{i}");
        s.record_external_finding(
            "acme",
            "key:test",
            FindingInput {
                source: "idryx",
                detector: "agent_shadow_tool",
                severity: tokenfuse_core::Severity::High,
                subject: &subject,
                summary: "",
                ts_millis: T0,
            },
        );
    }
}

#[test]
fn rotating_labels_cannot_create_an_unbounded_number_of_provider_incidents() {
    // Each label fails once and then never again, eleven minutes after the
    // last, so its window has emptied and given its slot back by the time the
    // next arrives. The labels never overlap; the incidents they opened stay.
    let s = store(1);
    let labels = MAX_PROVIDERS_PER_ORG * 3;
    for i in 0..labels {
        let at = T0 + i as i64 * 11 * MINUTE;
        s.note_provider_failures_at("acme", &format!("p{i}.example.test"), 1, "", at);
    }
    let n = provider_incidents(&s, "acme");
    assert!(
        n <= MAX_PROVIDERS_PER_ORG + 1,
        "{n} provider incidents from {labels} rotating labels"
    );
    assert!(
        s.incidents("acme")
            .iter()
            .any(|i| i.id == format!("{PROVIDER_ID_PREFIX}{PROVIDER_OVERFLOW_BUCKET}")),
        "the labels past the cap are still counted, in the shared bucket"
    );
}

#[test]
fn the_incident_cap_is_per_site_too() {
    let s = store(1);
    for i in 0..(MAX_PROVIDERS_PER_ORG * 2) {
        let at = T0 + i as i64 * 11 * MINUTE;
        s.note_provider_failures_from_at(
            "acme",
            Some("noisy"),
            &format!("p{i}.example.test"),
            1,
            "",
            at,
        );
    }
    let noisy = s
        .incidents("acme")
        .iter()
        .filter(|i| i.id.ends_with("@noisy"))
        .count();
    assert!(
        noisy <= MAX_PROVIDERS_PER_ORG + 1,
        "{noisy} incidents from one site's rotating labels"
    );
    let late = T0 + MAX_PROVIDERS_PER_ORG as i64 * 3 * 11 * MINUTE;
    let inc = s
        .note_provider_failures_from_at("acme", Some("quiet"), "real.example.test", 1, "", late)
        .unwrap();
    assert_eq!(inc.id, "dependency_failed:provider:real.example.test@quiet");
}

#[test]
fn a_flood_of_provider_incidents_never_evicts_an_incident_of_another_kind() {
    let s = store(1);
    let others = MAX_INCIDENTS_PER_ORG - 5;
    fill_with_other_incidents(&s, others);
    for i in 0..100 {
        let at = T0 + i as i64 * 11 * MINUTE;
        s.note_provider_failures_at("acme", &format!("flood{i}.example.test"), 1, "", at);
    }
    let all = s.incidents("acme");
    let elsewhere = all
        .iter()
        .filter(|i| !i.id.starts_with(PROVIDER_ID_PREFIX))
        .count();
    assert_eq!(
        elsewhere, others,
        "provider incidents evicted incidents of another kind"
    );
    assert!(
        provider_incidents(&s, "acme") > 5,
        "the provider incidents have a reserve of their own and were not held to the five places left among the others"
    );
}

#[test]
fn a_provider_incident_is_still_opened_when_the_table_is_full_of_other_kinds() {
    // Provider incidents have a reserve of their own, so a full table of other
    // kinds neither blocks them nor loses them.
    let s = store(1);
    fill_with_other_incidents(&s, MAX_INCIDENTS_PER_ORG);
    let opened = s.note_provider_failures_at("acme", PROVIDER, 1, "", T0);
    assert!(opened.is_some(), "a provider incident was refused room");
    assert_eq!(provider_incidents(&s, "acme"), 1);
    assert_eq!(s.incidents("acme").len(), MAX_INCIDENTS_PER_ORG + 1);
}

#[test]
fn a_flood_of_other_incidents_never_evicts_a_provider_incident() {
    let s = store(1);
    for i in 0..10 {
        // Older than every incident filed below, so the oldest-first rule
        // would take them first.
        let at = T0 - 3_600_000 + i as i64;
        s.note_provider_failures_at("acme", &format!("old{i}.example.test"), 1, "", at);
    }
    fill_with_other_incidents(&s, MAX_INCIDENTS_PER_ORG + 50);
    assert_eq!(
        provider_incidents(&s, "acme"),
        10,
        "incidents of other kinds evicted provider incidents"
    );
    let elsewhere = s.incidents("acme").len() - 10;
    assert_eq!(
        elsewhere, MAX_INCIDENTS_PER_ORG,
        "the other kinds keep their own cap"
    );
}

#[test]
fn a_provider_incident_over_the_reserve_is_filed_in_other_and_never_lost() {
    let s = store(1);
    let sites = MAX_PROVIDER_INCIDENTS_PER_ORG / MAX_PROVIDERS_PER_ORG;
    for site in 0..sites {
        let site = format!("gw-{site}");
        for i in 0..MAX_PROVIDERS_PER_ORG {
            let label = format!("p{i}.example.test");
            s.note_provider_failures_from_at("acme", Some(&site), &label, 1, "", T0);
        }
    }
    assert_eq!(
        provider_incidents(&s, "acme"),
        MAX_PROVIDER_INCIDENTS_PER_ORG
    );
    let inc = s
        .note_provider_failures_from_at("acme", Some("gw-new"), "late.example.test", 1, "", T0 + 1)
        .expect("a failure over the reserve is not lost");
    assert_eq!(inc.id, "dependency_failed:provider:other@gw-new");
    assert!(inc.summary.unwrap().contains("late.example.test"));
}

fn fill_site(s: &Store, site: &str, n: usize, at: i64) {
    for i in 0..n {
        let label = format!("p{i}.example.test");
        s.note_provider_failures_from_at("acme", Some(site), &label, 1, "", at);
    }
}

fn acknowledge_everything(s: &Store) {
    for inc in s.incidents("acme") {
        assert!(s.ack_incident("acme", &inc.id));
    }
}

#[test]
fn old_and_acknowledged_provider_incidents_free_their_place() {
    let s = store(1);
    fill_site(&s, "gw-1", MAX_PROVIDERS_PER_ORG, T0);
    acknowledge_everything(&s);
    let inc = s
        .note_provider_failures_from_at(
            "acme",
            Some("gw-1"),
            "fresh.example.test",
            1,
            "",
            T0 + 11 * MINUTE,
        )
        .unwrap();
    assert_eq!(inc.id, "dependency_failed:provider:fresh.example.test@gw-1");
}

#[test]
fn recent_provider_incidents_hold_their_place_even_when_acknowledged() {
    let s = store(1);
    fill_site(&s, "gw-1", MAX_PROVIDERS_PER_ORG, T0);
    acknowledge_everything(&s);
    let inc = s
        .note_provider_failures_from_at(
            "acme",
            Some("gw-1"),
            "fresh.example.test",
            1,
            "",
            T0 + MINUTE,
        )
        .unwrap();
    assert_eq!(inc.id, "dependency_failed:provider:other@gw-1");
}

#[test]
fn unacknowledged_provider_incidents_hold_their_place_however_old() {
    let s = store(1);
    fill_site(&s, "gw-1", MAX_PROVIDERS_PER_ORG, T0);
    let inc = s
        .note_provider_failures_from_at(
            "acme",
            Some("gw-1"),
            "fresh.example.test",
            1,
            "",
            T0 + 60 * MINUTE,
        )
        .unwrap();
    assert_eq!(inc.id, "dependency_failed:provider:other@gw-1");
}

#[test]
fn a_failure_folded_into_other_names_its_label_and_is_not_hidden_by_an_old_acknowledgement() {
    let s = store(1);
    fill_site(&s, "gw-1", MAX_PROVIDERS_PER_ORG, T0);
    let first = s
        .note_provider_failures_from_at("acme", Some("gw-1"), "extra1.example.test", 1, "", T0 + 1)
        .unwrap();
    assert_eq!(first.id, "dependency_failed:provider:other@gw-1");
    assert!(first.summary.unwrap().contains("extra1.example.test"));
    assert!(s.ack_incident("acme", &first.id));
    let again = s
        .note_provider_failures_from_at("acme", Some("gw-1"), "extra2.example.test", 1, "", T0 + 2)
        .unwrap();
    assert_eq!(again.id, first.id);
    assert!(
        !again.acknowledged,
        "a new failure hid behind an old acknowledgement"
    );
    assert!(again.summary.unwrap().contains("extra2.example.test"));
}

// --- one reporting site never adds to another's count -------------------------

#[test]
fn a_site_bound_report_is_filed_under_its_site() {
    let s = store(3);
    let inc = s
        .note_provider_failures_from_at("acme", Some("gw-1"), PROVIDER, 3, "HTTP 503", T0)
        .unwrap();
    assert_eq!(inc.id, "dependency_failed:provider:api.example.test@gw-1");
    let summary = inc.summary.unwrap();
    assert!(summary.contains("reported by site gw-1"), "{summary}");
}

#[test]
fn two_sites_reporting_one_provider_are_two_incidents_that_never_add_up() {
    let s = store(3);
    s.note_provider_failures_from_at("acme", Some("gw-1"), PROVIDER, 2, "", T0);
    let second = s.note_provider_failures_from_at("acme", Some("gw-2"), PROVIDER, 2, "", T0 + 1);
    assert!(
        second.is_none(),
        "two failures from each of two sites are not four from one"
    );
    assert!(s.incidents("acme").is_empty());
    s.note_provider_failures_from_at("acme", Some("gw-1"), PROVIDER, 1, "", T0 + 2);
    s.note_provider_failures_from_at("acme", Some("gw-2"), PROVIDER, 1, "", T0 + 3);
    let mut ids: Vec<String> = s.incidents("acme").into_iter().map(|i| i.id).collect();
    ids.sort();
    assert_eq!(
        ids,
        vec![
            "dependency_failed:provider:api.example.test@gw-1".to_string(),
            "dependency_failed:provider:api.example.test@gw-2".to_string()
        ]
    );
}

#[test]
fn a_key_bound_to_no_site_is_counted_apart_from_every_site() {
    let s = store(3);
    s.note_provider_failures_from_at("acme", Some("gw-1"), PROVIDER, 2, "", T0);
    assert!(s
        .note_provider_failures_at("acme", PROVIDER, 2, "", T0 + 1)
        .is_none());
    let inc = s
        .note_provider_failures_at("acme", PROVIDER, 1, "", T0 + 2)
        .unwrap();
    assert_eq!(inc.id, "dependency_failed:provider:api.example.test");
    assert!(!inc.summary.unwrap().contains("reported by site"));
}

#[test]
fn the_provider_cap_is_per_site_so_one_site_cannot_crowd_out_another() {
    let s = store(3);
    for i in 0..(MAX_PROVIDERS_PER_ORG * 2) {
        s.note_provider_failures_from_at(
            "acme",
            Some("noisy"),
            &format!("p{i}.example.test"),
            1,
            "",
            T0,
        );
    }
    let inc = s
        .note_provider_failures_from_at("acme", Some("quiet"), "real.example.test", 3, "", T0)
        .unwrap();
    assert_eq!(inc.id, "dependency_failed:provider:real.example.test@quiet");
}

#[test]
fn a_site_name_is_sanitised_and_a_blank_one_is_no_site() {
    let s = store(1);
    let inc = s
        .note_provider_failures_from_at("acme", Some("gw 1/<x>\r\n"), PROVIDER, 1, "", T0)
        .unwrap();
    assert!(inc.id.ends_with("@gw_1__x_"), "unexpected id {:?}", inc.id);
    let blank = s
        .note_provider_failures_from_at("acme", Some("   "), "other.example.test", 1, "", T0)
        .unwrap();
    assert_eq!(blank.id, "dependency_failed:provider:other.example.test");
}

// --- the route --------------------------------------------------------------

fn test_state() -> (AppState, Arc<Store>) {
    let store = Arc::new(Store::new());
    let mut keys = HashMap::new();
    for (key, role, site) in [
        ("adminkey", "admin", None),
        ("ingestkey", "ingest", None),
        ("sitekey", "ingest", Some("gw-1")),
        ("sitekey2", "ingest", Some("gw-2")),
        ("viewerkey", "viewer", None),
    ] {
        keys.insert(
            digest(key),
            Principal {
                org: "acme".into(),
                role: role.into(),
                site: site.map(str::to_string),
            },
        );
    }
    (
        AppState::new(Arc::clone(&store), Arc::new(keys), 0.8),
        store,
    )
}

async fn post_raw(
    state: &AppState,
    key: Option<&str>,
    body: Vec<u8>,
) -> (StatusCode, serde_json::Value) {
    let mut req = Request::post("/v1/provider-failures").header("content-type", "application/json");
    if let Some(k) = key {
        req = req.header("authorization", format!("Bearer {k}"));
    }
    let resp = app(state.clone())
        .oneshot(req.body(Body::from(body)).unwrap())
        .await
        .unwrap();
    let status = resp.status();
    let bytes = resp.into_body().collect().await.unwrap().to_bytes();
    (
        status,
        serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null),
    )
}

async fn post(
    state: &AppState,
    key: Option<&str>,
    body: serde_json::Value,
) -> (StatusCode, serde_json::Value) {
    post_raw(state, key, body.to_string().into_bytes()).await
}

fn report(provider: &str, count: u64) -> serde_json::Value {
    serde_json::json!({ "failures": [{ "provider": provider, "count": count, "detail": "HTTP 503" }] })
}

async fn incidents(state: &AppState) -> Vec<serde_json::Value> {
    let resp = app(state.clone())
        .oneshot(
            Request::get("/v1/incidents")
                .header("authorization", "Bearer adminkey")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let bytes = resp.into_body().collect().await.unwrap().to_bytes();
    serde_json::from_slice::<Vec<serde_json::Value>>(&bytes).unwrap()
}

#[tokio::test]
async fn an_ingest_key_an_admin_key_and_a_site_bound_ingest_key_may_report() {
    for key in ["ingestkey", "adminkey", "sitekey"] {
        let (state, _) = test_state();
        let (status, body) = post(&state, Some(key), report(PROVIDER, 1)).await;
        assert_eq!(status, StatusCode::OK, "{key}");
        assert_eq!(body["accepted"], 1, "{key}");
    }
}

#[tokio::test]
async fn a_viewer_is_forbidden_and_a_caller_with_no_key_is_unauthorized_and_nothing_is_counted() {
    let (state, store) = test_state();
    let (status, _) = post(&state, Some("viewerkey"), report(PROVIDER, 50)).await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    let (status, _) = post(&state, None, report(PROVIDER, 50)).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    let (status, _) = post(&state, Some("not-a-key"), report(PROVIDER, 50)).await;
    assert!(
        matches!(status, StatusCode::UNAUTHORIZED | StatusCode::FORBIDDEN),
        "a key this plane does not know was answered {status}"
    );
    assert!(
        store.incidents("acme").is_empty(),
        "fifty failures from callers who may not report opened an incident"
    );
}

#[tokio::test]
async fn three_reported_failures_are_one_incident_on_the_incidents_api() {
    let (state, _) = test_state();
    for _ in 0..3 {
        let (status, _) = post(&state, Some("ingestkey"), report(PROVIDER, 1)).await;
        assert_eq!(status, StatusCode::OK);
    }
    let all = incidents(&state).await;
    assert_eq!(all.len(), 1);
    assert_eq!(all[0]["id"], "dependency_failed:provider:api.example.test");
    assert_eq!(all[0]["kind"], "dependency_failed");
    assert_eq!(all[0]["severity"], "high");
    assert_eq!(all[0]["occurrences"], 3);
    assert!(all[0]["summary"].as_str().unwrap().contains(PROVIDER));
}

#[tokio::test]
async fn a_body_over_the_limit_is_refused_before_it_is_counted() {
    let (state, store) = test_state();
    let big = serde_json::json!({
        "failures": [{ "provider": PROVIDER, "count": 5, "detail": "x".repeat(17 * 1024) }]
    });
    let (status, _) = post(&state, Some("ingestkey"), big).await;
    assert_eq!(status, StatusCode::PAYLOAD_TOO_LARGE);
    assert!(store.incidents("acme").is_empty());

    // The limit is on the route, so it holds for a caller with no key too.
    let (status, _) = post_raw(&state, None, vec![b' '; 17 * 1024]).await;
    assert_eq!(status, StatusCode::PAYLOAD_TOO_LARGE);

    // And a body just inside it is read.
    let inside = serde_json::json!({
        "failures": [{ "provider": PROVIDER, "count": 1, "detail": "x".repeat(15 * 1024) }]
    });
    let (status, body) = post(&state, Some("ingestkey"), inside).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["accepted"], 1);
}

#[tokio::test]
async fn more_entries_than_allowed_are_refused_and_none_is_counted() {
    let (state, store) = test_state();
    let entries: Vec<_> = (0..65)
        .map(|i| serde_json::json!({ "provider": format!("p{i}"), "count": 5 }))
        .collect();
    let (status, _) = post(
        &state,
        Some("ingestkey"),
        serde_json::json!({ "failures": entries }),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert!(store.incidents("acme").is_empty());

    let entries: Vec<_> = (0..64)
        .map(|i| serde_json::json!({ "provider": format!("p{i}"), "count": 1 }))
        .collect();
    let (status, body) = post(
        &state,
        Some("ingestkey"),
        serde_json::json!({ "failures": entries }),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["accepted"], 64);
}

#[tokio::test]
async fn a_malformed_report_is_a_bad_request_and_counts_nothing() {
    let (state, store) = test_state();
    for raw in [
        "not json".to_string(),
        r#"{"failures": "x"}"#.to_string(),
        r#"{"failures":[{"provider":"p","count":-1}]}"#.to_string(),
        r#"{"failures":[{"provider":"p","count":1.5}]}"#.to_string(),
        r#"{"failures":[{"provider":"p","count":"9"}]}"#.to_string(),
        r#"{"failures":[{"provider":"p"}]}"#.to_string(),
        r#"{"failures":[{"count":9}]}"#.to_string(),
        r#"{"failures":[{"provider":7,"count":9}]}"#.to_string(),
        r#"{"failures":[{"provider":"p","count":18446744073709551616}]}"#.to_string(),
    ] {
        let (status, _) = post_raw(&state, Some("ingestkey"), raw.clone().into_bytes()).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{raw}");
    }
    assert!(store.incidents("acme").is_empty());
}

#[tokio::test]
async fn an_empty_report_a_blank_provider_and_a_zero_count_are_accepted_as_nothing() {
    let (state, store) = test_state();
    let (status, body) = post(&state, Some("ingestkey"), serde_json::json!({})).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["accepted"], 0);
    let (status, body) = post(
        &state,
        Some("ingestkey"),
        serde_json::json!({ "failures": [
            { "provider": "  ", "count": 9 },
            { "provider": PROVIDER, "count": 0 },
        ] }),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["accepted"], 0);
    assert!(store.incidents("acme").is_empty());
}

#[tokio::test]
async fn a_provider_name_cannot_carry_markup_into_an_incident() {
    let (state, _) = test_state();
    let (status, _) = post(
        &state,
        Some("ingestkey"),
        report("<img src=x onerror=alert(1)>", 3),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let all = incidents(&state).await;
    assert_eq!(all.len(), 1);
    let id = all[0]["id"].as_str().unwrap();
    assert!(
        !id.contains('<') && !id.contains('>') && !id.contains(' '),
        "{id}"
    );
}

#[tokio::test]
async fn a_key_bound_to_one_site_cannot_add_to_another_sites_count() {
    let (state, store) = test_state();
    for _ in 0..2 {
        post(&state, Some("sitekey"), report(PROVIDER, 1)).await;
    }
    for _ in 0..2 {
        post(&state, Some("sitekey2"), report(PROVIDER, 1)).await;
    }
    assert!(
        store.incidents("acme").is_empty(),
        "two sites each under the threshold added up to an incident"
    );
    post(&state, Some("sitekey"), report(PROVIDER, 1)).await;
    let all = incidents(&state).await;
    assert_eq!(
        all.len(),
        1,
        "the first site's own third failure opens its own incident"
    );
    assert_eq!(
        all[0]["id"],
        "dependency_failed:provider:api.example.test@gw-1"
    );
}

#[tokio::test]
async fn the_site_comes_from_the_key_and_never_from_the_body() {
    let (state, _) = test_state();
    for _ in 0..3 {
        let body = serde_json::json!({
            "site": "gw-2",
            "failures": [{ "provider": PROVIDER, "count": 1, "site": "gw-2" }]
        });
        let (status, _) = post(&state, Some("sitekey"), body).await;
        assert_eq!(status, StatusCode::OK);
    }
    let all = incidents(&state).await;
    assert_eq!(all.len(), 1);
    assert_eq!(
        all[0]["id"], "dependency_failed:provider:api.example.test@gw-1",
        "a report from the gw-1 key was filed under a site its body named"
    );
}
