//! TokenFuse Radar (W1): eBPF-based discovery of LLM traffic / shadow agents.
//!
//! Attaches to the `sys_enter_connect` tracepoint and reports every outbound
//! IPv4 connect(), TCP or UDP (pid, comm, dest ip:port), flagging those that go to known
//! LLM providers or local model servers, with zero configuration in the apps.

use std::collections::HashSet;
use std::net::{Ipv4Addr, ToSocketAddrs};
use std::os::unix::fs::MetadataExt;

use aya::maps::{MapData, PerCpuArray, RingBuf};
use aya::programs::TracePoint;

#[repr(C)]
#[derive(Clone, Copy)]
struct ConnEvent {
    pid: u32,
    dport: u16,
    _pad: u16,
    daddr: u32,
    comm: [u8; 16],
}

fn resolve_llm_ips() -> HashSet<Ipv4Addr> {
    let hosts = [
        "api.anthropic.com:443",
        "api.openai.com:443",
        "generativelanguage.googleapis.com:443",
    ];
    let mut set = HashSet::new();
    for h in hosts {
        if let Ok(addrs) = h.to_socket_addrs() {
            for a in addrs {
                if let std::net::IpAddr::V4(v4) = a.ip() {
                    set.insert(v4);
                }
            }
        }
    }
    set
}

/// Ports a local model server is expected on: Ollama's own, and the two vLLM
/// defaults.
///
/// One list, read by both the loopback filter and `is_llm`, because they had
/// two and disagreed: the filter admitted 11434 and 8000, `is_llm` also
/// claimed 8001, and the filter runs first. A local vLLM on 8001 was
/// therefore dropped before anything could recognise it, and the classifier
/// branch that named it could never run. Two lists that must agree are one
/// list.
fn is_local_model_port(port: u16) -> bool {
    matches!(port, 11434 | 8000 | 8001)
}

fn is_llm(ip: Ipv4Addr, port: u16, llm: &HashSet<Ipv4Addr>) -> Option<&'static str> {
    // A provider address is LLM traffic only on 443, the one port those
    // providers serve. A resolver choosing a source address per RFC 6724
    // connect()s a UDP socket to every candidate address and sends nothing:
    // Go on 53, musl on 65535. Flagged by address alone, a name lookup printed
    // as an API call (idryx#67, the same defect, graded HIGH).
    if port == 443 && llm.contains(&ip) {
        return Some("LLM provider");
    }

    // A LOCAL model server is one on this machine, and until 2026-09-09 the two
    // branches below tested the port alone. So every host anywhere reached on
    // 8000 was reported as "local vLLM?" and on 11434 as "local Ollama", in a
    // tool whose whole job is telling somebody where their models are.
    //
    // Found by RUNNING the sensor rather than reading it, on the first live run
    // this program has ever had: a connection to 192.0.2.9:8000, a TEST-NET
    // address routed nowhere, came out flagged as a local vLLM. Port 8000 is
    // one of the most common ports on the internet, so this was a false
    // positive generator, not an edge case.
    //
    // It is the same shape as the 443 rule above, which is why that rule's
    // reasoning applies unchanged: a label goes on evidence that supports it.
    // The connection is still reported either way. Only the claim about what it
    // is gets withheld.
    if !ip.is_loopback() {
        return None;
    }
    if port == 11434 {
        Some("local Ollama")
    } else if port == 8000 || port == 8001 {
        Some("local vLLM?")
    } else {
        None
    }
}

/// The inode the kernel gives `/proc/self/ns/pid` in the initial PID namespace
/// (`PROC_PID_INIT_INO`, `include/linux/proc_ns.h`). Fixed by the kernel, and
/// the same constant idryx's sensor uses to ask the same question.
const PROC_PID_INIT_INO: u64 = 0xEFFF_FFFC;

/// Whether radar can recognise its own connections here at all.
///
/// An event carries the pid the kernel assigned in the INITIAL namespace
/// (`bpf_get_current_pid_tgid`), while `std::process::id()` is this process's
/// pid in whatever namespace it happens to be in. On a host those are one
/// number. Inside a container they are two, they never agree, and a self-filter
/// comparing them matches nothing while looking like it works: idryx measured
/// exactly that, its sensor reporting 16 of its own 21 flows from a container
/// (TAIPANBOX/idryx#66).
///
/// idryx solved it by teaching the program about namespaces, because idryx is
/// deployed in containers. radar is run by hand on a host, so it refuses to
/// start instead, which is the posture this crate already takes with the
/// `compile_error!` in radar-ebpf: say no rather than report something untrue.
fn self_filter_can_work(pid_ns_ino: u64) -> bool {
    pid_ns_ino == PROC_PID_INIT_INO
}

/// Whether a captured event is one of radar's own connections.
///
/// Decided on the pid the KERNEL assigned, never on `comm`. Until 2026-09-09
/// this compared `comm` against the literal `"tokenfuse-radar"`, and any
/// process could adopt that name with `prctl(PR_SET_NAME)` and thereby vanish
/// from the sensor completely. A tool for finding undeclared traffic handed
/// every process a one-line way to be invisible to it. A pid is assigned, not
/// chosen.
///
/// Two more reasons the old filter was weaker than it looked. `comm` is 16
/// bytes including its NUL and `"tokenfuse-radar"` is exactly 15, so the string
/// fitted with nothing to spare and renaming the binary one character longer
/// would have broken the filter in silence. And `comm` is per THREAD: the
/// filter worked only because `resolve_llm_ips` happens to run on the main
/// thread, and moving that call onto the tokio pool would have left the
/// resolver's own connections reported as findings.
fn is_own_connection(event_pid: u32, self_pid: u32) -> bool {
    event_pid == self_pid
}

/// Mirror of `SkippedCounts` in radar-ebpf, hand-kept in step because there is
/// no crate shared between the two halves and nothing compares them. `ConnEvent`
/// has carried the same risk since this sensor was written; the size assertion
/// in the tests below is the cheap half of the answer, and a shared
/// `radar-common` crate is the real one, which is a change of its own.
#[repr(C)]
#[derive(Clone, Copy, Default, Debug, PartialEq, Eq)]
struct SkippedCounts {
    other_family: u64,
    unreadable: u64,
    ringbuf_full: u64,
}

// Safety: a `#[repr(C)]` struct of three `u64`s has no padding, no pointers and
// no invalid bit patterns, which is what `Pod` asks for.
unsafe impl aya::Pod for SkippedCounts {}

impl SkippedCounts {
    /// The whole machine's counts. The map is per-CPU, so a reader that took
    /// one entry would report one core's share of the truth.
    fn total(per_cpu: &[SkippedCounts]) -> SkippedCounts {
        per_cpu.iter().fold(SkippedCounts::default(), |mut acc, c| {
            acc.other_family += c.other_family;
            acc.unreadable += c.unreadable;
            acc.ringbuf_full += c.ringbuf_full;
            acc
        })
    }

    /// Traffic this sensor was never going to report. Deliberately excludes the
    /// ring buffer, so the two lines an operator reads say different things
    /// rather than one repeating a number from the other.
    fn out_of_scope(&self) -> bool {
        self.other_family > 0 || self.unreadable > 0
    }

    /// Evidence in scope that was dropped. A million AF_UNIX connects say
    /// nothing is wrong; one full ring buffer says the table cannot be trusted
    /// to be complete.
    fn lost(&self) -> bool {
        self.ringbuf_full > 0
    }
}

/// Reads the whole machine's counters, or `None` if the map cannot be read.
///
/// A failure here returns nothing rather than an error: the connections already
/// printed are real either way, and losing a capture over an unreadable counter
/// would trade the thing this sensor is for against the thing that describes it.
fn read_skipped(map: &PerCpuArray<MapData, SkippedCounts>) -> Option<SkippedCounts> {
    map.get(&0, 0)
        .ok()
        .map(|values| SkippedCounts::total(&values))
}

/// On stderr, never in the table, and that is what makes it survive invariant
/// 21: when radar stops printing a table and starts emitting agent-event
/// NDJSON, a consumer cannot see a terminal and needs these counts more, not
/// less.
fn report_skipped(counts: &SkippedCounts) {
    if counts.out_of_scope() {
        eprintln!(
            "tokenfuse-radar: not reported -- {} connect(s) over other address \
             families (AF_UNIX, netlink, and every IPv6 connection on this box), \
             {} unreadable sockaddr(s)",
            counts.other_family, counts.unreadable
        );
    }
    if counts.lost() {
        eprintln!(
            "tokenfuse-radar: WARNING: {} connection(s) were dropped because the \
             ring buffer was full; this table is incomplete",
            counts.ringbuf_full
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The regression that motivated `is_local_model_port`: before it, the
    /// loopback filter and `is_llm` carried separate lists and disagreed on
    /// 8001. This asserts the property that fixes it rather than the two
    /// lists' contents: every port `is_llm` calls a local model server must
    /// survive the loopback filter.
    #[test]
    fn every_port_is_llm_calls_local_survives_the_loopback_filter() {
        let none = HashSet::new();
        for port in 0..=u16::MAX {
            if let Some(flag) = is_llm(Ipv4Addr::LOCALHOST, port, &none) {
                assert!(
                    is_local_model_port(port),
                    "is_llm calls port {port} \"{flag}\" but the loopback filter drops it, \
                     so that branch is unreachable"
                );
            }
        }
    }

    #[test]
    fn ordinary_loopback_chatter_is_still_dropped() {
        assert!(!is_local_model_port(22));
        assert!(!is_local_model_port(5432));
        assert!(!is_local_model_port(0));
    }

    /// A provider's address on a port it does not serve is not LLM traffic.
    /// A resolver choosing a source address per RFC 6724 connect()s a UDP
    /// socket to every candidate address of a multi-address name and sends
    /// nothing: Go on port 53 (net/addrselect.go) and musl on 65535, both
    /// measured 2026-09-08 on idryx's sensor, which shares this shape
    /// (TAIPANBOX/idryx#67, graded HIGH there). The tracepoint sees each one,
    /// so flagged by address alone a process that merely resolved
    /// api.openai.com read as one that called it.
    ///
    /// This comment claimed glibc probes on port 0 until 2026-09-09. Nothing
    /// established that: the run it cites shows a glibc client connecting only
    /// to its real destination, and a port-0 probe could not have appeared in
    /// it either way, because both that sensor and this one drop `dport == 0`
    /// before recording. The honest statement is that glibc was not observed
    /// probing, not that it probes somewhere this cannot see.
    #[test]
    fn a_provider_address_is_llm_traffic_only_on_443() {
        let openai = Ipv4Addr::new(162, 159, 140, 245);
        let llm: HashSet<Ipv4Addr> = HashSet::from([openai]);
        assert_eq!(is_llm(openai, 443, &llm), Some("LLM provider"));
        assert_eq!(
            is_llm(openai, 53, &llm),
            None,
            "a resolver's source-address probe on 53 is not an API call"
        );
        assert_eq!(
            is_llm(openai, 65535, &llm),
            None,
            "musl probes on 65535; still not an API call"
        );
        assert_eq!(
            is_llm(openai, 8080, &llm),
            None,
            "the providers serve nothing but 443"
        );
    }

    /// A LOCAL model server is one on this machine. Found by running the sensor
    /// on 2026-09-09, its first live run: a connection to 192.0.2.9:8000, a
    /// TEST-NET address routed nowhere, was reported as a local vLLM, because
    /// the branch tested the port and not the address. Port 8000 is one of the
    /// commonest ports there is, so this was a false positive generator.
    #[test]
    fn a_local_model_label_requires_a_local_address() {
        let none = HashSet::new();
        let elsewhere = Ipv4Addr::new(192, 0, 2, 9); // TEST-NET-1, routed nowhere
        let lan = Ipv4Addr::new(10, 0, 0, 5);

        for port in [11434, 8000, 8001] {
            assert_eq!(
                is_llm(elsewhere, port, &none),
                None,
                "a host on the internet reached on {port} is not a LOCAL model server"
            );
            assert_eq!(
                is_llm(lan, port, &none),
                None,
                "a host on the LAN reached on {port} is not a LOCAL model server either"
            );
            assert!(
                is_llm(Ipv4Addr::LOCALHOST, port, &none).is_some(),
                "on loopback, {port} is still what it always was"
            );
        }
    }

    /// The self-filter is the pid the kernel assigned, and nothing a process
    /// can choose about itself. It compared `comm` against "tokenfuse-radar"
    /// until 2026-09-09, so `prctl(PR_SET_NAME)` was a one-line way for any
    /// process to disappear from a sensor whose job is finding undeclared
    /// traffic.
    #[test]
    fn the_self_filter_uses_a_pid_that_no_process_can_choose() {
        let ours = 4242;
        assert!(is_own_connection(ours, ours));
        // The impostor: whatever it calls itself, its pid is not radar's.
        assert!(
            !is_own_connection(9001, ours),
            "another process must never be filtered out as if it were radar"
        );
    }

    /// The map is per-CPU, so a reader that took one entry would report one
    /// core's share of the truth and read low on exactly the busy host where
    /// these numbers matter.
    #[test]
    fn the_counts_are_the_whole_machines_and_not_one_cores() {
        let per_cpu = [
            SkippedCounts {
                other_family: 3,
                unreadable: 0,
                ringbuf_full: 1,
            },
            SkippedCounts {
                other_family: 4,
                unreadable: 2,
                ringbuf_full: 0,
            },
            SkippedCounts::default(),
        ];
        assert_eq!(
            SkippedCounts::total(&per_cpu),
            SkippedCounts {
                other_family: 7,
                unreadable: 2,
                ringbuf_full: 1
            }
        );
    }

    /// Two lines that say different things. Out-of-scope traffic is a fact
    /// about the host; a full ring buffer is a fact about this table, and
    /// folding them would let a million AF_UNIX connects read as lost evidence.
    #[test]
    fn out_of_scope_traffic_is_not_lost_evidence() {
        let clean = SkippedCounts::default();
        assert!(!clean.out_of_scope() && !clean.lost());

        let busy = SkippedCounts {
            other_family: 4096,
            unreadable: 3,
            ringbuf_full: 0,
        };
        assert!(
            busy.out_of_scope(),
            "a quiet table on a busy host has to be explainable"
        );
        assert!(
            !busy.lost(),
            "traffic this sensor never wanted is not evidence it dropped"
        );

        let lost = SkippedCounts {
            other_family: 0,
            unreadable: 0,
            ringbuf_full: 1,
        };
        assert!(
            lost.lost(),
            "one dropped connection means the table is incomplete"
        );
        assert!(
            !lost.out_of_scope(),
            "a dropped connection is not out-of-scope traffic, and printing it as both \
             would repeat one number in two lines"
        );
    }

    /// The struct is written twice, here and in radar-ebpf, with nothing
    /// comparing them: a field added to one and not the other would be read
    /// off the wrong offsets, silently. This is the cheap half of that
    /// problem; a shared crate is the real one.
    #[test]
    fn the_counter_struct_is_the_size_the_bpf_side_writes() {
        assert_eq!(
            std::mem::size_of::<SkippedCounts>(),
            24,
            "three u64 counters, no padding; if this moved, radar-ebpf's copy moved too"
        );
    }

    /// And where that pid cannot be compared, radar refuses rather than
    /// filtering nothing. Inside a PID namespace the event's pid comes from the
    /// initial namespace and `std::process::id()` does not, so the comparison
    /// is meaningless: idryx measured its own sensor reporting 16 of its own 21
    /// flows that way (TAIPANBOX/idryx#66).
    #[test]
    fn radar_refuses_where_its_self_filter_could_not_work() {
        assert!(
            self_filter_can_work(PROC_PID_INIT_INO),
            "on a host the pids are comparable and radar runs"
        );
        assert!(
            !self_filter_can_work(4026532567),
            "a nested PID namespace has some other inode, and there the filter is a lie"
        );
        assert!(
            !self_filter_can_work(0),
            "a stat that produced nothing is not evidence of the initial namespace"
        );
    }
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Before anything is attached: can this process tell its own connections
    // from everyone else's? If not, radar would report its own resolver traffic
    // as a finding, and the operator would have no way to know. See
    // `self_filter_can_work`.
    let pid_ns_ino = std::fs::metadata("/proc/self/ns/pid")
        .map(|m| m.ino())
        .map_err(|e| {
            anyhow::anyhow!(
                "cannot read /proc/self/ns/pid ({e}), so radar cannot tell whether \
                 its own connections are distinguishable from anyone else's. It \
                 refuses to run rather than report its own traffic as a finding."
            )
        })?;
    if !self_filter_can_work(pid_ns_ino) {
        anyhow::bail!(
            "radar cannot recognise its own connections here: /proc/self/ns/pid is \
             inode {pid_ns_ino}, not the initial PID namespace's {PROC_PID_INIT_INO}, \
             so this process is in a PID namespace of its own. An event carries a pid \
             from the initial namespace and std::process::id() is the namespaced one; \
             the two never agree, so the self-filter would match nothing and radar \
             would report its own resolver connections as findings. Run it on the \
             host, or use idryx's sensor (internal/ebpfcapture), which is \
             namespace-aware. See invariant 21 in CLAUDE.md."
        );
    }
    let self_pid = std::process::id();

    let mut ebpf = aya::Ebpf::load(aya::include_bytes_aligned!(concat!(
        env!("OUT_DIR"),
        "/radar"
    )))?;
    let program: &mut TracePoint = ebpf.program_mut("radar").unwrap().try_into()?;
    program.load()?;
    program.attach("syscalls", "sys_enter_connect")?;

    let llm = resolve_llm_ips();
    println!(
        "tokenfuse-radar: watching outbound connections (known LLM IPs: {})",
        llm.len()
    );
    println!("{:<8} {:<16} {:<21} {}", "PID", "COMM", "DEST", "FLAG");

    // take_map, not map_mut, and the difference is what lets the counters exist
    // at all: the ring buffer borrows `ebpf` mutably for the whole life of the
    // loop below, so a second `ebpf.map(..)` inside it does not borrow-check.
    // Taking both maps out first is the fix, and it is the one hidden cost of
    // this change.
    let mut ring = RingBuf::try_from(
        ebpf.take_map("EVENTS")
            .ok_or_else(|| anyhow::anyhow!("the loaded object has no EVENTS map"))?,
    )?;
    let skipped: PerCpuArray<MapData, SkippedCounts> = PerCpuArray::try_from(
        ebpf.take_map("SKIPPED")
            .ok_or_else(|| anyhow::anyhow!("the loaded object has no SKIPPED map"))?,
    )?;

    // Warned once, not once per poll: the same full ring buffer is still full
    // 200ms later, and a warning per poll would bury the connections it sits
    // among. The totals at the end say how many in the end.
    let mut warned_lost = false;

    loop {
        while let Some(item) = ring.next() {
            if item.len() < core::mem::size_of::<ConnEvent>() {
                continue;
            }
            let ev = unsafe { std::ptr::read_unaligned(item.as_ptr() as *const ConnEvent) };
            let ip = Ipv4Addr::from(ev.daddr);
            if ev.dport == 0 {
                continue; // a connect with no port is not a destination
            }
            // Ours, decided on the pid the kernel assigned. Early, because a
            // connection radar made is not evidence about the host and there is
            // nothing further to spend on it.
            if is_own_connection(ev.pid, self_pid) {
                continue;
            }
            // Every port `is_llm` treats as a local model server has to be
            // listed here too, or the filter drops the packet before the
            // classifier ever sees it. 8001 was missing: `is_llm` called it
            // vLLM and this line threw it away first, so that branch was
            // unreachable and a local vLLM on 8001 was never reported.
            if ip.is_loopback() && !is_local_model_port(ev.dport) {
                continue; // skip local chatter unless a model port
            }
            let comm = String::from_utf8_lossy(&ev.comm)
                .trim_end_matches('\0')
                .to_string();
            let flag = is_llm(ip, ev.dport, &llm).unwrap_or("");
            let marker = if flag.is_empty() { "" } else { "  <== " };
            println!(
                "{:<8} {:<16} {:<21} {marker}{flag}",
                ev.pid,
                comm,
                format!("{ip}:{}", ev.dport)
            );
        }
        if !warned_lost {
            if let Some(counts) = read_skipped(&skipped) {
                if counts.lost() {
                    eprintln!(
                        "tokenfuse-radar: WARNING: the ring buffer filled and \
                         connections were dropped; this table is incomplete. \
                         Totals on exit."
                    );
                    warned_lost = true;
                }
            }
        }

        // Ctrl-C is where the totals get printed, so a run that is stopped the
        // way runs are actually stopped still says what it could not observe.
        // Before this, the only way to learn was to already know.
        tokio::select! {
            _ = tokio::signal::ctrl_c() => {
                if let Some(counts) = read_skipped(&skipped) {
                    report_skipped(&counts);
                }
                return Ok(());
            }
            _ = tokio::time::sleep(std::time::Duration::from_millis(200)) => {}
        }
    }
}
