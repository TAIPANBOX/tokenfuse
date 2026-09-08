//! TokenFuse Radar (W1): eBPF-based discovery of LLM traffic / shadow agents.
//!
//! Attaches to the `sys_enter_connect` tracepoint and reports every outbound
//! IPv4 connect(), TCP or UDP (pid, comm, dest ip:port), flagging those that go to known
//! LLM providers or local model servers — with zero configuration in the apps.

use std::collections::HashSet;
use std::net::{Ipv4Addr, ToSocketAddrs};

use aya::maps::RingBuf;
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
    // Go on 53, glibc on 0, musl on 65535. Flagged by address alone, a name
    // lookup printed as an API call (idryx#67, the same defect, graded HIGH).
    if port == 443 && llm.contains(&ip) {
        Some("LLM provider")
    } else if port == 11434 {
        Some("local Ollama")
    } else if port == 8000 || port == 8001 {
        Some("local vLLM?")
    } else {
        None
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
    /// nothing: Go on port 53 (net/addrselect.go), glibc on port 0, musl on
    /// 65535. The tracepoint sees each one, so flagged by address alone a
    /// process that merely resolved api.openai.com read as one that called
    /// it. Measured 2026-09-08 on idryx's sensor, which shares this shape
    /// (TAIPANBOX/idryx#67, graded HIGH there).
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
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
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

    let mut ring = RingBuf::try_from(ebpf.map_mut("EVENTS").unwrap())?;
    loop {
        while let Some(item) = ring.next() {
            if item.len() < core::mem::size_of::<ConnEvent>() {
                continue;
            }
            let ev = unsafe { std::ptr::read_unaligned(item.as_ptr() as *const ConnEvent) };
            let ip = Ipv4Addr::from(ev.daddr);
            if ev.dport == 0 {
                continue; // ignore name-resolution / non-TCP noise
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
            if comm == "tokenfuse-radar" {
                continue; // don't report our own resolver connections
            }
            let flag = is_llm(ip, ev.dport, &llm).unwrap_or("");
            let marker = if flag.is_empty() { "" } else { "  <== " };
            println!(
                "{:<8} {:<16} {:<21} {marker}{flag}",
                ev.pid,
                comm,
                format!("{ip}:{}", ev.dport)
            );
        }
        tokio::time::sleep(std::time::Duration::from_millis(200)).await;
    }
}
