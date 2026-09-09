#![no_std]
#![no_main]
#![allow(nonstandard_style, dead_code)]

use aya_ebpf::{
    helpers::{bpf_get_current_comm, bpf_get_current_pid_tgid, gen::bpf_probe_read_user},
    macros::{map, tracepoint},
    maps::{PerCpuArray, RingBuf},
    programs::TracePointContext,
};
use core::mem;

#[repr(C)]
pub struct ConnEvent {
    pub pid: u32,
    pub dport: u16,
    pub _pad: u16,
    pub daddr: u32,
    pub comm: [u8; 16],
}

/// What this program saw and did NOT put on the ring buffer, per reason.
///
/// Without it, an empty table has four indistinguishable meanings: nothing
/// connected, everything connected over a family this sensor does not observe,
/// a sockaddr could not be read, or the ring buffer filled and real evidence
/// went on the floor. The last one is the reason this exists: a full ring
/// buffer is silent, `reserve` simply returns `None`, and the kernel keeps no
/// drop counter for a BPF ring buffer the way it does for a perf buffer.
///
/// `other_family` is the one an operator will actually see move, and on this
/// sensor it means more than it does on idryx's: radar observes AF_INET only,
/// so every IPv6 connection on the box lands in this counter. That does not
/// make radar see IPv6, and it does stop the blind spot being silent.
///
/// The three names are idryx's `skipped_counts` names verbatim, so the two
/// sensors in this estate answer the same question with the same vocabulary.
#[repr(C)]
pub struct SkippedCounts {
    pub other_family: u64,
    pub unreadable: u64,
    pub ringbuf_full: u64,
}

/// PER-CPU, and the choice is not incidental. A plain `Array<u64>` incremented
/// with `*p += 1` is a read-modify-write from several CPUs at once and loses
/// counts under exactly the load that makes these numbers worth having. The
/// atomic alternative in Rust is `AtomicU64::fetch_add`, whose result must be
/// dead for LLVM's BPF backend to emit `XADD`; aya-ebpf uses no atomics
/// anywhere, so radar would be the first thing in this toolchain to lean on
/// that codegen path, in a program nothing tests.
///
/// A per-CPU array with a plain increment has one race left, a nested
/// preemption on the same CPU, which can lose an increment and can never turn
/// a nonzero count into a zero. That is all the userspace side needs: it warns
/// the first time a counter moves and prints totals at the end, so an
/// undercount is a smaller number and never a silent one.
#[map]
static SKIPPED: PerCpuArray<SkippedCounts> = PerCpuArray::with_max_entries(1, 0);

/// Which counter a skipped connection belongs to. An enum rather than three
/// call sites so the map lookup is written once.
enum Skipped {
    OtherFamily,
    Unreadable,
    RingbufFull,
}

#[inline(always)]
fn bump(which: Skipped) {
    // A one-element per-CPU array is always present, but the verifier requires
    // the None arm regardless and it costs nothing.
    if let Some(counts) = SKIPPED.get_ptr_mut(0) {
        unsafe {
            match which {
                Skipped::OtherFamily => (*counts).other_family += 1,
                Skipped::Unreadable => (*counts).unreadable += 1,
                Skipped::RingbufFull => (*counts).ringbuf_full += 1,
            }
        }
    }
}

#[repr(C)]
struct SockAddrIn {
    sin_family: u16,
    sin_port: u16,
    sin_addr: u32,
}

const AF_INET: u16 = 2;

// `try_radar` reads the syscall argument at a fixed byte offset into the
// tracepoint context. The build refuses anywhere but x86_64, and until
// 2026-09-09 the reason written here was that offset 24 "on aarch64 reads a
// different field". THAT WAS WRONG, and the correction is left in place of the
// claim rather than quietly swapped for a better one.
//
// `struct trace_entry` is 8 bytes (`short unsigned int` + two `unsigned char` +
// `int`), and `trace_event_raw_sys_enter` is that, then `long id`, then
// `unsigned long args[6]` from offset 16. So `args[1]` sits at offset 24 on
// every LP64 architecture, aarch64 included. Read off an aarch64 kernel's own
// BTF, and then confirmed by running: with this refusal lifted in a throwaway
// copy, the program built for aarch64, loaded on Linux 7.0.12 aarch64, and
// reported 127.0.0.1:11434 and 192.0.2.9:8000, both exactly as connected. That
// was the first live run this program has ever had.
//
// 32-bit is a different matter and the refusal covers it correctly: there
// `long` is 4 bytes and the offset genuinely moves.
//
// THE REFUSAL STAYS ANYWAY, and now says why. `@decided 2026-09-09`: keep the
// architecture gate as it is. It is not a claim that the read breaks elsewhere;
// it is invariant 21 in CLAUDE.md, which puts every capability this sensor
// gains in idryx and narrows radar to reporting what it sees. Widening what
// radar supports is growth in the repository that is supposed to stop growing,
// and idryx's `connect.c` already reads this argument through BTF rather than
// counting bytes, which is portable by construction instead of by two
// measurements.
//
// THE CONDITION IS `bpf_target_arch`, NOT `target_arch`, and the difference is
// the whole thing. This crate compiles for `bpfel-unknown-none`, where
// `target_arch` is "bpf" on every host, so `not(target_arch = "x86_64")` is
// always true and the first version of this refused to build everywhere,
// including the machine it was meant to allow. `bpf_target_arch` is what aya
// passes for the HOST architecture the object will run against:
// `--cfg=bpf_target_arch="x86_64"` appears verbatim in the build command.
//
// A plain comment rather than a doc comment, because a doc comment on a macro
// invocation documents nothing and warns about it (`unused_doc_comments`),
// which in this crate's `#![warn(unused)]` is noise on every build.
#[cfg(not(bpf_target_arch = "x86_64"))]
compile_error!(
    "radar's tracepoint argument offset is x86_64-specific and would silently \
     read the wrong field here. Use idryx's CO-RE sensor (internal/ebpfcapture) \
     on this architecture; see invariant 21 in CLAUDE.md."
);

#[map]
static EVENTS: RingBuf = RingBuf::with_byte_size(256 * 1024, 0);

#[tracepoint]
pub fn radar(ctx: TracePointContext) -> u32 {
    let _ = try_radar(&ctx);
    0
}

fn try_radar(ctx: &TracePointContext) -> Result<(), i64> {
    // sys_enter_connect: uservaddr is args[1], at offset 24 on any LP64
    // architecture. See the header for how that offset is arrived at and what
    // the compile_error above is actually for, which is not this.
    let addr_ptr: u64 = unsafe { ctx.read_at::<u64>(24)? };
    if addr_ptr == 0 {
        return Ok(());
    }
    let mut sa: SockAddrIn = unsafe { mem::zeroed() };
    let ret = unsafe {
        bpf_probe_read_user(
            &mut sa as *mut _ as *mut core::ffi::c_void,
            mem::size_of::<SockAddrIn>() as u32,
            addr_ptr as *const core::ffi::c_void,
        )
    };
    // Split from the family check below, which it used to share a condition
    // with: an unreadable sockaddr and a family this sensor does not observe
    // are different facts about the host and belong in different counters.
    if ret != 0 {
        bump(Skipped::Unreadable);
        return Ok(());
    }
    if sa.sin_family != AF_INET {
        bump(Skipped::OtherFamily);
        return Ok(());
    }
    let pid = (bpf_get_current_pid_tgid() >> 32) as u32;
    let comm = bpf_get_current_comm().unwrap_or([0u8; 16]);
    if let Some(mut entry) = EVENTS.reserve::<ConnEvent>(0) {
        let p = entry.as_mut_ptr();
        unsafe {
            (*p).pid = pid;
            (*p).dport = u16::from_be(sa.sin_port);
            (*p)._pad = 0;
            (*p).daddr = u32::from_be(sa.sin_addr);
            (*p).comm = comm;
        }
        entry.submit(0);
    } else {
        // The counter that matters most. The other two are traffic this sensor
        // was never going to report; this one is a connection it wanted to
        // report and could not, so the table is incomplete in a way no other
        // number would show.
        bump(Skipped::RingbufFull);
    }
    Ok(())
}

#[link_section = "license"]
#[used]
static LICENSE: [u8; 4] = *b"GPL\0";

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}
