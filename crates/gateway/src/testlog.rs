//! A captured `tracing` subscriber, shared by every test module that needs to
//! read a `warn`/`debug` line rather than a counter added for its benefit.
//!
//! Moved verbatim out of `cloudsink.rs`'s `mod tests` (invariant 50, S9): the
//! settle guard's retain warn (`settle.rs::tests`) needs the exact same
//! capture, and a process may install only one global `tracing` subscriber,
//! so one copy is the only option.

#![cfg(test)]
#![allow(clippy::await_holding_lock)]

use std::sync::{Arc, Mutex, MutexGuard, OnceLock};

/// A `MakeWriter` that appends formatted tracing output to a shared buffer.
#[derive(Clone)]
pub(crate) struct Captured(Arc<Mutex<Vec<u8>>>);

impl std::io::Write for Captured {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(buf);
        Ok(buf.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for Captured {
    type Writer = Captured;
    fn make_writer(&'a self) -> Self::Writer {
        self.clone()
    }
}

/// The one buffer, behind the process-wide default subscriber. It has to be
/// global rather than per-test: `ship` does its work in a spawned task, so
/// a thread-local subscriber set by the test's own thread would never see
/// the line it is waiting for.
pub(crate) fn captured_log() -> &'static Arc<Mutex<Vec<u8>>> {
    static BUF: OnceLock<Arc<Mutex<Vec<u8>>>> = OnceLock::new();
    BUF.get_or_init(|| {
        let buf = Arc::new(Mutex::new(Vec::new()));
        let subscriber = tracing_subscriber::fmt()
            .with_writer(Captured(Arc::clone(&buf)))
            .with_ansi(false)
            .with_max_level(tracing::Level::DEBUG)
            .finish();
        tracing::subscriber::set_global_default(subscriber).expect(
            "these assertions read the subscriber installed here, so nothing \
             else in this test binary may install one first",
        );
        buf
    })
}

/// Serialises the tests that read the shared buffer. Cargo runs a binary's
/// tests on parallel threads, and without this they would count each
/// other's lines. Same reason, and the same shape, as the exporter tests in
/// `crate::events`.
pub(crate) fn log_lock() -> MutexGuard<'static, ()> {
    static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    LOCK.get_or_init(|| Mutex::new(()))
        .lock()
        .unwrap_or_else(|e| e.into_inner())
}
