//! Regression test for a `siginfo_t` -> `signalfd_siginfo` layout-confusion bug
//! in the Linux crash handler.
//!
//! The two structs only share their first three fields (signo/errno/code); the
//! buggy code `cast`ed one to the other and byte-copied, so `ssi_addr` was read
//! from empty tail bytes of the `siginfo_t` and every Linux crash reported a
//! `0x0` faulting address.
//!
//! `sadness_generator::raise_segfault` writes to a fixed, non-zero address
//! (`SEGFAULT_ADDRESS`), so a correctly captured minidump must report exactly
//! that address. Windows and macOS already assert this; before the fix the
//! Linux assertion in `assert_minidump` was commented out because it read 0.

#[cfg(unix)]
use minidumper_test::*;

/// A real SIGSEGV at a known address must preserve that address through the
/// crash handler's siginfo translation and into the minidump exception record.
#[cfg(unix)]
#[test]
fn segfault_preserves_faulting_address() {
    // A unique id so we don't collide with `segfault_simple` /
    // `segfault_threaded`, which derive their socket name + dump path from it.
    let md_buf = generate_minidump("segv-address-regression", Signal::Segv, false, None);

    let md = minidump::Minidump::read(md_buf.as_slice()).expect("failed to parse minidump");
    let exc: minidump::MinidumpException<'_> = md.get_stream().expect("missing exception stream");

    let crash_address = exc.get_crash_address(get_native_os(), get_native_cpu());

    // Guard against a silent regression to 0x0 specifically...
    assert_ne!(
        crash_address, 0,
        "faulting address was lost in the siginfo_t -> signalfd_siginfo translation"
    );
    // ...and pin it to the exact address the client faulted on.
    assert_eq!(
        crash_address,
        sadness_generator::SEGFAULT_ADDRESS as u64,
        "reported faulting address does not match the address the client wrote to"
    );
}
