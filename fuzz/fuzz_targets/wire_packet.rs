#![no_main]
//! Drive the entire front door from one buffer: header + body + signature, the
//! exact sequence the daemon applies. Any byte string must yield a verdict
//! without panicking, hanging, or over-allocating.
use libfuzzer_sys::fuzz_target;
use ts_wire::classify_packet;

fuzz_target!(|data: &[u8]| {
    let _ = classify_packet(data, b"fuzz-secret-key");
});
