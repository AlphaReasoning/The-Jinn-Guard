#![no_main]
//! Fuzz the envelope/signature parser: UTF-8 + JSON decode of a framed body and
//! HMAC verification, on fully attacker-controlled bytes. Parsing must never
//! panic, and a parsed envelope must verify-or-reject without crashing for any
//! secret (including an empty one).
use libfuzzer_sys::fuzz_target;
use ts_wire::{parse_body, verify_envelope};

fuzz_target!(|data: &[u8]| {
    if let Ok(envelope) = parse_body(data) {
        let _ = verify_envelope(&envelope, b"fuzz-secret-key");
        let _ = verify_envelope(&envelope, &[]);
    }
});
