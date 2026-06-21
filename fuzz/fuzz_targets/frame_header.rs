#![no_main]
//! Fuzz the 5-byte frame header: decode + protocol validation. For any input
//! the decode is total and the validation must return a verdict, never panic.
use libfuzzer_sys::fuzz_target;
use ts_wire::{classify_frame_header, decode_frame_header, HEADER_LEN};

fuzz_target!(|data: &[u8]| {
    if data.len() < HEADER_LEN {
        return;
    }
    let mut hdr = [0u8; HEADER_LEN];
    hdr.copy_from_slice(&data[..HEADER_LEN]);
    // Decode is infallible; validation returns Ok(len) or a typed reject.
    let _ = classify_frame_header(decode_frame_header(&hdr));
});
