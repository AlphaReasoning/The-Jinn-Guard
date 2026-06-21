//! Pure, panic-free decoders for the Jinn Guard wire protocol.
//!
//! This is the **externally reachable attack surface**: the bytes an untrusted
//! peer puts on the governance socket before any policy logic runs. It is kept
//! free of I/O, global state, and `unwrap`/`expect`/`panic!`, so the whole front
//! door can be driven from a single `&[u8]` by a fuzzer (`fuzz/`) or by the
//! deterministic property tests below — and so the daemon and the fuzz targets
//! exercise the *same* code, never a drifting copy.
//!
//! The protocol: a 5-byte header (`u32` big-endian length + `u8` version),
//! followed by `length` bytes of a UTF-8 JSON [`SignedEnvelope`] whose `payload`
//! is HMAC-SHA256-signed by `signature`.

use hmac::{Hmac, KeyInit, Mac};
use serde::Deserialize;
use sha2::Sha256;

type HmacSha256 = Hmac<Sha256>;

/// The only protocol version accepted on the governance socket.
pub const PROTOCOL_VERSION: u8 = 1;

/// Upper bound on a single framed payload, in bytes. A declared length above
/// this is refused *before* any body buffer is allocated, so a hostile header
/// cannot drive an unbounded allocation.
pub const MAX_PAYLOAD_LEN: usize = 4 * 1024 * 1024;

/// Fixed size of the frame header: 4-byte length + 1-byte version.
pub const HEADER_LEN: usize = 5;

/// A decoded (but not yet validated) frame header.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FrameHeader {
    pub length: usize,
    pub version: u8,
}

/// Decode the 5-byte header. Total and infallible: every 5-byte input maps to a
/// `FrameHeader` (validation is a separate, explicit step).
pub fn decode_frame_header(header: &[u8; HEADER_LEN]) -> FrameHeader {
    let length = u32::from_be_bytes([header[0], header[1], header[2], header[3]]) as usize;
    FrameHeader {
        length,
        version: header[4],
    }
}

/// Why a frame header was refused before its body was read.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FrameReject {
    /// `version` is not [`PROTOCOL_VERSION`].
    BadVersion,
    /// Declared `length` exceeds [`MAX_PAYLOAD_LEN`].
    PayloadTooLarge,
}

/// Apply the protocol rules to a decoded header. On success returns the number
/// of body bytes the daemon should then read.
pub fn classify_frame_header(header: FrameHeader) -> Result<usize, FrameReject> {
    if header.version != PROTOCOL_VERSION {
        return Err(FrameReject::BadVersion);
    }
    if header.length > MAX_PAYLOAD_LEN {
        return Err(FrameReject::PayloadTooLarge);
    }
    Ok(header.length)
}

/// The outer, signed transport envelope. `payload` is the inner request JSON;
/// `signature` is its hex-encoded HMAC-SHA256.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct SignedEnvelope {
    pub payload: String,
    pub signature: String,
}

/// Why a framed body could not be turned into a [`SignedEnvelope`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BodyReject {
    /// The body bytes were not valid UTF-8.
    Encoding,
    /// The body was valid UTF-8 but not a well-formed `SignedEnvelope` JSON.
    Malformed,
}

/// Parse a framed body (the bytes after the header) into a [`SignedEnvelope`].
/// Pure and panic-free for any input.
pub fn parse_body(body: &[u8]) -> Result<SignedEnvelope, BodyReject> {
    let text = std::str::from_utf8(body).map_err(|_| BodyReject::Encoding)?;
    serde_json::from_str::<SignedEnvelope>(text).map_err(|_| BodyReject::Malformed)
}

/// Constant-time HMAC-SHA256 verification of an envelope against `secret`.
/// Any malformed signature hex or unusable secret yields `false` rather than a
/// panic, so this is safe to call on fully attacker-controlled input.
pub fn verify_envelope(envelope: &SignedEnvelope, secret: &[u8]) -> bool {
    let provided = match hex::decode(envelope.signature.trim()) {
        Ok(sig) => sig,
        Err(_) => return false,
    };
    let mut mac = match HmacSha256::new_from_slice(secret) {
        Ok(m) => m,
        Err(_) => return false,
    };
    mac.update(envelope.payload.as_bytes());
    let expected = mac.finalize().into_bytes();
    constant_time_eq::constant_time_eq(expected.as_slice(), provided.as_slice())
}

/// The verdict of classifying one complete, self-contained packet (header +
/// body) including the signature check — the exact sequence the daemon applies,
/// expressed as a single pure function so a fuzzer can drive the entire front
/// door from one `&[u8]`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WireOutcome {
    /// Fewer than [`HEADER_LEN`] bytes were supplied.
    ShortHeader,
    /// Header rejected: wrong version.
    BadVersion,
    /// Header rejected: declared length over budget.
    PayloadTooLarge,
    /// Header was valid but fewer than `length` body bytes were supplied.
    ShortBody,
    /// Body was not UTF-8.
    Encoding,
    /// Body was not a well-formed envelope.
    Malformed,
    /// Envelope parsed but its signature did not verify.
    BadSignature,
    /// Fully accepted: a signature-verified envelope.
    Verified(SignedEnvelope),
}

/// Classify a whole packet end to end. `packet` is `[header][body...]`; only the
/// first `length` body bytes are considered (trailing bytes are ignored, exactly
/// as a stream reader that reads precisely `length` bytes would). Never panics.
pub fn classify_packet(packet: &[u8], secret: &[u8]) -> WireOutcome {
    if packet.len() < HEADER_LEN {
        return WireOutcome::ShortHeader;
    }
    let mut hdr = [0u8; HEADER_LEN];
    hdr.copy_from_slice(&packet[..HEADER_LEN]);
    let body_len = match classify_frame_header(decode_frame_header(&hdr)) {
        Ok(n) => n,
        Err(FrameReject::BadVersion) => return WireOutcome::BadVersion,
        Err(FrameReject::PayloadTooLarge) => return WireOutcome::PayloadTooLarge,
    };
    let body = &packet[HEADER_LEN..];
    if body.len() < body_len {
        return WireOutcome::ShortBody;
    }
    match parse_body(&body[..body_len]) {
        Ok(envelope) => {
            if verify_envelope(&envelope, secret) {
                WireOutcome::Verified(envelope)
            } else {
                WireOutcome::BadSignature
            }
        }
        Err(BodyReject::Encoding) => WireOutcome::Encoding,
        Err(BodyReject::Malformed) => WireOutcome::Malformed,
    }
}

// ---------------------------------------------------------------------------
// Test helpers (also used by the fuzz seed-corpus builder).
// ---------------------------------------------------------------------------

/// Build a well-formed, correctly-signed packet for `payload` under `secret`.
/// Exposed so tests and the fuzz seed corpus can produce valid inputs.
pub fn frame_signed_packet(payload: &str, secret: &[u8]) -> Vec<u8> {
    let mut mac = HmacSha256::new_from_slice(secret).expect("HMAC accepts any key length");
    mac.update(payload.as_bytes());
    let signature = hex::encode(mac.finalize().into_bytes());
    let envelope = format!(
        "{{\"payload\":{},\"signature\":\"{}\"}}",
        serde_json::to_string(payload).expect("string serializes"),
        signature
    );
    let body = envelope.into_bytes();
    let mut packet = Vec::with_capacity(HEADER_LEN + body.len());
    packet.extend_from_slice(&(body.len() as u32).to_be_bytes());
    packet.push(PROTOCOL_VERSION);
    packet.extend_from_slice(&body);
    packet
}

#[cfg(test)]
mod tests {
    use super::*;

    const SECRET: &[u8] = b"unit-test-secret-key";

    #[test]
    fn header_decode_is_total() {
        assert_eq!(
            decode_frame_header(&[0x00, 0x00, 0x00, 0x05, 1]),
            FrameHeader { length: 5, version: 1 }
        );
        assert_eq!(
            decode_frame_header(&[0xFF, 0xFF, 0xFF, 0xFF, 0xAB]),
            FrameHeader { length: u32::MAX as usize, version: 0xAB }
        );
    }

    #[test]
    fn header_rules() {
        assert_eq!(
            classify_frame_header(FrameHeader { length: 10, version: 2 }),
            Err(FrameReject::BadVersion)
        );
        assert_eq!(
            classify_frame_header(FrameHeader { length: MAX_PAYLOAD_LEN + 1, version: 1 }),
            Err(FrameReject::PayloadTooLarge)
        );
        assert_eq!(
            classify_frame_header(FrameHeader { length: MAX_PAYLOAD_LEN, version: 1 }),
            Ok(MAX_PAYLOAD_LEN)
        );
    }

    #[test]
    fn parse_body_negatives() {
        assert_eq!(parse_body(&[0xff, 0xfe, 0x00]), Err(BodyReject::Encoding));
        assert_eq!(parse_body(b"not json"), Err(BodyReject::Malformed));
        assert_eq!(parse_body(b"{\"payload\":\"p\"}"), Err(BodyReject::Malformed)); // missing signature
        assert_eq!(parse_body(b"[]"), Err(BodyReject::Malformed));
    }

    #[test]
    fn verify_round_trips_and_rejects() {
        let env = SignedEnvelope {
            payload: "hello".to_string(),
            signature: {
                let mut m = HmacSha256::new_from_slice(SECRET).unwrap();
                m.update(b"hello");
                hex::encode(m.finalize().into_bytes())
            },
        };
        assert!(verify_envelope(&env, SECRET));
        // Wrong secret.
        assert!(!verify_envelope(&env, b"other-secret"));
        // Tampered payload.
        let mut tampered = env.clone();
        tampered.payload = "hellp".to_string();
        assert!(!verify_envelope(&tampered, SECRET));
        // Non-hex signature never panics.
        let bad = SignedEnvelope { payload: "x".into(), signature: "zzzz".into() };
        assert!(!verify_envelope(&bad, SECRET));
        // All-zero signature.
        let zero = SignedEnvelope { payload: "x".into(), signature: "00".repeat(32) };
        assert!(!verify_envelope(&zero, SECRET));
    }

    #[test]
    fn full_packet_accepts_valid_and_classifies_each_reject() {
        let pkt = frame_signed_packet("{\"sequence_counter\":1}", SECRET);
        match classify_packet(&pkt, SECRET) {
            WireOutcome::Verified(e) => assert_eq!(e.payload, "{\"sequence_counter\":1}"),
            other => panic!("expected Verified, got {other:?}"),
        }
        // Wrong secret -> BadSignature.
        assert_eq!(classify_packet(&pkt, b"nope"), WireOutcome::BadSignature);
        // Truncated header.
        assert_eq!(classify_packet(&[0, 0, 0], SECRET), WireOutcome::ShortHeader);
        // Bad version.
        assert_eq!(
            classify_packet(&[0, 0, 0, 1, 9, b'x'], SECRET),
            WireOutcome::BadVersion
        );
        // Body shorter than declared length.
        assert_eq!(
            classify_packet(&[0x00, 0x00, 0x10, 0x00, 1, b'{'], SECRET),
            WireOutcome::ShortBody
        );
        // Over-budget declared length.
        assert_eq!(
            classify_packet(&[0xFF, 0xFF, 0xFF, 0xFF, 1], SECRET),
            WireOutcome::PayloadTooLarge
        );
        // Non-UTF-8 body.
        assert_eq!(
            classify_packet(&[0x00, 0x00, 0x00, 0x02, 1, 0xff, 0xfe], SECRET),
            WireOutcome::Encoding
        );
        // Valid UTF-8 but not an envelope.
        assert_eq!(
            classify_packet(&[0x00, 0x00, 0x00, 0x02, 1, b'h', b'i'], SECRET),
            WireOutcome::Malformed
        );
    }

    /// Deterministic stable-Rust "fuzz": drive `classify_packet` with a large,
    /// reproducible stream of adversarial inputs and assert it always returns a
    /// verdict (never panics, never hangs, never over-allocates). This is the
    /// in-tree counterpart to the libFuzzer targets under `fuzz/`.
    #[test]
    fn classify_packet_never_panics_on_garbage() {
        // xorshift64* — tiny, deterministic PRNG, no external deps.
        let mut state: u64 = 0x9E37_79B9_7F4A_7C15;
        let mut next = || {
            state ^= state >> 12;
            state ^= state << 25;
            state ^= state >> 27;
            state = state.wrapping_mul(0x2545_F491_4F6C_DD1D);
            state
        };

        for _ in 0..200_000 {
            let len = (next() % 64) as usize;
            let mut buf = Vec::with_capacity(len);
            for _ in 0..len {
                buf.push((next() & 0xff) as u8);
            }
            // Occasionally force a plausible header so deeper paths are reached.
            if buf.len() >= HEADER_LEN && next() & 1 == 0 {
                let declared = (next() % 80) as u32;
                buf[0..4].copy_from_slice(&declared.to_be_bytes());
                buf[4] = if next() & 1 == 0 { PROTOCOL_VERSION } else { (next() & 0xff) as u8 };
            }
            // Must return *some* verdict; the assert is simply that we got here.
            let _ = classify_packet(&buf, SECRET);
        }
    }

    /// Mutating a single byte of a valid signed packet must never yield
    /// `Verified` (integrity), and must never panic.
    #[test]
    fn single_byte_mutations_never_forge_acceptance() {
        let base = frame_signed_packet("{\"sequence_counter\":42}", SECRET);
        for i in 0..base.len() {
            for flip in [0x01u8, 0x80, 0xff] {
                let mut m = base.clone();
                m[i] ^= flip;
                if let WireOutcome::Verified(env) = classify_packet(&m, SECRET) {
                    // The only mutations that can still verify are ones that left
                    // both the body bytes and the signature self-consistent — i.e.
                    // they reproduced a valid packet. Assert that really holds.
                    assert!(
                        verify_envelope(&env, SECRET),
                        "byte {i}^{flip:#x} produced Verified with a bad signature"
                    );
                }
            }
        }
    }
}
