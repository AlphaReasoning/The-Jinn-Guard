# Wire-protocol fuzzing

libFuzzer targets for the externally reachable parsers in the
[`ts_wire`](../ts_wire) crate — the bytes an untrusted peer puts on the
governance socket before any policy logic runs. These exercise the **same code
the daemon calls** (the daemon decodes frames via `ts_wire`), so a finding here
is a finding in production, not in a drifting copy.

## Targets

| Target | Surface |
|---|---|
| `frame_header` | the 5-byte frame header decode + version/length validation |
| `envelope` | UTF-8 + JSON `SignedEnvelope` parse and HMAC signature verification |
| `wire_packet` | the whole front door end to end (`classify_packet`) |

## Run it

Requires nightly + [`cargo-fuzz`](https://github.com/rust-fuzz/cargo-fuzz):

```bash
rustup toolchain install nightly
cargo install cargo-fuzz

# from the repo root:
cargo +nightly fuzz run wire_packet      # or frame_header / envelope
cargo +nightly fuzz run envelope -- -max_total_time=300
```

The `fuzz/` crate is intentionally **excluded from the main workspace** (see the
root `Cargo.toml`), so a normal `cargo build`/`cargo test` never needs the fuzz
toolchain.

## Stable-Rust counterpart (no nightly needed)

The same invariants are checked deterministically on stable as ordinary unit
tests, so CI and `cargo test` get robustness coverage without libFuzzer:

```bash
cargo test -p ts_wire
```

See `classify_packet_never_panics_on_garbage` (200k adversarial inputs) and
`single_byte_mutations_never_forge_acceptance` in `ts_wire/src/lib.rs`.

## Seeding

To seed a target with a valid packet, use `ts_wire::frame_signed_packet(payload,
secret)` to generate one and drop it in `fuzz/corpus/<target>/`.
