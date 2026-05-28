# Jinn Guard (rt_parser_v3)

[![Language](https://img.shields.io/badge/language-Rust-orange.svg)](https://www.rust-lang.org/)
[![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Security Standard](https://img.shields.io/badge/NIST%20SP-800--90B-red)](https://csrc.nist.gov/)

Jinn Guard is an ultra-lightweight (~484 KB memory footprint), zero-dependency semantic firewall operating natively over local Unix Domain Sockets (`jinnguard.sock`).

## Architectural Performance (Verified P95 Telemetry)
Under a 50-thread concurrent saturation blitz across 2,000 transaction cycles, the runtime state machine yields a completely flat tail-latency curve:
* **Throughput Capacity:** 7,048.43 Requests/Sec
* **P50 Median Latency:** 5.343 ms
* **P95 Tail Threshold:** 7.340 ms
* **Active Memory Allocation:** 484 KB

## Core Philosophy: Out-of-Band Context Protection
Traditional guardrails rely on system prompts or inline model evaluations, introducing extreme token bloat. Jinn Guard treats language models as completely untrusted compute blocks.
By intercepting the token proposal downstream at the host transport layer, Jinn Guard utilizes a strict compiler-grade lexer grammar to deconstruct natural language proposals into discrete functional intent nodes.

## Quick Start / Local Installation
Compile the release binary natively:
```bash
cargo build --release
sudo ./target/release/ts_cli
```
Developed by **Cassey Snider**, Systems Architect & Adversarial Security Researcher. Contact via `underdogishereneverfear@gmail.com`.
