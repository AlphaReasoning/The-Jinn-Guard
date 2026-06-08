#!/usr/bin/env bash
set -euo pipefail

# Build the default workspace inside the sandbox. This intentionally avoids
# enterprise/kernel telemetry features because those need privileged Linux + BPF.
cargo build --workspace --locked
