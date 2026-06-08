#!/usr/bin/env bash
set -euo pipefail

echo "Jinn Guard Rust sandbox ready"
rustc --version
cargo --version
python3 --version

if [[ -f Cargo.lock ]]; then
  echo
  echo "Fetching Cargo dependencies into the shared cache..."
  cargo fetch --locked || echo "cargo fetch failed; the next build will retry."
fi
