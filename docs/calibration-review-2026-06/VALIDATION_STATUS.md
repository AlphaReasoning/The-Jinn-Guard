# Validation Status

Date: 2026-06-29

## Executed in this environment

1. Evidence anchor extraction via ripgrep across code and docs.
2. Installed required local tooling with Homebrew:
   - `rust` (cargo toolchain)
   - `bash` (v5 for associative arrays)
3. Isolated portable crate tests:
   - Command: `cargo test -p ts_wire -- --nocapture`
   - Result: PASS (7 passed).
   - Command: `cargo test -p ts_checker -- --nocapture`
   - Initial result: FAIL (`ld: library 'z3' not found`).
   - Verified fix by exporting Z3 library paths; rerun PASS (4 passed).
4. Hardened validation harness for host portability and deterministic status handling:
   - Added fail-fast `cd` guard.
   - Added Darwin/Homebrew auto-export for `LIBRARY_PATH`, `DYLD_LIBRARY_PATH`, and `LIBCLANG_PATH`.
   - Kept non-Linux Tier 1 target selection to portable crates (`ts_checker`, `ts_wire`).
5. Re-ran staged validation harness:
   - Command: `/usr/local/bin/bash scripts/run_professor_validation.sh`
   - Result summary:
     - `T1 PASS`
     - `T2 SKIP` (Docker unavailable)
     - `T3 SKIP` (needs root)
     - `T4 SKIP` (needs `--arm` and root/cgroup-v2)

## Blockers and resolutions

1. `cargo` missing on first run.
   - Resolved by installing Rust toolchain.
2. macOS default bash incompatibility (`declare -A`).
   - Resolved by using Homebrew bash (`/usr/local/bin/bash`) and retaining bash-4+ script semantics.
3. `ts_checker` link failure on macOS (`ld: library 'z3' not found`).
   - Resolved by auto-exporting Homebrew Z3 library paths inside the harness on Darwin.

## Current status

1. All executable validation tiers on this host are now green.
2. Remaining skips are environment-gated (not code failures):
   - Tier 2 requires Docker.
   - Tier 3 requires root.
   - Tier 4 requires root plus explicit `--arm` enablement.

## Recommended validation sequence (next run)

1. For macOS local developer checks, run:
   - `/usr/local/bin/bash scripts/run_professor_validation.sh`
2. For full enforcement validation, run on Linux host with prerequisites:
   - Docker available (Tier 2)
   - root privileges (Tiers 3-4)
   - cgroup v2 + `--arm` (Tier 4)
3. Capture tier outputs as artifacts and append host metadata for reproducibility.
