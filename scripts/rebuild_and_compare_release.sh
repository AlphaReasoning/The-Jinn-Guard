#!/usr/bin/env bash
#
# Build the ts_cli release binary twice from clean git-archive checkouts and
# verify the resulting bytes match. This is intentionally source-only: untracked
# files and the caller's working tree are not copied into the build inputs.
set -euo pipefail

usage() {
  cat <<'USAGE'
Usage: scripts/rebuild_and_compare_release.sh [--ref <git-ref>] [--output <path>] [--report <path>] [--keep-work]

Options:
  --ref <git-ref>   Git ref to archive and rebuild (default: HEAD).
  --output <path>   Copy the verified release binary to this path.
  --report <path>   Write a small rebuild report to this path.
  --keep-work       Keep temporary source/target directories for debugging.
USAGE
}

REF="HEAD"
OUTPUT=""
REPORT=""
KEEP_WORK=0

while [[ $# -gt 0 ]]; do
  case "$1" in
    --ref)
      REF="${2:?missing value for --ref}"
      shift 2
      ;;
    --output)
      OUTPUT="${2:?missing value for --output}"
      shift 2
      ;;
    --report)
      REPORT="${2:?missing value for --report}"
      shift 2
      ;;
    --keep-work)
      KEEP_WORK=1
      shift
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "error: unknown argument: $1" >&2
      usage >&2
      exit 2
      ;;
  esac
done

have() { command -v "$1" >/dev/null 2>&1; }
for cmd in cargo git sha256sum cmp tar mktemp; do
  if ! have "$cmd"; then
    echo "error: required command not found: $cmd" >&2
    exit 2
  fi
done

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
RESOLVED_REF="$(git -C "$REPO_ROOT" rev-parse "$REF")"
SOURCE_DATE_EPOCH="${SOURCE_DATE_EPOCH:-$(git -C "$REPO_ROOT" log -1 --pretty=%ct "$RESOLVED_REF")}"
CARGO_HOME_FOR_REMAP="${CARGO_HOME:-${HOME:-}/.cargo}"
WORK_DIR="$(mktemp -d "${TMPDIR:-/tmp}/jinnguard-repro.XXXXXX")"

cleanup() {
  if [[ "$KEEP_WORK" -eq 0 ]]; then
    rm -rf "$WORK_DIR"
  else
    echo "kept temporary rebuild directory: $WORK_DIR"
  fi
}
trap cleanup EXIT

echo "reproducible release build"
echo "  ref:                $REF"
echo "  resolved_ref:       $RESOLVED_REF"
echo "  source_date_epoch:  $SOURCE_DATE_EPOCH"
echo "  work_dir:           $WORK_DIR"

archive_to() {
  local dst="$1"
  mkdir -p "$dst"
  git -C "$REPO_ROOT" archive --format=tar "$RESOLVED_REF" | tar -xf - -C "$dst"
}

build_one() {
  local label="$1"
  local src="$2"
  local target="$3"
  local out="$4"
  local rustflags

  rustflags="--remap-path-prefix=$src=/workspace"
  if [[ -n "$CARGO_HOME_FOR_REMAP" ]]; then
    rustflags="$rustflags --remap-path-prefix=$CARGO_HOME_FOR_REMAP=/cargo"
  fi
  rustflags="$rustflags -C strip=symbols"

  echo "  building $label from $src"
  (
    cd "$src"
    export CARGO_INCREMENTAL=0
    export CARGO_TERM_COLOR=never
    export LC_ALL=C
    export RUST_BACKTRACE=0
    export RUSTFLAGS="$rustflags"
    export SOURCE_DATE_EPOCH
    export TZ=UTC
    cargo build --quiet -p ts_cli --release --locked --target-dir "$target"
  )

  cp "$target/release/ts_cli" "$out"
  sha256sum "$out"
}

SRC_A="$WORK_DIR/source-a"
SRC_B="$WORK_DIR/source-b"
TARGET_A="$WORK_DIR/target-a"
TARGET_B="$WORK_DIR/target-b"
BIN_A="$WORK_DIR/ts_cli.a"
BIN_B="$WORK_DIR/ts_cli.b"

archive_to "$SRC_A"
archive_to "$SRC_B"

build_one "A" "$SRC_A" "$TARGET_A" "$BIN_A"
build_one "B" "$SRC_B" "$TARGET_B" "$BIN_B"

SHA_A="$(sha256sum "$BIN_A" | awk '{print $1}')"
SHA_B="$(sha256sum "$BIN_B" | awk '{print $1}')"

if ! cmp -s "$BIN_A" "$BIN_B"; then
  echo "error: release rebuilds are not byte-for-byte identical" >&2
  echo "  build_a_sha256=$SHA_A" >&2
  echo "  build_b_sha256=$SHA_B" >&2
  cmp -l "$BIN_A" "$BIN_B" | head -20 >&2 || true
  exit 1
fi

echo "  matched_sha256:     $SHA_A"

if [[ -n "$OUTPUT" ]]; then
  mkdir -p "$(dirname "$OUTPUT")"
  cp "$BIN_A" "$OUTPUT"
  chmod 0755 "$OUTPUT"
  echo "  output:             $OUTPUT"
fi

if [[ -n "$REPORT" ]]; then
  mkdir -p "$(dirname "$REPORT")"
  {
    echo "status=match"
    echo "ref=$REF"
    echo "resolved_ref=$RESOLVED_REF"
    echo "source_date_epoch=$SOURCE_DATE_EPOCH"
    echo "sha256=$SHA_A"
    echo "rustc_version=$(rustc --version)"
    echo "cargo_version=$(cargo --version)"
    echo "rustflags=--remap-path-prefix=<source>=/workspace --remap-path-prefix=<cargo-home>=/cargo -C strip=symbols"
  } > "$REPORT"
  echo "  report:             $REPORT"
fi
