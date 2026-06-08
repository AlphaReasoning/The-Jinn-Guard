#!/usr/bin/env bash
set -e

# Define names and destination paths
ARCHIVE_NAME="jinn_guard_v1.0.0_release.zip"
EXPORT_DIR="jinn_guard_submission"

echo "📦 [ARCHIVER] Initializing clean packaging environment..."
rm -rf "$EXPORT_DIR" "$ARCHIVE_NAME"
mkdir -p "$EXPORT_DIR"

echo "🧹 [ARCHIVER] Cleaning Rust target files to minimize file size..."
cargo clean

echo "📂 [ARCHIVER] Collecting verified production source vectors..."
# Copying core framework architecture layers
cp -r ts_cli "$EXPORT_DIR/"
cp -r ts_checker "$EXPORT_DIR/"
cp -r jinnguard_py "$EXPORT_DIR/"

# Copying workspace manifests and dynamic policy layers
cp Cargo.toml "$EXPORT_DIR/"
cp Cargo.lock "$EXPORT_DIR/"
cp jinnguard_policy.json "$EXPORT_DIR/"
cp run_fabric_swarm.py "$EXPORT_DIR/"

# ── eBPF object ──────────────────────────────────────────────────────────────
# Prefer a pre-built artifact downloaded from CI (dist/jinnguard_ebpf.o).
# Fall back to building from source if clang/llvm are available.
mkdir -p "$EXPORT_DIR/dist"
if [ -f "dist/jinnguard_ebpf.o" ]; then
    echo "✅  [eBPF] Using pre-built dist/jinnguard_ebpf.o"
    cp dist/jinnguard_ebpf.o "$EXPORT_DIR/dist/jinnguard_ebpf.o"
elif [ -f "bpf/jinnguard_ebpf.o" ]; then
    echo "✅  [eBPF] Using locally compiled bpf/jinnguard_ebpf.o"
    cp bpf/jinnguard_ebpf.o "$EXPORT_DIR/dist/jinnguard_ebpf.o"
elif command -v clang &>/dev/null && command -v make &>/dev/null; then
    echo "🔨  [eBPF] Building from source (clang found)..."
    make -C bpf
    cp bpf/jinnguard_ebpf.o "$EXPORT_DIR/dist/jinnguard_ebpf.o"
else
    echo "⚠️   [eBPF] No pre-built object and clang not found — skipping eBPF object"
    echo "            Install clang+llvm and run 'make -C bpf' to enable kernel telemetry."
fi

# If there's an active main script or technical memo file, scoop it up
if [ -f "make_release.sh" ]; then
    cp make_release.sh "$EXPORT_DIR/"
fi

echo "🗜️  [ARCHIVER] Compressing workspace into secure production zip..."
zip -r "$ARCHIVE_NAME" "$EXPORT_DIR"

echo "🧹 [ARCHIVER] Cleaning up intermediate deployment directory..."
rm -rf "$EXPORT_DIR"

echo -e "\n🎯 [SUCCESS] Jinn Guard is packed and ready for submission!"
echo "📦 Archive File: ./$ARCHIVE_NAME"
ls -lh "$ARCHIVE_NAME"
