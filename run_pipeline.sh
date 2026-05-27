#!/usr/bin/env bash
# Clear out any global set -e flags from the interactive workspace
set +e

echo "=== 1. Writing Unified System Specification ==="
cat << 'EOF' > current_intent.ts
system UnifiedRootAI_TopologyS:
    state RootAI_GraphNodes:
        intent_entropy: F64
        ast_consistency: F64
        guard_integrity: F64
        flow_determinism: F64
    invariant JinnGuard_SecurityGate:
        guarantee ast_consistency >= guard_integrity
    execute DeterministicTransformation:
        transform intent_entropy -> (intent_entropy + ast_consistency) / flow_determinism
EOF

echo "=== 2. Compiling and running through Z3 Gatekeeper ==="
# We execute the workspace binary natively without letting a failure crash the shell
cargo run --bin ts_cli
STATUS=$?

echo -e "\n----------------------------------------------------------"
if [ $STATUS -eq 0 ]; then
    echo "🎯 PIPELINE STATUS: Safe. (SMT Proof Unsat)"
else
    echo "🛑 PIPELINE STATUS: Aborted. Jinn Guard blocked execution."
fi
echo "----------------------------------------------------------"
