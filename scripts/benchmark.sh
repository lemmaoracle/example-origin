#!/usr/bin/env bash
# benchmark.sh — Measure example-origin ZK proof generation & verification times
#
# Usage:
#   ./scripts/benchmark.sh           # single run
#   ./scripts/benchmark.sh 5         # 5 iterations (median reported)

set -euo pipefail
cd "$(dirname "$0")/.."

ITERATIONS="${1:-1}"
SNARKJS="node_modules/.bin/snarkjs"

# snarkjs lives in the circuits package
if [ ! -f "packages/circuits/$SNARKJS" ]; then
  echo "✗ snarkjs not found in packages/circuits/node_modules" >&2
  exit 1
fi
SNARKJS="packages/circuits/$SNARKJS"

CIRCUITS=("bridge-approval-origin" "lst-collateral-origin")
BUILD_DIR="packages/circuits/build"

declare -A COMPILE_TIMES PROVE_TIMES VERIFY_TIMES PROOF_SIZES CONSTRAINTS

timestamp() { date +%s%N; }
elapsed_ns() { echo $(( $(timestamp) - $1 )); }
ns_to_ms() { echo "$(( $1 / 1000000 ))"; }

# ── Per-circuit benchmark ────────────────────────────────────────────────────

for CIRCUIT in "${CIRCUITS[@]}"; do
  CIRCUIT_DIR="$BUILD_DIR/$CIRCUIT"

  if [ ! -f "$CIRCUIT_DIR/$CIRCUIT.r1cs" ]; then
    echo "⚠  No build artifacts for $CIRCUIT — run 'pnpm circuits:prove' first"
    continue
  fi

  # ── Constraint count ──
  CONSTRAINT_LINE=$($SNARKJS r1cs info "$CIRCUIT_DIR/$CIRCUIT.r1cs" 2>/dev/null | grep -i constraint | sed 's/.*:.*: //' || echo "?")
  CONSTRAINTS[$CIRCUIT]="$CONSTRAINT_LINE"

  # ── Proof size ──
  PROOF_SIZES[$CIRCUIT]=$(wc -c < "$CIRCUIT_DIR/proof.json")

  # ── Artifacts ──
  WASM_PATH="$CIRCUIT_DIR/${CIRCUIT}_js/${CIRCUIT}.wasm"
  ZKEY_PATH="$CIRCUIT_DIR/${CIRCUIT}_final.zkey"
  INPUT_PATH="$CIRCUIT_DIR/input.json"
  VKEY_PATH="$CIRCUIT_DIR/verification_key.json"

  if [ ! -f "$WASM_PATH" ] || [ ! -f "$ZKEY_PATH" ]; then
    echo "⚠  Missing wasm/zkey for $CIRCUIT"
    continue
  fi

  # ── Prove ──
  PROVE_MS_LIST=()
  for i in $(seq 1 "$ITERATIONS"); do
    START=$(timestamp)
    $SNARKJS groth16 fullprove \
      "$INPUT_PATH" \
      "$WASM_PATH" \
      "$ZKEY_PATH" \
      "$CIRCUIT_DIR/bench_proof.json" \
      "$CIRCUIT_DIR/bench_public.json" \
      >/dev/null 2>&1
    ELAPSED=$(elapsed_ns "$START")
    PROVE_MS_LIST+=($(ns_to_ms "$ELAPSED"))
  done

  # ── Verify ──
  VERIFY_MS_LIST=()
  for i in $(seq 1 "$ITERATIONS"); do
    START=$(timestamp)
    $SNARKJS groth16 verify \
      "$VKEY_PATH" \
      "$CIRCUIT_DIR/bench_public.json" \
      "$CIRCUIT_DIR/bench_proof.json" \
      >/dev/null 2>&1
    ELAPSED=$(elapsed_ns "$START")
    VERIFY_MS_LIST+=($(ns_to_ms "$ELAPSED"))
  done

  # ── Medians ──
  IFS=$'\n' SORTED_PROVE=($(printf '%s\n' "${PROVE_MS_LIST[@]}" | sort -n)); unset IFS
  IFS=$'\n' SORTED_VERIFY=($(printf '%s\n' "${VERIFY_MS_LIST[@]}" | sort -n)); unset IFS
  MID=$((ITERATIONS / 2))
  PROVE_MEDIAN=${SORTED_PROVE[$MID]:-${SORTED_PROVE[0]}}
  VERIFY_MEDIAN=${SORTED_VERIFY[$MID]:-${SORTED_VERIFY[0]}}

  PROVE_TIMES[$CIRCUIT]="$PROVE_MEDIAN"
  VERIFY_TIMES[$CIRCUIT]="$VERIFY_MEDIAN"

  echo "✓ $CIRCUIT: prove=${PROVE_MEDIAN}ms verify=${VERIFY_MEDIAN}ms (n=$ITERATIONS)"
done

# ── Compile-time benchmark ───────────────────────────────────────────────────

for CIRCUIT in "${CIRCUITS[@]}"; do
  SRC_FILE=$(find packages/circuits/src -name "${CIRCUIT}.circom" | head -1)
  if [ -z "$SRC_FILE" ]; then continue; fi

  COMPILE_MS_LIST=()
  BENCH_TMPDIR=$(mktemp -d -t example-origin-bench.XXXXXX)
  for i in $(seq 1 "$ITERATIONS"); do
    START=$(timestamp)
    circom "$SRC_FILE" --r1cs --wasm --sym \
      -l packages/circuits/node_modules \
      -o "$BENCH_TMPDIR" \
      >/dev/null 2>&1
    ELAPSED=$(elapsed_ns "$START")
    COMPILE_MS_LIST+=($(ns_to_ms "$ELAPSED"))
  done

  IFS=$'\n' SORTED_COMPILE=($(printf '%s\n' "${COMPILE_MS_LIST[@]}" | sort -n)); unset IFS
  MID=$((ITERATIONS / 2))
  COMPILE_MEDIAN=${SORTED_COMPILE[$MID]:-${SORTED_COMPILE[0]}}
  COMPILE_TIMES[$CIRCUIT]="$COMPILE_MEDIAN"
  rm -rf "$BENCH_TMPDIR"
done

# ── Output ───────────────────────────────────────────────────────────────────

CPU_MODEL=$(grep 'model name' /proc/cpuinfo 2>/dev/null | head -1 | sed 's/model name\s*:\s*//' || echo '?')
NPROC=$(nproc)
MEM_GB=$(( $(grep MemTotal /proc/meminfo 2>/dev/null | awk '{print $2}' || echo 0) / 1024 / 1024 ))

echo ""
echo "## Benchmark results (median of $ITERATIONS run(s))"
echo ""
echo "**Host:** ${CPU_MODEL}, ${NPROC} cores, ${MEM_GB}GB RAM"
echo ""
echo "| Circuit | Constraints | Compile | Prove | Verify | Proof size |"
echo "|---|---|---|---|---|---|"
for CIRCUIT in "${CIRCUITS[@]}"; do
  CT="${COMPILE_TIMES[$CIRCUIT]:-?}ms"
  PT="${PROVE_TIMES[$CIRCUIT]:-?}ms"
  VT="${VERIFY_TIMES[$CIRCUIT]:-?}ms"
  PS="${PROOF_SIZES[$CIRCUIT]:-?} bytes"
  CC="${CONSTRAINTS[$CIRCUIT]:-?}"
  echo "| $CIRCUIT | $CC | $CT | $PT | $VT | $PS |"
done
