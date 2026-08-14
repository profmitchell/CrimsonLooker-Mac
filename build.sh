#!/usr/bin/env bash
# Build and ad-hoc sign CrimsonLooker.dylib (arm64).
#
# Signing locally is deliberate. An ad-hoc signature is only trusted on the
# machine that produced it, which is what you want for something that observes
# and writes into another process. Read the source, then build it yourself.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SRC="${ROOT}/src"
OUT_DIR="${ROOT}/build"
OUT="${OUT_DIR}/CrimsonLooker.dylib"

if [[ "$(uname -s)" != "Darwin" ]]; then
  echo "error: build.sh requires macOS" >&2
  exit 1
fi

if [[ "$(uname -m)" != "arm64" ]]; then
  echo "warning: host is $(uname -m); this targets Apple Silicon" >&2
fi

mkdir -p "${OUT_DIR}"

clang++ \
  -arch arm64 \
  -dynamiclib \
  -std=c++17 \
  -O2 \
  -Wall \
  -Wextra \
  -include strings.h \
  -I"${SRC}" \
  -o "${OUT}" \
  "${SRC}/CrimsonLooker.mm" \
  "${SRC}/equipment_probe.mm" \
  "${SRC}/axiom_patch.mm" \
  "${SRC}/axiom_runtime.cpp" \
  "${SRC}/axiom_force_service.mm" \
  "${SRC}/axiom_force_runtime.cpp" \
  "${SRC}/capture_research_with_equipment.mm"

codesign --force --sign - --timestamp=none "${OUT}"
xattr -cr "${OUT}" 2>/dev/null || true
codesign --verify --verbose=2 "${OUT}"

echo "Architectures: $(lipo -archs "${OUT}")"
echo "Built: ${OUT}"
