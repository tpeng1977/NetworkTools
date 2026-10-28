#!/usr/bin/env bash
# Build Vortex Linux binaries runnable on Ubuntu 22.04 / glibc ≤ 2.35 hosts.
#
# Why Docker (not full static / not host g++ on Ubuntu 24.04+):
#   - Host toolchain (e.g. glibc 2.39) emits symbols like GLIBC_2.38 that older
#     deploy hosts lack. Fully-static glibc is fragile; musl is a bigger jump.
#   - Building inside ubuntu:22.04 pins glibc to ~2.35; -static-libstdc++ /
#     -static-libgcc avoids needing a matching newer libstdc++ on the target.
#
# Usage:
#   ./build-portable.sh              # docker build → dist/portable-linux/
#   ./build-portable.sh --verify-only dist/portable-linux/server
#   OUT_DIR=... IMAGE_TAG=... ./build-portable.sh
#
# Requires: docker (or podman with DOCKER=podman)
set -euo pipefail

ROOT="$(cd "$(dirname "$0")" && pwd)"
cd "$ROOT"

DOCKER="${DOCKER:-docker}"
IMAGE_TAG="${IMAGE_TAG:-vortex-portable:ubuntu2204}"
OUT_DIR="${OUT_DIR:-$ROOT/dist/portable-linux}"
MAX_GLIBC="${MAX_GLIBC:-2.35}"
DOCKERFILE="${DOCKERFILE:-$ROOT/Dockerfile.portable}"

BINARIES=(server client smartlink multilink local peer linux_network)

version_le() {
  # Return 0 if $1 <= $2 (dotted numeric versions).
  printf '%s\n%s\n' "$1" "$2" | sort -VC
}

verify_binary() {
  local bin="$1"
  local max_glibc="$2"
  if [[ ! -f "$bin" ]]; then
    echo "ERROR: missing binary: $bin" >&2
    return 1
  fi
  if ! command -v objdump >/dev/null 2>&1; then
    echo "WARN: objdump not found; skip GLIBC check for $bin" >&2
    return 0
  fi

  local vers highest="0"
  mapfile -t vers < <(objdump -T "$bin" 2>/dev/null | grep -oE 'GLIBC_[0-9.]+' | sed 's/^GLIBC_//' | sort -Vu)
  if [[ ${#vers[@]} -eq 0 ]]; then
    echo "WARN: no GLIBC_* versions found in $bin (fully static?)" >&2
    return 0
  fi
  highest="${vers[-1]}"
  echo "  $(basename "$bin"): max GLIBC_${highest}"
  if ! version_le "$highest" "$max_glibc"; then
    echo "ERROR: $bin requires GLIBC_${highest} > ${max_glibc} (not portable to Ubuntu 22.04)" >&2
    echo "       All GLIBC versions:" >&2
    printf '         GLIBC_%s\n' "${vers[@]}" >&2
    return 1
  fi

  # Informative: show max GLIBCXX if still dynamically linked to libstdc++.
  if command -v readelf >/dev/null 2>&1; then
    local cxx
    cxx="$(readelf -V "$bin" 2>/dev/null | grep -oE 'GLIBCXX_[0-9.]+' | sed 's/^GLIBCXX_//' | sort -Vu | tail -1 || true)"
    if [[ -n "$cxx" ]]; then
      echo "           (dynamic GLIBCXX_${cxx} still referenced — prefer -static-libstdc++)"
    fi
  fi
  return 0
}

if [[ "${1:-}" == "--verify-only" ]]; then
  shift
  if [[ $# -eq 0 ]]; then
    echo "Usage: $0 --verify-only <binary> [more binaries...]" >&2
    exit 2
  fi
  ok=0
  for b in "$@"; do
    verify_binary "$b" "$MAX_GLIBC" || ok=1
  done
  exit "$ok"
fi

if ! command -v "$DOCKER" >/dev/null 2>&1; then
  echo "ERROR: '$DOCKER' not found. Install Docker (or set DOCKER=podman)." >&2
  exit 1
fi

echo "[portable] building image $IMAGE_TAG (ubuntu:22.04 toolchain)..."
"$DOCKER" build -f "$DOCKERFILE" -t "$IMAGE_TAG" "$ROOT"

echo "[portable] extracting binaries → $OUT_DIR"
rm -rf "$OUT_DIR"
mkdir -p "$OUT_DIR"

cid="$("$DOCKER" create "$IMAGE_TAG")"
trap '"$DOCKER" rm -f "$cid" >/dev/null 2>&1 || true' EXIT
for b in "${BINARIES[@]}"; do
  "$DOCKER" cp "$cid:/src/$b" "$OUT_DIR/$b"
  chmod +x "$OUT_DIR/$b"
done

echo "[portable] verifying GLIBC ≤ ${MAX_GLIBC}..."
fail=0
for b in "${BINARIES[@]}"; do
  verify_binary "$OUT_DIR/$b" "$MAX_GLIBC" || fail=1
done
if [[ "$fail" -ne 0 ]]; then
  echo "[portable] FAIL: some binaries exceed GLIBC ${MAX_GLIBC}" >&2
  exit 1
fi

echo "[portable] OK → $OUT_DIR"
echo "  Deploy examples:"
echo "    scp $OUT_DIR/server $OUT_DIR/peer user@host:~/"
echo "    # on Ubuntu 22.04 host:"
echo "    ./server config/server.json"
echo "  Re-check on any machine:"
echo "    ./build-portable.sh --verify-only $OUT_DIR/server"
echo "    objdump -T $OUT_DIR/server | grep -oE 'GLIBC_[0-9.]+' | sort -Vu"
