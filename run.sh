#!/usr/bin/env bash
set -euo pipefail

# ─── Host Vulnerability Assessment Tool ───────────────────────────────────────
# Builds and runs the Dockerized security assessment against the host system.
# Usage: ./run.sh [OPTIONS passed to assessment CLI]
# Example: ./run.sh --skip lynis --verbose
# ──────────────────────────────────────────────────────────────────────────────

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
IMAGE_NAME="host-sec-assessment:latest"
OUTPUT_DIR="${SCRIPT_DIR}/output"

# ─── Pre-flight checks ────────────────────────────────────────────────────────

echo ""
echo "╔══════════════════════════════════════════════╗"
echo "║     HOST VULNERABILITY ASSESSMENT TOOL       ║"
echo "╚══════════════════════════════════════════════╝"
echo ""

# Check Docker is running
if ! docker info &>/dev/null; then
  echo "ERROR: Docker is not running or not accessible."
  exit 1
fi

# Check API key
if [[ -z "${ANTHROPIC_API_KEY:-}" ]]; then
  echo "WARNING: ANTHROPIC_API_KEY is not set."
  echo "         AI analysis will be disabled unless you pass --no-ai"
  echo ""
  read -rp "Continue without AI analysis? (y/N): " confirm
  if [[ "${confirm,,}" != "y" ]]; then
    echo "Aborted. Set ANTHROPIC_API_KEY and re-run."
    exit 1
  fi
  EXTRA_FLAGS="--no-ai"
fi

# ─── Build image ──────────────────────────────────────────────────────────────

echo "► Building Docker image..."
docker build -t "${IMAGE_NAME}" "${SCRIPT_DIR}" --quiet
echo "  Image built: ${IMAGE_NAME}"

# ─── Prepare output directory ─────────────────────────────────────────────────

mkdir -p "${OUTPUT_DIR}"

# ─── Security notice ──────────────────────────────────────────────────────────

echo ""
echo "┌─────────────────────────────────────────────────────┐"
echo "│  This tool will run with the following host access:  │"
echo "│  • --pid=host     (read host process table)          │"
echo "│  • --network=host (use host network namespace)       │"
echo "│  • -v /:/host:ro  (read host filesystem)             │"
echo "│  • CAP_NET_RAW, CAP_NET_ADMIN (nmap SYN scans)       │"
echo "│  • CAP_SYS_PTRACE (read /proc/<pid>/exe)             │"
echo "│                                                       │"
echo "│  All mounts are READ-ONLY. No changes to host.       │"
echo "└─────────────────────────────────────────────────────┘"
echo ""
read -rp "Proceed with assessment? (y/N): " confirm
if [[ "${confirm,,}" != "y" ]]; then
  echo "Aborted."
  exit 0
fi

# ─── Run assessment ───────────────────────────────────────────────────────────

echo ""
echo "► Starting assessment..."
echo "  Output will be written to: ${OUTPUT_DIR}"
echo ""

docker run --rm \
  --pid=host \
  --network=host \
  --cap-add=NET_ADMIN \
  --cap-add=NET_RAW \
  --cap-add=SYS_PTRACE \
  --cap-add=AUDIT_READ \
  -v /:/host:ro \
  -v /proc:/host/proc:ro \
  -v /sys:/host/sys:ro \
  -v /var/log:/host/var/log:ro \
  -v "${OUTPUT_DIR}:/output" \
  -e "ANTHROPIC_API_KEY=${ANTHROPIC_API_KEY:-}" \
  -e "HOST_ROOT=/host" \
  -e "OUTPUT_DIR=/output" \
  "${IMAGE_NAME}" \
  ${EXTRA_FLAGS:-} \
  "$@"

echo ""
echo "► Assessment complete. Reports in: ${OUTPUT_DIR}"
ls -lh "${OUTPUT_DIR}"/*.{html,md} 2>/dev/null || true
