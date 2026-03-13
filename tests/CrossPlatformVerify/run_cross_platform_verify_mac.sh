#!/usr/bin/env bash
# Run CrossPlatformVerify on macOS with a fixed seed and write output to a file.
# Use the same seed on Windows, Linux, and macOS, then diff the output files.
# Usage: ./run_cross_platform_verify_mac.sh [seed] [output_file]
# Example: ./run_cross_platform_verify_mac.sh 12345 results_mac.txt

set -e
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"
SEED="${1:-12345}"
OUT="${2:-results_mac.txt}"

echo "Building and running on macOS with SEED=$SEED, output to $OUT"
dotnet run --project CrossPlatformVerify.csproj -- "$SEED" | tee "$OUT"
echo ""
echo "Output saved to $OUT. Compare with Windows and Linux:"
echo "  diff results_windows.txt results_mac.txt"
echo "  diff results_linux.txt results_mac.txt"
