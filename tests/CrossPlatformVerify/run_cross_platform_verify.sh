#!/usr/bin/env bash
# Run CrossPlatformVerify with a fixed seed and write output to a file.
# Use the same seed on Windows and Linux, then diff the two output files.
# Usage: ./run_cross_platform_verify.sh [seed] [output_file]
# Example: ./run_cross_platform_verify.sh 12345 results_linux.txt

set -e
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"
SEED="${1:-12345}"
OUT="${2:-cross_platform_verify_output.txt}"

echo "Building and running with SEED=$SEED, output to $OUT"
dotnet run --project CrossPlatformVerify.csproj -- "$SEED" | tee "$OUT"
echo ""
echo "Output saved to $OUT. On the other OS run with the same seed and compare:"
echo "  diff results_windows.txt results_linux.txt"
echo "  (or use run_cross_platform_verify.bat on Windows with same seed and output file name)"
