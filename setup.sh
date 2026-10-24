#!/bin/bash
# Author: al4n4n (Dadb0d)
# Lab setup for ZDI-CAN-33774: ksmbd ops-flip race condition.
# Run inside the QEMU VM as root.
set -eu

echo "=== ZDI-CAN-33774 Lab Setup ==="

# 1. Install ksmbd-tools if not present
if ! command -v ksmbd.mountd &>/dev/null; then
    echo "[*] Installing ksmbd-tools..."
    apt-get update -qq && apt-get install -y -qq ksmbd-tools
fi

# 2. Create share directory
mkdir -p /srv/share
chmod 777 /srv/share
echo "test" > /srv/share/test.txt

# 3. Write ksmbd config with guest access
cat > /etc/ksmbd/ksmbd.conf << 'KCEOF'
[global]
    netbios name = TESTSERVER

[share]
    path = /srv/share
    guest ok = yes
    read only = no
    browsable = yes
KCEOF

# 4. Add test user (ksmbd requires at least one user even with guest)
echo -e "test\ntest" | ksmbd.adduser -a testuser 2>/dev/null || true

# 5. Start ksmbd
if lsmod | grep -q ksmbd; then
    ksmbd.mountd --reload 2>/dev/null || true
else
    modprobe ksmbd
fi
ksmbd.mountd -n &
sleep 1

# 6. Build opsflip
echo "[*] Building opsflip..."
cd "$(dirname "$0")/poc"
make clean && make
cd ..

echo ""
echo "=== Setup complete ==="
echo "ksmbd running with guest share at /srv/share"
echo ""
echo "Run the PoC:"
echo "  bash poc.sh $(hostname -I | awk '{print $1}')"
echo ""
echo "Verify:"
echo "  bash verify.sh $(hostname -I | awk '{print $1}')"
