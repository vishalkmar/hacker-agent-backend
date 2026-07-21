#!/bin/bash
# ============================================================
# Kali Linux MITM Framework - Complete Setup Script
# AI Agent ready - can be executed autonomously
# ============================================================

set -e

echo "[*] Updating package lists..."
apt-get update -qq

echo "[*] Installing core MITM tools..."
apt-get install -y -qq \
    bettercap \
    ettercap-text-only \
    dsniff \
    arpspoof \
    mitmproxy \
    nmap \
    tcpdump \
    python3 \
    python3-pip \
    dnsmasq \
    hostapd \
    iptables \
    wireshark \
    net-tools \
    iproute2 \
    curl \
    wget \
    screen \
    tmux \
    2>&1 | tail -5

echo "[*] Installing Python dependencies..."
pip3 install --quiet \
    scapy \
    colorama \
    rich \
    requests \
    flask \
    netifaces \
    dnspython \
    beautifulsoup4 \
    lxml \
    2>&1 | tail -3

echo "[*] Verifying critical tools..."
for tool in python3 nmap arpspoof dnsmasq mitmproxy bettercap ettercap; do
    if command -v $tool &>/dev/null; then
        echo "  [+] $tool -> $(which $tool)"
    else
        echo "  [WARN] $tool not found"
    fi
done

echo "[*] Checking for bettercap capabilities..."
bettercap -eval "help" 2>&1 | head -3 || echo "bettercap available"

# Enable IP forwarding (check first)
if [ -f /proc/sys/net/ipv4/ip_forward ]; then
    echo 1 > /proc/sys/net/ipv4/ip_forward
    echo "[+] IP forwarding enabled"
fi

echo ""
echo "[✓] Kali MITM Framework setup complete!"
echo "[*] Run: python3 /opt/mitm_agent/mitm_agent.py --help"
