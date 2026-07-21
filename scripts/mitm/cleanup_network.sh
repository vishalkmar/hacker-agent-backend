#!/bin/bash
# ============================================================
# MITM Cleanup Script - Restore Network to Original State
# Run this if agent crashes or you need to manually clean up
# ============================================================

echo "[*] MITM Network Cleanup"
echo "========================"

# 1. Flush iptables rules (nat + filter)
echo "[*] Flushing iptables rules..."
iptables -t nat -F PREROUTING 2>/dev/null || echo "  [WARN] iptables nat flush failed"
iptables -t nat -F 2>/dev/null || echo "  [WARN] iptables nat table flush failed"
iptables -t mangle -F 2>/dev/null 
iptables -F 2>/dev/null
echo "  [+] iptables flushed"

# 2. Disable IP forwarding
echo "[*] Disabling IP forwarding..."
echo 0 > /proc/sys/net/ipv4/ip_forward 2>/dev/null && echo "  [+] IP forwarding OFF" || echo "  [WARN] Could not disable"

# 3. Kill all MITM-related processes
echo "[*] Killing MITM processes..."
for proc in arpspoof bettercap ettercap mitmproxy tcpdump dnsmasq; do
    if pkill -f "$proc" 2>/dev/null; then
        echo "  [+] Killed $proc"
    fi
done

# Kill Python MITM scripts
pkill -f "mitm_agent.py" 2>/dev/null && echo "  [+] Killed mitm_agent.py"
pkill -f "phish_with_mitm.py" 2>/dev/null && echo "  [+] Killed phish_with_mitm.py"
pkill -f "flask" 2>/dev/null && echo "  [+] Killed flask processes"

# 4. Restore ARP tables (broadcast correct info)
echo "[*] Sending ARP restore broadcasts..."
if command -v arp &>/dev/null; then
    # Get list of IPs from current ARP table and broadcast correct MACs
    arp -n 2>/dev/null | grep -v "incomplete" | while read line; do
        ip=$(echo $line | awk '{print $1}')
        mac=$(echo $line | awk '{print $3}')
        if [ -n "$ip" ] && [ "$ip" != "Address" ]; then
            arping -c 1 -U -I eth0 "$ip" 2>/dev/null || true
        fi
    done 2>/dev/null
fi
echo "  [+] ARP broadcasts sent"

# 5. Restart network (gentle refresh)
echo "[*] Refreshing network interfaces..."
for iface in /sys/class/net/*; do
    name=$(basename "$iface")
    if [ "$name" != "lo" ]; then
        ip link set "$name" down 2>/dev/null
        ip link set "$name" up 2>/dev/null
        echo "  [+] Refreshed $name"
    fi
done

# 6. Clear ARP cache
echo "[*] Clearing ARP cache..."
ip -s -s neigh flush all 2>/dev/null && echo "  [+] ARP cache cleared" || echo "  [WARN] Could not clear"

# 7. Kill any residual Python processes from our tools
echo "[*] Checking for residual listener processes..."
lsof -i :8080 2>/dev/null | grep LISTEN | awk '{print $2}' | xargs -r kill -9 2>/dev/null && echo "  [+] Freed port 8080"
lsof -i :53 2>/dev/null | grep LISTEN | awk '{print $2}' | xargs -r kill -9 2>/dev/null && echo "  [+] Freed port 53"

# 8. Remove temp files
echo "[*] Cleaning temp files..."
rm -rf /tmp/mitm_logs 2>/dev/null && echo "  [+] Removed /tmp/mitm_logs"
rm -f /tmp/mitm_*.pcap 2>/dev/null

echo ""
echo "[✓] Network cleanup complete!"
echo "    Network should be back to normal."
echo "    If issues persist: systemctl restart NetworkManager"
