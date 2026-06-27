#!/usr/bin/env bash
# Runs INSIDE the Kali container. Reports tool availability as JSON:
#   {"image_kind","binaries","packages","everything_installed","present":[...],"missing":[...]}
# Usage (inside container):  bash audit-tools.sh
set -u

# Curated "must exist in a real Kali" check-list across categories.
CHECK=(nmap masscan rustscan dnsrecon dnsenum fierce amass subfinder whatweb \
  nikto gobuster ffuf feroxbuster dirb wfuzz sqlmap nuclei dalfox wpscan \
  hydra john hashcat hash-identifier crunch cewl cupp medusa ncrack \
  metasploit-framework msfconsole searchsploit exploitdb \
  aircrack-ng airodump-ng reaver wifite bettercap ettercap responder \
  enum4linux smbclient smbmap crackmapexec impacket-scripts \
  set seclists wordlists tcpdump wireshark tshark hping3 \
  recon-ng theharvester maltego spiderfoot \
  burpsuite zaproxy proxychains4 tor)

present=(); missing=()
for t in "${CHECK[@]}"; do
  if command -v "$t" >/dev/null 2>&1 || dpkg -l "$t" 2>/dev/null | grep -q '^ii'; then
    present+=("$t")
  else
    missing+=("$t")
  fi
done

binaries=$(ls -1 /usr/bin /usr/sbin /usr/local/bin 2>/dev/null | sort -u | wc -l)
packages=$(dpkg-query -W 2>/dev/null | wc -l)
everything="no"
dpkg -l kali-linux-everything 2>/dev/null | grep -q '^ii' && everything="yes"
large="no"
dpkg -l kali-linux-large 2>/dev/null | grep -q '^ii' && large="yes"

# emit JSON (jq if available, else hand-rolled)
arr() { printf '%s\n' "$@" | jq -R . | jq -s . 2>/dev/null; }
if command -v jq >/dev/null 2>&1; then
  jq -nc \
    --argjson binaries "$binaries" \
    --argjson packages "$packages" \
    --arg everything "$everything" \
    --arg large "$large" \
    --argjson present "$(arr "${present[@]:-}")" \
    --argjson missing "$(arr "${missing[@]:-}")" \
    '{binaries:$binaries, packages:$packages, kali_everything:$everything, kali_large:$large,
      checked:($present|length)+($missing|length), present:$present, missing:$missing}'
else
  echo "{\"binaries\":$binaries,\"packages\":$packages,\"kali_everything\":\"$everything\",\"kali_large\":\"$large\",\"present_count\":${#present[@]},\"missing\":\"${missing[*]:-}\"}"
fi
