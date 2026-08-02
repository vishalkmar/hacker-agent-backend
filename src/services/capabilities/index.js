// Phase D4 — machine capability detection ("what powers are live on THIS machine").
//
// The desktop app runs the exec engine on the user's own hardware, which unlocks things the cloud/WSL
// backend physically cannot do: host shell, a local Docker sandbox, and — on suitable Linux hardware —
// real monitor-mode Wi-Fi and a Bluetooth radio. This module probes the local machine and reports, HONESTLY,
// which of those are actually available (no fabrication — same philosophy as the wireless/bluetooth preflights).

import { spawn } from 'node:child_process';
import os from 'node:os';
import { env } from '../../config/env.js';
import { dockerDaemonUp } from '../exec/docker.js';

// Minimal, dependency-free command probe (independent of the agent's exec shell — capabilities describe the
// real host, so we invoke tools directly). Never throws; resolves { ok, out, code }.
function probe(file, args, timeoutMs = 8000) {
  return new Promise((resolve) => {
    let out = '';
    let child;
    try {
      child = spawn(file, args, { windowsHide: true });
    } catch (e) {
      return resolve({ ok: false, out: '', code: 127, err: e.message });
    }
    const t = setTimeout(() => { try { child.kill('SIGKILL'); } catch { /* */ } }, timeoutMs);
    child.stdout?.on('data', (c) => (out += c.toString()));
    child.stderr?.on('data', (c) => (out += c.toString()));
    child.on('error', (e) => { clearTimeout(t); resolve({ ok: false, out, code: 127, err: e.message }); });
    child.on('close', (code) => { clearTimeout(t); resolve({ ok: code === 0, out, code: code ?? 1 }); });
  });
}

// Is a CLI tool on PATH? (where on Windows, command -v elsewhere.)
async function hasTool(name) {
  if (process.platform === 'win32') return (await probe('where', [name], 4000)).ok;
  return (await probe('sh', ['-c', `command -v ${name}`], 4000)).ok;
}

async function detectDocker() {
  const ver = await probe(process.platform === 'win32' ? 'docker' : 'docker', ['--version'], 5000);
  const present = ver.ok || /docker/i.test(ver.out);
  let daemonUp = false;
  if (present) { try { daemonUp = await dockerDaemonUp(); } catch { daemonUp = false; } }
  return {
    present,
    daemonUp,
    version: present ? (ver.out.trim().split('\n')[0] || '') : '',
    image: env.exec.image,
  };
}

async function detectWifi() {
  if (process.platform === 'linux') {
    const dev = await probe('iw', ['dev'], 6000);
    const adapters = [...dev.out.matchAll(/Interface\s+(\S+)/g)].map((m) => m[1]);
    const phy = await probe('iw', ['phy'], 6000);
    // "Supported interface modes:" block lists "* monitor" when the radio can enter monitor mode.
    const monitorCapable = /\*\s*monitor/i.test(phy.out);
    return {
      adapters,
      monitorCapable: monitorCapable && adapters.length > 0,
      note: adapters.length === 0
        ? 'No wireless interface detected (iw dev empty).'
        : monitorCapable
          ? 'Monitor mode supported — real Wi-Fi capture/deauth possible with an in-range target.'
          : 'Adapter present but no monitor mode — Wi-Fi attacks need a monitor-capable radio (e.g. Alfa AWUS036ACH).',
    };
  }
  if (process.platform === 'win32') {
    const ifc = await probe('netsh', ['wlan', 'show', 'interfaces'], 6000);
    const adapters = [...ifc.out.matchAll(/^\s*Name\s*:\s*(.+)$/gim)].map((m) => m[1].trim());
    return {
      adapters,
      monitorCapable: false, // Windows native drivers don't expose monitor mode
      note: adapters.length
        ? 'Windows adapter detected, but monitor-mode Wi-Fi attacks are not possible on Windows drivers. Use a Linux exec host (bare-metal/SSH) with a monitor-capable USB adapter.'
        : 'No Wi-Fi interface detected via netsh (WLAN service may be off).',
    };
  }
  return { adapters: [], monitorCapable: false, note: `Wi-Fi capability detection not implemented for ${process.platform}.` };
}

async function detectBluetooth() {
  if (process.platform === 'linux') {
    const hci = await probe('sh', ['-c', 'hciconfig 2>/dev/null || hcitool dev 2>/dev/null'], 6000);
    const adapters = [...hci.out.matchAll(/\b(hci\d+)\b/g)].map((m) => m[1]);
    const present = adapters.length > 0;
    return {
      present,
      adapters: [...new Set(adapters)],
      note: present
        ? 'Bluetooth radio present — scan/snarf possible with a device in range.'
        : 'No hciN device. A Linux Bluetooth radio is required (see the bluetooth tool preflight).',
    };
  }
  if (process.platform === 'win32') {
    const bt = await probe(
      'powershell',
      ['-NoProfile', '-NonInteractive', '-Command',
        "Get-PnpDevice -Class Bluetooth -Status OK -ErrorAction SilentlyContinue | Select-Object -First 3 -ExpandProperty FriendlyName"],
      8000,
    );
    const names = bt.out.split('\n').map((s) => s.trim()).filter(Boolean);
    const present = names.length > 0;
    return {
      present,
      adapters: names.slice(0, 3),
      note: present
        ? 'Windows Bluetooth present, but bluesnarfer/hci attacks need a Linux BT stack — use a Linux exec host (bare-metal/SSH).'
        : 'No Bluetooth device detected.',
    };
  }
  return { present: false, adapters: [], note: `Bluetooth detection not implemented for ${process.platform}.` };
}

// Key offensive tools worth surfacing on the capabilities screen.
const TOOL_LIST = ['nmap', 'aircrack-ng', 'bettercap', 'hydra', 'sqlmap', 'msfconsole', 'bluesnarfer', 'tshark', 'nuclei'];

async function detectTools() {
  const entries = await Promise.all(TOOL_LIST.map(async (t) => [t, await hasTool(t)]));
  return Object.fromEntries(entries);
}

// Aggregate everything into one report + a UI-friendly "powers" summary.
export async function getCapabilities() {
  const [docker, wifi, bluetooth, tools] = await Promise.all([
    detectDocker(), detectWifi(), detectBluetooth(), detectTools(),
  ]);

  const host = {
    platform: process.platform,
    arch: process.arch,
    hostname: os.hostname(),
    release: os.release(),
    shell: env.exec.shell,
    desktop: env.desktop,
    execBackend: env.exec.backend,
  };

  // Live/limited powers for the UI cards.
  const powers = [
    {
      key: 'host-exec',
      label: 'Host shell execution',
      live: true,
      detail: `Runs ${host.shell} on ${host.platform}/${host.arch} — real cmd/PowerShell/bash on this machine.`,
    },
    {
      key: 'filesystem',
      label: 'Local filesystem access',
      live: !!env.desktop,
      detail: env.desktop ? 'Full read/write on your machine.' : 'Sandboxed to the server workspace (web mode).',
    },
    {
      key: 'docker',
      label: 'Docker Kali sandbox',
      live: docker.daemonUp,
      detail: docker.daemonUp
        ? `Docker running — isolated Kali sandbox available (${docker.image}).`
        : docker.present ? 'Docker installed but the daemon is not running — start Docker Desktop.' : 'Docker not installed.',
    },
    {
      key: 'wifi',
      label: 'Wi-Fi monitor mode',
      live: wifi.monitorCapable,
      detail: wifi.note,
    },
    {
      key: 'bluetooth',
      label: 'Bluetooth radio',
      live: bluetooth.present && host.platform === 'linux',
      detail: bluetooth.note,
    },
  ];

  return { host, docker, wifi, bluetooth, tools, powers, checkedAt: new Date().toISOString() };
}
