// Host-protection denylist. This is NOT about limiting hacking — it only blocks commands
// that would wipe/brick the machine CypherMind itself runs on (your own box). Offensive
// security commands against targets are fully allowed.
//
// Toggle with EXEC_GUARD_HOST=false (not recommended).
//
// NOTE: we avoid `\b` directly before hyphenated flags (e.g. `\b-Recurse`) because a
// hyphen is a non-word char, so the boundary never matches. We use lookaheads instead.

const PATTERNS = [
  // rm -rf on root / home / wildcard root
  /\brm\s+(-[a-z]*\s+)*-?[a-z]*r[a-z]*f?[a-z]*\s+(--no-preserve-root\s+)?(\/|~)(\s|$|\*)/i,
  /\brm\s+-[rf]+\s+\/\*/i,

  // PowerShell recursive+forced delete aimed at a drive root or system path
  /Remove-Item\b(?=[\s\S]*-Recurse)(?=[\s\S]*-Force)[\s\S]*?([A-Za-z]:\\?(\s|\\|"|'|$)|\$env:(SystemRoot|SystemDrive|windir)|\\Windows\b|\\System32\b)/i,
  // PowerShell recursive delete of a bare drive root even without -Force
  /Remove-Item\b(?=[\s\S]*-Recurse)[\s\S]*?[A-Za-z]:\\(\s|"|'|$)/i,

  // cmd-style mass delete of a system drive
  /\bdel\s+\/[a-z]\s.*[A-Za-z]:\\/i,
  /\brd\s+\/[sq]\s.*[A-Za-z]:\\/i,
  /\brmdir\s+\/[sq]\s.*[A-Za-z]:\\/i,

  // Filesystem / disk destruction
  /\bmkfs(\.\w+)?\b/i,
  /\bdd\s+if=.*\bof=\/dev\/(sd|nvme|hd|disk)/i,
  /Format-Volume\b/i,
  /\bformat\s+[a-z]:/i,
  /(Clear|Clean)-Disk\b/i,
  />\s*\/dev\/(sd|nvme|hd)[a-z]/i,

  // Fork bombs
  /:\(\)\s*\{\s*:\s*\|\s*:\s*&\s*\}\s*;\s*:/,

  // Power / system control of the host
  /\b(shutdown|reboot|halt|poweroff)\b/i,
  /(Stop|Restart)-Computer\b/i,

  // Secure-wipe the whole volume
  /\bcipher\s+\/w/i,
];

export function checkDenylist(command) {
  for (const re of PATTERNS) {
    if (re.test(command)) {
      return { blocked: true, reason: `Blocked by host-protection guard (matched ${re}).` };
    }
  }
  return { blocked: false };
}
