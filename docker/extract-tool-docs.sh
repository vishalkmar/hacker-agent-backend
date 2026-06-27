#!/usr/bin/env bash
# Runs INSIDE the Kali container. Extracts each tool's docs (package desc + man + --help)
# into NDJSON at /workspace/tool-docs.ndjson, one JSON object per line:
#   {"name","package","category","summary","help","man"}
# Safe: only calls `--help`/`-h`/`--version` (time-boxed). Never runs tools bare.
#
# Usage (inside container):  bash extract-tool-docs.sh [maxTools]
set -u
OUT=/workspace/tool-docs.ndjson
: > "$OUT"
MAX="${1:-100000}"

# Build the set of REAL Kali tool packages = direct deps of installed kali-tools-*/kali-linux-*
# metapackages. This lets us index only actual tools (nmap, sqlmap…), not coreutils/libs/helpers.
# If no such metapackages exist (e.g. the lean image), TOOLPKGS stays empty and we index all.
declare -A TOOLPKG
META="$(dpkg-query -W -f='${Package}\n' 2>/dev/null | grep -E '^kali-(linux|tools)-' || true)"
if [ -n "$META" ]; then
  for m in $META; do
    apt-cache depends "$m" 2>/dev/null | awk '/Depends:|Recommends:/{print $2}' | grep -v '^<' | while read -r p; do
      echo "$p"
    done
  done | sort -u > /tmp/_toolpkgs.txt
  while read -r p; do [ -n "$p" ] && TOOLPKG["$p"]=1; done < /tmp/_toolpkgs.txt
fi
FILTER=$([ "${#TOOLPKG[@]}" -gt 0 ] && echo yes || echo no)
echo "tool-package filter: $FILTER (${#TOOLPKG[@]} kali tool packages)" >&2

# Candidate tools = unique executables in the standard bin dirs.
mapfile -t TOOLS < <(ls -1 /usr/bin /usr/sbin /usr/local/bin 2>/dev/null | sort -u)

count=0
for name in "${TOOLS[@]}"; do
  [ -z "$name" ] && continue
  bin="$(command -v "$name" 2>/dev/null)" || continue

  # package + category (best-effort)
  pkg="$(dpkg -S "$bin" 2>/dev/null | head -1 | cut -d: -f1)"

  # When the filter is active, only index binaries that belong to a real Kali tool package.
  if [ "$FILTER" = "yes" ]; then
    [ -n "$pkg" ] || continue
    [ -n "${TOOLPKG[$pkg]:-}" ] || continue
  fi
  summary=""
  category=""
  if [ -n "$pkg" ]; then
    summary="$(apt-cache show "$pkg" 2>/dev/null | awk -F': ' '/^Description(-en)?:/{print $2; exit}')"
    category="$(apt-cache show "$pkg" 2>/dev/null | awk -F': ' '/^Section:/{print $2; exit}')"
  fi

  # man page (rendered, trimmed). stdin from /dev/null so nothing can block.
  man_txt="$(timeout -k 2 6 man -P cat "$name" </dev/null 2>/dev/null | col -bx 2>/dev/null | head -c 6000)"

  # --help / -h / --version. CRITICAL: redirect stdin from /dev/null so interactive tools
  # (vim/python/nc/less…) exit instead of hanging; timeout -k force-kills stubborn ones.
  help_txt="$(timeout -k 2 6 "$bin" --help </dev/null 2>&1 | head -c 6000)"
  if [ -z "${help_txt// }" ]; then help_txt="$(timeout -k 2 6 "$bin" -h </dev/null 2>&1 | head -c 6000)"; fi
  if [ -z "${help_txt// }" ]; then help_txt="$(timeout -k 2 6 "$bin" --version </dev/null 2>&1 | head -c 1500)"; fi

  # Skip pure-noise entries (no docs at all).
  if [ -z "${summary// }" ] && [ -z "${man_txt// }" ] && [ -z "${help_txt// }" ]; then continue; fi

  jq -nc \
    --arg name "$name" \
    --arg package "${pkg:-}" \
    --arg category "${category:-}" \
    --arg summary "${summary:-}" \
    --arg help "$help_txt" \
    --arg man "$man_txt" \
    '{name:$name, package:$package, category:$category, summary:$summary, help:$help, man:$man}' >> "$OUT"

  count=$((count+1))
  [ "$count" -ge "$MAX" ] && break
done

echo "WROTE $count $OUT"
