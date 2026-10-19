#!/usr/bin/env bash
# =============================================================================
# hsts-verify.sh — VAPT evidence collection for "Missing HSTS" findings
#
# Usage:
#   ./hsts-verify.sh <before|after> [options] [host ...]
#
# Options:
#   -f FILE   file with hosts, one per line (# comments and blank lines ignored)
#   -a FILE   file with extra asset URLs to test, one per line
#   -u URL    single extra asset URL (repeatable)
#   -m SECS   minimum acceptable max-age (default 31536000 = 1 year)
#   -N        skip nmap
#   -T        skip testssl
#   -h        show help
#
# Examples:
#   ./hsts-verify.sh before example.com api.example.com
#   ./hsts-verify.sh before -f hosts.txt -a assets.txt
#   ./hsts-verify.sh after  -f hosts.txt -u https://cdn.example.com/app.js
#
# Hosts may be given as bare hostnames or URLs (scheme/path are stripped).
#
# Output: a timestamped folder + .tar.gz containing raw headers, nmap and
#         testssl results, a summary CSV, a readable log and a SHA-256 manifest.
#
# Light, read-only checks only (a handful of GET requests per host).
# Run only against hosts you are authorised to test.
# =============================================================================

set -uo pipefail

# ----------------------------- DEFAULTS --------------------------------------
# Paths tested on every host: root + a non-existent path (to check 403/404s)
TEST_PATHS=("/" "/hsts-verify-404-check")
MIN_MAX_AGE=31536000
RUN_NMAP=1
RUN_TESTSSL=1
UA="Mozilla/5.0 (VAPT HSTS verification)"
HOSTS=()
ASSET_URLS=()
# -----------------------------------------------------------------------------

usage() { sed -n '/^# Usage:/,/^# Hosts may/p' "$0" | sed 's/^# \{0,1\}//'; exit "${1:-0}"; }

# Read non-empty, non-comment lines from a file
read_list() {
  [[ -r "$1" ]] || { echo "Cannot read file: $1" >&2; exit 1; }
  grep -vE '^\s*(#|$)' "$1" | tr -d '\r' | sed 's/^\s*//; s/\s*$//'
}

# Normalise "https://host/path" -> "host" and validate
add_host() {
  local h
  h="$(echo "$1" | sed -E 's#^[a-zA-Z]+://##; s#[/?].*$##' | tr 'A-Z' 'a-z')"
  if [[ "$h" =~ ^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)+$ ]]; then
    HOSTS+=("$h")
  else
    echo "Skipping invalid host: $1" >&2
  fi
}

add_url() {
  if [[ "$1" =~ ^https?:// ]]; then ASSET_URLS+=("$1"); else echo "Skipping invalid URL: $1" >&2; fi
}

[[ "${1:-}" == "-h" || "${1:-}" == "--help" ]] && usage 0
PHASE="${1:-}"
if [[ "$PHASE" != "before" && "$PHASE" != "after" ]]; then
  echo "Error: first argument must be 'before' or 'after'." >&2
  usage 1
fi
shift

while getopts ":f:a:u:m:NTh" opt; do
  case "$opt" in
    f) while IFS= read -r l; do add_host "$l"; done < <(read_list "$OPTARG") ;;
    a) while IFS= read -r l; do add_url  "$l"; done < <(read_list "$OPTARG") ;;
    u) add_url "$OPTARG" ;;
    m) [[ "$OPTARG" =~ ^[0-9]+$ ]] || { echo "-m needs a number" >&2; exit 1; }; MIN_MAX_AGE="$OPTARG" ;;
    N) RUN_NMAP=0 ;;
    T) RUN_TESTSSL=0 ;;
    h) usage 0 ;;
    :) echo "Option -$OPTARG needs a value" >&2; usage 1 ;;
    \?) echo "Unknown option -$OPTARG" >&2; usage 1 ;;
  esac
done
shift $((OPTIND - 1))
for h in "$@"; do add_host "$h"; done

# De-duplicate hosts, keep order
if ((${#HOSTS[@]})); then
  mapfile -t HOSTS < <(printf '%s\n' "${HOSTS[@]}" | awk '!seen[$0]++')
fi
((${#HOSTS[@]})) || { echo "Error: no valid hosts given (pass them as arguments or with -f)." >&2; usage 1; }

command -v curl >/dev/null || { echo "curl not found"; exit 1; }

TS="$(date -u +%Y%m%dT%H%M%SZ)"
OUT="hsts-${PHASE}-${TS}"
mkdir -p "$OUT"/{raw,nmap,testssl}
LOG="$OUT/evidence.log"
CSV="$OUT/summary.csv"

R=$'\e[31m'; G=$'\e[32m'; Y=$'\e[33m'; B=$'\e[1m'; N=$'\e[0m'
log()  { echo -e "$*" | sed 's/\x1b\[[0-9;]*m//g' >> "$LOG"; echo -e "$*"; }
safe() { echo "$1" | sed -E 's#^https?://##; s#[^A-Za-z0-9._-]#_#g'; }

PRESENT=0; MISSING=0; WEAK=0; NORESP=0

log "${B}=== HSTS verification — phase: ${PHASE^^} ===${N}"
log "Date (UTC) : $(date -u '+%Y-%m-%d %H:%M:%S')"
log "Tester     : $(whoami)@$(hostname)"
log "Hosts      : ${HOSTS[*]}"
log ""
echo "phase,timestamp_utc,url,http_status,hsts_header,max_age,result" > "$CSV"

# ---------- 1. HTTPS header checks ----------
check_url() {
  local url="$1"
  local hdr="$OUT/raw/$(safe "$url").headers"
  curl -sS -D "$hdr" -o /dev/null --max-time 20 -A "$UA" "$url" 2>>"$LOG"

  local status hsts maxage result colour
  status="$(head -n1 "$hdr" 2>/dev/null | tr -d '\r')"
  hsts="$(grep -i '^strict-transport-security:' "$hdr" 2>/dev/null | head -n1 | cut -d: -f2- | tr -d '\r' | sed 's/^ *//')"
  maxage="$(echo "$hsts" | grep -oiE 'max-age=[0-9]+' | cut -d= -f2)"

  if [[ -z "$status" ]]; then
    result="NO RESPONSE"; colour=$Y; ((NORESP++))
  elif [[ -z "$hsts" ]]; then
    result="MISSING"; colour=$R; ((MISSING++))
  elif [[ -n "$maxage" && "$maxage" -ge "$MIN_MAX_AGE" ]]; then
    result="PRESENT"; colour=$G; ((PRESENT++))
  else
    result="PRESENT (max-age < $MIN_MAX_AGE)"; colour=$Y; ((WEAK++))
  fi

  log "  ${url}"
  log "    status : ${status:-none}"
  log "    hsts   : ${hsts:-<not set>}"
  log "    result : ${colour}${result}${N}"
  echo "$PHASE,$(date -u +%FT%TZ),\"$url\",\"$status\",\"$hsts\",${maxage:-},$result" >> "$CSV"
}

log "${B}[1] HTTPS response headers${N}"
for h in "${HOSTS[@]}"; do
  for p in "${TEST_PATHS[@]}"; do check_url "https://${h}${p}"; done
done
if ((${#ASSET_URLS[@]})); then
  for u in "${ASSET_URLS[@]}"; do check_url "$u"; done
else
  log "  ${Y}No asset URLs given — add real asset URLs with -a FILE or -u URL for full coverage.${N}"
fi
log ""

# ---------- 2. HTTP -> HTTPS redirect ----------
log "${B}[2] HTTP -> HTTPS redirect${N}"
for h in "${HOSTS[@]}"; do
  hdr="$OUT/raw/http_$(safe "$h").headers"
  curl -sS -D "$hdr" -o /dev/null --max-time 20 -A "$UA" "http://${h}/" 2>>"$LOG"
  status="$(head -n1 "$hdr" 2>/dev/null | tr -d '\r')"
  loc="$(grep -i '^location:' "$hdr" 2>/dev/null | cut -d: -f2- | tr -d '\r' | sed 's/^ *//')"
  if [[ "$status" =~ 30[1278] && "$loc" == https://* ]]; then r="${G}OK${N}"; else r="${R}CHECK${N}"; fi
  log "  http://${h}/ -> ${status:-none} ${loc:+-> $loc}  [$r]"
done
log ""

# ---------- 3. nmap http-security-headers ----------
if ((RUN_NMAP)) && command -v nmap >/dev/null; then
  log "${B}[3] nmap http-security-headers${N}"
  nmap -Pn -p 443 --script http-security-headers "${HOSTS[@]}" \
       -oN "$OUT/nmap/http-security-headers.txt" >/dev/null 2>>"$LOG"
  grep -iE 'Nmap scan report|Strict_Transport_Security|HSTS' -A1 \
       "$OUT/nmap/http-security-headers.txt" | sed 's/^/  /' | tee -a "$LOG"
  log ""
elif ((RUN_NMAP)); then
  log "${Y}[3] nmap not found — skipped${N}\n"
fi

# ---------- 4. testssl.sh --headers ----------
TESTSSL="$(command -v testssl.sh || command -v testssl || true)"
if ((RUN_TESTSSL)) && [[ -n "$TESTSSL" ]]; then
  log "${B}[4] testssl --headers${N}"
  for h in "${HOSTS[@]}"; do
    "$TESTSSL" --headers --quiet --warnings batch --ip one --color 0 \
      --htmlfile "$OUT/testssl/${h}.html" --logfile "$OUT/testssl/${h}.log" \
      "https://${h}" >/dev/null 2>&1
    line="$(grep -i 'Strict Transport Security' "$OUT/testssl/${h}.log" 2>/dev/null | head -n1 | sed 's/^ *//')"
    log "  ${h}: ${line:-<no HSTS line found — see testssl/${h}.log>}"
  done
  log ""
elif ((RUN_TESTSSL)); then
  log "${Y}[4] testssl not found (sudo apt install testssl.sh) — skipped${N}\n"
fi

# ---------- 5. Verdict ----------
log "${B}=== SUMMARY (${PHASE^^}) ===${N}"
log "  Present : $PRESENT   Weak max-age : $WEAK   Missing : $MISSING   No response : $NORESP"
if [[ "$PHASE" == "before" ]]; then
  if ((MISSING > 0)); then
    log "  ${R}Finding CONFIRMED (true positive): HSTS missing on $MISSING response(s).${N}"
  else
    log "  ${G}HSTS not missing on any tested response — finding may be a false positive or already fixed.${N}"
  fi
else
  if ((MISSING == 0 && WEAK == 0 && NORESP == 0)); then
    log "  ${G}REMEDIATED: HSTS present with max-age >= $MIN_MAX_AGE on all tested responses.${N}"
  else
    log "  ${R}NOT fully remediated — review MISSING/weak/no-response entries above.${N}"
  fi
fi

# ---------- 6. Integrity manifest + archive ----------
( cd "$OUT" && find . -type f ! -name MANIFEST.sha256 -exec sha256sum {} \; > MANIFEST.sha256 )
tar -czf "${OUT}.tar.gz" "$OUT"
log ""
log "Evidence folder : $(pwd)/$OUT"
log "Archive         : $(pwd)/${OUT}.tar.gz"
