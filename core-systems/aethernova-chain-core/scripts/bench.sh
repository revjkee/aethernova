#!/usr/bin/env bash
#===============================================================================
#  Aethernova Chain Core • bench.sh
#  Industrial-grade system & RPC benchmark harness
#===============================================================================
#  Features:
#    - Safe Bash: strict modes, traps, sanitized env
#    - System profile: OS, kernel, CPU, RAM, disk layout
#    - CPU/memory microbench (portable; uses openssl speed if present)
#    - Disk I/O (sequential write/read; fallbacks if oflag=direct unsupported)
#    - Network: ICMP latency (ping), optional iperf3 throughput
#    - RPC: latency distribution & simple throughput via concurrent curl
#    - Block height probe (JSON-RPC or /health autodetect)
#    - Outputs: pretty table, JSON, or both; machine-readable artifacts
#    - Logs: structured log file + raw samples
#
#  Usage:
#    scripts/bench.sh \
#      --rpc-url http://127.0.0.1:8545 \
#      --rpc-method auto \
#      --duration 15 \
#      --concurrency 16 \
#      --format both \
#      --out ./bench-out
#
#  Exit codes:
#    0 success; non-zero on failures
#===============================================================================

set -Eeuo pipefail
IFS=$'\n\t'

#------------------------------- Defaults -------------------------------------#
DURATION="${DURATION:-15}"              # seconds for timed benches
CONCURRENCY="${CONCURRENCY:-16}"        # parallel clients for RPC
FORMAT="${FORMAT:-both}"                # json|table|both
RPC_URL="${RPC_URL:-}"                  # e.g., http://127.0.0.1:8545
RPC_METHOD="${RPC_METHOD:-auto}"        # auto|jsonrpc|health
RPC_JSONRPC_METHOD="${RPC_JSONRPC_METHOD:-eth_blockNumber}"  # used if jsonrpc
RPC_TIMEOUT="${RPC_TIMEOUT:-5}"         # seconds curl timeout
OUT_DIR="${OUT_DIR:-./bench-out}"
PING_COUNT="${PING_COUNT:-10}"
DISK_SIZE_MB="${DISK_SIZE_MB:-512}"     # tmp file size for disk bench
IPERF3_HOST="${IPERF3_HOST:-}"          # optional iperf3 server (host:port)
NO_DISK="${NO_DISK:-0}"                 # 1 to skip disk tests
NO_NET="${NO_NET:-0}"                   # 1 to skip network tests
NO_RPC="${NO_RPC:-0}"                   # 1 to skip RPC tests

#------------------------------- Globals --------------------------------------#
START_TS="$(date -u +%FT%TZ)"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
TMPDIR="$(mktemp -d -t benchXXXXXX)"
LOG_DIR=""
LOG_FILE=""
SAMPLES_DIR=""
ART_JSON=""
ART_TABLE=""
OS_NAME=""
OS_PRETTY=""
KERNEL=""
ARCH=""
CPU_MODEL=""
CPU_CORES=""
RAM_TOTAL=""
DISK_SUMMARY=""

cleanup() {
  local ec=$?
  trap - EXIT INT TERM
  if [[ -n "${TMPDIR:-}" && -d "${TMPDIR:-}" ]]; then
    rm -rf "${TMPDIR}" || true
  fi
  exit "${ec}"
}
trap cleanup EXIT INT TERM

#------------------------------- Logging --------------------------------------#
ts() { date -u +%FT%TZ; }
log() { printf "[%s] %s\n" "$(ts)" "$*" | tee -a "${LOG_FILE}"; }
die() { printf "[%s] ERROR: %s\n" "$(ts)" "$*" | tee -a "${LOG_FILE}" >&2; exit 1; }

#---------------------------- Utilities ---------------------------------------#
require_cmd() {
  command -v "$1" >/dev/null 2>&1 || return 1
}
numfmt_si() {
  # humanize numbers if numfmt exists
  if require_cmd numfmt; then numfmt --to=iec --suffix=B "$1" 2>/dev/null || echo "$1"; else echo "$1"; fi
}
json_escape() {
  # minimal JSON string escaper
  local s="$1"
  s="${s//\\/\\\\}"; s="${s//\"/\\\"}"; s="${s//$'\n'/\\n}"
  printf "%s" "${s}"
}
extract_host_from_url() {
  # naive host:port extractor for http(s)://host[:port]/...
  local url="$1"
  # strip scheme
  url="${url#*://}"
  # split path
  url="${url%%/*}"
  printf "%s" "${url}"
}
timer_ns() { date +%s%N; }
elapsed_ms() {
  # args: start_ns end_ns
  awk -v s="$1" -v e="$2" 'BEGIN{printf "%.3f", (e - s)/1000000.0}'
}

#--------------------------- Arg parsing --------------------------------------#
usage() {
  cat <<EOF
Aethernova Chain Core • bench.sh

Options:
  --rpc-url URL                 RPC base URL (e.g., http://127.0.0.1:8545)
  --rpc-method MODE             auto|jsonrpc|health (default: auto)
  --rpc-jsonrpc-method NAME     JSON-RPC method to call (default: eth_blockNumber)
  --duration SEC                Duration for timed benches (default: ${DURATION})
  --concurrency N               Parallel clients for RPC (default: ${CONCURRENCY})
  --timeout SEC                 RPC HTTP timeout seconds (default: ${RPC_TIMEOUT})
  --format FMT                  json|table|both (default: ${FORMAT})
  --out DIR                     Output directory (default: ${OUT_DIR})
  --ping-count N                ICMP samples (default: ${PING_COUNT})
  --disk-size-mb MB             tmpfile size for disk bench (default: ${DISK_SIZE_MB})
  --iperf3 host[:port]          Optional iperf3 server to test TCP throughput
  --no-disk                     Skip disk I/O tests
  --no-net                      Skip network tests
  --no-rpc                      Skip RPC tests
  -h, --help                    Show help

Examples:
  scripts/bench.sh --rpc-url http://localhost:8545 --format both --out ./bench-out
EOF
}

parse_args() {
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --rpc-url) RPC_URL="$2"; shift 2;;
      --rpc-method) RPC_METHOD="$2"; shift 2;;
      --rpc-jsonrpc-method) RPC_JSONRPC_METHOD="$2"; shift 2;;
      --duration) DURATION="$2"; shift 2;;
      --concurrency) CONCURRENCY="$2"; shift 2;;
      --timeout) RPC_TIMEOUT="$2"; shift 2;;
      --format) FORMAT="$2"; shift 2;;
      --out) OUT_DIR="$2"; shift 2;;
      --ping-count) PING_COUNT="$2"; shift 2;;
      --disk-size-mb) DISK_SIZE_MB="$2"; shift 2;;
      --iperf3) IPERF3_HOST="$2"; shift 2;;
      --no-disk) NO_DISK=1; shift;;
      --no-net) NO_NET=1; shift;;
      --no-rpc) NO_RPC=1; shift;;
      -h|--help) usage; exit 0;;
      *) die "Unknown argument: $1";;
    esac
  done
}

#--------------------------- Setup outputs ------------------------------------#
prepare_outputs() {
  mkdir -p "${OUT_DIR}"
  LOG_DIR="${OUT_DIR}/logs"
  SAMPLES_DIR="${OUT_DIR}/samples"
  mkdir -p "${LOG_DIR}" "${SAMPLES_DIR}"
  LOG_FILE="${LOG_DIR}/bench_$(date -u +%Y%m%dT%H%M%SZ).log"
  ART_JSON="${OUT_DIR}/bench_report.json"
  ART_TABLE="${OUT_DIR}/bench_report.txt"
  : > "${LOG_FILE}"
  : > "${ART_TABLE}"
  log "Aethernova bench started at ${START_TS}"
  log "Output dir: ${OUT_DIR}"
}

#--------------------------- System profile -----------------------------------#
system_profile() {
  OS_NAME="$(uname -s)"
  KERNEL="$(uname -r)"
  ARCH="$(uname -m)"
  if [[ "$OS_NAME" == "Linux" ]]; then
    if [[ -f /etc/os-release ]]; then
      # shellcheck disable=SC1091
      . /etc/os-release || true
      OS_PRETTY="${PRETTY_NAME:-Linux}"
    else
      OS_PRETTY="Linux"
    fi
    CPU_MODEL="$(awk -F: '/model name/{print $2}' /proc/cpuinfo | sed 's/^ //;q' || echo "")"
    CPU_CORES="$(getconf _NPROCESSORS_ONLN || echo "")"
    RAM_TOTAL="$(awk '/MemTotal/{print $2*1024}' /proc/meminfo 2>/dev/null || echo "")"
    if require_cmd lsblk; then
      DISK_SUMMARY="$(lsblk -o NAME,SIZE,ROTA,TYPE,MOUNTPOINT -dn 2>/dev/null | sed 's/  */ /g')"
    else
      DISK_SUMMARY="lsblk not available"
    fi
  elif [[ "$OS_NAME" == "Darwin" ]]; then
    OS_PRETTY="$(sw_vers -productName) $(sw_vers -productVersion)"
    CPU_MODEL="$(sysctl -n machdep.cpu.brand_string || echo "")"
    CPU_CORES="$(sysctl -n hw.ncpu || echo "")"
    RAM_TOTAL="$(($(sysctl -n hw.memsize || echo 0)))"
    DISK_SUMMARY="$(diskutil list 2>/dev/null | sed -n 's/^ *//p' | head -n 50)"
  else
    OS_PRETTY="${OS_NAME}"
    CPU_MODEL=""
    CPU_CORES="$(getconf _NPROCESSORS_ONLN || echo "")"
    RAM_TOTAL=""
    DISK_SUMMARY=""
  fi

  log "System: ${OS_PRETTY} | kernel ${KERNEL} | arch ${ARCH}"
  log "CPU: ${CPU_MODEL} | cores ${CPU_CORES}"
  if [[ -n "${RAM_TOTAL}" ]]; then
    log "RAM: $(numfmt_si "${RAM_TOTAL}")"
  fi
}

#--------------------------- CPU & Memory bench -------------------------------#
bench_cpu_mem() {
  log "CPU/MEM bench: started"
  local cpu_bench note tmpfile
  local openssl_ok=0
  local sha_mb_s=""
  local memcpy_mb_s=""

  if require_cmd openssl; then
    openssl_ok=1
    # OpenSSL speed for SHA256 for ~${DURATION}s
    # capture last line with 'evp' or 'sha256'
    local out="${SAMPLES_DIR}/openssl_speed.txt"
    openssl speed -seconds "${DURATION}" sha256 evp > "${out}" 2>&1 || true
    # parse MB/s (portable heuristic)
    sha_mb_s="$(awk '/sha256 .*bytes/{val=$NF} /evp .*bytes/{val=$NF} END{print val}' "${out}" 2>/dev/null || true)"
    note="openssl speed"
  else
    # Portable fallback: timed /dev/zero -> sha256sum to /dev/null
    local start end bytes total_ms rate
    bytes=$((1024*1024*128))  # 128MB chunks
    local iters=0
    local elapsed=0
    start="$(timer_ns)"
    while :; do
      head -c "${bytes}" /dev/zero | shasum -a 256 >/dev/null 2>&1 || head -c "${bytes}" /dev/zero >/dev/null
      iters=$((iters+1))
      end="$(timer_ns)"
      elapsed_ms="$(elapsed_ms "${start}" "${end}")"
      elapsed="${elapsed_ms%.*}"
      [[ "${elapsed}" -ge "${DURATION}000" ]] && break
    done
    total_ms="${elapsed_ms}"
    bytes=$((bytes*iters))
    # MB/s
    rate=$(awk -v b="${bytes}" -v ms="${total_ms}" 'BEGIN{if(ms>0) printf "%.2f", (b/1048576)/(ms/1000); else print "0"}')
    sha_mb_s="${rate}"
    note="portable fallback"
  fi

  # Memory copy throughput fallback with dd to tmpfs (or regular FS)
  tmpfile="${TMPDIR}/memcpy_test.bin"
  local t_start t_end t_ms m_rate
  : > "${tmpfile}" || true
  t_start="$(timer_ns)"
  dd if=/dev/zero of="${tmpfile}" bs=8M count=$((128/8)) status=none conv=fdatasync 2>/dev/null || true
  t_end="$(timer_ns)"
  t_ms="$(elapsed_ms "${t_start}" "${t_end}")"
  m_rate=$(awk -v ms="${t_ms}" 'BEGIN{if(ms>0) printf "%.2f", (128)/(ms/1000); else print "0"}') # 128MB wrote
  memcpy_mb_s="${m_rate}"

  log "CPU SHA256 MB/s: ${sha_mb_s} (${note})"
  log "Memory copy MB/s (dd 128MB): ${memcpy_mb_s}"

  cat > "${SAMPLES_DIR}/cpu_mem.json" <<JSON
{
  "cpu_sha256_mb_s": ${sha_mb_s:-0},
  "memcpy_mb_s": ${memcpy_mb_s:-0},
  "method": "$(json_escape "${note}")",
  "duration_sec": ${DURATION}
}
JSON
}

#--------------------------- Disk I/O bench -----------------------------------#
bench_disk() {
  [[ "${NO_DISK}" -eq 1 ]] && { log "Disk bench: skipped (--no-disk)"; return; }
  log "Disk bench: started (size=${DISK_SIZE_MB}MB)"
  local f="${TMPDIR}/disk_test.bin"
  local write_ms read_ms write_mb_s read_mb_s

  # Write
  local t1 t2
  t1="$(timer_ns)"
  if dd if=/dev/zero of="${f}" bs=4M count=$((DISK_SIZE_MB/4)) oflag=direct status=none 2>"${SAMPLES_DIR}/disk_write.err"; then
    :
  else
    # Fallback without oflag=direct
    dd if=/dev/zero of="${f}" bs=4M count=$((DISK_SIZE_MB/4)) conv=fdatasync status=none 2>>"${SAMPLES_DIR}/disk_write.err" || true
  fi
  sync
  t2="$(timer_ns)"
  write_ms="$(elapsed_ms "${t1}" "${t2}")"
  write_mb_s=$(awk -v sz="${DISK_SIZE_MB}" -v ms="${write_ms}" 'BEGIN{if(ms>0) printf "%.2f", sz/(ms/1000); else print "0"}')

  # Read (drop cache attempt on Linux; best effort)
  if [[ -w /proc/sys/vm/drop_caches ]]; then
    echo 3 > /proc/sys/vm/drop_caches 2>/dev/null || true
  fi
  t1="$(timer_ns)"
  if dd if="${f}" of=/dev/null bs=4M iflag=direct status=none 2>"${SAMPLES_DIR}/disk_read.err"; then
    :
  else
    dd if="${f}" of=/dev/null bs=4M status=none 2>>"${SAMPLES_DIR}/disk_read.err" || true
  fi
  t2="$(timer_ns)"
  read_ms="$(elapsed_ms "${t1}" "${t2}")"
  read_mb_s=$(awk -v sz="${DISK_SIZE_MB}" -v ms="${read_ms}" 'BEGIN{if(ms>0) printf "%.2f", sz/(ms/1000); else print "0"}')

  log "Disk write MB/s: ${write_mb_s}"
  log "Disk read  MB/s: ${read_mb_s}"

  cat > "${SAMPLES_DIR}/disk.json" <<JSON
{
  "file_size_mb": ${DISK_SIZE_MB},
  "write_mb_s": ${write_mb_s:-0},
  "read_mb_s": ${read_mb_s:-0}
}
JSON
}

#--------------------------- Network bench ------------------------------------#
bench_net() {
  [[ "${NO_NET}" -eq 1 ]] && { log "Network bench: skipped (--no-net)"; return; }
  log "Network bench: started"
  local target_host=""
  if [[ -n "${RPC_URL}" ]]; then
    target_host="$(extract_host_from_url "${RPC_URL}")"
  fi

  # ICMP latency via ping
  local ping_host=""
  if [[ -n "${target_host}" ]]; then
    ping_host="${target_host%%:*}"
  else
    ping_host="8.8.8.8"
  fi

  local avg_ms="null" min_ms="null" max_ms="null" mdev_ms="null"
  if require_cmd ping; then
    if [[ "$(uname -s)" == "Darwin" ]]; then
      # macOS ping summary format
      local out="${SAMPLES_DIR}/ping.txt"
      ping -c "${PING_COUNT}" -W 3000 "${ping_host}" >"${out}" 2>&1 || true
      # parse "round-trip min/avg/max/stddev = 10.431/12.345/..."
      if grep -qi "round-trip" "${out}"; then
        IFS=/ read -r _ min avg max mdev _ < <(awk -F' = ' '/round-trip/{print $2}' "${out}" | tr '/' ' ')
        avg_ms="${avg:-null}"; min_ms="${min:-null}"; max_ms="${max:-null}"; mdev_ms="${mdev:-null}"
      fi
    else
      # Linux ping summary: rtt min/avg/max/mdev = ...
      local out="${SAMPLES_DIR}/ping.txt"
      ping -c "${PING_COUNT}" -w 10 "${ping_host}" >"${out}" 2>&1 || true
      if awk '/min\/avg\/max\/mdev/{print; found=1} END{exit !found}' "${out}" >/dev/null 2>&1; then
        local line
        line="$(awk -F'= ' '/min\/avg\/max\/mdev/{print $2}' "${out}" | tr '/' ' ')"
        read -r min avg max mdev _ <<< "${line}"
        avg_ms="${avg:-null}"; min_ms="${min:-null}"; max_ms="${max:-null}"; mdev_ms="${mdev:-null}"
      fi
    fi
    log "Ping ${ping_host}: avg=${avg_ms} ms min=${min_ms} ms max=${max_ms} ms mdev=${mdev_ms} ms"
  else
    log "ping not available; skipping ICMP latency"
  fi

  # iperf3 throughput (optional)
  local iperf_mbps="null"
  if [[ -n "${IPERF3_HOST}" ]] && require_cmd iperf3; then
    local out="${SAMPLES_DIR}/iperf3.txt"
    iperf3 -c "${IPERF3_HOST}" -t "${DURATION}" -J > "${out}" 2>&1 || true
    if require_cmd jq; then
      iperf_mbps="$(jq -r '.end.sum_received.bits_per_second // .end.sum_sent.bits_per_second' "${out}" 2>/dev/null | awk '{printf "%.2f", $1/1000000}' 2>/dev/null || echo null)"
    else
      iperf_mbps="$(awk -F, '/bits_per_second/{print $2;exit}' "${out}" 2>/dev/null | awk '{printf "%.2f", $1/1000000}' 2>/dev/null || echo null)"
    fi
    log "iperf3 TCP throughput: ${iperf_mbps} Mbps (server=${IPERF3_HOST})"
  elif [[ -n "${IPERF3_HOST}" ]]; then
    log "iperf3 not available; skipping throughput test"
  fi

  cat > "${SAMPLES_DIR}/net.json" <<JSON
{
  "ping_host": "$(json_escape "${ping_host}")",
  "ping_avg_ms": ${avg_ms},
  "ping_min_ms": ${min_ms},
  "ping_max_ms": ${max_ms},
  "ping_mdev_ms": ${mdev_ms},
  "iperf3_mbps": ${iperf_mbps}
}
JSON
}

#--------------------------- RPC helpers --------------------------------------#
rpc_health_probe() {
  # GET ${RPC_URL}/health
  curl -fsS --max-time "${RPC_TIMEOUT}" "${RPC_URL%/}/health" -o "${SAMPLES_DIR}/rpc_health.json" || return 1
  return 0
}
rpc_jsonrpc_blocknumber() {
  # POST JSON-RPC method (default eth_blockNumber)
  local payload='{"jsonrpc":"2.0","id":1,"method":"'"${RPC_JSONRPC_METHOD}"'","params":[]}'
  curl -fsS --max-time "${RPC_TIMEOUT}" -H "Content-Type: application/json" -d "${payload}" "${RPC_URL}" -o "${SAMPLES_DIR}/rpc_blocknum.json" || return 1
  return 0
}
rpc_autodetect() {
  case "${RPC_METHOD}" in
    health)
      rpc_health_probe
      ;;
    jsonrpc)
      rpc_jsonrpc_blocknumber
      ;;
    auto)
      rpc_health_probe || rpc_jsonrpc_blocknumber || return 1
      ;;
    *)
      return 1
      ;;
  esac
}

rpc_latency_sample() {
  # one request; prints total_ms to stdout or "NaN"
  local start end t_ms
  start="$(timer_ns)"
  if [[ "${RPC_METHOD}" == "health" ]]; then
    curl -fsS --max-time "${RPC_TIMEOUT}" "${RPC_URL%/}/health" -o /dev/null || { echo "NaN"; return; }
  else
    local payload='{"jsonrpc":"2.0","id":1,"method":"'"${RPC_JSONRPC_METHOD}"'","params":[]}'
    curl -fsS --max-time "${RPC_TIMEOUT}" -H "Content-Type: application/json" -d "${payload}" "${RPC_URL}" -o /dev/null || { echo "NaN"; return; }
  fi
  end="$(timer_ns)"
  t_ms="$(elapsed_ms "${start}" "${end}")"
  echo "${t_ms}"
}

rpc_latency_bench() {
  [[ "${NO_RPC}" -eq 1 ]] && { log "RPC bench: skipped (--no-rpc)"; return; }
  [[ -z "${RPC_URL}" ]] && { log "RPC URL not provided; skipping RPC bench"; return; }

  log "RPC detect: method=${RPC_METHOD} url=${RPC_URL}"
  if ! rpc_autodetect; then
    log "RPC autodetect failed (health/jsonrpc). Continuing but metrics may be empty."
  fi

  log "RPC latency bench: duration=${DURATION}s concurrency=${CONCURRENCY}"
  local end_ts=$(( $(date +%s) + DURATION ))
  local tmp="${SAMPLES_DIR}/rpc_latency_samples.txt"
  : > "${tmp}"

  # Spawn background workers
  rpc_worker() {
    while [[ $(date +%s) -lt ${end_ts} ]]; do
      rpc_latency_sample >> "${tmp}" 2>/dev/null || echo "NaN" >> "${tmp}"
    done
  }
  for _ in $(seq 1 "${CONCURRENCY}"); do
    rpc_worker &
  done
  wait || true

  # Filter numerics
  local samples_file="${SAMPLES_DIR}/rpc_latency_ms.txt"
  awk '/^[0-9]+(\.[0-9]+)?$/{print}' "${tmp}" > "${samples_file}" || true

  local count avg p50 p90 p99 min max
  if [[ -s "${samples_file}" ]]; then
    count="$(wc -l < "${samples_file}" | tr -d ' ')"
    sort -n "${samples_file}" -o "${samples_file}.sorted"
    min="$(head -n1 "${samples_file}.sorted")"
    max="$(tail -n1 "${samples_file}.sorted")"
    # avg
    avg="$(awk '{s+=$1} END{if(NR>0) printf "%.3f", s/NR; else print "NaN"}' "${samples_file}.sorted")"
    # quantiles
    q() { # args: percentile (e.g., 50)
      local q="$1" n idx
      n="$(wc -l < "${samples_file}.sorted" | tr -d ' ')"
      if [[ "${n}" -eq 0 ]]; then echo "NaN"; return; fi
      idx=$(( (q*n + 99)/100 )) # ceil(q% of n)
      sed -n "${idx}p" "${samples_file}.sorted"
    }
    p50="$(q 50)"; p90="$(q 90)"; p99="$(q 99)"
  else
    count="0"; avg="NaN"; p50="NaN"; p90="NaN"; p99="NaN"; min="NaN"; max="NaN"
  fi

  log "RPC latency ms: count=${count} avg=${avg} p50=${p50} p90=${p90} p99=${p99} min=${min} max=${max}"

  cat > "${SAMPLES_DIR}/rpc.json" <<JSON
{
  "url": "$(json_escape "${RPC_URL}")",
  "method_mode": "$(json_escape "${RPC_METHOD}")",
  "jsonrpc_method": "$(json_escape "${RPC_JSONRPC_METHOD}")",
  "duration_sec": ${DURATION},
  "concurrency": ${CONCURRENCY},
  "samples": ${count},
  "latency_ms": {
    "avg": ${avg},
    "p50": ${p50},
    "p90": ${p90},
    "p99": ${p99},
    "min": ${min},
    "max": ${max}
  }
}
JSON
}

#--------------------------- Block rate probe ---------------------------------#
probe_block_rate() {
  [[ "${NO_RPC}" -eq 1 ]] && { log "Block rate: skipped (--no-rpc)"; return; }
  [[ -z "${RPC_URL}" ]] && { log "Block rate: RPC URL not provided; skipping"; return; }

  log "Block rate probe: sampling over 10s"
  local h1 h2
  get_height() {
    if [[ "${RPC_METHOD}" == "health" ]]; then
      # Try to fetch height from /health if present (heuristic)
      local j="${SAMPLES_DIR}/health_now.json"
      curl -fsS --max-time "${RPC_TIMEOUT}" "${RPC_URL%/}/health" -o "${j}" || return 1
      if require_cmd jq; then
        jq -r '..|.height? // empty' "${j}" 2>/dev/null | head -n1
      else
        awk -F'[,:}]' '/height/{for(i=1;i<=NF;i++) if($i ~ /height/){print $(i+1); exit}}' "${j}" 2>/dev/null
      fi
    else
      local payload='{"jsonrpc":"2.0","id":1,"method":"'"${RPC_JSONRPC_METHOD}"'","params":[]}'
      local j="${SAMPLES_DIR}/blocknum_now.json"
      curl -fsS --max-time "${RPC_TIMEOUT}" -H "Content-Type: application/json" -d "${payload}" "${RPC_URL}" -o "${j}" || return 1
      if require_cmd jq; then
        jq -r '.result' "${j}" 2>/dev/null | sed 's/^0x//; s/^/16 /' | awk '{printf "%d", strtonum("0x"$2)}' 2>/dev/null
      else
        # crude hex to int (if starts with 0x)
        local hex
        hex="$(awk -F'"' '/result/{print $4}' "${j}" 2>/dev/null)"
        hex="${hex#0x}"
        printf "%d\n" "0x${hex}" 2>/dev/null || echo ""
      fi
    fi
  }
  h1="$(get_height || echo "")"
  sleep 10
  h2="$(get_height || echo "")"

  local rate="null"
  if [[ -n "${h1}" && -n "${h2}" ]]; then
    if [[ "${h2}" =~ ^[0-9]+$ && "${h1}" =~ ^[0-9]+$ ]]; then
      rate=$(awk -v a="${h1}" -v b="${h2}" 'BEGIN{printf "%.2f", (b-a)/10.0}')
    fi
  fi
  log "Block height delta over 10s: h1=${h1:-NaN} h2=${h2:-NaN} rate=${rate} blocks/s"

  cat > "${SAMPLES_DIR}/blockrate.json" <<JSON
{
  "height_t0": ${h1:-null},
  "height_t1": ${h2:-null},
  "window_sec": 10,
  "blocks_per_sec": ${rate}
}
JSON
}

#--------------------------- Aggregate report ---------------------------------#
emit_json_report() {
  local cpu_mem="${SAMPLES_DIR}/cpu_mem.json"
  local disk="${SAMPLES_DIR}/disk.json"
  local net="${SAMPLES_DIR}/net.json"
  local rpc="${SAMPLES_DIR}/rpc.json"
  local blockrate="${SAMPLES_DIR}/blockrate.json"

  # Read fragments if exist, otherwise nulls
  read_or_null() { [[ -s "$1" ]] && cat "$1" || echo "null"; }

  cat > "${ART_JSON}" <<JSON
{
  "metadata": {
    "timestamp_utc": "$(json_escape "${START_TS}")",
    "os": "$(json_escape "${OS_PRETTY}")",
    "kernel": "$(json_escape "${KERNEL}")",
    "arch": "$(json_escape "${ARCH}")",
    "cpu_model": "$(json_escape "${CPU_MODEL}")",
    "cpu_cores": "$(json_escape "${CPU_CORES}")",
    "ram_total_bytes": ${RAM_TOTAL:-0}
  },
  "disk_overview": "$(json_escape "${DISK_SUMMARY}")",
  "results": {
    "cpu_mem": $(read_or_null "${cpu_mem}"),
    "disk": $(read_or_null "${disk}"),
    "network": $(read_or_null "${net}"),
    "rpc": $(read_or_null "${rpc}"),
    "blockrate": $(read_or_null "${blockrate}")
  }
}
JSON
  log "JSON report: ${ART_JSON}"
}

emit_table_report() {
  {
    echo "Aethernova Chain Core – Benchmark Report (${START_TS} UTC)"
    echo "System: ${OS_PRETTY} | kernel ${KERNEL} | arch ${ARCH}"
    echo "CPU: ${CPU_MODEL} | cores ${CPU_CORES} | RAM: $(numfmt_si "${RAM_TOTAL:-0}")"
    echo ""
    printf "%-28s | %-20s | %-20s\n" "SECTION" "METRIC" "VALUE"
    printf -- "----------------------------+----------------------+----------------------\n"

    # CPU/MEM
    if [[ -s "${SAMPLES_DIR}/cpu_mem.json" ]]; then
      local sha mem method
      sha="$(awk -F'[: ,}]' '/cpu_sha256_mb_s/{print $3}' "${SAMPLES_DIR}/cpu_mem.json")"
      mem="$(awk -F'[: ,}]' '/memcpy_mb_s/{print $3}' "${SAMPLES_DIR}/cpu_mem.json")"
      method="$(awk -F'"' '/"method"/{print $4}' "${SAMPLES_DIR}/cpu_mem.json")"
      printf "%-28s | %-20s | %-20s\n" "CPU/MEM" "SHA256 MB/s" "${sha}"
      printf "%-28s | %-20s | %-20s\n" "CPU/MEM" "memcpy MB/s" "${mem}"
      printf "%-28s | %-20s | %-20s\n" "CPU/MEM" "method" "${method}"
    else
      printf "%-28s | %-20s | %-20s\n" "CPU/MEM" "status" "no data"
    fi

    # Disk
    if [[ -s "${SAMPLES_DIR}/disk.json" ]]; then
      local w r size
      w="$(awk -F'[: ,}]' '/"write_mb_s"/{print $3}' "${SAMPLES_DIR}/disk.json")"
      r="$(awk -F'[: ,}]' '/"read_mb_s"/{print $3}' "${SAMPLES_DIR}/disk.json")"
      size="$(awk -F'[: ,}]' '/"file_size_mb"/{print $3}' "${SAMPLES_DIR}/disk.json")"
      printf "%-28s | %-20s | %-20s\n" "Disk" "Write MB/s" "${w}"
      printf "%-28s | %-20s | %-20s\n" "Disk" "Read MB/s" "${r}"
      printf "%-28s | %-20s | %-20s\n" "Disk" "File size MB" "${size}"
    else
      printf "%-28s | %-20s | %-20s\n" "Disk" "status" "skipped/no data"
    fi

    # Network
    if [[ -s "${SAMPLES_DIR}/net.json" ]]; then
      local host avg min max mdev mbps
      host="$(awk -F'"' '/"ping_host"/{print $4}' "${SAMPLES_DIR}/net.json")"
      avg="$(awk -F'[: ,}]' '/"ping_avg_ms"/{print $3}' "${SAMPLES_DIR}/net.json")"
      min="$(awk -F'[: ,}]' '/"ping_min_ms"/{print $3}' "${SAMPLES_DIR}/net.json")"
      max="$(awk -F'[: ,}]' '/"ping_max_ms"/{print $3}' "${SAMPLES_DIR}/net.json")"
      mdev="$(awk -F'[: ,}]' '/"ping_mdev_ms"/{print $3}' "${SAMPLES_DIR}/net.json")"
      mbps="$(awk -F'[: ,}]' '/"iperf3_mbps"/{print $3}' "${SAMPLES_DIR}/net.json")"
      printf "%-28s | %-20s | %-20s\n" "Network" "Ping host" "${host}"
      printf "%-28s | %-20s | %-20s\n" "Network" "avg ms" "${avg}"
      printf "%-28s | %-20s | %-20s\n" "Network" "min/max ms" "${min}/${max}"
      printf "%-28s | %-20s | %-20s\n" "Network" "mdev ms" "${mdev}"
      printf "%-28s | %-20s | %-20s\n" "Network" "iperf3 Mbps" "${mbps}"
    else
      printf "%-28s | %-20s | %-20s\n" "Network" "status" "skipped/no data"
    fi

    # RPC
    if [[ -s "${SAMPLES_DIR}/rpc.json" ]]; then
      local url avg p50 p90 p99 min max smp
      url="$(awk -F'"' '/"url"/{print $4; exit}' "${SAMPLES_DIR}/rpc.json")"
      smp="$(awk -F'[: ,}]' '/"samples"/{print $3; exit}' "${SAMPLES_DIR}/rpc.json")"
      avg="$(awk -F'[: ,}]' '/"avg"/{print $3; exit}' "${SAMPLES_DIR}/rpc.json")"
      p50="$(awk -F'[: ,}]' '/"p50"/{print $3; exit}' "${SAMPLES_DIR}/rpc.json")"
      p90="$(awk -F'[: ,}]' '/"p90"/{print $3; exit}' "${SAMPLES_DIR}/rpc.json")"
      p99="$(awk -F'[: ,}]' '/"p99"/{print $3; exit}' "${SAMPLES_DIR}/rpc.json")"
      min="$(awk -F'[: ,}]' '/"min"/{print $3; exit}' "${SAMPLES_DIR}/rpc.json")"
      max="$(awk -F'[: ,}]' '/"max"/{print $3; exit}' "${SAMPLES_DIR}/rpc.json")"
      printf "%-28s | %-20s | %-20s\n" "RPC" "URL" "${url}"
      printf "%-28s | %-20s | %-20s\n" "RPC" "samples" "${smp}"
      printf "%-28s | %-20s | %-20s\n" "RPC" "avg ms" "${avg}"
      printf "%-28s | %-20s | %-20s\n" "RPC" "p50/p90/p99" "${p50}/${p90}/${p99}"
      printf "%-28s | %-20s | %-20s\n" "RPC" "min/max ms" "${min}/${max}"
    else
      printf "%-28s | %-20s | %-20s\n" "RPC" "status" "skipped/no data"
    fi

    # Block rate
    if [[ -s "${SAMPLES_DIR}/blockrate.json" ]]; then
      local h0 h1 bps
      h0="$(awk -F'[: ,}]' '/"height_t0"/{print $3; exit}' "${SAMPLES_DIR}/blockrate.json")"
      h1="$(awk -F'[: ,}]' '/"height_t1"/{print $3; exit}' "${SAMPLES_DIR}/blockrate.json")"
      bps="$(awk -F'[: ,}]' '/"blocks_per_sec"/{print $3; exit}' "${SAMPLES_DIR}/blockrate.json")"
      printf "%-28s | %-20s | %-20s\n" "Block rate" "h0->h1" "${h0}/${h1}"
      printf "%-28s | %-20s | %-20s\n" "Block rate" "blocks/sec" "${bps}"
    else
      printf "%-28s | %-20s | %-20s\n" "Block rate" "status" "skipped/no data"
    fi
  } | tee -a "${ART_TABLE}" >/dev/null
  log "Table report: ${ART_TABLE}"
}

#--------------------------- Main ---------------------------------------------#
main() {
  parse_args "$@"
  prepare_outputs
  system_profile
  bench_cpu_mem
  bench_disk
  bench_net
  rpc_latency_bench
  probe_block_rate

  case "${FORMAT}" in
    json)  emit_json_report ;;
    table) emit_table_report ;;
    both)  emit_json_report; emit_table_report ;;
    *)     log "Unknown format '${FORMAT}', defaulting to both"; emit_json_report; emit_table_report ;;
  esac

  log "Benchmark completed."
  log "Artifacts:"
  log "  JSON : ${ART_JSON}"
  log "  Table: ${ART_TABLE}"
  log "  Logs : ${LOG_FILE}"
}

main "$@"
