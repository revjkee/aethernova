# поддержка профилей: --finality-gadget --parallel-exec --zk-priv-tx#!/usr/bin/env bash
# aethernova-chain-core/scripts/start_node.sh
# Industrial-grade launcher and lifecycle manager for a blockchain node.
# Safe defaults, strict mode, systemd integration, checksum verification, health checks, backups.

set -Eeuo pipefail

# ========== Defaults (can be overridden by .env or CLI flags) ==========
: "${APP_NAME:=aethernova-node}"
: "${APP_USER:=aether}"
: "${APP_GROUP:=aether}"
: "${BINARY_NAME:=aethernova-node}"            # final executable file name
: "${BINARY_VERSION:=v1.0.0}"                  # informational; can be used in DOWNLOAD_URL templates
: "${DOWNLOAD_URL:=}"                          # e.g. https://example.com/aethernova-node-v1.0.0-linux-amd64
: "${CHECKSUM_SHA256:=}"                       # expected sha256 for downloaded binary
: "${BIN_DIR:=/usr/local/bin}"
: "${BASE_DIR:=/var/lib/aethernova}"
: "${DATA_DIR:=${BASE_DIR}/data}"
: "${CONFIG_DIR:=${BASE_DIR}/config}"
: "${LOG_DIR:=/var/log/aethernova}"
: "${RUN_DIR:=/run/aethernova}"
: "${BACKUP_DIR:=${BASE_DIR}/backup}"
: "${ENV_FILE:=.env}"

# Execution / runtime
: "${EXEC_OPTS:=}"                              # node CLI args (e.g., --rpc.addr=127.0.0.1:8545)
: "${ENV_EXPORTS:=}"                            # KEY=VALUE pairs exported before run
: "${ULIMIT_NOFILE:=65536}"

# Health check
: "${HEALTH_CMD:=}"                             # custom cmd returning 0 healthy
: "${HEALTH_HTTP_URL:=}"                        # e.g., http://127.0.0.1:8545/health
: "${HEALTH_TCP_ADDR:=}"                        # e.g., 127.0.0.1:30303
: "${HEALTH_TIMEOUT_SEC:=60}"                   # startup wait
: "${HEALTH_INTERVAL_SEC:=2}"

# Systemd
: "${SYSTEMD_SERVICE_NAME:=${APP_NAME}.service}"
: "${SYSTEMD_AFTER:=network-online.target}"
: "${SYSTEMD_WANTS:=network-online.target}"
: "${SYSTEMD_LIMIT_NOFILE:=65536}"
: "${SYSTEMD_RESTART:=on-failure}"
: "${SYSTEMD_RESTART_SEC:=3s}"
: "${SYSTEMD_USER:=}"                           # if empty, system service; set to username for user service

# Logging
: "${STDOUT_LOG_FILE:=${LOG_DIR}/${APP_NAME}.out.log}"
: "${STDERR_LOG_FILE:=${LOG_DIR}/${APP_NAME}.err.log}"
: "${ENABLE_LOGROTATE:=false}"
: "${LOGROTATE_CONF:=/etc/logrotate.d/${APP_NAME}}"
: "${LOG_MAX_SIZE:=50M}"
: "${LOG_ROTATE_COUNT:=7}"

# Backup
: "${ENABLE_BACKUP:=false}"
: "${BACKUP_RETENTION:=7}"                      # number of snapshots to keep

# Download behavior
: "${DOWNLOAD_TMP_DIR:=/tmp/${APP_NAME}-dl}"
: "${DOWNLOAD_MODE:=skip_if_exists}"            # force, skip_if_exists
: "${BINARY_SYMLINK:=/usr/local/bin/${APP_NAME}}" # symlink for convenience

# Misc
umask 027

# ========== Helpers ==========
warn()  { echo "[WARN] $*" >&2; }
info()  { echo "[INFO] $*"; }
err()   { echo "[ERROR] $*" >&2; }
die()   { err "$*"; exit 1; }

cleanup() {
  # Reserved for future temporary cleanup
  :
}
trap cleanup EXIT

# ========== Usage ==========
usage() {
  cat <<'EOF'
Usage: start_node.sh [command] [options]

Commands:
  install-binary         Download and install the node binary (with SHA256 verification if provided)
  install-systemd        Generate and install systemd unit
  uninstall-systemd      Remove systemd unit
  start                  Start node (foreground by default; use --daemon to run in background)
  stop                   Stop node (tries systemd if installed, otherwise by PID)
  restart                Restart node (systemd if installed; else stop+start)
  status                 Show running status
  logs                   Tail logs (systemd journal or files)
  health                 Run health checks until success or timeout
  backup                 Create a data snapshot (if ENABLE_BACKUP=true)
  prune                  Simple prune placeholder (customize per node)
  show-config            Print effective configuration
  help                   Show this help

Common options:
  --env-file PATH          Path to .env file (default: ./.env)
  --daemon                 Background run (non-systemd mode)
  --no-color               Disable ANSI colors (reserved)
  --as-user USER          Run service as specific user (overrides APP_USER)
  --download-url URL      Override DOWNLOAD_URL
  --checksum SHA256       Expected sha256 checksum for binary
  --exec-opts "ARGS"      CLI arguments passed to node process
  --force                 Force actions (e.g., re-download)
EOF
}

# ========== Args Parser ==========
COMMAND=""
DAEMON=false
FORCE=false
NO_COLOR=false

parse_args() {
  local opt
  while [[ $# -gt 0 ]]; do
    opt="$1"
    case "$opt" in
      install-binary|install-systemd|uninstall-systemd|start|stop|restart|status|logs|health|backup|prune|show-config|help)
        COMMAND="$opt"; shift;;
      --env-file) ENV_FILE="$2"; shift 2;;
      --daemon) DAEMON=true; shift;;
      --no-color) NO_COLOR=true; shift;;
      --as-user) APP_USER="$2"; APP_GROUP="$2"; shift 2;;
      --download-url) DOWNLOAD_URL="$2"; shift 2;;
      --checksum) CHECKSUM_SHA256="$2"; shift 2;;
      --exec-opts) EXEC_OPTS="$2"; shift 2;;
      --force) FORCE=true; shift;;
      -h|--help) usage; exit 0;;
      *) die "Unknown argument: $opt";;
    esac
  done
}

# ========== .env Loader ==========
load_env() {
  if [[ -f "$ENV_FILE" ]]; then
    # shellcheck disable=SC2046
    set -a
    # shellcheck disable=SC1090
    . "$ENV_FILE"
    set +a
    info "Loaded environment from $ENV_FILE"
  fi
}

# ========== Checks ==========
require_cmd() {
  command -v "$1" >/dev/null 2>&1 || die "Missing required command: $1"
}

check_prereqs() {
  require_cmd bash
  require_cmd awk
  require_cmd sed
  require_cmd grep
  require_cmd cut
  require_cmd tr
  require_cmd id
  require_cmd date
  require_cmd sha256sum
  require_cmd curl
  require_cmd jq
  # systemd is optional; checked when needed
}

# ========== Users / Directories ==========
ensure_user_group() {
  if id -u "$APP_USER" >/dev/null 2>&1; then
    info "User $APP_USER exists"
  else
    info "Creating user $APP_USER"
    useradd --system --create-home --home-dir "/home/${APP_USER}" --shell /usr/sbin/nologin "$APP_USER"
  fi
  if getent group "$APP_GROUP" >/dev/null 2>&1; then
    :
  else
    groupadd --system "$APP_GROUP"
    usermod -a -G "$APP_GROUP" "$APP_USER" || true
  fi
}

ensure_dirs() {
  install -d -m 0750 -o "$APP_USER" -g "$APP_GROUP" "$BASE_DIR" "$DATA_DIR" "$CONFIG_DIR" "$LOG_DIR" "$RUN_DIR" "$BACKUP_DIR"
  install -d -m 0755 "$DOWNLOAD_TMP_DIR"
}

# ========== Binary Install ==========
download_and_install_binary() {
  [[ -n "$DOWNLOAD_URL" ]] || die "DOWNLOAD_URL is not set. Provide --download-url or set in env/.env"
  ensure_dirs

  local tmp_file="${DOWNLOAD_TMP_DIR}/${BINARY_NAME}.download"
  local final_bin="${BIN_DIR}/${BINARY_NAME}"
  local arch
  arch="$(uname -m)"

  info "Downloading binary from: $DOWNLOAD_URL"
  curl -fsSL "$DOWNLOAD_URL" -o "$tmp_file"

  if [[ -n "${CHECKSUM_SHA256:-}" ]]; then
    info "Verifying SHA256 checksum"
    echo "${CHECKSUM_SHA256}  ${tmp_file}" | sha256sum -c - || die "Checksum verification failed"
  else
    warn "CHECKSUM_SHA256 not provided; skipping checksum verification"
  fi

  chmod +x "$tmp_file"
  # Atomic install
  install -m 0755 -o root -g root "$tmp_file" "$final_bin"
  rm -f "$tmp_file"

  # Create convenience symlink
  if [[ "$BINARY_SYMLINK" != "$final_bin" ]]; then
    ln -sf "$final_bin" "$BINARY_SYMLINK"
  fi

  info "Installed ${BINARY_NAME} to ${final_bin} (arch: ${arch})"
}

# ========== Systemd Integration ==========
systemd_available() {
  command -v systemctl >/dev/null 2>&1
}

generate_systemd_unit() {
  local svc="${SYSTEMD_SERVICE_NAME}"
  local run_user="${SYSTEMD_USER:-$APP_USER}"
  local run_group="${SYSTEMD_USER:-$APP_GROUP}"

  cat <<EOF
[Unit]
Description=${APP_NAME} service
After=${SYSTEMD_AFTER}
Wants=${SYSTEMD_WANTS}
StartLimitIntervalSec=0

[Service]
Type=simple
User=${run_user}
Group=${run_group}
EnvironmentFile=-${CONFIG_DIR}/runtime.env
WorkingDirectory=${BASE_DIR}
ExecStart=/usr/bin/env bash -lc '${ENV_EXPORTS} ulimit -n ${SYSTEMD_LIMIT_NOFILE} && exec ${BIN_DIR}/${BINARY_NAME} ${EXEC_OPTS} --data-dir="${DATA_DIR}" --config="${CONFIG_DIR}"'
Restart=${SYSTEMD_RESTART}
RestartSec=${SYSTEMD_RESTART_SEC}
LimitNOFILE=${SYSTEMD_LIMIT_NOFILE}
# Hardening
NoNewPrivileges=yes
ProtectSystem=full
ProtectHome=true
PrivateTmp=true
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectControlGroups=yes
LockPersonality=yes
MemoryDenyWriteExecute=yes
RestrictRealtime=yes
RestrictSUIDSGID=yes
CapabilityBoundingSet=
AmbientCapabilities=
SystemCallArchitectures=native
SystemCallFilter=@system-service
ReadWritePaths=${BASE_DIR} ${LOG_DIR} ${RUN_DIR}
LogsDirectory=aethernova

[Install]
WantedBy=multi-user.target
EOF
}

install_systemd() {
  systemd_available || die "systemd not available"
  ensure_dirs
  ensure_user_group

  local unit_path="/etc/systemd/system/${SYSTEMD_SERVICE_NAME}"
  info "Installing systemd unit: ${unit_path}"
  generate_systemd_unit > "${unit_path}"
  chmod 0644 "${unit_path}"

  # runtime env file
  cat > "${CONFIG_DIR}/runtime.env" <<EOF
# exported at service start
${ENV_EXPORTS}
EOF
  chown "$APP_USER:$APP_GROUP" "${CONFIG_DIR}/runtime.env"
  chmod 0640 "${CONFIG_DIR}/runtime.env"

  systemctl daemon-reload
  systemctl enable "${SYSTEMD_SERVICE_NAME}"
  info "Systemd unit installed and enabled: ${SYSTEMD_SERVICE_NAME}"
}

uninstall_systemd() {
  systemd_available || die "systemd not available"
  if systemctl is-enabled --quiet "${SYSTEMD_SERVICE_NAME}"; then
    systemctl disable "${SYSTEMD_SERVICE_NAME}" || true
  fi
  systemctl stop "${SYSTEMD_SERVICE_NAME}" || true
  rm -f "/etc/systemd/system/${SYSTEMD_SERVICE_NAME}"
  systemctl daemon-reload
  info "Systemd unit removed: ${SYSTEMD_SERVICE_NAME}"
}

# ========== Health Checks ==========
check_health_once() {
  # 1) Command check
  if [[ -n "${HEALTH_CMD:-}" ]]; then
    if bash -lc "$HEALTH_CMD"; then
      return 0
    fi
  fi
  # 2) HTTP check
  if [[ -n "${HEALTH_HTTP_URL:-}" ]]; then
    if curl -fsS -m 2 "$HEALTH_HTTP_URL" >/dev/null; then
      return 0
    fi
  fi
  # 3) TCP check
  if [[ -n "${HEALTH_TCP_ADDR:-}" ]]; then
    # format host:port
    if timeout 2 bash -lc ">/dev/tcp/${HEALTH_TCP_ADDR/:/\/}"; then
      return 0
    fi
  fi
  return 1
}

wait_for_health() {
  local end=$(( $(date +%s) + HEALTH_TIMEOUT_SEC ))
  info "Waiting for health (timeout: ${HEALTH_TIMEOUT_SEC}s, interval: ${HEALTH_INTERVAL_SEC}s)"
  while (( $(date +%s) < end )); do
    if check_health_once; then
      info "Node is healthy"
      return 0
    fi
    sleep "${HEALTH_INTERVAL_SEC}"
  done
  die "Health check timed out"
}

# ========== Start/Stop/Status/Logs ==========
pid_file() {
  echo "${RUN_DIR}/${APP_NAME}.pid"
}

is_running() {
  local pf; pf="$(pid_file)"
  if [[ -f "$pf" ]]; then
    local p; p="$(cat "$pf" || true)"
    [[ -n "$p" ]] && kill -0 "$p" 2>/dev/null
    return $?
  fi
  return 1
}

start_foreground() {
  ensure_dirs
  ensure_user_group
  ulimit -n "${ULIMIT_NOFILE}" || warn "Failed to set ulimit -n ${ULIMIT_NOFILE}"

  # Prepare env exports file (non-systemd path)
  local envfile="${CONFIG_DIR}/runtime.env"
  echo "${ENV_EXPORTS}" > "${envfile}"
  chown "$APP_USER:$APP_GROUP" "${envfile}" || true
  chmod 0640 "${envfile}" || true

  info "Starting ${APP_NAME} (foreground)"
  # shellcheck disable=SC2086
  bash -lc "${ENV_EXPORTS} exec ${BIN_DIR}/${BINARY_NAME} ${EXEC_OPTS} --data-dir=\"${DATA_DIR}\" --config=\"${CONFIG_DIR}\""
}

start_background() {
  ensure_dirs
  ensure_user_group
  ulimit -n "${ULIMIT_NOFILE}" || warn "Failed to set ulimit -n ${ULIMIT_NOFILE}"

  info "Starting ${APP_NAME} (daemon)"
  # Redirect stdout/stderr
  : > "${STDOUT_LOG_FILE}"; : > "${STDERR_LOG_FILE}"
  chown "$APP_USER:$APP_GROUP" "${STDOUT_LOG_FILE}" "${STDERR_LOG_FILE}" || true
  chmod 0640 "${STDOUT_LOG_FILE}" "${STDERR_LOG_FILE}" || true

  # shellcheck disable=SC2086
  nohup bash -lc "${ENV_EXPORTS} exec ${BIN_DIR}/${BINARY_NAME} ${EXEC_OPTS} --data-dir=\"${DATA_DIR}\" --config=\"${CONFIG_DIR}\"" \
    >> "${STDOUT_LOG_FILE}" 2>> "${STDERR_LOG_FILE}" &
  echo $! > "$(pid_file)"
  disown || true
  info "Started with PID $(cat "$(pid_file)")"
}

stop_process() {
  if systemd_available && systemctl is-active --quiet "${SYSTEMD_SERVICE_NAME}"; then
    info "Stopping via systemd: ${SYSTEMD_SERVICE_NAME}"
    systemctl stop "${SYSTEMD_SERVICE_NAME}"
    return
  fi

  if is_running; then
    local p; p="$(cat "$(pid_file)")"
    info "Stopping PID ${p}"
    kill "$p" || true
    local t=0
    local timeout=30
    while kill -0 "$p" 2>/dev/null; do
      sleep 1; t=$((t+1))
      if (( t >= timeout )); then
        warn "Force killing PID ${p}"
        kill -9 "$p" || true
        break
      fi
    done
    rm -f "$(pid_file)"
    info "Stopped"
  else
    warn "Not running"
  fi
}

status_process() {
  if systemd_available && systemctl status "${SYSTEMD_SERVICE_NAME}" >/dev/null 2>&1; then
    systemctl --no-pager status "${SYSTEMD_SERVICE_NAME}" || true
    return
  fi

  if is_running; then
    info "${APP_NAME} is running (PID $(cat "$(pid_file)"))"
  else
    info "${APP_NAME} is not running"
  fi
}

logs_tail() {
  if systemd_available && systemctl status "${SYSTEMD_SERVICE_NAME}" >/dev/null 2>&1; then
    journalctl -u "${SYSTEMD_SERVICE_NAME}" -f -n 200 --output=cat
  else
    tail -n 200 -F "${STDOUT_LOG_FILE}" "${STDERR_LOG_FILE}"
  fi
}

# ========== Logrotate ==========
install_logrotate() {
  [[ "${ENABLE_LOGROTATE}" == "true" ]] || { info "Logrotate disabled"; return; }
  cat > "${LOGROTATE_CONF}" <<EOF
${STDOUT_LOG_FILE} ${STDERR_LOG_FILE} {
  size ${LOG_MAX_SIZE}
  rotate ${LOG_ROTATE_COUNT}
  missingok
  notifempty
  compress
  delaycompress
  copytruncate
}
EOF
  info "Installed logrotate config at ${LOGROTATE_CONF}"
}

# ========== Backups / Prune ==========
backup_snapshot() {
  [[ "${ENABLE_BACKUP}" == "true" ]] || { warn "Backups disabled"; return 0; }
  ensure_dirs
  local ts; ts="$(date -u +%Y%m%dT%H%M%SZ)"
  local dest="${BACKUP_DIR}/snapshot-${ts}.tar.zst"
  require_cmd tar
  require_cmd zstd

  info "Creating backup: ${dest}"
  tar --use-compress-program zstd -cf "${dest}" -C "${DATA_DIR}" .
  chown "$APP_USER:$APP_GROUP" "${dest}" || true
  chmod 0640 "${dest}" || true

  # retention
  find "${BACKUP_DIR}" -type f -name 'snapshot-*.tar.zst' -printf '%T@ %p\n' \
    | sort -n | awk -v keep="${BACKUP_RETENTION}" 'NR<=NF-keep {print $2}' | xargs -r rm -f
  info "Backup complete"
}

prune_data() {
  # Placeholder: implement chain-specific pruning here
  warn "Prune is a placeholder. Implement chain-specific pruning logic as needed."
}

# ========== Show Config ==========
show_config() {
  cat <<EOF
APP_NAME=${APP_NAME}
APP_USER=${APP_USER}
APP_GROUP=${APP_GROUP}
BINARY_NAME=${BINARY_NAME}
BINARY_VERSION=${BINARY_VERSION}
DOWNLOAD_URL=${DOWNLOAD_URL}
CHECKSUM_SHA256=${CHECKSUM_SHA256}
BIN_DIR=${BIN_DIR}
BASE_DIR=${BASE_DIR}
DATA_DIR=${DATA_DIR}
CONFIG_DIR=${CONFIG_DIR}
LOG_DIR=${LOG_DIR}
RUN_DIR=${RUN_DIR}
BACKUP_DIR=${BACKUP_DIR}
ULIMIT_NOFILE=${ULIMIT_NOFILE}
EXEC_OPTS=${EXEC_OPTS}
ENV_EXPORTS=${ENV_EXPORTS}
HEALTH_CMD=${HEALTH_CMD}
HEALTH_HTTP_URL=${HEALTH_HTTP_URL}
HEALTH_TCP_ADDR=${HEALTH_TCP_ADDR}
HEALTH_TIMEOUT_SEC=${HEALTH_TIMEOUT_SEC}
HEALTH_INTERVAL_SEC=${HEALTH_INTERVAL_SEC}
SYSTEMD_SERVICE_NAME=${SYSTEMD_SERVICE_NAME}
SYSTEMD_AFTER=${SYSTEMD_AFTER}
SYSTEMD_WANTS=${SYSTEMD_WANTS}
SYSTEMD_LIMIT_NOFILE=${SYSTEMD_LIMIT_NOFILE}
SYSTEMD_RESTART=${SYSTEMD_RESTART}
SYSTEMD_RESTART_SEC=${SYSTEMD_RESTART_SEC}
SYSTEMD_USER=${SYSTEMD_USER}
STDOUT_LOG_FILE=${STDOUT_LOG_FILE}
STDERR_LOG_FILE=${STDERR_LOG_FILE}
ENABLE_LOGROTATE=${ENABLE_LOGROTATE}
LOGROTATE_CONF=${LOGROTATE_CONF}
LOG_MAX_SIZE=${LOG_MAX_SIZE}
LOG_ROTATE_COUNT=${LOG_ROTATE_COUNT}
ENABLE_BACKUP=${ENABLE_BACKUP}
BACKUP_RETENTION=${BACKUP_RETENTION}
DOWNLOAD_TMP_DIR=${DOWNLOAD_TMP_DIR}
DOWNLOAD_MODE=${DOWNLOAD_MODE}
BINARY_SYMLINK=${BINARY_SYMLINK}
ENV_FILE=${ENV_FILE}
EOF
}

# ========== Main ==========
main() {
  parse_args "$@"
  load_env
  check_prereqs

  case "${COMMAND:-help}" in
    install-binary)
      if [[ "$DOWNLOAD_MODE" == "force" || "$FORCE" == true ]]; then
        info "Force enabled"
      fi
      download_and_install_binary
      install_logrotate
      ;;
    install-systemd)
      install_systemd
      ;;
    uninstall-systemd)
      uninstall_systemd
      ;;
    start)
      if systemd_available && systemctl status "${SYSTEMD_SERVICE_NAME}" >/dev/null 2>&1; then
        info "Starting via systemd"
        systemctl start "${SYSTEMD_SERVICE_NAME}"
      else
        if [[ "$DAEMON" == true ]]; then
          start_background
        else
          start_foreground
        fi
      fi
      ;;
    stop)
      stop_process
      ;;
    restart)
      if systemd_available && systemctl status "${SYSTEMD_SERVICE_NAME}" >/dev/null 2>&1; then
        systemctl restart "${SYSTEMD_SERVICE_NAME}"
      else
        stop_process
        start_background
      fi
      ;;
    status)
      status_process
      ;;
    logs)
      logs_tail
      ;;
    health)
      wait_for_health
      ;;
    backup)
      backup_snapshot
      ;;
    prune)
      prune_data
      ;;
    show-config)
      show_config
      ;;
    help|*)
      usage
      ;;
  esac
}

main "$@"
