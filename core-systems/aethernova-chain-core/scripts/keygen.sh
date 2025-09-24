#!/usr/bin/env bash
# shellcheck shell=bash
# Industrial key/secret generator for Aethernova
set -Eeuo pipefail

# --- Globals -----------------------------------------------------------------
SCRIPT_NAME="$(basename "${0}")"
UMASK_OLD=
TMPDIR_DEFAULT="${TMPDIR:-/tmp}"

# --- Logging -----------------------------------------------------------------
log()  { printf '[%s] %s\n' "INFO" "$*" >&2; }
warn() { printf '[%s] %s\n' "WARN" "$*" >&2; }
err()  { printf '[%s] %s\n' "ERROR" "$*" >&2; }
die()  { err "$*"; exit 1; }

# --- Cleanup -----------------------------------------------------------------
cleanup() { [ -n "${UMASK_OLD:-}" ] && umask "${UMASK_OLD}"; }
trap cleanup EXIT

# --- Helpers -----------------------------------------------------------------
need() { command -v "$1" >/dev/null 2>&1 || die "Required dependency not found: $1"; }

secure_umask() { UMASK_OLD="$(umask)"; umask 077; }

mkoutdir() {
  local d="$1"
  [ -z "${d}" ] && die "Output directory is empty"
  mkdir -p -- "${d}"
}

# join array by delimiter
join_by() { local IFS="$1"; shift; printf '%s' "$*"; }

# parse comma-separated SANs -> OpenSSL config section lines
render_san_lines() {
  # Input: DNS:example.com,IP:10.0.0.1,URI:https://a.example
  local list="$1"
  local out=()
  IFS=',' read -r -a items <<< "${list}"
  for it in "${items[@]}"; do
    it="${it#"${it%%[![:space:]]*}"}"; it="${it%"${it##*[![:space:]]}"}"
    [ -z "${it}" ] && continue
    case "${it}" in
      DNS:*) out+=("${it}");;
      IP:*)  out+=("${it}");;
      URI:*) out+=("${it}");;
      email:*) out+=("${it}");;
      *) die "Unsupported SAN element: '${it}'. Use DNS:, IP:, URI:, email:";;
    esac
  done
  if [ "${#out[@]}" -gt 0 ]; then
    printf 'subjectAltName=%s\n' "$(join_by , "${out[@]}")"
  fi
}

openssl_supports_addext() {
  openssl req -help 2>&1 | grep -q -- '-addext' || return 1
}

random_bytes() {
  # args: <bytes> <base64|hex>
  local bytes="$1" fmt="${2:-base64}"
  need openssl
  case "${fmt}" in
    base64) openssl rand -base64 "${bytes}";;  # CSPRNG per docs
    hex)    openssl rand -hex "${bytes}";;
    *) die "Unsupported format: ${fmt}";;
  esac
}

fingerprint_ssh() { need ssh-keygen; ssh-keygen -lf "$1"; }

# --- Usage -------------------------------------------------------------------
usage() {
cat >&2 <<'EOF'
Usage:
  keygen.sh ssh [--type ed25519|rsa] [--bits 4096] [--comment "user@host"] [--out DIR] [--file NAME] [--passfile FILE] [--no-agent]
  keygen.sh tls selfsigned [--algo ec|rsa] [--curve P-256|P-384] [--bits 2048] [--cn "example.com"] [--san "DNS:example.com,IP:1.2.3.4"] [--days N] [--out DIR] [--name BASENAME] [--passfile FILE]
  keygen.sh tls csr        [--algo ec|rsa] [--curve P-256|P-384] [--bits 2048] [--cn "..."] [--san "..."] [--out DIR] [--name BASENAME] [--passfile FILE]
  keygen.sh jwt secret [--bytes 32] [--format base64|hex] [--out FILE]
  keygen.sh random   [--bytes N] [--format base64|hex]
  keygen.sh age      [--out DIR] [--name BASENAME]
  keygen.sh gpg quick --uid "Name <email>" [--expire 1y] [--algo default]

Notes:
  - Secrets and private keys are written with umask 077.
  - Passphrases (if provided) are read from --passfile to avoid TTY echo.

EOF
}

# --- Subcommands --------------------------------------------------------------
cmd_ssh() {
  need ssh-keygen
  secure_umask

  local type="ed25519" bits="" comment="${USER-}@${HOSTNAME-}" out="." file="id_${type}" passfile="" add_agent=1
  while [ $# -gt 0 ]; do
    case "$1" in
      --type) type="$2"; shift 2;;
      --bits) bits="$2"; shift 2;;
      --comment) comment="$2"; shift 2;;
      --out) out="$2"; shift 2;;
      --file) file="$2"; shift 2;;
      --passfile) passfile="$2"; shift 2;;
      --no-agent) add_agent=0; shift 1;;
      *) die "Unknown ssh option: $1";;
    esac
  done
  mkoutdir "${out}"
  local keypath="${out%/}/${file}"

  local -a args=(-t "${type}" -C "${comment}" -f "${keypath}")
  [ -n "${bits}" ] && args+=(-b "${bits}")
  if [ -n "${passfile}" ]; then
    [ -f "${passfile}" ] || die "Passfile not found: ${passfile}"
    args+=(-N "$(cat "${passfile}")")
  else
    args+=(-N "")  # empty pass by default; adjust with --passfile
  fi

  ssh-keygen "${args[@]}"

  chmod 600 -- "${keypath}"
  [ -f "${keypath}.pub" ] && chmod 644 -- "${keypath}.pub"
  log "SSH key generated: ${keypath}"
  fingerprint_ssh "${keypath}.pub" || true

  if [ "${add_agent}" -eq 1 ] && command -v ssh-add >/dev/null 2>&1; then
    ssh-add "${keypath}" >/dev/null 2>&1 || warn "ssh-add failed (agent not running?)"
  fi
}

_make_openssl_key() {
  # args: algo(ec|rsa) curve bits keyout passfile
  local algo="$1" curve="$2" bits="$3" keyout="$4" passfile="${5:-}"
  case "${algo}" in
    ec)
      local -a ecopts=(-algorithm EC -pkeyopt "ec_paramgen_curve:${curve}" -pkeyopt ec_param_enc:named_curve)
      if [ -n "${passfile}" ]; then
        openssl genpkey "${ecopts[@]}" -aes-256-cbc -pass file:"${passfile}" -out "${keyout}"
      else
        openssl genpkey "${ecopts[@]}" -out "${keyout}"
      fi
      ;;
    rsa)
      local -a rsaopts=(-algorithm RSA -pkeyopt "rsa_keygen_bits:${bits:-2048}")
      if [ -n "${passfile}" ]; then
        openssl genpkey "${rsaopts[@]}" -aes-256-cbc -pass file:"${passfile}" -out "${keyout}"
      else
        openssl genpkey "${rsaopts[@]}" -out "${keyout}"
      fi
      ;;
    *) die "Unsupported algo: ${algo}";;
  esac
  chmod 600 -- "${keyout}"
}

_make_openssl_req() {
  # args: key path, subj, san, out csrpath, passfile
  local key="$1" subj="$2" san="$3" csr="$4" passfile="${5:-}"
  if [ -n "${san}" ] && openssl_supports_addext; then
    if [ -n "${passfile}" ]; then
      openssl req -new -key "${key}" -passin file:"${passfile}" -subj "${subj}" \
        -addext "$(render_san_lines "${san}")" -out "${csr}"
    else
      openssl req -new -key "${key}" -subj "${subj}" \
        -addext "$(render_san_lines "${san}")" -out "${csr}"
    fi
  else
    # Portable SAN via temp config (works on OpenSSL 1.0.2+)
    local cfg; cfg="$(mktemp "${TMPDIR_DEFAULT}/keygen-req-XXXX.cnf")"
    {
      printf "[req]\ndistinguished_name=dn\nreq_extensions=req_ext\nprompt=no\n"
      printf "[dn]\nCN=%s\n" "${subj#*/CN=}"
      printf "[req_ext]\n"
      [ -n "${san}" ] && render_san_lines "${san}"
    } > "${cfg}"
    if [ -n "${passfile}" ]; then
      openssl req -new -key "${key}" -passin file:"${passfile}" -subj "${subj}" -config "${cfg}" -extensions req_ext -out "${csr}"
    else
      openssl req -new -key "${key}" -subj "${subj}" -config "${cfg}" -extensions req_ext -out "${csr}"
    fi
    rm -f -- "${cfg}"
  fi
}

cmd_tls_selfsigned() {
  need openssl
  secure_umask
  local algo="ec" curve="P-256" bits="2048" cn="" san="" days="365" out="." name="tls"
  local passfile=""
  while [ $# -gt 0 ]; do
    case "$1" in
      --algo) algo="$2"; shift 2;;
      --curve) curve="$2"; shift 2;;
      --bits) bits="$2"; shift 2;;
      --cn) cn="$2"; shift 2;;
      --san) san="$2"; shift 2;;
      --days) days="$2"; shift 2;;
      --out) out="$2"; shift 2;;
      --name) name="$2"; shift 2;;
      --passfile) passfile="$2"; shift 2;;
      *) die "Unknown tls selfsigned option: $1";;
    esac
  done
  [ -n "${cn}" ] || die "--cn is required"
  mkoutdir "${out}"

  local key="${out%/}/${name}.key.pem"
  local crt="${out%/}/${name}.crt.pem"

  _make_openssl_key "${algo}" "${curve}" "${bits}" "${key}" "${passfile}"

  local subj="/CN=${cn}"
  # Create self-signed cert with SAN support
  if [ -n "${san}" ] && openssl_supports_addext; then
    if [ -n "${passfile}" ]; then
      openssl req -x509 -new -key "${key}" -passin file:"${passfile}" -days "${days}" -subj "${subj}" \
        -addext "$(render_san_lines "${san}")" -out "${crt}"
    else
      openssl req -x509 -new -key "${key}" -days "${days}" -subj "${subj}" \
        -addext "$(render_san_lines "${san}")" -out "${crt}"
    fi
  else
    # via temp config
    local cfg; cfg="$(mktemp "${TMPDIR_DEFAULT}/keygen-x509-XXXX.cnf")"
    {
      printf "[req]\ndistinguished_name=dn\nx509_extensions=v3_req\nprompt=no\n"
      printf "[dn]\nCN=%s\n" "${cn}"
      printf "[v3_req]\n"
      [ -n "${san}" ] && render_san_lines "${san}"
    } > "${cfg}"
    if [ -n "${passfile}" ]; then
      openssl req -x509 -new -key "${key}" -passin file:"${passfile}" -days "${days}" -subj "${subj}" \
        -config "${cfg}" -extensions v3_req -out "${crt}"
    else
      openssl req -x509 -new -key "${key}" -days "${days}" -subj "${subj}" \
        -config "${cfg}" -extensions v3_req -out "${crt}"
    fi
    rm -f -- "${cfg}"
  fi

  chmod 644 -- "${crt}"
  log "TLS self-signed certificate created: ${crt}"
  openssl x509 -noout -fingerprint -sha256 -in "${crt}" || true
}

cmd_tls_csr() {
  need openssl
  secure_umask
  local algo="ec" curve="P-256" bits="2048" cn="" san="" out="." name="tls" passfile=""
  while [ $# -gt 0 ]; do
    case "$1" in
      --algo) algo="$2"; shift 2;;
      --curve) curve="$2"; shift 2;;
      --bits) bits="$2"; shift 2;;
      --cn) cn="$2"; shift 2;;
      --san) san="$2"; shift 2;;
      --out) out="$2"; shift 2;;
      --name) name="$2"; shift 2;;
      --passfile) passfile="$2"; shift 2;;
      *) die "Unknown tls csr option: $1";;
    esac
  done
  [ -n "${cn}" ] || die "--cn is required"
  mkoutdir "${out}"
  local key="${out%/}/${name}.key.pem"
  local csr="${out%/}/${name}.csr.pem"

  _make_openssl_key "${algo}" "${curve}" "${bits}" "${key}" "${passfile}"
  _make_openssl_req "${key}" "/CN=${cn}" "${san}" "${csr}" "${passfile}"

  chmod 644 -- "${csr}"
  log "CSR created: ${csr}"
}

cmd_jwt_secret() {
  need openssl
  local bytes=32 fmt="base64" outfile=""
  while [ $# -gt 0 ]; do
    case "$1" in
      --bytes) bytes="$2"; shift 2;;
      --format) fmt="$2"; shift 2;;
      --out) outfile="$2"; shift 2;;
      *) die "Unknown jwt option: $1";;
    esac
  done
  secure_umask
  local secret; secret="$(random_bytes "${bytes}" "${fmt}")"
  if [ -n "${outfile}" ]; then
    printf '%s\n' "${secret}" > "${outfile}"
    chmod 600 -- "${outfile}"
    log "JWT secret written to ${outfile}"
  else
    printf '%s\n' "${secret}"
  fi
}

cmd_random() {
  need openssl
  local bytes=32 fmt="base64"
  while [ $# -gt 0 ]; do
    case "$1" in
      --bytes) bytes="$2"; shift 2;;
      --format) fmt="$2"; shift 2;;
      *) die "Unknown random option: $1";;
    esac
  done
  secure_umask
  random_bytes "${bytes}" "${fmt}"
}

cmd_age() {
  need age-keygen
  secure_umask
  local out="." name="age"
  while [ $# -gt 0 ]; do
    case "$1" in
      --out) out="$2"; shift 2;;
      --name) name="$2"; shift 2;;
      *) die "Unknown age option: $1";;
    esac
  done
  mkoutdir "${out}"
  local id="${out%/}/${name}.agekey"
  local pub="${out%/}/${name}.agekey.pub"
  age-keygen -o "${id}"
  chmod 600 -- "${id}"
  age-keygen -y "${id}" > "${pub}"
  chmod 644 -- "${pub}"
  log "age identity: ${id}"
  log "age recipient: $(cat "${pub}")"
}

cmd_gpg_quick() {
  need gpg
  secure_umask
  local uid="" expire="1y" algo="default"
  while [ $# -gt 0 ]; do
    case "$1" in
      --uid) uid="$2"; shift 2;;
      --expire) expire="$2"; shift 2;;
      --algo) algo="$2"; shift 2;;
      *) die "Unknown gpg option: $1";;
    esac
  done
  [ -n "${uid}" ] || die "--uid is required (e.g. 'Alice Example <alice@example.com>')"
  # Non-interactive key generation
  gpg --batch --yes --quick-gen-key "${uid}" "${algo}" default "${expire}"
  log "GPG key created for: ${uid}"
}

# --- Dispatcher --------------------------------------------
