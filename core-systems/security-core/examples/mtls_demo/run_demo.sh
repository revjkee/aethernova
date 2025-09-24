#!/usr/bin/env bash
# examples/mtls_demo/run_demo.sh
# Промышленный демонстрационный скрипт mTLS + CRL:
# - Генерирует Root CA и Intermediate CA
# - Выпускает server/client сертификаты (SAN для localhost/127.0.0.1)
# - Настраивает CRL и CDP (file://)
# - Запускает OpenSSL s_server с обязательной верификацией клиентского сертификата
# - Проверяет успешное mTLS подключение (curl/openssl s_client)
# - Отзывает клиентский сертификат, регенерирует CRL и демонстрирует отвергание через openssl verify -crl_check
# - Опционально демонстрирует проверку revocation вашим security-core CLI
set -Eeuo pipefail

# -------------------------------
# Параметры
# -------------------------------
PORT="${PORT:-8443}"
BASE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
WORK_DIR="${WORK_DIR:-"$BASE_DIR/.work"}"
OPENSSL_BIN="${OPENSSL_BIN:-openssl}"
CURL_BIN="${CURL_BIN:-curl}"       # опционально
CLI_BIN="${CLI_BIN:-security-core}" # опционально (ваш CLI)

# -------------------------------
# Примитивы логирования
# -------------------------------
log() { printf '%s %s\n' "$(date -u +'%Y-%m-%dT%H:%M:%SZ')" "$*"; }
step() { log "==> $*"; }
die() { log "ERROR: $*"; exit 1; }

# -------------------------------
# Проверка зависимостей
# -------------------------------
command -v "$OPENSSL_BIN" >/dev/null 2>&1 || die "openssl не найден"
HAVE_CURL=0; command -v "$CURL_BIN" >/dev/null 2>&1 && HAVE_CURL=1
HAVE_CLI=0; command -v "$CLI_BIN" >/dev/null 2>&1 && HAVE_CLI=1

# -------------------------------
# Каталоги и переменные
# -------------------------------
ROOT_DIR="$WORK_DIR/root"
INT_DIR="$WORK_DIR/intermediate"
SRV_DIR="$WORK_DIR/server"
CLI_DIR="$WORK_DIR/client"
CRL_DIR="$INT_DIR/crl"
CRL_PEM="$CRL_DIR/intermediate.crl.pem"
CRL_URI="file://$CRL_PEM"

# Очистка и создание
cleanup() {
  if [[ -f "$WORK_DIR/s_server.pid" ]]; then
    local pid; pid="$(cat "$WORK_DIR/s_server.pid" || true)"
    if [[ -n "${pid:-}" ]] && ps -p "$pid" >/dev/null 2>&1; then
      kill "$pid" || true
      sleep 0.2 || true
    fi
    rm -f "$WORK_DIR/s_server.pid"
  fi
}
trap cleanup EXIT

mkdir -p "$WORK_DIR"
rm -rf "$WORK_DIR"/{root,intermediate,server,client} || true

# Root CA dirs
mkdir -p "$ROOT_DIR"/{certs,crl,newcerts,private}
chmod 700 "$ROOT_DIR/private"
touch "$ROOT_DIR/index.txt"
echo 1000 > "$ROOT_DIR/serial"

# Intermediate CA dirs
mkdir -p "$INT_DIR"/{certs,crl,newcerts,private,csr}
chmod 700 "$INT_DIR/private"
touch "$INT_DIR/index.txt"
echo 1000 > "$INT_DIR/serial"
echo 1000 > "$INT_DIR/crlnumber"

# Server/Client dirs
mkdir -p "$SRV_DIR" "$CLI_DIR"

# -------------------------------
# OpenSSL конфиги (Root & Intermediate & CSR)
# -------------------------------

# Root OpenSSL config
cat > "$ROOT_DIR/openssl.cnf" <<EOF
[ ca ]
default_ca = CA_default

[ CA_default ]
dir               = $ROOT_DIR
database          = \$dir/index.txt
unique_subject    = no
new_certs_dir     = \$dir/newcerts
certificate       = \$dir/certs/ca.crt
private_key       = \$dir/private/ca.key
serial            = \$dir/serial
default_md        = sha256
default_days      = 3650
policy            = policy_loose
x509_extensions   = v3_ca
copy_extensions   = copy
name_opt          = ca_default
cert_opt          = ca_default
crlnumber         = \$dir/crlnumber
crl               = \$dir/crl/root.crl.pem
crl_extensions    = crl_ext
default_crl_days  = 30

[ policy_loose ]
countryName             = optional
stateOrProvinceName     = optional
localityName            = optional
organizationName        = optional
organizationalUnitName  = optional
commonName              = supplied
emailAddress            = optional

[ req ]
default_bits        = 4096
prompt              = no
distinguished_name  = req_dn
x509_extensions     = v3_ca

[ req_dn ]
C  = SE
O  = Aethernova Demo
CN = Demo Root CA

[ v3_ca ]
subjectKeyIdentifier    = hash
authorityKeyIdentifier  = keyid:always,issuer
basicConstraints        = critical, CA:true, pathlen:1
keyUsage                = critical, keyCertSign, cRLSign

[ v3_intermediate_ca ]
subjectKeyIdentifier    = hash
authorityKeyIdentifier  = keyid:always,issuer
basicConstraints        = critical, CA:true, pathlen:0
keyUsage                = critical, keyCertSign, cRLSign

[ crl_ext ]
authorityKeyIdentifier  = keyid:always
EOF

# Intermediate OpenSSL config
cat > "$INT_DIR/openssl.cnf" <<EOF
[ ca ]
default_ca = CA_default

[ CA_default ]
dir               = $INT_DIR
database          = \$dir/index.txt
unique_subject    = no
new_certs_dir     = \$dir/newcerts
certificate       = \$dir/certs/ca.crt
private_key       = \$dir/private/ca.key
serial            = \$dir/serial
default_md        = sha256
default_days      = 1825
policy            = policy_loose
copy_extensions   = copy
name_opt          = ca_default
cert_opt          = ca_default
crlnumber         = \$dir/crlnumber
crl               = $CRL_PEM
crl_extensions    = crl_ext
default_crl_days  = 14
x509_extensions   = usr_cert

[ policy_loose ]
countryName             = optional
stateOrProvinceName     = optional
localityName            = optional
organizationName        = optional
organizationalUnitName  = optional
commonName              = supplied
emailAddress            = optional

[ req ]
default_bits        = 4096
prompt              = no
distinguished_name  = req_dn

[ req_dn ]
C  = SE
O  = Aethernova Demo
CN = Demo Intermediate CA

[ usr_cert ]
basicConstraints        = CA:false
authorityKeyIdentifier  = keyid,issuer
subjectKeyIdentifier    = hash
keyUsage                = critical, digitalSignature, keyEncipherment
extendedKeyUsage        = clientAuth, serverAuth
crlDistributionPoints   = URI:$CRL_URI

[ server_cert ]
basicConstraints        = CA:false
authorityKeyIdentifier  = keyid,issuer
subjectKeyIdentifier    = hash
keyUsage                = critical, digitalSignature, keyEncipherment
extendedKeyUsage        = serverAuth
crlDistributionPoints   = URI:$CRL_URI

[ client_cert ]
basicConstraints        = CA:false
authorityKeyIdentifier  = keyid,issuer
subjectKeyIdentifier    = hash
keyUsage                = critical, digitalSignature, keyEncipherment
extendedKeyUsage        = clientAuth
crlDistributionPoints   = URI:$CRL_URI

[ v3_intermediate_ca ]
subjectKeyIdentifier    = hash
authorityKeyIdentifier  = keyid:always,issuer
basicConstraints        = critical, CA:true, pathlen:0
keyUsage                = critical, keyCertSign, cRLSign

[ crl_ext ]
authorityKeyIdentifier  = keyid:always
EOF

# Server CSR config (с SAN)
cat > "$SRV_DIR/req.cnf" <<'EOF'
[ req ]
default_bits        = 2048
prompt              = no
default_md          = sha256
distinguished_name  = dn
req_extensions      = v3_req

[ dn ]
C  = SE
O  = Aethernova Demo
CN = localhost

[ v3_req ]
subjectAltName      = @alt_names
keyUsage            = critical, digitalSignature, keyEncipherment
extendedKeyUsage    = serverAuth

[ alt_names ]
DNS.1 = localhost
IP.1  = 127.0.0.1
EOF

# Client CSR config
cat > "$CLI_DIR/req.cnf" <<'EOF'
[ req ]
default_bits        = 2048
prompt              = no
default_md          = sha256
distinguished_name  = dn

[ dn ]
C  = SE
O  = Aethernova Demo
CN = demo-client
EOF

# -------------------------------
# Генерация Root CA
# -------------------------------
step "Генерация Root CA"
$OPENSSL_BIN genrsa -out "$ROOT_DIR/private/ca.key" 4096 >/dev/null 2>&1
$OPENSSL_BIN req -config "$ROOT_DIR/openssl.cnf" -key "$ROOT_DIR/private/ca.key" -new -x509 -days 3650 -sha256 -out "$ROOT_DIR/certs/ca.crt" >/dev/null 2>&1

# -------------------------------
# Генерация Intermediate CA (подписано Root CA)
# -------------------------------
step "Генерация Intermediate CA"
$OPENSSL_BIN genrsa -out "$INT_DIR/private/ca.key" 4096 >/dev/null 2>&1
$OPENSSL_BIN req -config "$INT_DIR/openssl.cnf" -key "$INT_DIR/private/ca.key" -new -sha256 -out "$INT_DIR/csr/ca.csr" >/dev/null 2>&1
$OPENSSL_BIN ca -batch -config "$ROOT_DIR/openssl.cnf" -extensions v3_intermediate_ca -days 1825 -notext -md sha256 -in "$INT_DIR/csr/ca.csr" -out "$INT_DIR/certs/ca.crt" >/dev/null 2>&1
cat "$INT_DIR/certs/ca.crt" "$ROOT_DIR/certs/ca.crt" > "$INT_DIR/certs/chain.crt"

# -------------------------------
# Генерация Server cert
# -------------------------------
step "Выпуск server сертификата (SAN localhost, 127.0.0.1)"
$OPENSSL_BIN req -new -nodes -newkey rsa:2048 -keyout "$SRV_DIR/server.key" -out "$SRV_DIR/server.csr" -config "$SRV_DIR/req.cnf" >/dev/null 2>&1
# Копируем SAN из CSR (copy_extensions=copy) и задаём профиль server_cert
$OPENSSL_BIN ca -batch -config "$INT_DIR/openssl.cnf" -extensions server_cert -days 825 -notext -md sha256 -in "$SRV_DIR/server.csr" -out "$SRV_DIR/server.crt" >/dev/null 2>&1
# fullchain для сервера
cat "$SRV_DIR/server.crt" "$INT_DIR/certs/ca.crt" > "$SRV_DIR/server.fullchain.crt"

# -------------------------------
# Генерация Client cert
# -------------------------------
step "Выпуск client сертификата"
$OPENSSL_BIN req -new -nodes -newkey rsa:2048 -keyout "$CLI_DIR/client.key" -out "$CLI_DIR/client.csr" -config "$CLI_DIR/req.cnf" >/dev/null 2>&1
$OPENSSL_BIN ca -batch -config "$INT_DIR/openssl.cnf" -extensions client_cert -days 825 -notext -md sha256 -in "$CLI_DIR/client.csr" -out "$CLI_DIR/client.crt" >/dev/null 2>&1

# -------------------------------
# Генерация начального CRL (пустой)
# -------------------------------
step "Генерация начального CRL (empty)"
$OPENSSL_BIN ca -config "$INT_DIR/openssl.cnf" -gencrl -out "$CRL_PEM" >/dev/null 2>&1

# -------------------------------
# Запуск OpenSSL s_server (mTLS: требуем клиентский сертификат)
# -------------------------------
step "Старт OpenSSL s_server на :$PORT (mTLS: verify client cert)"
# Верифицируем клиентов по Intermediate CA
$OPENSSL_BIN s_server \
  -accept "$PORT" \
  -www \
  -cert "$SRV_DIR/server.fullchain.crt" \
  -key "$SRV_DIR/server.key" \
  -CAfile "$INT_DIR/certs/ca.crt" \
  -verify 1 \
  -verify_return_error \
  -quiet \
  >"$WORK_DIR/s_server.log" 2>&1 &
echo $! > "$WORK_DIR/s_server.pid"
sleep 0.5

# -------------------------------
# Проверка успешного mTLS‑подключения
# -------------------------------
step "Проверка подключения к серверу (mTLS)"
if [[ "$HAVE_CURL" -eq 1 ]]; then
  # Клиент доверяет Root CA, предъявляет client cert
  $CURL_BIN --silent --show-error --fail \
    --cacert "$ROOT_DIR/certs/ca.crt" \
    --cert "$CLI_DIR/client.crt" --key "$CLI_DIR/client.key" \
    "https://localhost:$PORT/" >/dev/null
  step "mTLS с curl: OK"
else
  step "curl не найден; используем openssl s_client"
  printf 'GET / HTTP/1.1\r\nHost: localhost\r\n\r\n' | \
    $OPENSSL_BIN s_client -quiet -verify_return_error \
      -CAfile "$ROOT_DIR/certs/ca.crt" \
      -cert "$CLI_DIR/client.crt" -key "$CLI_DIR/client.key" \
      -connect "localhost:$PORT" >/dev/null
  step "mTLS с s_client: OK"
fi

# -------------------------------
# Ревокация client сертификата и регенерация CRL
# -------------------------------
step "Отзыв client сертификата и регенерация CRL"
$OPENSSL_BIN ca -config "$INT_DIR/openssl.cnf" -revoke "$CLI_DIR/client.crt" >/dev/null 2>&1
$OPENSSL_BIN ca -config "$INT_DIR/openssl.cnf" -gencrl -out "$CRL_PEM" >/dev/null 2>&1

# -------------------------------
# Демонстрация отказа проверки через CRL (офлайн проверка)
# -------------------------------
step "Проверка revocation офлайн (openssl verify -crl_check): ожидается 'certificate revoked'"
set +e
VERIFY_OUT="$($OPENSSL_BIN verify -crl_check -CRLfile "$CRL_PEM" -CAfile "$INT_DIR/certs/ca.crt" "$CLI_DIR/client.crt" 2>&1)"
set -e
echo "$VERIFY_OUT"
if echo "$VERIFY_OUT" | grep -qi "revoked"; then
  step "Отзыв подтверждён через CRL"
else
  die "Не удалось подтвердить отзыв (ожидалось 'revoked')"
fi

# -------------------------------
# Опционально: проверка через security-core CLI (если доступен)
# -------------------------------
if [[ "$HAVE_CLI" -eq 1 ]]; then
  step "Проверка revocation через security-core CLI (использует CDP=file:// в сертификате)"
  # Для CLI требуется cert (end-entity) и issuer (Intermediate)
  $CLI_BIN pki crl check --cert "$CLI_DIR/client.crt" --issuer "$INT_DIR/certs/ca.crt" || true
else
  step "security-core CLI не найден; пропускаем CLI‑демонстрацию"
fi

step "Готово. Логи s_server: $WORK_DIR/s_server.log"
