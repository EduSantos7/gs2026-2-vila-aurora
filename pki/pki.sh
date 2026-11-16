#!/usr/bin/env bash
# PKI da Rede Vila Aurora (laboratório): CA raiz OFFLINE -> CA intermediária -> certificados
# Uso (dentro do container de ferramentas):
#   pki.sh init                         cria raiz (se não existir) e intermediária
#   pki.sh issue <CN> client|server [SAN]
#   pki.sh revoke <CN>                  revoga e regenera a CRL
#   pki.sh crl                          regenera a CRL
set -euo pipefail
export PKI_DIR="${PKI_DIR:-/w/secrets/pki}"
ROOT_DIR="${ROOT_DIR:-/root-offline}"
CNF="$(dirname "$0")/openssl-int.cnf"
ORG="/O=Rede Vila Aurora (LAB)"
INT="$PKI_DIR/int"
export SAN="${SAN:-DNS:localhost}"

genkey() { openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out "$1" 2>/dev/null; chmod 644 "$1"; }

init() {
  mkdir -p "$ROOT_DIR" "$INT/newcerts" "$PKI_DIR/issued" "$PKI_DIR/crl"
  if [ ! -f "$ROOT_DIR/root.key" ]; then
    echo "[pki] criando CA RAIZ offline em $ROOT_DIR"
    genkey "$ROOT_DIR/root.key"; chmod 600 "$ROOT_DIR/root.key"
    openssl req -x509 -new -key "$ROOT_DIR/root.key" -sha256 -days 3650 \
      -subj "$ORG/CN=VA Root CA" \
      -addext "basicConstraints=critical,CA:TRUE" \
      -addext "keyUsage=critical,keyCertSign,cRLSign" -out "$ROOT_DIR/root.crt"
  fi
  cp "$ROOT_DIR/root.crt" "$PKI_DIR/root.crt"
  if [ ! -f "$INT/int.key" ]; then
    echo "[pki] criando CA INTERMEDIÁRIA"
    genkey "$INT/int.key"; chmod 600 "$INT/int.key"
    openssl req -new -key "$INT/int.key" -subj "$ORG/CN=VA Intermediate CA" -out "$INT/int.csr"
    printf "basicConstraints=critical,CA:TRUE,pathlen:0\nkeyUsage=critical,keyCertSign,cRLSign\nsubjectKeyIdentifier=hash\nauthorityKeyIdentifier=keyid\n" > "$INT/int.ext"
    openssl x509 -req -in "$INT/int.csr" -CA "$ROOT_DIR/root.crt" -CAkey "$ROOT_DIR/root.key" \
      -CAcreateserial -days 1825 -sha256 -extfile "$INT/int.ext" -out "$INT/int.crt" 2>/dev/null
    : > "$INT/index.txt"; echo 1000 > "$INT/serial"; echo 1000 > "$INT/crlnumber"
  fi
  cat "$INT/int.crt" "$PKI_DIR/root.crt" > "$PKI_DIR/ca-chain.crt"
  crl
}

issue() {
  local cn="$1" kind="$2"; export SAN="${3:-DNS:localhost}"
  local d="$PKI_DIR/issued/$cn"
  if [ -f "$d/$cn.crt" ] && openssl x509 -checkend 2592000 -noout -in "$d/$cn.crt" >/dev/null; then return 0; fi
  mkdir -p "$d"; genkey "$d/$cn.key"
  openssl req -new -key "$d/$cn.key" -subj "$ORG/CN=$cn" -out "$d/$cn.csr"
  openssl ca -batch -config "$CNF" -extensions "ext_$kind" -in "$d/$cn.csr" -out "$d/$cn.crt" -notext 2>/dev/null
  rm -f "$d/$cn.csr"
  echo "[pki] emitido $kind: $cn (serial $(openssl x509 -noout -serial -in "$d/$cn.crt" | cut -d= -f2))"
}

crl() {
  openssl ca -config "$CNF" -gencrl -out "$PKI_DIR/crl/crl.pem" 2>/dev/null
  chmod 644 "$PKI_DIR/crl/crl.pem"
  # distribui a CRL a todos os brokers
  find "$PKI_DIR" -path "*/broker/crl.pem" -exec cp "$PKI_DIR/crl/crl.pem" {} \; 2>/dev/null || true
}

revoke() {
  local cn="$1" crt="$PKI_DIR/issued/$1/$1.crt"
  [ -f "$crt" ] || { echo "certificado $cn não encontrado"; exit 1; }
  openssl ca -config "$CNF" -revoke "$crt" -crl_reason keyCompromise 2>/dev/null
  crl
  mkdir -p "$PKI_DIR/revoked"; mv "$PKI_DIR/issued/$cn" "$PKI_DIR/revoked/$cn-$(date +%s)"
  echo "[pki] REVOGADO: $cn (a cópia que está no dispositivo continua lá, mas será recusada pelo broker)"
}

case "${1:-}" in
  init) init ;;
  issue) issue "$2" "$3" "${4:-}" ;;
  revoke) revoke "$2" ;;
  crl) crl ;;
  *) echo "uso: $0 init|issue|revoke|crl"; exit 1 ;;
esac
