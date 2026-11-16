#!/usr/bin/env bash
# Gera PKI, chaves e senhas do laboratório. Requer apenas Docker.
set -euo pipefail
cd "$(dirname "$0")/.."
ROOT_CA_DIR="${ROOT_CA_DIR:-$HOME/va-ca-raiz-offline}"
mkdir -p "$ROOT_CA_DIR" secrets && chmod 700 "$ROOT_CA_DIR" secrets
docker build -q -t va-tools tools >/dev/null
docker run --rm --user "$(id -u):$(id -g)" \
  -v "$PWD":/w -v "$ROOT_CA_DIR":/root-offline -e ROOT_DIR=/root-offline \
  va-tools python scripts/gen_secrets.py
echo "Lembrete: em produção a pasta $ROOT_CA_DIR iria para mídia criptografada no cofre."
