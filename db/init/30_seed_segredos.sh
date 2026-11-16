#!/bin/sh
# Carrega operadores (hash de senha) e crachás autorizados (pseudônimos HMAC),
# gerados por scripts/gen-secrets.sh e montados em /seed-secret (fora do Git).
set -e
for f in /seed-secret/*.sql; do
  [ -f "$f" ] && psql -v ON_ERROR_STOP=1 -U "$POSTGRES_USER" -d "$POSTGRES_DB" -f "$f"
done
