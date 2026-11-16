#!/bin/sh
# Cria os usuários de banco de MENOR PRIVILÉGIO. Senhas vêm de secrets/db.env.
set -e
psql -v ON_ERROR_STOP=1 -U "$POSTGRES_USER" -d "$POSTGRES_DB" <<SQL
-- não registrar estes comandos: o log gravaria as senhas em texto claro
SET log_statement = 'none';
CREATE ROLE painel_app LOGIN PASSWORD '$PAINEL_DB_PASS';
CREATE ROLE ingest_app LOGIN PASSWORD '$INGEST_DB_PASS';
CREATE ROLE config_app LOGIN PASSWORD '$CONFIG_DB_PASS';
REVOKE ALL ON DATABASE $POSTGRES_DB FROM PUBLIC;
GRANT CONNECT ON DATABASE $POSTGRES_DB TO painel_app, ingest_app, config_app;
SQL
