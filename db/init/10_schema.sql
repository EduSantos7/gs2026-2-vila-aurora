-- ===================================================================
-- Rede Vila Aurora - esquema do banco (laboratório)
-- ===================================================================
CREATE EXTENSION IF NOT EXISTS pgcrypto;

-- ---------- LEGADO: reproduz a base vulnerável do INC-VA-0712 ----------
CREATE SCHEMA legado;
CREATE TABLE legado.usuarios (
  id serial PRIMARY KEY, nome text, cpf text, telefone text, endereco text,
  funcao text, login text, senha text            -- senha em texto puro (falha proposital)
);
CREATE TABLE legado.acessos (
  id serial PRIMARY KEY, data_hora timestamptz, cracha text, espaco text, evento text
);

-- ---------- PESSOAL: dados pessoais isolados (painel NÃO tem acesso) ----------
CREATE SCHEMA pessoal;
CREATE TABLE pessoal.voluntarios (
  id serial PRIMARY KEY, nome text NOT NULL, funcao text, telefone text, espacos text
);

-- ---------- Operação ----------
CREATE TABLE operadores (
  login text PRIMARY KEY,
  senha_hash text NOT NULL,
  papel text NOT NULL CHECK (papel IN ('operador','tecnico','coordenacao','auditor')),
  espaco text,                                   -- operador vê só o próprio espaço
  ativo boolean NOT NULL DEFAULT true
);

CREATE TABLE telemetria (
  dispositivo_id text NOT NULL, seq bigint NOT NULL, msg_uuid uuid NOT NULL,
  ts_utc timestamptz NOT NULL, espaco text NOT NULL, tipo text NOT NULL,
  payload jsonb NOT NULL, recebido_em timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (dispositivo_id, seq)              -- ingestão idempotente
);
CREATE INDEX telemetria_ts ON telemetria (espaco, ts_utc DESC);

CREATE TABLE alarmes (
  origem text NOT NULL, seq bigint NOT NULL, msg_uuid uuid NOT NULL, ts_utc timestamptz NOT NULL,
  espaco text NOT NULL, dispositivo text, severidade text NOT NULL, mensagem text NOT NULL,
  recebido_em timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (origem, seq)
);

CREATE TABLE acessos (                           -- somente pseudônimo (HMAC) do crachá
  origem text NOT NULL, seq bigint NOT NULL, msg_uuid uuid NOT NULL, ts_utc timestamptz NOT NULL,
  espaco text NOT NULL, dispositivo text, cracha_pseudo text NOT NULL, evento text NOT NULL,
  PRIMARY KEY (origem, seq)
);

CREATE TABLE agenda_bomba (
  espaco text PRIMARY KEY,
  janelas jsonb NOT NULL,                        -- [{"inicio":"07:00","fim":"07:40"}]
  versao integer NOT NULL DEFAULT 1,
  atualizado_em timestamptz NOT NULL DEFAULT now()
);
CREATE FUNCTION agenda_versiona() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN NEW.versao := OLD.versao + 1; NEW.atualizado_em := now(); RETURN NEW; END $$;
CREATE TRIGGER agenda_versiona BEFORE UPDATE ON agenda_bomba
  FOR EACH ROW EXECUTE FUNCTION agenda_versiona();

CREATE TABLE crachas_autorizados (
  cracha_pseudo text NOT NULL, espaco text NOT NULL,
  atualizado_em timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (cracha_pseudo, espaco)
);

CREATE TABLE auditoria (
  id bigserial PRIMARY KEY, ts timestamptz NOT NULL DEFAULT now(),
  login text, papel text, acao text NOT NULL, detalhe jsonb
);

-- ---------- Visões expostas ao painel ----------
CREATE VIEW vw_acessos AS
  SELECT ts_utc AS data_hora, cracha_pseudo, espaco, dispositivo, evento FROM acessos;
CREATE VIEW vw_telemetria_ultima AS
  SELECT DISTINCT ON (dispositivo_id) dispositivo_id, espaco, tipo, ts_utc, payload
  FROM telemetria ORDER BY dispositivo_id, ts_utc DESC;
CREATE VIEW vw_alarmes AS
  SELECT ts_utc, espaco, dispositivo, severidade, mensagem FROM alarmes;

-- Login sem dar ao painel acesso à tabela operadores
CREATE FUNCTION autenticar(p_login text)
RETURNS TABLE (senha_hash text, papel text, espaco text)
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = public, pg_temp AS $$
  SELECT o.senha_hash, o.papel, o.espaco FROM operadores o WHERE o.login = p_login AND o.ativo
$$;

INSERT INTO agenda_bomba (espaco, janelas) VALUES
  ('esc', '[{"inicio":"07:00","fim":"07:40"},{"inicio":"16:00","fim":"16:40"}]');
