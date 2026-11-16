-- =========== MENOR PRIVILÉGIO ===========
REVOKE ALL ON SCHEMA legado, pessoal FROM PUBLIC;
REVOKE ALL ON ALL TABLES IN SCHEMA public FROM PUBLIC;
REVOKE EXECUTE ON FUNCTION autenticar(text) FROM PUBLIC;

-- Painel: só lê VISÕES, grava auditoria e chama autenticar(). Sem acesso a
-- operadores, pessoal.*, legado.* nem agenda_bomba.
GRANT USAGE ON SCHEMA public TO painel_app;
GRANT SELECT ON vw_acessos, vw_telemetria_ultima, vw_alarmes TO painel_app;
GRANT INSERT ON auditoria TO painel_app;
GRANT USAGE ON SEQUENCE auditoria_id_seq TO painel_app;
GRANT EXECUTE ON FUNCTION autenticar(text) TO painel_app;

-- Ingestão: só INSERT nas tabelas de dados de campo
GRANT USAGE ON SCHEMA public TO ingest_app;
GRANT INSERT ON telemetria, alarmes, acessos TO ingest_app;

-- Publicador de configuração: só leitura de agenda e crachás autorizados
GRANT USAGE ON SCHEMA public TO config_app;
GRANT SELECT ON agenda_bomba, crachas_autorizados TO config_app;
