# Rede Vila Aurora - atalhos do laboratório (rodar no terminal do WSL/Ubuntu)
SITES ?= cc esc ubs hrt abr
CLOUD = docker compose -f infra/docker-compose.cloud.yml
EDGE  = docker compose -f infra/docker-compose.edge.yml
MODE ?= seguro

.PHONY: help secrets cloud legado edges edges-legado up down status logs-edge injetar revogar clean coletar coletar-rapido
help:
	@grep -E '^[a-z-]+:.*##' $(MAKEFILE_LIST) | sed 's/:.*##/\t/'

secrets: ## gera PKI, chaves e senhas em ./secrets (nada vai para o Git)
	./scripts/gen-secrets.sh

cloud: ## sobe a nuvem (banco, broker central, ingestão, painel corrigido + WAF)
	$(CLOUD) up -d --build

legado: ## sobe TAMBÉM o painel legado vulnerável (http://127.0.0.1:8081)
	$(CLOUD) --profile legado up -d --build

edges: ## sobe as 5 bordas (MODE=seguro|legado)
	@for s in $(SITES); do RULES_MODE=$(MODE) $(EDGE) -p edge-$$s --env-file infra/sites/$$s.env up -d --build; done

edges-legado: ## bordas sem regras locais (reproduz o INC-VA-0712)
	$(MAKE) edges MODE=legado

up: cloud edges ## nuvem + bordas

status: ## contêineres e consumo de memória
	@docker stats --no-stream --format 'table {{.Name}}\t{{.MemUsage}}\t{{.CPUPerc}}'

logs-edge: ## logs das regras de um espaço: make logs-edge S=ubs
	$(EDGE) -p edge-$(S) --env-file infra/sites/$(S).env logs -f edge-rules

injetar: ## falha simulada: make injetar S=ubs D=ubs-temp-01 V='{"temp_alvo":12}'
	$(EDGE) -p edge-$(S) --env-file infra/sites/$(S).env exec simulador python -m app.injetar $(D) '$(V)'

revogar: ## revoga certificado: make revogar CN=ubs-temp-01 S=ubs
	docker run --rm --user "$$(id -u):$$(id -g)" -v "$$PWD":/w va-tools bash pki/pki.sh revoke $(CN)
	$(EDGE) -p edge-$(S) --env-file infra/sites/$(S).env restart mosquitto

down: ## para tudo (mantém dados)
	@for s in $(SITES); do $(EDGE) -p edge-$$s --env-file infra/sites/$$s.env down; done
	$(CLOUD) --profile legado down

clean: ## APAGA volumes (banco, buffers). Segredos em ./secrets são mantidos
	@for s in $(SITES); do $(EDGE) -p edge-$$s --env-file infra/sites/$$s.env down -v; done
	$(CLOUD) --profile legado down -v

coletar: ## coleta resultados p/ o relatório (caos oficial de 45 min)
	python3 scripts/coletar_resultados.py

coletar-rapido: ## ensaio da coleta (caos de 3 min)
	python3 scripts/coletar_resultados.py --caos-min 3
