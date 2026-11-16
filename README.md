# Rede Vila Aurora – Resilient Community Infrastructure
**FIAP · Global Solution 2026.2 · Cybersecurity · Turma 4ECR · Grupo [G__]**
Eduardo Cicero dos Santos (RM 551415) · Leonardo Yukio Uliana Seno (RM 550648)

Protótipo funcional (entregável **E2**) de uma infraestrutura segura e resiliente para os cinco espaços da
Rede Comunitária Vila Aurora. Tudo roda em contêineres com **dados 100% sintéticos**.

> ⚠️ **Uso ético.** Este repositório contém, de propósito, um painel vulnerável (`cloud/painel-legado`) para
> reproduzir o incidente INC-VA-0712. Execute **somente** no seu laboratório isolado. Todas as portas são
> publicadas apenas em `127.0.0.1`. Testar sistemas de terceiros é crime (Lei 12.737/2012).

---

## 1. Arquitetura do protótipo

| Camada | O que roda | Onde |
|---|---|---|
| Campo | 15 dispositivos simulados, **cada um com seu próprio certificado X.509** | `edge/app/sim.py` |
| Borda (×5) | Mosquitto (mTLS + ACL + CRL), regras locais, buffer SQLite store-and-forward, painel local | `edge/` |
| Nuvem | PostgreSQL (menor privilégio), broker central, ingestão idempotente, publicador de configuração assinada (Ed25519), painel Flask, WAF ModSecurity/CRS | `cloud/` |
| Supervisão | Painel web acessível (`https://127.0.0.1:8443`) e painéis locais (`http://127.0.0.1:9001` a `9005`) | – |

Espaços e portas do painel local: `cc` Centro Comunitário (9001) · `esc` Escola (9002) · `ubs` UBS (9003) ·
`hrt` Horta (9004) · `abr` Abrigo (9005).

**Redes Docker = segmentação:** `iot` é interna (dispositivos só alcançam o broker da borda);
`dados` é interna (banco sem saída); `wan` simula a internet entre bordas e nuvem.
Desconectar uma borda da `wan` reproduz a queda da fibra.

## 2. Preparar o Windows (uma vez)

1. Instale o **Docker Desktop** com o backend **WSL 2** e uma distribuição **Ubuntu** (`wsl --install -d Ubuntu`).
2. Limite a memória do WSL (máquina de 16 GB). Crie `C:\Users\<seu-usuario>\.wslconfig`:
   ```ini
   [wsl2]
   memory=10GB
   processors=4
   swap=4GB
   ```
   Depois rode `wsl --shutdown` no PowerShell e reabra o Docker Desktop.
3. No Docker Desktop: *Settings → Resources → WSL integration* → habilite o Ubuntu.
4. **Abra o terminal do Ubuntu** (não o PowerShell) e instale o `make` e o `git`:
   ```bash
   sudo apt update && sudo apt install -y make git
   ```
5. **Clone dentro do sistema de arquivos do Linux** (`~/`), **nunca** em `/mnt/c/...`.
   Em `/mnt/c` as permissões de arquivo não funcionam e os scripts quebram.

Consumo medido da Parte 1: cerca de 1 GB de RAM com as 5 bordas. O SIEM (Parte 2) acrescenta de 3 a 4 GB.

## 3. Subir o ambiente

```bash
git clone <URL-DO-REPOSITORIO> ~/vila-aurora && cd ~/vila-aurora
make secrets        # PKI (CA raiz offline em ~/va-ca-raiz-offline), chaves, senhas
make cloud          # nuvem: banco, broker central, ingestão, painel corrigido + WAF
make edges          # 5 bordas com regras locais e dispositivos simulados
make status         # consumo de memória/CPU de cada contêiner
```

- Painel corrigido: **https://127.0.0.1:8443**. O certificado é da CA do laboratório; importe
  `secrets/pki/root.crt` no navegador ou aceite o aviso.
- Usuários e senhas: `secrets/usuarios-lab.txt` (gerados aleatoriamente; **não versionados**).
  Perfis: `op.ubs` e `op.esc` (operador), `tecnico1`, `tecnico2`, `coord1`, `auditor1`.
- Painéis locais: `http://127.0.0.1:9001` a `9005`. Continuam funcionando sem internet.

## 4. Roteiros de demonstração

### 4.1 SQL Injection antes e depois (RT-08)
```bash
make legado         # sobe o painel legado vulnerável em http://127.0.0.1:8081
```

| Teste | Legado (8081) | Corrigido (8443) |
|---|---|---|
| `'` no campo de busca | HTTP 500 com erro do PostgreSQL e a consulta SQL | HTTP 400 “Busca inválida” |
| `x' OR 1=1--` | todos os registros | HTTP 400 |
| `UNION SELECT` em `legado.usuarios` | extrai os 60 usuários (CPF, senha) | HTTP 400; e `painel_app` não tem permissão |
| `'; UPDATE agenda_bomba ...--` | altera a agenda da bomba (empilhado) | HTTP 400; e `painel_app` não pode escrever |

A automação dos testes (incluindo sqlmap contra o próprio laboratório) vem na Parte 3 (`tests/`).

### 4.2 Câmara fria sem nuvem (RT-02)
```bash
make injetar S=ubs D=ubs-temp-01 V='{"temp_alvo": 12}'
make logs-edge S=ubs          # após 5 min fora da faixa: alarme crítico + sirene + SMS (simulado)
make injetar S=ubs D=ubs-temp-01 V='{"temp_alvo": 5}'   # normaliza
```
Para demonstrar mais rápido: `TEMP_HOLD_S=30 SIM_SPEED=10 make edges`.

### 4.3 Ataque à agenda da bomba e intertravamento
No painel legado, a injeção altera `agenda_bomba` para funcionar o dia inteiro. O publicador assina a nova
agenda e a borda da Escola liga a bomba.
- `make edges-legado` (sem regras locais): o reservatório **esvazia**, como no incidente.
- `make edges` (modo seguro): a borda **desliga a bomba em 20%** e gera alarme; o reservatório não esvazia.

### 4.4 Queda da internet e reconciliação (RT-02, RT-23)
```bash
docker network disconnect va_wan edge-ubs-sync-agent-1     # “cai a fibra” da UBS
# abra http://127.0.0.1:9003 → “SEM INTERNET – operando localmente”; mensagens acumulam no buffer
docker network connect    va_wan edge-ubs-sync-agent-1     # volta o link
```
Depois, confira se não há lacunas nem duplicatas:
```bash
docker compose -f infra/docker-compose.cloud.yml exec postgres psql -U postgres -d vilaaurora -c \
 "SELECT dispositivo_id, count(*) recebidas, max(seq)-min(seq)+1-count(*) lacunas FROM telemetria GROUP BY 1 ORDER BY 1;"
```
O teste completo de 45 minutos com coleta de métricas (`make chaos`) vem na Parte 3.

### 4.5 Revogação de dispositivo (RT-05)
```bash
make revogar CN=ubs-temp-01 S=ubs
make logs-edge S=ubs     # o dispositivo passa a ser recusado: "certificate revoked"
```

## 5. Coletar os resultados para o relatório
Com a nuvem, o legado e as bordas no ar (`make cloud legado edges`):
```bash
make coletar-rapido   # ensaio: todos os testes + caos de 3 min (≈ 10 min no total)
make coletar          # oficial: caos de 45 min (RT-23 exige ≥ 30 min)
```
O script executa mTLS, ACL, revogação (com certificado descartável), SQL Injection antes e depois
(direto na aplicação e via WAF), o efeito do ataque na bomba e o teste de caos. Ao final ele gera:
- `docs/resultados/parte1-<data>.md`: os valores já organizados pelos quadros do relatório;
- `docs/evidencias/parte1-<data>/`: arquivos brutos e `hashes.txt` (SHA-256 na coleta, fora do Git).

## 6. Segurança do repositório
- `secrets/` e `*.key` estão no `.gitignore`. A **CA raiz fica fora do repositório** (`~/va-ca-raiz-offline`).
- `.gitattributes` força finais de linha LF, porque scripts com CRLF quebram no Linux.
- Antes de cada `git push`: `git status` não deve listar nada em `secrets/`.

## 7. Estrutura
```
infra/        docker-compose da nuvem e da borda; lista de dispositivos; .env por espaço
pki/          scripts da CA (OpenSSL): raiz offline → intermediária → certificados de 90 dias
edge/         regras locais, buffer, sync, simulador, Mosquitto (mTLS, ACL)
cloud/        ingestão, publicador de config assinada, painel corrigido, painel legado, broker central
db/init/      esquema, papéis de menor privilégio, dados sintéticos
dados/        gerador de dados sintéticos (Faker, seed fixa)
ia/           detecção de anomalias (Isolation Forest) e resultados
scripts/      geração de segredos
docs/         evidências (fora do Git) e formulários de custódia
```

## 8. Roteiro do protótipo
- [x] **Parte 1:** PKI e mTLS, bordas autônomas, store-and-forward, painel corrigido e legado, WAF, dados sintéticos
- [ ] **Parte 2:** WireGuard (hub-and-spoke), Keycloak com MFA (TOTP/WebAuthn), Wazuh com as 4 regras, respostas automatizadas com aprovação humana
- [x] Isolation Forest (`python3 ia/anomalias.py`): treino/teste sintéticos e comparação IF × IF + regras
- [ ] **Parte 3:** triagem com LLM local + testes de prompt injection, e-mail com SPF/DKIM/DMARC, Gophish, testes automatizados, teste de caos e métricas

## Uso de IA
Desenvolvido com apoio de IA generativa (Claude, Anthropic) para geração e revisão de código e
documentação. Todo o conteúdo foi testado e é de responsabilidade da equipe.
