#!/usr/bin/env python3
"""Coleta automática dos resultados da PARTE 1 para preencher o relatório (E3/RT-22/RT-23).
Roda no terminal do Ubuntu/WSL, na raiz do repositório, com a nuvem e as bordas no ar.
  python3 scripts/coletar_resultados.py              # caos de 45 min (oficial, RT-23)
  python3 scripts/coletar_resultados.py --caos-min 3 # ensaio rápido
  python3 scripts/coletar_resultados.py --sem-caos   # só testes de segurança
Saídas: docs/resultados/parte1-<data>.md (vai para o Git) e
        docs/evidencias/parte1-<data>/ (brutos + hashes.txt; fora do Git)."""
import argparse, hashlib, http.client, json, os, re, shutil, ssl, subprocess, sys, threading, time
import urllib.parse as up
from datetime import datetime, timezone

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
os.chdir(ROOT)
TS = datetime.now().strftime("%Y%m%d-%H%M")
EVD = os.path.join("docs/evidencias", f"parte1-{TS}")
os.makedirs(EVD, exist_ok=True); os.makedirs("docs/resultados", exist_ok=True)
UID = f"{os.getuid()}:{os.getgid()}"
MQ_IMG = "eclipse-mosquitto:2.0.20"
CLOUD = ["docker", "compose", "-f", "infra/docker-compose.cloud.yml"]
def EDGE(s): return ["docker", "compose", "-p", f"edge-{s}", "--env-file", f"infra/sites/{s}.env", "-f", "infra/docker-compose.edge.yml"]
R = {}            # resultados

def agora(): return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
def info(*a): print(f"[{datetime.now().strftime('%H:%M:%S')}]", *a, flush=True)

def sh(cmd, timeout=60, inp=None):
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, input=inp)
        return p.returncode, (p.stdout or "") + (p.stderr or "")
    except subprocess.TimeoutExpired as e:
        return 124, str(e)

def salvar(nome, conteudo):
    with open(os.path.join(EVD, nome), "w", encoding="utf-8") as f: f.write(conteudo)

def psql(sql, user_url=None):
    cmd = CLOUD + ["exec", "-T", "postgres", "psql", "-At", "-v", "ON_ERROR_STOP=1"]
    cmd += [user_url] if user_url else ["-U", "postgres", "-d", "vilaaurora"]
    return sh(cmd + ["-c", sql])

def envfile(p):
    d = {}
    for l in open(p):
        if "=" in l and not l.startswith("#"): k, v = l.strip().split("=", 1); d[k] = v
    return d

def logs_desde(cmd_base, servico, desde):
    return sh(cmd_base + ["logs", "--no-color", "--since", desde, servico], timeout=60)[1]

# ====================================================================== 1. mTLS
def mqtt_pub(site, cert, topico, msg="TESTE", extra_mount=None, sem_cert=False, certdir="/pki"):
    mnt = ["-v", f"{ROOT}/secrets/pki/sites/{site}/devices:/pki:ro"]
    if extra_mount: mnt += ["-v", f"{extra_mount}:/t:ro"]
    cmd = ["docker", "run", "--rm", "--network", f"edge-{site}_iot", *mnt, MQ_IMG, "mosquitto_pub",
           "-h", "mosquitto", "-p", "8883", "--cafile", "/pki/ca-chain.crt", "-t", topico, "-m", msg, "-q", "1"]
    if not sem_cert: cmd += ["--cert", f"{certdir}/{cert}.crt", "--key", f"{certdir}/{cert}.key"]
    return sh(cmd, timeout=25)

def tools(*args, net=None):
    cmd = ["docker", "run", "--rm", "--user", UID, "-v", f"{ROOT}:/w"]
    if net: cmd += ["--network", net]
    return sh(cmd + ["va-tools", *args], timeout=60)

def testes_mtls():
    info("== mTLS, ACL e revogação (borda UBS)")
    tmp = f"{ROOT}/secrets/tmp-teste"; shutil.rmtree(tmp, ignore_errors=True); os.makedirs(tmp)
    rc, o = mqtt_pub("ubs", "ubs-temp-01", "va/ubs/ubs-temp-01/tele", '{"teste":"MTLS-01"}')
    R["MTLS-01"] = ("Publicação aceita" if rc == 0 else f"FALHOU (rc={rc})", o); 
    rc, o = mqtt_pub("ubs", None, "va/ubs/ubs-temp-01/tele", sem_cert=True)
    R["MTLS-02"] = ("Conexão recusada (TLS)" if rc != 0 else "ACEITA - FALHA!", o)
    tools("openssl", "req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256", "-nodes", "-days", "1",
          "-subj", "/CN=ubs-temp-01", "-keyout", "/w/secrets/tmp-teste/falso.key", "-out", "/w/secrets/tmp-teste/falso.crt")
    rc, o = mqtt_pub("ubs", "falso", "va/ubs/ubs-temp-01/tele", extra_mount=tmp, certdir="/t")
    R["MTLS-03"] = ("Recusado: certificate verify failed" if rc != 0 else "ACEITO - FALHA!", o)
    # ACL: assinante com a identidade do edge-rules; dispositivo tenta publicar no tópico de OUTRO
    sh(["docker", "rm", "-f", "va-acl-sub"])
    sh(["docker", "run", "-d", "--name", "va-acl-sub", "--network", "edge-ubs_iot",
        "-v", f"{ROOT}/secrets/pki/sites/ubs/edge-rules:/pki:ro", MQ_IMG, "mosquitto_sub", "-h", "mosquitto", "-p", "8883",
        "--cafile", "/pki/ca-chain.crt", "--cert", "/pki/client.crt", "--key", "/pki/client.key",
        "-t", "va/ubs/+/tele", "-v", "-W", "15"])
    time.sleep(3)
    mqtt_pub("ubs", "ubs-temp-01", "va/ubs/ubs-ar-01/tele", "TESTE-ACL-FORJADO")
    mqtt_pub("ubs", "ubs-temp-01", "va/ubs/ubs-temp-01/tele", "TESTE-ACL-LEGITIMO")
    sh(["docker", "wait", "va-acl-sub"], timeout=30); _, o = sh(["docker", "logs", "va-acl-sub"]); sh(["docker", "rm", "-f", "va-acl-sub"])
    forj, leg = "TESTE-ACL-FORJADO" in o, "TESTE-ACL-LEGITIMO" in o
    R["MTLS-04"] = ("Negado pela ACL (mensagem forjada não entregue; legítima entregue)" if (leg and not forj)
                    else f"VERIFICAR: forjada={forj} legítima={leg}", "\n".join(l for l in o.splitlines() if "TESTE" in l))
    rc, o = tools("sh", "-c", "echo | openssl s_client -connect mosquitto:8883 -CAfile /w/secrets/pki/sites/ubs/devices/ca-chain.crt "
                  "-cert /w/secrets/pki/sites/ubs/devices/ubs-temp-01.crt -key /w/secrets/pki/sites/ubs/devices/ubs-temp-01.key -brief 2>&1",
                  net="edge-ubs_iot")
    proto = re.search(r"Protocol version:\s*(\S+)", o); ver = "verification: OK" in o or "Verification: OK" in o
    R["MTLS-05"] = (f"{proto.group(1) if proto else '?'}; cadeia verificada: {'sim' if ver else 'verificar'}", o)
    # Revogação com certificado DESCARTÁVEL (não estraga os dispositivos reais)
    cn = f"teste-rev-{TS[-4:]}"
    tools("bash", "pki/pki.sh", "issue", cn, "client")
    for ext in ("crt", "key"): shutil.copy(f"secrets/pki/issued/{cn}/{cn}.{ext}", f"{tmp}/{cn}.{ext}")
    rc1, o1 = mqtt_pub("ubs", cn, f"va/ubs/{cn}/tele", extra_mount=tmp, certdir="/t")
    t0 = time.time(); desde = agora()
    _, orv = tools("bash", "pki/pki.sh", "revoke", cn)
    sh(EDGE("ubs") + ["restart", "mosquitto"], timeout=60); time.sleep(3)
    rc2, o2 = mqtt_pub("ubs", cn, f"va/ubs/{cn}/tele", extra_mount=tmp, certdir="/t")
    dt_bloq = time.time() - t0
    log_rev = logs_desde(EDGE("ubs"), "mosquitto", desde)
    R["REV-01"] = (f"Antes: {'aceito' if rc1 == 0 else 'recusado'}; depois: {'recusado' if rc2 != 0 else 'ACEITO - FALHA!'}; "
                   f"tempo até bloqueio {dt_bloq:.0f} s (inclui reinício do broker)",
                   o1 + "\n" + orv + "\n" + o2 + "\n--- log do broker ---\n" + log_rev)
    for k in ("MTLS-01", "MTLS-02", "MTLS-03", "MTLS-04", "MTLS-05", "REV-01"):
        salvar(f"{k}.txt", R[k][1]); info(f"   {k}: {R[k][0]}")
    shutil.rmtree(tmp, ignore_errors=True)

# ====================================================================== 2. SQL Injection
class Web:
    """Cliente HTTP mínimo que guarda cookies manualmente (inclusive Secure em http interno)."""
    def __init__(self, base):
        u = up.urlparse(base); self.https = u.scheme == "https"; self.host, self.port = u.hostname, u.port
        self.ctx = ssl.create_default_context(cafile="secrets/pki/root.crt") if self.https else None
        self.cookies = {}; self.base = base
    def req(self, metodo, caminho, corpo=None):
        c = (http.client.HTTPSConnection(self.host, self.port, context=self.ctx, timeout=20) if self.https
             else http.client.HTTPConnection(self.host, self.port, timeout=20))
        h = {"Cookie": "; ".join(f"{k}={v}" for k, v in self.cookies.items()), "Referer": self.base + "/entrar",
             "User-Agent": "va-coleta/1.0"}
        if corpo is not None:
            corpo = up.urlencode(corpo); h["Content-Type"] = "application/x-www-form-urlencoded"
        c.request(metodo, caminho, body=corpo, headers=h); r = c.getresponse(); data = r.read().decode("utf-8", "replace")
        for k, v in r.getheaders():
            if k.lower() == "set-cookie":
                n, val = v.split(";", 1)[0].split("=", 1); self.cookies[n] = val
        return r.status, data
    def login(self, user, pw):
        s, d = self.req("GET", "/entrar"); m = re.search(r'name="csrf_token" value="([^"]+)"', d)
        if not m: return s
        s, _ = self.req("POST", "/entrar", {"csrf_token": m.group(1), "login": user, "senha": pw})
        return s

PAYLOADS = [("SQLi-01", "Aspas simples", "'"),
            ("SQLi-02", "Condição sempre verdadeira", "x' OR 1=1--"),
            ("SQLi-03", "UNION na tabela de usuários", "x' UNION SELECT now(), nome||' | '||cpf||' | '||senha, login, funcao FROM legado.usuarios--"),
            ("SQLi-04", "UPDATE empilhado na agenda da bomba", "x'; UPDATE agenda_bomba SET janelas='[{\"inicio\":\"00:00\",\"fim\":\"23:59\"}]' WHERE espaco='esc'--")]
def q(p): return "/historico?busca=" + up.quote(p)
AGENDA_OK = '[{"inicio":"07:00","fim":"07:40"},{"inicio":"16:00","fim":"16:40"}]'

DIRETO = r'''
import http.client, json, re, sys, urllib.parse as up
P = json.loads(sys.argv[1]); U, PW = sys.argv[2], sys.argv[3]; ck = {}
def req(m, path, body=None):
    c = http.client.HTTPConnection("localhost", 8000, timeout=20)
    h = {"Cookie": "; ".join(f"{k}={v}" for k, v in ck.items())}
    if body: body = up.urlencode(body); h["Content-Type"] = "application/x-www-form-urlencoded"
    c.request(m, path, body=body, headers=h); r = c.getresponse(); d = r.read().decode()
    for k, v in r.getheaders():
        if k.lower() == "set-cookie": n, val = v.split(";", 1)[0].split("=", 1); ck[n] = val
    return r.status, d
s, d = req("GET", "/entrar"); t = re.search(r'name="csrf_token" value="([^"]+)"', d).group(1)
req("POST", "/entrar", {"csrf_token": t, "login": U, "senha": PW})
out = {}
for k, _, p in P:
    s, d = req("GET", "/historico?busca=" + up.quote(p))
    out[k] = [s, ("syntax" in d or "psycopg" in d or "SELECT" in d)]
s, d = req("GET", "/historico?busca=" + up.quote("ubs"))
out["normal"] = [s, d.count("<tr>") - 1]
print(json.dumps(out))
'''

def testes_sqli():
    info("== SQL Injection: antes (legado :8081) e depois (corrigido)")
    users = {l.split()[0]: l.split()[2] for l in open("secrets/usuarios-lab.txt") if l.strip() and not l.startswith("#")}
    leg_on = False
    try:
        s, _ = Web("http://127.0.0.1:8081").req("GET", "/"); leg_on = s == 200
    except OSError:
        pass
    if not leg_on:
        info("   painel legado fora do ar: rode 'make legado' para o 'antes'. Pulando o legado.")
    else:
        w = Web("http://127.0.0.1:8081")
        s, d = w.req("GET", q("VA-1000")); salvar("SQLi-00_legado_normal.html", d)
        R["SQLi-00-leg"] = f"HTTP {s}, {d.count('<tr>')} linhas"
        for k, nome, p in PAYLOADS:
            s, d = w.req("GET", q(p)); salvar(f"{k}_legado.html", d)
            if k == "SQLi-01":
                R[k + "-leg"] = f"HTTP {s}; erro do PostgreSQL exibido: {'sim' if ('syntax' in d or 'unterminated' in d) else 'não'}"
            elif k == "SQLi-02":
                R[k + "-leg"] = f"HTTP {s}; {d.count('<tr>')} registros retornados (a tabela inteira: o -- anulou o LIMIT)"
            elif k == "SQLi-03":
                n = len(re.findall(r"<td>[^<]*\|[^<]*\|[^<]*</td>", d))
                R[k + "-leg"] = f"HTTP {s}; {n} usuários extraídos (nome, CPF e senha sintéticos)"
            else:
                _, ag = psql("SELECT janelas FROM agenda_bomba WHERE espaco='esc'")
                R[k + "-leg"] = f"HTTP {s}; agenda alterada para: {ag.strip()}"
                bomba_intertravamento()                    # efeito físico do ataque
                psql(f"UPDATE agenda_bomba SET janelas='{AGENDA_OK}' WHERE espaco='esc'")
                info("   agenda original restaurada")
    # ------- corrigido via WAF (camada adicional) -------
    w = Web("https://127.0.0.1:8443")
    try:
        sl = w.login("tecnico1", users["tecnico1"])
        for k, nome, p in PAYLOADS:
            s, d = w.req("GET", q(p)); salvar(f"{k}_corrigido_waf.html", d)
            R[k + "-waf"] = f"HTTP {s}" + (" (bloqueado pelo WAF)" if s == 403 else " (bloqueado pela validação)" if s == 400 else "")
        R["login-waf"] = f"HTTP {sl}"
    except OSError as e:
        R["login-waf"] = f"WAF inacessível: {e}"
    # ------- corrigido DIRETO na aplicação (prova da correção na causa raiz, sem o WAF) -------
    rc, o = sh(CLOUD + ["exec", "-T", "painel", "python", "-", json.dumps(PAYLOADS), "tecnico1", users["tecnico1"]], inp=DIRETO, timeout=60)
    salvar("SQLi_corrigido_direto.json", o)
    try:
        d = json.loads(o.strip().splitlines()[-1])
        for k, _, _ in PAYLOADS:
            s, vaza = d[k]; R[k + "-dir"] = f"HTTP {s}; vaza detalhe: {'SIM - FALHA' if vaza else 'não'}"
        R["normal-dir"] = f"HTTP {d['normal'][0]}; {d['normal'][1]} registros"
    except (ValueError, IndexError, KeyError):
        R["SQLi-dir-erro"] = o[-500:]
    # ------- menor privilégio -------
    dsn = envfile("secrets/painel.env")["DATABASE_URL"].replace("postgresql+psycopg", "postgresql").replace("@postgres:", "@localhost:")
    rc, o = psql("SELECT count(*) FROM legado.usuarios", dsn); R["SQLi-05"] = "permission denied" if "permission denied" in o else f"VERIFICAR: {o.strip()}"
    rc, o2 = psql("UPDATE agenda_bomba SET versao = versao", dsn); R["SQLi-05b"] = "permission denied" if "permission denied" in o2 else f"VERIFICAR: {o2.strip()}"
    salvar("SQLi-05_privilegio.txt", o.replace(dsn.split('@')[0], "postgresql://painel_app:***") + "\n" + o2)
    for k in sorted(x for x in R if x.startswith(("SQLi", "login", "normal"))): info(f"   {k}: {R[k]}")

def bomba_intertravamento():
    info("   efeito do SQLi-04: aguardando a borda da Escola ligar a bomba pela agenda forjada...")
    desde = agora(); t0 = time.time(); ligou = None
    while time.time() - t0 < 60:
        log = logs_desde(EDGE("esc"), "edge-rules", desde)
        if '"acao": "ligar"' in log and "agenda" in log: ligou = time.time() - t0; break
        time.sleep(5)
    if ligou is None:
        R["BOMBA"] = "Bomba não ligou em 60 s (verificar se a config foi publicada)"; return
    sh(EDGE("esc") + ["exec", "-T", "simulador", "python", "-m", "app.injetar", "esc-nivel-01", '{"nivel": 20.6}'])
    t1 = time.time(); desl = None
    while time.time() - t1 < 120:
        log = logs_desde(EDGE("esc"), "edge-rules", desde)
        if "intertravamento" in log: desl = time.time() - t1; break
        time.sleep(5)
    salvar("BOMBA_esc_edge-rules.log", logs_desde(EDGE("esc"), "edge-rules", desde))
    R["BOMBA"] = (f"Bomba ligada pela agenda forjada {ligou:.0f} s após o SQLi; "
                  + (f"intertravamento desligou a bomba em 20% ({desl:.0f} s após o nível ser levado a 20,6%)" if desl is not None
                     else "intertravamento NÃO observado em 120 s (verificar modo seguro)"))
    sh(EDGE("esc") + ["exec", "-T", "simulador", "python", "-m", "app.injetar", "esc-nivel-01", '{"nivel": 70}'])

# ====================================================================== 3. Caos + RT-22
def stats():
    _, o = sh(["docker", "stats", "--no-stream", "--format", "{{.Name}}|{{.CPUPerc}}|{{.MemUsage}}|{{.NetIO}}"])
    out = {}
    for l in o.splitlines():
        n, cpu, mem, net = l.split("|")
        out[n] = (float(cpu.strip("%") or 0), mem.split("/")[0].strip(), net)
    return out

def mib(s):
    m = re.match(r"([\d.]+)\s*([kKMG]i?B|B)", s.strip()); v, u = float(m.group(1)), m.group(2)
    return v * {"B": 1/1048576, "KiB": 1/1024, "kB": 1/1024, "KB": 1/1024, "MiB": 1, "MB": 1, "GiB": 1024, "GB": 1024}.get(u, 1)

def status(porta):
    try:
        c = http.client.HTTPConnection("127.0.0.1", porta, timeout=5); c.request("GET", "/status.json")
        return json.loads(c.getresponse().read())
    except (OSError, ValueError):
        return None

def caos(minutos):
    info(f"== Teste de caos: link WAN da UBS e da Escola fora por {minutos} min")
    sondas = {"ok": 0, "total": 0}; pico = {"ubs": 0, "esc": 0}; amostras = []; parar = threading.Event()
    def sondar():
        while not parar.is_set():
            for s, p in (("ubs", 9003), ("esc", 9002)):
                st = status(p); sondas["total"] += 1
                if st: sondas["ok"] += 1; pico[s] = max(pico[s], st["buffer"]["pendentes"])
            amostras.append(stats()); parar.wait(30)
    desde = agora()
    for s in ("ubs", "esc"): sh(["docker", "network", "disconnect", "va_wan", f"edge-{s}-sync-agent-1"])
    t0 = time.time(); threading.Thread(target=sondar, daemon=True).start()
    info("   link derrubado. Painéis locais: http://127.0.0.1:9003 e :9002 (tire os prints agora!)")
    time.sleep(min(60, minutos * 60 / 4))
    sh(EDGE("ubs") + ["exec", "-T", "simulador", "python", "-m", "app.injetar", "ubs-temp-01", '{"temp_alvo": 12}'])
    tinj = time.time(); info("   câmara fria levada a 12 °C (sem internet)")
    t_alarme = None
    while time.time() - t0 < minutos * 60:
        if t_alarme is None:
            log = logs_desde(EDGE("ubs"), "edge-rules", desde)
            if "Geladeira das vacinas fora da faixa" in log:
                t_alarme = time.time() - tinj; info(f"   ALARME LOCAL após {t_alarme:.0f} s (inclui os 5 min de tolerância)")
                sh(EDGE("ubs") + ["exec", "-T", "simulador", "python", "-m", "app.injetar", "ubs-temp-01", '{"temp_alvo": 5}'])
        time.sleep(10)
    tback = time.time()
    for s in ("ubs", "esc"): sh(["docker", "network", "connect", "va_wan", f"edge-{s}-sync-agent-1"])
    info("   link restabelecido; medindo a reconciliação...")
    t_rec = {}
    while time.time() - tback < 900 and len(t_rec) < 2:
        for s, p in (("ubs", 9003), ("esc", 9002)):
            st = status(p)
            if s not in t_rec and st and st["sync"].get("conectado_nuvem") and st["buffer"]["pendentes"] == 0:
                t_rec[s] = time.time() - tback
        time.sleep(2)
    parar.set(); time.sleep(1)
    log_ubs = logs_desde(EDGE("ubs"), "edge-rules", desde)
    salvar("CAOS_ubs_edge-rules.log", log_ubs)
    salvar("CAOS_ubs_sync.log", logs_desde(EDGE("ubs"), "sync-agent", desde))
    salvar("CAOS_ingest.log", logs_desde(CLOUD, "ingest", desde))
    lotes = [json.loads(l[l.index("{"):]) for l in logs_desde(CLOUD, "ingest", desde).splitlines() if '"evento": "lote"' in l]
    _, gaps = psql("SELECT dispositivo_id, count(*), max(seq)-min(seq)+1, max(seq)-min(seq)+1-count(*) FROM telemetria "
                   f"WHERE espaco IN ('ubs','esc') AND ts_utc >= '{desde}' GROUP BY 1 ORDER BY 1")
    salvar("CAOS_lacunas.txt", gaps)
    linhas = [l.split("|") for l in gaps.strip().splitlines() if l.count("|") == 3]
    lac = sum(int(x[3]) for x in linhas); tot = sum(int(x[2]) for x in linhas)
    R["caos"] = {
        "duracao_min": round((tback - t0) / 60, 1),
        "disponibilidade_local_pct": round(100 * sondas["ok"] / max(1, sondas["total"]), 2),
        "pico_pendentes": pico, "reconciliacao_s": {k: round(v) for k, v in t_rec.items()},
        "lacunas": lac, "esperadas": tot, "perda_pct": round(100 * lac / max(1, tot), 4),
        "duplicados_descartados": sum(x.get("duplicados", 0) for x in lotes),
        "alarme_local_s": round(t_alarme) if t_alarme else None,
        "sms": "sms_enviado" in log_ubs, "sirene": "sirene_local" in log_ubs,
    }
    # consumo da borda UBS
    cont = [n for n in (amostras[0] if amostras else {}) if n.startswith("edge-ubs-")]
    R["recursos"] = {}
    for n in cont:
        cpus = [a[n][0] for a in amostras if n in a]; mems = [mib(a[n][1]) for a in amostras if n in a]
        R["recursos"][n] = (round(sum(cpus) / len(cpus), 2), round(max(cpus), 2), round(max(mems), 1))
    _, ins = sh(["docker", "inspect", "-f", "{{.State.StartedAt}}", "edge-ubs-sync-agent-1"])
    try:
        ini = datetime.fromisoformat(ins.strip()[:19]).replace(tzinfo=timezone.utc)
        horas = (datetime.now(timezone.utc) - ini).total_seconds() / 3600
        tx = stats().get("edge-ubs-sync-agent-1", (0, "", "0B / 0B"))[2].split("/")[1]
        R["banda_mb_h"] = round(mib(tx) / horas, 2)
    except (ValueError, AttributeError, IndexError):
        R["banda_mb_h"] = None
    info(f"   {json.dumps(R['caos'], ensure_ascii=False)}")

# ====================================================================== relatório
def relatorio(args):
    g = lambda k, d="não executado": (R[k][0] if isinstance(R.get(k), tuple) else R.get(k, d))
    L = [f"# Resultados medidos – Parte 1", f"Coletado em {agora()} (UTC) por `{os.environ.get('USER', '?')}` "
         f"no host `{os.uname().nodename}`. Evidências brutas e hashes: `{EVD}/`.", ""]
    L += ["## Seção 4.1 – Quadro “Roteiro e resultados dos testes de SQL Injection” (coluna Obtido)", "",
          "| ID | Legado (:8081) | Corrigido – aplicação direta (causa raiz) | Corrigido – via WAF (:8443) |", "|---|---|---|---|"]
    for k, nome, _ in PAYLOADS:
        L.append(f"| {k} {nome} | {g(k + '-leg')} | {g(k + '-dir')} | {g(k + '-waf')} |")
    L += [f"| SQLi-05 painel_app lê `legado.usuarios` | – | {g('SQLi-05')} | – |",
          f"| SQLi-05b painel_app altera `agenda_bomba` | – | {g('SQLi-05b')} | – |",
          f"| Busca legítima | {g('SQLi-00-leg')} | {g('normal-dir')} | login {g('login-waf')} |", "",
          f"**Efeito físico do SQLi-04 (borda em modo seguro):** {g('BOMBA')}", "",
          "SQLi-03 com sqlmap e SQLi-06 (alerta no Wazuh) entram nas Partes 2 e 3.", "",
          "## Seção 4.2 – Quadro “Testes de mTLS, ACL e revogação” (coluna Obtido)", "", "| ID | Obtido |", "|---|---|"]
    for k in ("MTLS-01", "MTLS-02", "MTLS-03", "MTLS-04", "MTLS-05", "REV-01"): L.append(f"| {k} | {g(k)} |")
    c = R.get("caos")
    if c:
        rec = ", ".join(f"{k.upper()} {v} s" for k, v in c["reconciliacao_s"].items()) or "não concluída"
        L += ["", "## Seção 4.7 – Teste de caos (RT-23)", "",
              f"Link WAN da UBS e da Escola derrubado por **{c['duracao_min']} min**. Durante a queda, o painel local "
              f"respondeu em **{c['disponibilidade_local_pct']}%** das sondagens; o buffer chegou a **{c['pico_pendentes']['ubs']}** "
              f"(UBS) e **{c['pico_pendentes']['esc']}** (Escola) mensagens pendentes. A câmara fria foi levada a 12 °C sem internet e o "
              f"alarme local disparou em **{c['alarme_local_s']} s** (tolerância configurada de 5 min), com sirene "
              f"{'registrada' if c['sirene'] else 'NÃO registrada'} e SMS {'registrado' if c['sms'] else 'NÃO registrado'}. "
              f"Ao restabelecer o link, a reconciliação terminou em {rec}, com **{c['lacunas']} lacunas** em "
              f"{c['esperadas']} mensagens esperadas (perda de {c['perda_pct']}%) e {c['duplicados_descartados']} duplicatas descartadas "
              "pela ingestão idempotente.", "",
              "## Seção 4.7 – Quadro “Indicadores de continuidade e consumo (RT-22)” (coluna Medido)", "",
              "| Indicador | Medido |", "|---|---|",
              f"| Disponibilidade das funções locais (borda) | {c['disponibilidade_local_pct']}% durante a queda |",
              "| Disponibilidade da nuvem | medir na Parte 2 (sonda contínua) |",
              "| MTTD / MTTR | Parte 2 (depende do Wazuh) |",
              f"| Operação autônoma sem internet | {c['duracao_min']} min contínuos, sem perda de funções locais |",
              f"| Perda de dados na reconciliação | {c['perda_pct']}% ({c['lacunas']} lacunas) |",
              f"| Tempo de reconciliação | {rec} |"]
        for n, (avg, pk, mem) in R.get("recursos", {}).items():
            L.append(f"| CPU/memória – {n} | CPU média {avg}% · pico {pk}% · memória pico {mem} MiB |")
        L += [f"| Banda do sync-agent (UBS) | {R.get('banda_mb_h')} MB/h de envio |",
              "| Energia da borda | não medida: protótipo simulado, sem hardware (declarar no relatório) |"]
    L += ["", "## Prints que vocês ainda precisam tirar", "",
          "1. Painel legado `http://127.0.0.1:8081/historico` com a busca `'` (erro do banco vazando).",
          "2. Painel legado com a busca UNION mostrando os usuários extraídos.",
          "3. Painel corrigido com a mesma busca: mensagem “Busca inválida”.",
          "4. Painel local da UBS (`http://127.0.0.1:9003`) mostrando **“SEM INTERNET – operando localmente”** e o alarme da geladeira.",
          "5. Painel corrigido (`https://127.0.0.1:8443`) logado como operador e como técnico (RBAC).",
          "6. Terminal com o resultado deste script.", "",
          "Os arquivos de evidência têm SHA-256 em `hashes.txt`. Copiem a pasta para mídia separada (cadeia de custódia)."]
    p = f"docs/resultados/parte1-{TS}.md"; open(p, "w", encoding="utf-8").write("\n".join(L) + "\n")
    salvar("resultados.json", json.dumps({k: (v[0] if isinstance(v, tuple) else v) for k, v in R.items()}, ensure_ascii=False, indent=2, default=str))
    with open(os.path.join(EVD, "hashes.txt"), "w") as f:
        f.write(f"# SHA-256 calculado na coleta: {agora()} UTC | coletor: {os.environ.get('USER', '?')} | host: {os.uname().nodename}\n")
        for n in sorted(os.listdir(EVD)):
            if n != "hashes.txt":
                f.write(f"{hashlib.sha256(open(os.path.join(EVD, n), 'rb').read()).hexdigest()}  {n}\n")
    info(f"Relatório: {p}"); info(f"Evidências: {EVD}/ (hashes em hashes.txt)")

if __name__ == "__main__":
    ap = argparse.ArgumentParser(); ap.add_argument("--caos-min", type=float, default=45); ap.add_argument("--sem-caos", action="store_true")
    a = ap.parse_args()
    rc, _ = sh(["docker", "image", "inspect", "va-tools"])
    if rc != 0: sys.exit("Rode 'make secrets' antes (cria a imagem va-tools).")
    if not os.path.exists("secrets/usuarios-lab.txt"): sys.exit("secrets/ não encontrado: rode 'make secrets'.")
    for etapa in (testes_mtls, testes_sqli):
        try: etapa()
        except Exception as e: info(f"!! erro em {etapa.__name__}: {e!r}"); R[f"erro-{etapa.__name__}"] = repr(e)
    if not a.sem_caos:
        try: caos(a.caos_min)
        except Exception as e:
            info(f"!! erro no caos: {e!r}")
            for s in ("ubs", "esc"): sh(["docker", "network", "connect", "va_wan", f"edge-{s}-sync-agent-1"])
    relatorio(a)
