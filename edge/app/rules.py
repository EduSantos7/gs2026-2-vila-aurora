"""edge-rules: regras locais da borda (funcionam SEM internet).
- grava toda telemetria no buffer store-and-forward
- câmara fria, intertravamento da bomba, agenda assinada, alagamento, energia, ar
- controle de acesso por crachá (pseudônimo HMAC; o número do crachá nunca é armazenado)
- painel local de supervisão em http://<borda>:8080
RULES_MODE=legado desliga as regras locais para reproduzir o INC-VA-0712."""
import hashlib, hmac, html, json, os, threading, time
from collections import deque
from datetime import datetime
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from zoneinfo import ZoneInfo
from cryptography.hazmat.primitives.serialization import load_pem_public_key
from cryptography.exceptions import InvalidSignature
from .buffer import Buffer
from .common import SITE, NOMES, agora_iso, canonico, cliente_mqtt, log, novo_uuid

SRV = "edge-rules"
MODO = os.environ.get("RULES_MODE", "seguro")
TEMP_MIN, TEMP_MAX = 2.0, 8.0
TEMP_HOLD_S = int(os.environ.get("TEMP_HOLD_S", "300"))
NIVEL_MIN = float(os.environ.get("NIVEL_MIN", "20"))
ORIGEM = f"edge-{SITE}"
TZ = ZoneInfo(os.environ.get("TZ_LOCAL", "America/Sao_Paulo"))
BUF = Buffer(os.environ.get("BUFFER_DB", "/buffer/edge.db"))
CFG_FILE = os.environ.get("CONFIG_FILE", "/buffer/config.json")
HMAC_KEY = open(os.environ.get("HMAC_KEY_FILE", "/keys/hmac.key")).read().strip().encode()
PUB = load_pem_public_key(open(os.environ.get("CONFIG_PUB", "/keys/config-sign.pub"), "rb").read())

lock = threading.RLock()
leituras, ativos, fora_desde, ultimo_cmd = {}, {}, {}, {}
alarmes = deque(maxlen=50)
try:
    config = json.load(open(CFG_FILE))
except (OSError, ValueError):
    config = {"versao": 0, "agenda": [], "crachas": []}

PKI = os.environ.get("PKI_DIR", "/pki")
cli = cliente_mqtt(f"edge-rules-{SITE}", f"{PKI}/ca-chain.crt", f"{PKI}/client.crt", f"{PKI}/client.key", persistente=True)

# ------------------------------------------------------------------ ações
def alarme(sev, msg, disp=None):
    seq, u, ts = BUF.proximo_seq(ORIGEM), novo_uuid(), agora_iso()
    payload = {"severidade": sev, "mensagem": msg, "dispositivo": disp}
    BUF.gravar("alarme", ORIGEM, seq, u, ts, payload)
    with lock:
        alarmes.appendleft({"ts": ts, **payload})
    cli.publish(f"va/{SITE}/alarme", json.dumps({"seq": seq, "ts": ts, **payload}, ensure_ascii=False), qos=1)
    log(SRV, "alarme", severidade=sev, mensagem=msg, dispositivo=disp)
    if sev == "critico":
        log(SRV, "sirene_local", estado="acionada", dispositivo=disp)
        log(SRV, "sms_enviado", canal="modem-4g (simulado)", destino="escala de plantão", texto=msg)

def comando(disp, acao, motivo):
    if time.time() - ultimo_cmd.get((disp, acao), 0) < 15:      # evita repetição
        return
    ultimo_cmd[(disp, acao)] = time.time()
    msg = {"acao": acao, "emitido": agora_iso(), "exp": time.time() + 60, "origem": ORIGEM, "motivo": motivo}
    cli.publish(f"va/{SITE}/{disp}/cmd", json.dumps(msg, ensure_ascii=False), qos=1)
    log(SRV, "comando_atuador", dispositivo=disp, acao=acao, motivo=motivo,
        usuario=ORIGEM, papel="borda-automatica", modo=MODO)

def pseudonimo(cracha):
    return hmac.new(HMAC_KEY, cracha.encode(), hashlib.sha256).hexdigest()[:24]

# ------------------------------------------------------------------ regras
def avaliar(dev, tipo, d):
    agora = time.time()
    if MODO == "legado":            # legado: alertas só existiam na nuvem
        return
    if tipo == "temp_camara":
        t = float(d["temp"])
        if t < TEMP_MIN or t > TEMP_MAX:
            ini = fora_desde.setdefault(dev, agora)
            if agora - ini >= TEMP_HOLD_S and not ativos.get(dev):
                ativos[dev] = True
                alarme("critico", f"Geladeira das vacinas fora da faixa segura: {t:.1f} °C", dev)
        else:
            fora_desde.pop(dev, None)
            if ativos.pop(dev, None):
                alarme("info", f"Geladeira das vacinas voltou à faixa segura: {t:.1f} °C", dev)
    elif tipo == "nivel":
        n = float(d["nivel_pct"])
        if n < NIVEL_MIN:
            for b, l in list(leituras.items()):
                if l["tipo"] == "bomba" and l["dados"].get("ligada"):
                    comando(b, "desligar", f"intertravamento: nível {n:.1f}% abaixo do mínimo de {NIVEL_MIN:.0f}%")
            if not ativos.get(dev):
                ativos[dev] = True
                alarme("alto", f"Reservatório baixo ({n:.1f}%). Bomba bloqueada pela borda.", dev)
        elif n > NIVEL_MIN + 10 and ativos.pop(dev, None):
            alarme("info", f"Reservatório normalizado ({n:.0f}%).", dev)
    elif tipo == "alagamento":
        if d.get("alagado") and not ativos.get(dev):
            ativos[dev] = True; alarme("critico", "Água detectada no piso do abrigo (sensor de alagamento).", dev)
        elif not d.get("alagado") and ativos.pop(dev, None):
            alarme("info", "Sensor de alagamento normalizado.", dev)
    elif tipo == "energia":
        bat, ger = float(d["bateria_pct"]), bool(d.get("gerador_ligado"))
        if bat < 30 and not ger:
            comando(dev, "ligar_gerador", f"bateria em {bat:.0f}%")
            if not ativos.get(dev):
                ativos[dev] = True; alarme("medio", f"Bateria baixa ({bat:.0f}%). Gerador de reserva acionado.", dev)
        elif bat > 80 and ger:
            comando(dev, "desligar_gerador", f"bateria recuperada ({bat:.0f}%)")
            ativos.pop(dev, None)
    elif tipo == "ar":
        co2 = float(d["co2_ppm"])
        if co2 > 1500 and not ativos.get(dev):
            ativos[dev] = True; alarme("medio", f"Ar abafado (CO₂ {co2:.0f} ppm): abrir janelas.", dev)
        elif co2 < 1000:
            ativos.pop(dev, None)

def acesso(dev, d):
    p = pseudonimo(str(d["cracha"]))          # número do crachá descartado aqui
    ok = p in config.get("crachas", [])
    comando(dev, "liberar" if ok else "negar", "crachá autorizado" if ok else "crachá não autorizado")
    seq, u, ts = BUF.proximo_seq(ORIGEM), novo_uuid(), agora_iso()
    BUF.gravar("acesso", ORIGEM, seq, u, ts, {"dispositivo": dev, "cracha_pseudo": p,
                                               "evento": "entrada" if ok else "negado"})
    log(SRV, "acesso", dispositivo=dev, cracha_pseudo=p, resultado="liberado" if ok else "negado")

def em_janela(agenda):
    hm = datetime.now(TZ).strftime("%H:%M")
    return any(j["inicio"] <= hm < j["fim"] for j in agenda)

def ciclo_agenda():
    while True:
        time.sleep(5)
        with lock:
            bombas = [(b, l) for b, l in leituras.items() if l["tipo"] == "bomba"]
            niveis = [float(l["dados"]["nivel_pct"]) for l in leituras.values() if l["tipo"] == "nivel"]
        nivel = min(niveis) if niveis else 100.0
        janela = em_janela(config.get("agenda", []))
        for b, l in bombas:
            ligada = l["dados"].get("ligada")
            if janela and not ligada and (MODO == "legado" or nivel >= NIVEL_MIN + 10):
                comando(b, "ligar", f"agenda v{config.get('versao')}")
            elif not janela and ligada:
                comando(b, "desligar", "fora da janela da agenda")

# ------------------------------------------------------------------ MQTT
def aplicar_config(raw):
    try:
        cfg = json.loads(raw)
        assin = bytes.fromhex(cfg.pop("assinatura"))
        PUB.verify(assin, canonico(cfg))                      # Ed25519
    except (ValueError, KeyError, InvalidSignature) as e:
        log(SRV, "config_rejeitada", motivo=type(e).__name__); return
    global config
    if cfg["versao"] <= config.get("versao", 0):
        return
    config = cfg
    json.dump(cfg, open(CFG_FILE, "w"))
    log(SRV, "config_aplicada", versao=cfg["versao"], agenda=cfg["agenda"], crachas=len(cfg["crachas"]))

def on_connect(c, u, flags, rc, props):
    log(SRV, "mqtt_conectado", rc=str(rc))
    c.subscribe([(f"va/{SITE}/+/tele", 1), (f"va/{SITE}/config", 1)])

def on_message(c, u, m):
    if m.topic.endswith("/config"):
        return aplicar_config(m.payload)
    try:
        msg = json.loads(m.payload)
        dev = m.topic.split("/")[2]
        if msg.get("dev") != dev:
            raise ValueError("dispositivo do tópico difere do conteúdo")
        tipo, dados = str(msg["tipo"]), dict(msg["dados"])
        seq, u_, ts = int(msg["seq"]), str(msg["uuid"]), str(msg["ts"])
    except (ValueError, KeyError, TypeError) as e:
        log(SRV, "mensagem_rejeitada", topico=m.topic, motivo=str(e)); return
    if tipo == "porta":
        return acesso(dev, dados)
    if BUF.gravar("tele", dev, seq, u_, ts, {"tipo": tipo, "dados": dados}):
        with lock:
            leituras[dev] = {"tipo": tipo, "dados": dados, "ts": ts}
            avaliar(dev, tipo, dados)

# ------------------------------------------------------------------ painel local
def descrever(tipo, d):
    if tipo == "temp_camara":
        t = d["temp"]; return f"Geladeira das vacinas: {t:.1f} °C", TEMP_MIN <= t <= TEMP_MAX
    if tipo == "nivel":
        return f"Reservatório: {d['nivel_pct']:.0f}% cheio", d["nivel_pct"] >= NIVEL_MIN
    if tipo == "bomba":
        return ("Bomba: LIGADA" if d.get("ligada") else "Bomba: desligada"), True
    if tipo == "energia":
        return f"Bateria: {d['bateria_pct']:.0f}% · Gerador {'ligado' if d.get('gerador_ligado') else 'desligado'}", d["bateria_pct"] >= 30
    if tipo == "alagamento":
        return ("ÁGUA NO PISO" if d.get("alagado") else "Piso seco"), not d.get("alagado")
    if tipo == "ar":
        return f"Ar: CO₂ {d['co2_ppm']:.0f} ppm · umidade {d['umidade']:.0f}%", d["co2_ppm"] <= 1500
    if tipo == "umidade_solo":
        return f"Umidade do solo: {d['umidade']:.0f}%", True
    return json.dumps(d, ensure_ascii=False), True

class Painel(BaseHTTPRequestHandler):
    def log_message(self, *a): pass
    def do_GET(self):
        try:
            sync = json.load(open(os.environ.get("STATUS_FILE", "/buffer/sync_status.json")))
        except (OSError, ValueError):
            sync = {}
        with lock:
            lst, als = dict(leituras), list(alarmes)
        if self.path == "/status.json":
            corpo = json.dumps({"espaco": SITE, "modo": MODO, "leituras": lst, "alarmes": als,
                                "sync": sync, "buffer": BUF.contagens()}, ensure_ascii=False).encode()
            tipo = "application/json"
        else:
            linhas = "".join(
                f"<tr><th scope='row'>{html.escape(dev)}</th><td>{'✔ Normal' if ok else '⚠ ATENÇÃO'}</td>"
                f"<td>{html.escape(txt)}</td><td>{html.escape(l['ts'][11:19])} UTC</td></tr>"
                for dev, l in sorted(lst.items()) for txt, ok in [descrever(l["tipo"], l["dados"])])
            als_html = "".join(f"<li><strong>{html.escape(a['severidade'].upper())}</strong> "
                               f"{html.escape(a['ts'][11:19])} – {html.escape(a['mensagem'])}</li>" for a in als[:15]) or "<li>Nenhum alarme.</li>"
            net = "✔ Conectado à nuvem" if sync.get("conectado_nuvem") else "⚠ SEM INTERNET – operando localmente"
            corpo = f"""<!doctype html><html lang="pt-BR"><head><meta charset="utf-8">
<meta http-equiv="refresh" content="5"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Painel local – {NOMES.get(SITE, SITE)}</title><style>
body{{font:16px/1.5 system-ui,Arial,sans-serif;margin:1rem;color:#111;background:#fff}}
h1{{font-size:1.4rem}} table{{border-collapse:collapse;width:100%}} th,td{{border:1px solid #555;padding:.4rem;text-align:left}}
.st{{padding:.5rem;border:2px solid #111;font-weight:bold;margin:.5rem 0}}</style></head><body>
<h1>Painel local – {html.escape(NOMES.get(SITE, SITE))}</h1>
<p class="st" role="status">{net} · Mensagens aguardando envio: {BUF.contagens()['pendentes']} · Modo: {MODO}</p>
<h2>Alarmes recentes</h2><ul aria-live="polite">{als_html}</ul>
<h2>Equipamentos</h2><table><caption>Últimas leituras (atualiza a cada 5 s)</caption>
<thead><tr><th scope="col">Equipamento</th><th scope="col">Situação</th><th scope="col">Leitura</th><th scope="col">Hora</th></tr></thead>
<tbody>{linhas}</tbody></table></body></html>""".encode()
            tipo = "text/html; charset=utf-8"
        self.send_response(200); self.send_header("Content-Type", tipo)
        self.send_header("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'")
        self.end_headers(); self.wfile.write(corpo)

def main():
    log(SRV, "inicio", modo=MODO, temp_hold_s=TEMP_HOLD_S, nivel_min=NIVEL_MIN, config_versao=config.get("versao"))
    threading.Thread(target=ciclo_agenda, daemon=True).start()
    threading.Thread(target=ThreadingHTTPServer(("0.0.0.0", int(os.environ.get("PAINEL_PORT", "8080"))), Painel).serve_forever, daemon=True).start()
    cli.on_connect, cli.on_message = on_connect, on_message
    cli.connect_async(os.environ.get("BROKER_HOST", "mosquitto"), int(os.environ.get("BROKER_PORT", "8883")))
    cli.loop_forever(retry_first_connection=True)

if __name__ == "__main__":
    main()
