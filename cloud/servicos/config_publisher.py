"""Publica a configuração de cada borda (agenda da bomba + crachás autorizados)
ASSINADA com Ed25519. A borda só aplica configuração com assinatura válida e versão maior.
Observação: o publicador confia no banco. Por isso, na arquitetura nova, a agenda
só pode ser alterada por fluxo com aprovação humana dupla (e nunca pelo painel diretamente)."""
import json, os, time, psycopg
from cryptography.hazmat.primitives.serialization import load_pem_private_key
from comum import cliente_mqtt, log, agora_iso

SRV = "config-publisher"
ESPACOS = ["cc", "esc", "ubs", "hrt", "abr"]
SK = load_pem_private_key(open(os.environ.get("SIGN_KEY", "/keys/config-sign.key"), "rb").read(), None)
c = cliente_mqtt("svc-config", os.environ.get("PKI_DIR", "/pki"))
c.connect_async(os.environ.get("CENTRAL_HOST", "mqtt-central"), int(os.environ.get("CENTRAL_PORT", "8883"))); c.loop_start()
log(SRV, "inicio")
publicado = {}

def canonico(o): return json.dumps(o, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()

while True:
    try:
        with psycopg.connect(os.environ["CONFIG_DSN"]) as db:
            ag = {e: (j, t) for e, j, t in db.execute("SELECT espaco, janelas, atualizado_em FROM agenda_bomba")}
            cr = {}
            for p, e, t in db.execute("SELECT cracha_pseudo, espaco, atualizado_em FROM crachas_autorizados ORDER BY 1"):
                cr.setdefault(e, []).append((p, t))
        for e in ESPACOS:
            janelas, t_ag = ag.get(e, ([], None))
            lst = cr.get(e, [])
            ts = [t for t in [t_ag] + [t for _, t in lst] if t]
            cfg = {"espaco": e, "versao": int(max(ts).timestamp()) if ts else 1, "agenda": janelas,
                   "crachas": [p for p, _ in lst], "emitido": agora_iso()}
            chave = (cfg["versao"], json.dumps(janelas), len(lst))
            if publicado.get(e) == chave and c.is_connected():
                continue
            corpo = {k: v for k, v in cfg.items()}
            corpo["assinatura"] = SK.sign(canonico(cfg)).hex()
            if c.is_connected():
                c.publish(f"config/edge-{e}", json.dumps(corpo, ensure_ascii=False), qos=1, retain=True)
                publicado[e] = chave
                log(SRV, "config_publicada", espaco=e, versao=cfg["versao"], agenda=janelas, crachas=len(lst))
    except psycopg.Error as ex:
        log(SRV, "erro_banco", motivo=type(ex).__name__)
    time.sleep(10)
