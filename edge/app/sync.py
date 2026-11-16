"""sync-agent: store-and-forward borda -> nuvem.
Envia lotes ordenados do buffer ao broker central; só considera entregue o que a
nuvem confirmar (ack). Sem internet, acumula; ao voltar, reconcilia.
Também repassa a configuração ASSINADA da nuvem para a borda (quem verifica é o edge-rules)."""
import json, os, threading, time
from .buffer import Buffer
from .common import SITE, agora_iso, cliente_mqtt, log

SRV = "sync-agent"
PKI = os.environ.get("PKI_DIR", "/pki")
BUF = Buffer(os.environ.get("BUFFER_DB", "/buffer/edge.db"))
ID = f"edge-{SITE}"
STATUS = os.environ.get("STATUS_FILE", "/buffer/sync_status.json")
LOTE = int(os.environ.get("SYNC_BATCH", "200"))
st = {"conectado_nuvem": False, "desde": agora_iso(), "ultimo_ack": None, "ultima_config": None}

nuvem = cliente_mqtt(ID, f"{PKI}/ca-chain.crt", f"{PKI}/central.crt", f"{PKI}/central.key")
local = cliente_mqtt(f"sync-{SITE}", f"{PKI}/ca-chain.crt", f"{PKI}/local.crt", f"{PKI}/local.key")

def salvar_status():
    st.update(BUF.contagens())
    tmp = STATUS + ".tmp"
    json.dump(st, open(tmp, "w")); os.replace(tmp, STATUS)

def on_connect(c, u, f, rc, p):
    if rc.is_failure:
        log(SRV, "nuvem_recusou", rc=str(rc)); return
    st.update(conectado_nuvem=True, desde=agora_iso())
    log(SRV, "nuvem_conectada", **BUF.contagens())
    c.subscribe([(f"sync/{ID}/ack", 1), (f"config/{ID}", 1)])
    BUF.reabrir_pendentes()                    # reconciliação: reenvia pendentes

def on_disconnect(c, u, f, rc, p):
    if st["conectado_nuvem"]:
        log(SRV, "nuvem_desconectada", rc=str(rc))
    st.update(conectado_nuvem=False, desde=agora_iso())

def on_message(c, u, m):
    if m.topic == f"config/{ID}":
        local.publish(f"va/{SITE}/config", m.payload, qos=1, retain=True)
        st["ultima_config"] = agora_iso(); log(SRV, "config_repassada", bytes=len(m.payload)); return
    try:
        itens = json.loads(m.payload)["itens"]
        BUF.confirmar([(k, o, int(s)) for k, o, s in itens])
        st["ultimo_ack"] = agora_iso()
    except (ValueError, KeyError, TypeError) as e:
        log(SRV, "ack_invalido", motivo=str(e))

def laco():
    ultimo_log, limpeza = 0, 0
    while True:
        time.sleep(2)
        try:
            if st["conectado_nuvem"]:
                rows = BUF.pendentes(LOTE)
                if rows:
                    itens = [{"kind": k, "origem": o, "seq": s, "uuid": u, "ts": ts, "payload": json.loads(p)}
                             for _, k, o, s, u, ts, p in rows]
                    info = nuvem.publish(f"sync/{ID}/batch", json.dumps({"espaco": SITE, "itens": itens}, ensure_ascii=False), qos=1)
                    if info.rc == 0:
                        BUF.marcar_enviado([r[0] for r in rows])
            if time.time() - limpeza > 3600:
                BUF.limpar(); limpeza = time.time()
            salvar_status()
            if time.time() - ultimo_log > 60:
                log(SRV, "estado", conectado=st["conectado_nuvem"], **BUF.contagens()); ultimo_log = time.time()
        except Exception as e:                     # o laço nunca pode morrer
            log(SRV, "erro_laco", motivo=repr(e))

def main():
    log(SRV, "inicio")
    local.connect_async(os.environ.get("BROKER_HOST", "mosquitto"), int(os.environ.get("BROKER_PORT", "8883"))); local.loop_start()
    nuvem.on_connect, nuvem.on_disconnect, nuvem.on_message = on_connect, on_disconnect, on_message
    nuvem.connect_async(os.environ.get("CENTRAL_HOST", "mqtt-central"), int(os.environ.get("CENTRAL_PORT", "8883")))
    threading.Thread(target=laco, daemon=True).start()
    nuvem.loop_forever(retry_first_connection=True)

if __name__ == "__main__":
    main()
