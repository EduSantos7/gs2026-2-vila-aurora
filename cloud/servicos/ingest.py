"""Ingestão idempotente na nuvem: recebe lotes das bordas, grava com
ON CONFLICT DO NOTHING (reenvio não duplica) e devolve confirmação (ack).
Rejeita itens de outro espaço (uma borda não pode se passar por outra)."""
import json, os, psycopg
from comum import cliente_mqtt, log

SRV = "ingest"
DSN = os.environ["INGEST_DSN"]
db = psycopg.connect(DSN, autocommit=False)

SQL = {
 "tele": ("INSERT INTO telemetria (dispositivo_id, seq, msg_uuid, ts_utc, espaco, tipo, payload) "
          "VALUES (%(origem)s, %(seq)s, %(uuid)s, %(ts)s, %(espaco)s, %(tipo)s, %(dados)s) ON CONFLICT DO NOTHING"),
 "alarme": ("INSERT INTO alarmes (origem, seq, msg_uuid, ts_utc, espaco, dispositivo, severidade, mensagem) "
            "VALUES (%(origem)s, %(seq)s, %(uuid)s, %(ts)s, %(espaco)s, %(dispositivo)s, %(severidade)s, %(mensagem)s) ON CONFLICT DO NOTHING"),
 "acesso": ("INSERT INTO acessos (origem, seq, msg_uuid, ts_utc, espaco, dispositivo, cracha_pseudo, evento) "
            "VALUES (%(origem)s, %(seq)s, %(uuid)s, %(ts)s, %(espaco)s, %(dispositivo)s, %(cracha_pseudo)s, %(evento)s) ON CONFLICT DO NOTHING"),
}

def on_connect(c, u, f, rc, p):
    log(SRV, "mqtt_conectado", rc=str(rc)); c.subscribe("sync/+/batch", qos=1)

def on_message(c, u, m):
    global db
    edge = m.topic.split("/")[1]                       # CN autenticado pelo mTLS + ACL
    espaco = edge.removeprefix("edge-")
    try:
        itens = json.loads(m.payload)["itens"]
    except (ValueError, KeyError):
        log(SRV, "lote_invalido", edge=edge); return
    ack, novos, rejeitados = [], 0, 0
    try:
        with db.cursor() as cur:
            for it in itens:
                k, origem, p = it.get("kind"), str(it.get("origem")), it.get("payload") or {}
                if k not in SQL or not (origem == edge or origem.startswith(espaco + "-")):
                    rejeitados += 1; continue
                params = {"origem": origem, "seq": int(it["seq"]), "uuid": it["uuid"], "ts": it["ts"], "espaco": espaco}
                if k == "tele":
                    params.update(tipo=p.get("tipo"), dados=json.dumps(p.get("dados"), ensure_ascii=False))
                else:
                    params.update({x: p.get(x) for x in ("dispositivo", "severidade", "mensagem", "cracha_pseudo", "evento")})
                cur.execute(SQL[k], params)
                novos += cur.rowcount
                ack.append([k, origem, params["seq"]])
        db.commit()
    except psycopg.Error as e:
        log(SRV, "erro_banco", edge=edge, motivo=type(e).__name__)
        try: db.rollback()
        except psycopg.Error: db = psycopg.connect(DSN, autocommit=False)
        return                                            # sem ack: a borda reenviará
    c.publish(f"sync/{edge}/ack", json.dumps({"itens": ack}), qos=1)
    log(SRV, "lote", edge=edge, recebidos=len(itens), novos=novos, duplicados=len(ack) - novos, rejeitados=rejeitados)
    if rejeitados:
        log(SRV, "itens_de_outro_espaco_rejeitados", edge=edge, quantidade=rejeitados)

c = cliente_mqtt("svc-ingest", os.environ.get("PKI_DIR", "/pki"), persistente=True)
c.on_connect, c.on_message = on_connect, on_message
c.connect_async(os.environ.get("CENTRAL_HOST", "mqtt-central"), int(os.environ.get("CENTRAL_PORT", "8883")))
log(SRV, "inicio")
c.loop_forever(retry_first_connection=True)
