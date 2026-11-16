import json, os, ssl, datetime as dt
import paho.mqtt.client as mqtt

def agora_iso():
    return dt.datetime.now(dt.timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")

def log(servico, evento, **campos):
    linha = json.dumps({"ts": agora_iso(), "servico": servico, "evento": evento, **campos}, ensure_ascii=False, default=str)
    print(linha, flush=True)
    try:
        with open(f"/logs/{servico}.log", "a", encoding="utf-8") as f: f.write(linha + "\n")
    except OSError:
        pass

def cliente_mqtt(cid, pki, persistente=False):
    c = mqtt.Client(mqtt.CallbackAPIVersion.VERSION2, client_id=cid, clean_session=not persistente)
    ctx = ssl.create_default_context(ssl.Purpose.SERVER_AUTH, cafile=f"{pki}/ca-chain.crt")
    ctx.minimum_version = ssl.TLSVersion.TLSv1_3
    ctx.load_cert_chain(f"{pki}/client.crt", f"{pki}/client.key")
    c.tls_set_context(ctx); c.reconnect_delay_set(1, 30)
    return c
