"""Funções comuns aos serviços da borda."""
import json, os, ssl, sys, time, uuid, datetime as dt
import paho.mqtt.client as mqtt

SITE = os.environ.get("SITE", "ubs")
NOMES = {"cc": "Centro Comunitário", "esc": "Escola Municipal", "ubs": "UBS",
         "hrt": "Horta e Cozinha Solidária", "abr": "Abrigo de Emergência"}
LOG_DIR = os.environ.get("LOG_DIR", "/logs")

def agora_iso():
    return dt.datetime.now(dt.timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")

def log(servico, evento, **campos):
    """Log estruturado em JSON (UTC, ISO 8601) para stdout e arquivo (lido pelo Wazuh)."""
    reg = {"ts": agora_iso(), "servico": servico, "espaco": SITE, "evento": evento, **campos}
    linha = json.dumps(reg, ensure_ascii=False)
    print(linha, flush=True)
    try:
        os.makedirs(LOG_DIR, exist_ok=True)
        with open(os.path.join(LOG_DIR, f"{servico}.log"), "a", encoding="utf-8") as f:
            f.write(linha + "\n")
    except OSError:
        pass

def cliente_mqtt(client_id, cafile, certfile, keyfile, persistente=False):
    """Cliente MQTT com mTLS: verifica o servidor e apresenta certificado próprio.
    persistente=True: o broker guarda as mensagens QoS 1 enquanto o cliente reconecta."""
    c = mqtt.Client(mqtt.CallbackAPIVersion.VERSION2, client_id=client_id, clean_session=not persistente)
    ctx = ssl.create_default_context(ssl.Purpose.SERVER_AUTH, cafile=cafile)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_3
    ctx.load_cert_chain(certfile, keyfile)
    c.tls_set_context(ctx)
    c.reconnect_delay_set(min_delay=1, max_delay=30)
    return c

def novo_uuid():
    return str(uuid.uuid4())

def canonico(obj):
    """Serialização canônica usada na assinatura de configurações."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()
