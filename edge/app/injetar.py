"""Injeta falhas SIMULADAS em um dispositivo (somente laboratório).
Ex.: python -m app.injetar ubs-temp-01 '{"temp_alvo": 12}'"""
import json, os, sys, time
from .common import SITE, cliente_mqtt
dev, valores = sys.argv[1], json.loads(sys.argv[2])
PKI = os.environ.get("PKI_DIR", "/pki")
c = cliente_mqtt(f"lab-injetor-{SITE}", f"{PKI}/ca-chain.crt", f"{PKI}/lab-injetor.crt", f"{PKI}/lab-injetor.key")
c.connect(os.environ.get("BROKER_HOST", "mosquitto"), int(os.environ.get("BROKER_PORT", "8883"))); c.loop_start()
c.publish(f"va/{SITE}/{dev}/sim", json.dumps(valores), qos=1).wait_for_publish(5)
print("injetado:", dev, valores); time.sleep(0.5); c.loop_stop()
