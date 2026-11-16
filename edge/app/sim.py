"""Simulador dos dispositivos de campo de um espaço. Cada dispositivo usa
SEU PRÓPRIO certificado X.509 (identidade única, sem segredo compartilhado).
Física simplificada: reservatório/bomba, câmara fria, baterias/gerador, ar, alagamento."""
import csv, json, math, os, random, threading, time
from datetime import datetime
from zoneinfo import ZoneInfo
from .common import SITE, agora_iso, cliente_mqtt, log, novo_uuid

SRV = "simulador"
PKI = os.environ.get("PKI_DIR", "/pki")
STATE = os.environ.get("STATE_DIR", "/state")
INTERVALO = float(os.environ.get("SIM_INTERVAL", "10"))
VEL = float(os.environ.get("SIM_SPEED", "1"))           # >1 acelera a física para demonstrações
TZ = ZoneInfo("America/Sao_Paulo")
lock = threading.Lock()
mundo = {"nivel": {}, "bomba": {}, "temp": 5.0, "temp_alvo": 5.0, "bateria": {}, "gerador": {},
         "alagado": False, "co2": {}, "umid": {}, "solo": {}}

def ler_csv(p):
    return list(csv.DictReader(open(p, encoding="utf-8")))

DEVS = [d for d in ler_csv(os.environ.get("DEVICES_CSV", "/config/devices.csv")) if d["espaco"] == SITE]
CRACHAS = [r["cracha_id"] for r in ler_csv(os.environ.get("CRACHAS_CSV", "/config/crachas.csv"))
           if SITE in r["espacos"].split("|")]

class Disp:
    def __init__(self, dev, tipo):
        self.dev, self.tipo = dev, tipo
        self.seqf = os.path.join(STATE, f"{dev}.seq")
        try: self.seq = int(open(self.seqf).read())
        except (OSError, ValueError): self.seq = 0
        self.c = cliente_mqtt(dev, f"{PKI}/ca-chain.crt", f"{PKI}/{dev}.crt", f"{PKI}/{dev}.key")
        self.c.on_connect = lambda c, u, f, rc, p: (log(SRV, "dispositivo_conectado", dispositivo=dev, rc=str(rc)),
            c.subscribe([(f"va/{SITE}/{dev}/cmd", 1), (f"va/{SITE}/{dev}/sim", 1)]))
        self.c.on_message = self.on_message
        self.c.connect_async(os.environ.get("BROKER_HOST", "mosquitto"), int(os.environ.get("BROKER_PORT", "8883")))
        self.c.loop_start()

    def publicar(self, dados):
        self.seq += 1
        open(self.seqf, "w").write(str(self.seq))
        msg = {"dev": self.dev, "seq": self.seq, "uuid": novo_uuid(), "ts": agora_iso(), "tipo": self.tipo, "dados": dados}
        self.c.publish(f"va/{SITE}/{self.dev}/tele", json.dumps(msg, ensure_ascii=False), qos=1)

    def on_message(self, c, u, m):
        try: msg = json.loads(m.payload)
        except ValueError: return
        if m.topic.endswith("/sim"):                       # injeção de falhas (somente laboratório)
            with lock:
                for k, v in msg.items():
                    if k in ("nivel", "bateria", "co2"): mundo[k][self.dev] = float(v)
                    elif k == "temp_alvo": mundo["temp_alvo"] = float(v)
                    elif k == "alagado": mundo["alagado"] = bool(v)
            log(SRV, "falha_injetada", dispositivo=self.dev, valores=msg); return
        if float(msg.get("exp", 0)) < time.time():
            log(SRV, "comando_expirado_descartado", dispositivo=self.dev, acao=msg.get("acao")); return
        acao = msg.get("acao")
        with lock:
            if acao in ("ligar", "desligar") and self.tipo == "bomba":
                mundo["bomba"][self.dev] = acao == "ligar"
            elif acao in ("ligar_gerador", "desligar_gerador"):
                mundo["gerador"][self.dev] = acao == "ligar_gerador"
        log(SRV, "comando_executado", dispositivo=self.dev, acao=acao, origem=msg.get("origem"), motivo=msg.get("motivo"))

    def leitura(self):
        with lock:
            if self.tipo == "nivel": return {"nivel_pct": round(mundo["nivel"][self.dev], 1)}
            if self.tipo == "bomba":
                on = mundo["bomba"][self.dev]
                return {"ligada": on, "corrente_a": round(random.gauss(4.2, 0.1), 2) if on else 0.0}
            if self.tipo == "temp_camara": return {"temp": round(mundo["temp"], 2)}
            if self.tipo == "energia":
                return {"bateria_pct": round(mundo["bateria"][self.dev], 1), "solar_w": round(solar(), 0),
                        "gerador_ligado": mundo["gerador"][self.dev]}
            if self.tipo == "alagamento": return {"alagado": mundo["alagado"]}
            if self.tipo == "ar": return {"co2_ppm": round(mundo["co2"][self.dev]), "umidade": round(mundo["umid"][self.dev], 1)}
            if self.tipo == "umidade_solo": return {"umidade": round(mundo["solo"][self.dev], 1)}
        return None

def solar():
    h = datetime.now(TZ).hour + datetime.now(TZ).minute / 60
    return max(0.0, 800 * math.sin(math.pi * (h - 6) / 12)) if 6 <= h <= 18 else 0.0

def fisica():
    while True:
        time.sleep(1)
        dt = VEL
        with lock:
            bombas = any(mundo["bomba"].values())
            for d in mundo["nivel"]:
                n = mundo["nivel"][d]
                n += (0.03 if n < 95 else 0) * dt                    # boia da rede municipal
                n -= (0.05 if (bombas and SITE == "esc") else random.uniform(0, 0.01)) * dt
                mundo["nivel"][d] = min(100.0, max(0.0, n))
                if mundo["nivel"][d] <= 0:
                    for b in mundo["bomba"]: mundo["bomba"][b] = False   # bomba seca / proteção térmica
            mundo["temp"] += (mundo["temp_alvo"] - mundo["temp"]) * 0.01 * dt + random.gauss(0, 0.02)
            for d in mundo["bateria"]:
                ganho = solar() - 300 + (600 if mundo["gerador"][d] else 0)
                mundo["bateria"][d] = min(100.0, max(0.0, mundo["bateria"][d] + ganho / 200000 * dt))
            for d in mundo["co2"]:
                mundo["co2"][d] += (650 - mundo["co2"][d]) * 0.002 * dt + random.gauss(0, 3)
                mundo["umid"][d] = min(95, max(30, mundo["umid"][d] + random.gauss(0, 0.1)))
            for d in mundo["solo"]:
                mundo["solo"][d] = min(90, max(10, mundo["solo"][d] + random.gauss(-0.005, 0.05)))

def portaria(disp):
    while True:
        time.sleep(random.uniform(20, 90) / VEL)
        cracha = random.choice(CRACHAS) if (CRACHAS and random.random() < 0.9) else f"VA-{random.randint(900000, 999999)}"
        disp.publicar({"cracha": cracha})                     # o número só trafega na VLAN IoT

def main():
    os.makedirs(STATE, exist_ok=True)
    for d in DEVS:
        k, t = d["dispositivo"], d["tipo"]
        if t == "nivel": mundo["nivel"][k] = 70.0
        if t == "bomba": mundo["bomba"][k] = False
        if t == "energia": mundo["bateria"][k] = 70.0; mundo["gerador"][k] = False
        if t == "ar": mundo["co2"][k] = 650.0; mundo["umid"][k] = 60.0
        if t == "umidade_solo": mundo["solo"][k] = 55.0
    disps = [Disp(d["dispositivo"], d["tipo"]) for d in DEVS]
    log(SRV, "inicio", dispositivos=[d.dev for d in disps], velocidade=VEL)
    threading.Thread(target=fisica, daemon=True).start()
    for d in disps:
        if d.tipo == "porta":
            threading.Thread(target=portaria, args=(d,), daemon=True).start()
    while True:
        for d in disps:
            dados = d.leitura()
            if dados is not None:
                d.publicar(dados)
        time.sleep(INTERVALO)

if __name__ == "__main__":
    main()
