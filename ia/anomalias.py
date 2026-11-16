"""RT-16: detecção de anomalias na telemetria com Isolation Forest (dados 100% sintéticos).
Treino: 14 dias normais (1 leitura/min). Teste: 7 dias com anomalias injetadas e rotuladas:
  A1 bomba ligada de madrugada esvaziando o reservatório (reprodução do INC-VA-0712)
  A2 deriva lenta de temperatura da câmara fria
  A3 sensor de temperatura travado (valor constante)
  A4 leituras forjadas (picos isolados de temperatura e nível)
Uso: python3 ia/anomalias.py  ->  imprime e grava ia/resultados.json"""
import json, numpy as np, pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.metrics import precision_score, recall_score, confusion_matrix

RNG = np.random.default_rng(42)
FEATS = ["nivel_pct", "delta_nivel_10min", "bomba_ligada", "corrente_a", "temp_camara", "hora_sen", "hora_cos"]

def gerar(dias, inicio="2026-10-01"):
    t = pd.date_range(inicio, periods=dias * 1440, freq="min")
    h = t.hour + t.minute / 60
    bomba = (((h >= 7) & (h < 7 + 40 / 60)) | ((h >= 16) & (h < 16 + 40 / 60))).astype(int)
    nivel = np.empty(len(t)); n = 80.0
    for i in range(len(t)):
        n += 0.6 * (n < 95) - 1.2 * bomba[i] - RNG.uniform(0, 0.15)        # boia, bomba, consumo (%/min)
        n = min(100, max(0, n)); nivel[i] = n
    temp = 5 + RNG.normal(0, 0.15, len(t))
    portas = RNG.random(len(t)) < (0.02 * ((h > 8) & (h < 17)))           # abertura da geladeira em horário de UBS
    for i in np.where(portas)[0]: temp[i:i + 6] += np.linspace(1.5, 0.2, len(temp[i:i + 6]))
    df = pd.DataFrame({"ts": t, "nivel_pct": nivel, "bomba_ligada": bomba,
                       "corrente_a": bomba * RNG.normal(4.2, 0.08, len(t)), "temp_camara": temp,
                       "hora_sen": np.sin(2 * np.pi * h / 24), "hora_cos": np.cos(2 * np.pi * h / 24), "anomalia": 0, "cenario": ""})
    return df

def recalcula(df):
    df["delta_nivel_10min"] = df["nivel_pct"].diff(10).fillna(0); return df

def injeta(df):
    eventos = []
    def marca(a, b, nome): df.loc[a:b - 1, ["anomalia", "cenario"]] = [1, nome]; eventos.append((nome, a, b))
    dia = 1440
    # A1: dias 1 e 4, bomba das 01:00 às 03:00 (como a agenda forjada)
    for d in (1, 4):
        a, b = d * dia + 60, d * dia + 180
        df.loc[a:b - 1, "bomba_ligada"] = 1; df.loc[a:b - 1, "corrente_a"] = RNG.normal(4.2, 0.08, b - a)
        n = df.loc[a - 1, "nivel_pct"]
        for i in range(a, b): n = max(0, n - 1.2 + 0.6 * (n < 95) - 0.1); df.loc[i, "nivel_pct"] = n
        for i in range(b, b + 300): n = min(100, n + 0.5); df.loc[i, "nivel_pct"] = max(df.loc[i, "nivel_pct"], 0) if False else n
        marca(a, b, "A1 bomba noturna")
    # A2: dia 2, deriva de +0,5 °C/h por 6 h a partir das 10:00
    a = 2 * dia + 600; b = a + 360
    df.loc[a:b - 1, "temp_camara"] += np.linspace(0, 3.0, b - a); marca(a, b, "A2 deriva lenta de temperatura")
    # A3: dia 3, sensor travado em 5,0 °C por 2 h
    a = 3 * dia + 840; b = a + 120; df.loc[a:b - 1, "temp_camara"] = 5.0; marca(a, b, "A3 sensor travado")
    # A4: dias 5 e 6, 10 leituras forjadas isoladas
    for i in RNG.choice(np.arange(5 * dia, 7 * dia), 10, replace=False):
        if RNG.random() < 0.5: df.loc[i, "temp_camara"] = RNG.uniform(14, 18)
        else: df.loc[i, "nivel_pct"] = RNG.uniform(0, 5)
        marca(i, i + 1, "A4 leituras forjadas")
    return df, eventos

treino = recalcula(gerar(14))
teste, eventos = injeta(gerar(7, "2026-10-20")); teste = recalcula(teste)
modelo = IsolationForest(n_estimators=200, contamination=0.01, random_state=42).fit(treino[FEATS])
teste["pred"] = (modelo.predict(teste[FEATS]) == -1).astype(int)
y, p = teste["anomalia"], teste["pred"]
tn, fp, fn, tp = confusion_matrix(y, p).ravel()
res = {"amostras_treino": len(treino), "amostras_teste": len(teste), "anomalas_teste": int(y.sum()),
       "precisao": round(precision_score(y, p), 3), "revocacao": round(recall_score(y, p), 3),
       "fpr": round(fp / (fp + tn), 4), "vp": int(tp), "fp": int(fp), "fn": int(fn), "vn": int(tn), "cenarios": {}}
for nome in sorted({e[0] for e in eventos}):
    evs = [e for e in eventos if e[0] == nome]; det, tempos = 0, []
    for _, a, b in evs:
        hit = np.where(teste.loc[a:b - 1, "pred"].values == 1)[0]
        if len(hit): det += 1; tempos.append(int(hit[0]))
    rec = teste[teste.cenario == nome]
    res["cenarios"][nome] = {"eventos": len(evs), "detectados": det, "revocacao_pontos": round(rec["pred"].mean(), 3),
                             "min_ate_detectar": tempos}
print(json.dumps(res, ensure_ascii=False, indent=1))
json.dump(res, open(__file__.replace("anomalias.py", "resultados.json"), "w"), ensure_ascii=False, indent=1)

# ---------------- Comparação: IF + regras determinísticas da borda ----------------
h = teste["ts"].dt.hour + teste["ts"].dt.minute / 60
na_agenda = ((h >= 7) & (h < 7 + 40 / 60)) | ((h >= 16) & (h < 16 + 40 / 60))
regras = ((teste["temp_camara"] < 2) | (teste["temp_camara"] > 8)                      # faixa da câmara fria
          | ((teste["bomba_ligada"] == 1) & ~na_agenda)                                # bomba fora da agenda (regra d)
          | (teste["temp_camara"].rolling(30).std().fillna(1) < 0.01)                 # sensor travado
          | (teste["nivel_pct"].diff().abs().fillna(0) > 20)).astype(int)             # salto físico impossível
teste["hibrido"] = ((teste["pred"] == 1) | (regras == 1)).astype(int)
p2 = teste["hibrido"]; tn2, fp2, fn2, tp2 = confusion_matrix(y, p2).ravel()
res["hibrido"] = {"precisao": round(precision_score(y, p2), 3), "revocacao": round(recall_score(y, p2), 3),
                  "fpr": round(fp2 / (fp2 + tn2), 4), "cenarios": {}}
for nome in sorted({e[0] for e in eventos}):
    evs = [e for e in eventos if e[0] == nome]; det, tempos = 0, []
    for _, a, b in evs:
        hit = np.where(teste.loc[a:b - 1, "hibrido"].values == 1)[0]
        if len(hit): det += 1; tempos.append(int(hit[0]))
    res["hibrido"]["cenarios"][nome] = {"eventos": len(evs), "detectados": det, "min_ate_detectar": tempos}
print("HÍBRIDO:", json.dumps(res["hibrido"], ensure_ascii=False))
json.dump(res, open(__file__.replace("anomalias.py", "resultados.json"), "w"), ensure_ascii=False, indent=1)
