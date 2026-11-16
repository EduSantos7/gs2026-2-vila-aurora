"""Gera TODOS os segredos do laboratório dentro de ./secrets (ignorado pelo Git).
Executado por scripts/gen-secrets.sh dentro do container de ferramentas.
Idempotente: não sobrescreve o que já existe."""
import csv, hashlib, hmac, os, secrets, shutil, stat, subprocess
from pathlib import Path
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from werkzeug.security import generate_password_hash

W = Path("/w"); S = W / "secrets"; PKI = S / "pki"
SITES = ["cc", "esc", "ubs", "hrt", "abr"]

def run(*a, **env):
    subprocess.run(["bash", str(W / "pki/pki.sh"), *a], check=True, env={**os.environ, **env})

def issued(cn): return PKI / "issued" / cn

def place(cn, dest_dir, name):
    dest_dir.mkdir(parents=True, exist_ok=True)
    shutil.copy(issued(cn) / f"{cn}.crt", dest_dir / f"{name}.crt")
    shutil.copy(issued(cn) / f"{cn}.key", dest_dir / f"{name}.key")
    os.chmod(dest_dir / f"{name}.key", 0o644)   # lab: lido por processos não-root nos containers
    shutil.copy(PKI / "ca-chain.crt", dest_dir / "ca-chain.crt")

def senha(n=20): return secrets.token_urlsafe(n).replace("-", "x").replace("_", "y")

def main():
    S.mkdir(exist_ok=True); os.chmod(S, 0o700)
    # ---------------- PKI ----------------
    run("init")
    devices = list(csv.DictReader(open(W / "infra/sites/devices.csv", encoding="utf-8")))
    for s in SITES:
        run("issue", f"mosquitto-{s}", "server", "DNS:mosquitto,DNS:localhost")
        for cn in (f"edge-rules-{s}", f"sync-{s}", f"edge-{s}", f"lab-injetor-{s}"):
            run("issue", cn, "client")
        for d in devices:
            if d["espaco"] == s:
                run("issue", d["dispositivo"], "client")
    run("issue", "mqtt-central", "server", "DNS:mqtt-central,DNS:localhost")
    run("issue", "painel.lab", "server", "DNS:localhost,DNS:painel.lab,IP:127.0.0.1")
    for cn in ("svc-ingest", "svc-config"):
        run("issue", cn, "client")
    # Organiza: cada serviço monta SOMENTE o que precisa
    for s in SITES:
        base = PKI / "sites" / s
        place(f"mosquitto-{s}", base / "broker", "server")
        place(f"edge-rules-{s}", base / "edge-rules", "client")
        place(f"sync-{s}", base / "sync", "local"); place(f"edge-{s}", base / "sync", "central")
        place(f"lab-injetor-{s}", base / "devices", "lab-injetor")
        for d in devices:
            if d["espaco"] == s:
                place(d["dispositivo"], base / "devices", d["dispositivo"])
    c = PKI / "cloud"
    place("mqtt-central", c / "broker", "server"); place("svc-ingest", c / "ingest", "client")
    place("svc-config", c / "config", "client"); place("painel.lab", c / "waf", "server")
    run("crl")
    for b in [c / "broker"] + [PKI / "sites" / s / "broker" for s in SITES]:
        shutil.copy(PKI / "crl/crl.pem", b / "crl.pem")

    # ---------------- Chaves de aplicação ----------------
    k = S / "keys"; k.mkdir(exist_ok=True)
    if not (k / "hmac.key").exists():
        (k / "hmac.key").write_text(secrets.token_hex(32))
    if not (k / "config-sign.key").exists():
        sk = Ed25519PrivateKey.generate()
        (k / "config-sign.key").write_bytes(sk.private_bytes(serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
        (k / "config-sign.pub").write_bytes(sk.public_key().public_bytes(serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo))
    for f in k.iterdir(): os.chmod(f, 0o644)

    # ---------------- Banco e aplicações ----------------
    if not (S / "db.env").exists():
        pg, pa, ia, ca = senha(), senha(), senha(), senha()
        (S / "db.env").write_text(f"POSTGRES_DB=vilaaurora\nPOSTGRES_USER=postgres\nPOSTGRES_PASSWORD={pg}\n"
                                  f"PAINEL_DB_PASS={pa}\nINGEST_DB_PASS={ia}\nCONFIG_DB_PASS={ca}\n")
        (S / "cloud.env").write_text(f"INGEST_DSN=postgresql://ingest_app:{ia}@postgres:5432/vilaaurora\n"
                                     f"CONFIG_DSN=postgresql://config_app:{ca}@postgres:5432/vilaaurora\n")
        (S / "painel.env").write_text(f"DATABASE_URL=postgresql+psycopg://painel_app:{pa}@postgres:5432/vilaaurora\n"
                                      f"SECRET_KEY={secrets.token_hex(32)}\n")
        # o LEGADO conecta como SUPERUSUÁRIO: é exatamente a falha a ser demonstrada
        (S / "legado.env").write_text(f"LEGADO_DSN=postgresql://postgres:{pg}@postgres:5432/vilaaurora\n")
    seed = S / "db/seed"; seed.mkdir(parents=True, exist_ok=True)
    if not (seed / "operadores.sql").exists():
        users = [("op.ubs", "operador", "ubs"), ("op.esc", "operador", "esc"), ("tecnico1", "tecnico", None),
                 ("tecnico2", "tecnico", None), ("coord1", "coordenacao", None), ("auditor1", "auditor", None)]
        sql, txt = [], ["# Usuários do painel (LAB). Senhas aleatórias; NÃO versionar.\n"]
        for login, papel, esp in users:
            pw = senha(9)
            esp_sql = f"'{esp}'" if esp else "NULL"
            sql.append(f"INSERT INTO operadores (login, senha_hash, papel, espaco) VALUES "
                       f"('{login}', '{generate_password_hash(pw)}', '{papel}', {esp_sql});")
            txt.append(f"{login:10s} {papel:12s} {pw}\n")
        (seed / "operadores.sql").write_text("\n".join(sql) + "\n")
        (S / "usuarios-lab.txt").write_text("".join(txt))
    key = (k / "hmac.key").read_text().strip().encode()
    rows = []
    for r in csv.DictReader(open(W / "dados/crachas.csv", encoding="utf-8")):
        p = hmac.new(key, r["cracha_id"].encode(), hashlib.sha256).hexdigest()[:24]
        rows += [f"INSERT INTO crachas_autorizados (cracha_pseudo, espaco) VALUES ('{p}', '{e}') ON CONFLICT DO NOTHING;"
                 for e in r["espacos"].split("|")]
    (seed / "crachas.sql").write_text("\n".join(rows) + "\n")
    for f in seed.iterdir(): os.chmod(f, 0o644)
    print("\n[ok] Segredos prontos em ./secrets  |  CA raiz OFFLINE em", os.environ.get("ROOT_DIR", "/root-offline"))
    print("[ok] Senhas do painel em secrets/usuarios-lab.txt")

if __name__ == "__main__":
    main()
