"""Buffer store-and-forward em SQLite (WAL). Tudo que chega à borda é gravado
antes de ser encaminhado; só é apagado depois da confirmação da nuvem."""
import json, sqlite3, threading, time

SCHEMA = """
CREATE TABLE IF NOT EXISTS msgs (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  kind TEXT NOT NULL,            -- tele | alarme | acesso
  origem TEXT NOT NULL,          -- dispositivo ou edge-<espaço>
  seq INTEGER NOT NULL,
  uuid TEXT NOT NULL,
  ts TEXT NOT NULL,
  payload TEXT NOT NULL,
  acked INTEGER NOT NULL DEFAULT 0,
  sent_at REAL,
  criado_em REAL NOT NULL,
  UNIQUE (kind, origem, seq)
);
CREATE INDEX IF NOT EXISTS msgs_pend ON msgs (acked, id);
CREATE TABLE IF NOT EXISTS contador (origem TEXT PRIMARY KEY, seq INTEGER NOT NULL);
"""

class Buffer:
    def __init__(self, path):
        self.db = sqlite3.connect(path, timeout=30, isolation_level=None, check_same_thread=False)
        self.db.execute("PRAGMA journal_mode=WAL")
        self.db.execute("PRAGMA synchronous=NORMAL")
        self.db.executescript(SCHEMA)
        self.lk = threading.RLock()

    def gravar(self, kind, origem, seq, uuid, ts, payload):
        with self.lk:
            cur = self.db.execute(
                "INSERT OR IGNORE INTO msgs (kind, origem, seq, uuid, ts, payload, criado_em) VALUES (?,?,?,?,?,?,?)",
                (kind, origem, int(seq), uuid, ts, json.dumps(payload, ensure_ascii=False), time.time()))
            return cur.rowcount == 1          # False = duplicata (reenvio do dispositivo)

    def proximo_seq(self, origem):
        with self.lk:
            self.db.execute("BEGIN IMMEDIATE")
            row = self.db.execute("SELECT seq FROM contador WHERE origem=?", (origem,)).fetchone()
            seq = (row[0] if row else 0) + 1
            self.db.execute("INSERT INTO contador (origem, seq) VALUES (?, ?) ON CONFLICT(origem) DO UPDATE SET seq=excluded.seq", (origem, seq))
            self.db.execute("COMMIT")
            return seq

    def pendentes(self, limite=200, reenviar_apos=30):
        with self.lk:
            return self.db.execute(
                "SELECT id, kind, origem, seq, uuid, ts, payload FROM msgs WHERE acked=0 "
                "AND (sent_at IS NULL OR sent_at < ?) ORDER BY id LIMIT ?",
                (time.time() - reenviar_apos, limite)).fetchall()

    def marcar_enviado(self, ids):
        with self.lk:
            self.db.executemany("UPDATE msgs SET sent_at=? WHERE id=?", [(time.time(), i) for i in ids])

    def confirmar(self, chaves):
        with self.lk:
            self.db.executemany("UPDATE msgs SET acked=1 WHERE kind=? AND origem=? AND seq=?", chaves)

    def contagens(self):
        with self.lk:
            r = self.db.execute("SELECT SUM(acked=0), SUM(acked=1), COUNT(*) FROM msgs").fetchone()
            return {"pendentes": r[0] or 0, "confirmadas": r[1] or 0, "total": r[2] or 0}

    def limpar(self, dias=7):
        with self.lk:
            self.db.execute("DELETE FROM msgs WHERE acked=1 AND criado_em < ?", (time.time() - dias * 86400,))

    def reabrir_pendentes(self):
        with self.lk:
            self.db.execute("UPDATE msgs SET sent_at=NULL WHERE acked=0")
