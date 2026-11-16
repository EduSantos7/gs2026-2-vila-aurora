"""Gera DADOS SINTÉTICOS (nenhuma pessoa real) para o laboratório.
Saídas: db/init/20_seed.sql e dados/crachas.csv. Determinístico (seed=42).
Uso: pip install faker && python dados/gerar_dados.py"""
import csv, random, datetime as dt
from pathlib import Path
from faker import Faker

fk = Faker("pt_BR"); Faker.seed(42); random.seed(42)
ROOT = Path(__file__).resolve().parent.parent
ESPACOS = ["cc", "esc", "ubs", "hrt", "abr"]
FUNCOES = ["voluntário", "técnico", "equipe UBS", "coordenação", "cozinha", "defesa civil", "professor"]

def q(s):  # escapa aspas para SQL literal (gerador offline, não é entrada de usuário)
    return "'" + str(s).replace("'", "''") + "'"

pessoas = []
for i in range(1, 61):
    nome = fk.name()
    pessoas.append({
        "id": i, "nome": nome, "cpf": fk.cpf(), "telefone": fk.cellphone_number(),
        "endereco": fk.street_address() + ", Vila Aurora, Serra Clara/SP",
        "funcao": random.choice(FUNCOES),
        "login": (nome.split()[0] + str(i)).lower().translate(str.maketrans("áâãàéêíóôõúç", "aaaaeeiooouc")),
        "senha": fk.password(length=10, special_chars=False),
        "cracha": f"VA-{100000 + i}",
        "espacos": sorted(random.sample(ESPACOS, k=random.randint(1, 3))),
    })

with open(ROOT / "dados/crachas.csv", "w", newline="", encoding="utf-8") as f:
    w = csv.writer(f, lineterminator="\n"); w.writerow(["cracha_id", "espacos"])
    for p in pessoas[:45]:                      # 45 crachás ativos; os demais foram desligados
        w.writerow([p["cracha"], "|".join(p["espacos"])])

out = ["-- DADOS SINTÉTICOS gerados por dados/gerar_dados.py. Nenhuma pessoa real.",
       "-- ===== Esquema LEGADO (reproduz o INC-VA-0712: senha em texto puro, crachá sem pseudônimo) ====="]
for p in pessoas:
    out.append("INSERT INTO legado.usuarios (nome, cpf, telefone, endereco, funcao, login, senha) VALUES (" +
               ", ".join(q(p[k]) for k in ["nome", "cpf", "telefone", "endereco", "funcao", "login", "senha"]) + ");")
base = dt.datetime(2026, 10, 1, tzinfo=dt.timezone.utc)
for _ in range(600):
    p = random.choice(pessoas)
    t = base + dt.timedelta(minutes=random.randint(0, 60 * 24 * 30))
    ev = random.choice(["entrada", "entrada", "saida", "negado"])
    out.append(f"INSERT INTO legado.acessos (data_hora, cracha, espaco, evento) VALUES ({q(t.isoformat())}, {q(p['cracha'])}, {q(random.choice(p['espacos']))}, {q(ev)});")
out.append("-- ===== Esquema PESSOAL (nova arquitetura: sem acesso pelo painel) =====")
for p in pessoas[:45]:
    out.append(f"INSERT INTO pessoal.voluntarios (nome, funcao, telefone, espacos) VALUES ({q(p['nome'])}, {q(p['funcao'])}, {q(p['telefone'])}, {q('|'.join(p['espacos']))});")
(ROOT / "db/init/20_seed.sql").write_text("\n".join(out) + "\n", encoding="utf-8")
print("ok:", len(pessoas), "pessoas sintéticas")
