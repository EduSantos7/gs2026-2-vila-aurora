"""Painel de supervisão CORRIGIDO (RT-08, RT-09, RT-21).
- consultas parametrizadas (SQLAlchemy text + parâmetros vinculados)
- validação de entrada no servidor por lista de permissão
- usuário de banco painel_app com privilégio mínimo (só visões)
- erros genéricos com código de correlação; detalhes só no log
- RBAC: operador, tecnico, coordenacao, auditor
(O segundo fator - MFA via Keycloak - é adicionado na Parte 2 do protótipo.)"""
import json, os, re, time, uuid, datetime as dt
from functools import wraps
from flask import Flask, abort, flash, g, redirect, render_template, request, session, url_for
from flask_wtf.csrf import CSRFProtect
from sqlalchemy import create_engine, text
from werkzeug.middleware.proxy_fix import ProxyFix
from werkzeug.security import check_password_hash

app = Flask(__name__)
app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1)
app.config.update(SECRET_KEY=os.environ["SECRET_KEY"], SESSION_COOKIE_SECURE=os.environ.get("COOKIE_SECURE", "1") == "1",
                  SESSION_COOKIE_HTTPONLY=True, SESSION_COOKIE_SAMESITE="Strict",
                  PERMANENT_SESSION_LIFETIME=dt.timedelta(hours=8))
CSRFProtect(app)
engine = create_engine(os.environ["DATABASE_URL"], pool_pre_ping=True, pool_size=5)

LOGIN_OK = re.compile(r"[a-z0-9.]{3,32}")
BUSCA_OK = re.compile(r"[A-Za-z0-9\- ]{1,32}")
NOMES = {"cc": "Centro Comunitário", "esc": "Escola Municipal", "ubs": "UBS",
         "hrt": "Horta e Cozinha", "abr": "Abrigo de Emergência"}
falhas = {}                                   # limitação simples de tentativas de login

def log(evento, **campos):
    reg = {"ts": dt.datetime.now(dt.timezone.utc).isoformat(timespec="milliseconds"), "servico": "painel",
           "evento": evento, "ip": request.remote_addr if request else None,
           "usuario": session.get("login"), "papel": session.get("papel"), **campos}
    linha = json.dumps(reg, ensure_ascii=False, default=str)
    print(linha, flush=True)
    try:
        with open("/logs/painel.log", "a", encoding="utf-8") as f: f.write(linha + "\n")
    except OSError:
        pass

def auditar(acao, detalhe=None):
    with engine.begin() as c:
        c.execute(text("INSERT INTO auditoria (login, papel, acao, detalhe) VALUES (:l, :p, :a, CAST(:d AS jsonb))"),
                  {"l": session.get("login"), "p": session.get("papel"), "a": acao, "d": json.dumps(detalhe or {})})

def login_required(f):
    @wraps(f)
    def w(*a, **k):
        if "login" not in session:
            return redirect(url_for("entrar"))
        return f(*a, **k)
    return w

def requer_papel(*papeis):
    def deco(f):
        @wraps(f)
        def w(*a, **k):
            if session.get("papel") not in papeis:
                log("acesso_negado", rota=request.path); abort(403)
            return f(*a, **k)
        return w
    return deco

def descrever(tipo, d):
    try:
        if tipo == "temp_camara":
            return f"Geladeira das vacinas: {d['temp']:.1f} °C", 2 <= d["temp"] <= 8
        if tipo == "nivel": return f"Reservatório: {d['nivel_pct']:.0f}% cheio", d["nivel_pct"] >= 20
        if tipo == "bomba": return ("Bomba de água: LIGADA" if d["ligada"] else "Bomba de água: desligada"), True
        if tipo == "energia":
            return f"Bateria: {d['bateria_pct']:.0f}% · gerador {'ligado' if d['gerador_ligado'] else 'desligado'}", d["bateria_pct"] >= 30
        if tipo == "alagamento": return ("Água no piso do abrigo!" if d["alagado"] else "Piso seco"), not d["alagado"]
        if tipo == "ar": return f"Qualidade do ar: CO₂ {d['co2_ppm']:.0f} ppm", d["co2_ppm"] <= 1500
        if tipo == "umidade_solo": return f"Umidade da terra da horta: {d['umidade']:.0f}%", True
    except (KeyError, TypeError):
        pass
    return "Leitura recebida", True

@app.after_request
def cabecalhos(r):
    r.headers.update({"Content-Security-Policy": "default-src 'self'; frame-ancestors 'none'; form-action 'self'",
                      "X-Content-Type-Options": "nosniff", "Referrer-Policy": "no-referrer",
                      "Cache-Control": "no-store"})
    return r

@app.route("/entrar", methods=["GET", "POST"])
def entrar():
    if request.method == "POST":
        login = request.form.get("login", "").strip().lower()
        senha = request.form.get("senha", "")
        chave = (request.remote_addr, login)
        n, t0 = falhas.get(chave, (0, time.time()))
        if n >= 5 and time.time() - t0 < 300:
            log("login_bloqueado", login_tentado=login[:32])
            flash("Muitas tentativas. Aguarde 5 minutos.")
            return render_template("entrar.html"), 429
        row = None
        if LOGIN_OK.fullmatch(login):
            with engine.connect() as c:
                row = c.execute(text("SELECT senha_hash, papel, espaco FROM autenticar(:l)"), {"l": login}).first()
        if row and check_password_hash(row.senha_hash, senha):
            falhas.pop(chave, None)
            session.clear(); session.permanent = True
            session.update(login=login, papel=row.papel, espaco=row.espaco)
            log("login_ok"); auditar("login")
            return redirect(url_for("inicio"))
        falhas[chave] = (n + 1, t0 if n else time.time())
        log("login_falha", login_tentado=login[:32])
        flash("Usuário ou senha inválidos.")
    return render_template("entrar.html")

@app.route("/sair", methods=["POST"])
def sair():
    log("logout"); session.clear()
    return redirect(url_for("entrar"))

@app.route("/")
@login_required
def inicio():
    esp = session["espaco"] if session["papel"] == "operador" else None
    with engine.connect() as c:
        tel = c.execute(text("SELECT dispositivo_id, espaco, tipo, ts_utc, payload FROM vw_telemetria_ultima "
                             "WHERE (CAST(:e AS text) IS NULL OR espaco = :e) ORDER BY espaco, dispositivo_id"), {"e": esp}).all()
        als = c.execute(text("SELECT ts_utc, espaco, dispositivo, severidade, mensagem FROM vw_alarmes "
                             "WHERE (CAST(:e AS text) IS NULL OR espaco = :e) ORDER BY ts_utc DESC LIMIT 20"), {"e": esp}).all()
    agora = dt.datetime.now(dt.timezone.utc)
    itens = []
    for r in tel:
        txt, ok = descrever(r.tipo, r.payload)
        atraso = (agora - r.ts_utc).total_seconds()
        itens.append({"espaco": NOMES.get(r.espaco, r.espaco), "disp": r.dispositivo_id, "texto": txt,
                      "ok": ok, "hora": r.ts_utc.astimezone().strftime("%d/%m %H:%M:%S"), "atrasado": atraso > 120})
    return render_template("inicio.html", itens=itens, alarmes=als, nomes=NOMES)

@app.route("/historico")
@login_required
@requer_papel("tecnico", "coordenacao", "auditor")
def historico():
    termo = request.args.get("busca", "").strip()
    rows = []
    if termo:
        if not BUSCA_OK.fullmatch(termo):                         # lista de permissão
            log("busca_invalida", termo=termo[:120])
            abort(400, "Busca inválida. Use apenas letras, números e hífen (até 32 caracteres).")
        stmt = text("SELECT data_hora, cracha_pseudo, espaco, evento FROM vw_acessos "
                    "WHERE cracha_pseudo ILIKE :t OR espaco ILIKE :t ORDER BY data_hora DESC LIMIT 200")
        with engine.connect() as c:
            rows = c.execute(stmt, {"t": f"%{termo}%"}).all()     # parâmetro vinculado
        log("busca_historico", termo=termo, resultados=len(rows)); auditar("busca_historico", {"termo": termo})
    return render_template("historico.html", termo=termo, rows=rows, nomes=NOMES)

@app.errorhandler(400)
def e400(e):
    return render_template("erro.html", titulo="Pedido inválido", msg=e.description), 400

@app.errorhandler(403)
def e403(e):
    return render_template("erro.html", titulo="Acesso negado", msg="Seu perfil não tem permissão para esta página."), 403

@app.errorhandler(404)
def e404(e):
    return render_template("erro.html", titulo="Página não encontrada", msg="Confira o endereço."), 404

@app.errorhandler(Exception)
def erro_generico(e):
    cid = uuid.uuid4().hex[:8]
    app.logger.exception("erro cid=%s", cid)                       # detalhe só no log
    log("erro_interno", cid=cid, tipo=type(e).__name__)
    return render_template("erro.html", titulo="Algo deu errado",
                           msg=f"Tente novamente. Se persistir, informe o código {cid} à coordenação."), 500
