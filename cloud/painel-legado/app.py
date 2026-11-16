"""PAINEL LEGADO - VULNERÁVEL DE PROPÓSITO (reprodução do INC-VA-0712).
Falhas reproduzidas: (1) SQL montado por concatenação; (2) conexão como SUPERUSUÁRIO;
(3) erro do banco devolvido ao navegador; (4) sem autenticação própria (confiava na VPN).
NÃO usar fora do laboratório isolado."""
import os, html, psycopg
from flask import Flask, request

app = Flask(__name__)
DSN = os.environ["LEGADO_DSN"]
PAG = """<!doctype html><html lang="pt-BR"><head><meta charset="utf-8"><title>Supervisão (legado)</title></head>
<body style="font-family:Arial"><h1>Painel de Supervisão – versão legada</h1>
<p><a href="/">Início</a> · <a href="/historico">Histórico de acessos</a> · <a href="/agenda">Agenda da bomba</a></p>{}</body></html>"""

def tabela(rows):
    return "<table border=1>" + "".join("<tr>" + "".join(f"<td>{html.escape(str(c))}</td>" for c in r) + "</tr>" for r in rows) + "</table>"

@app.route("/")
def inicio():
    return PAG.format("<p>Sistema legado. Acesso via VPN.</p>")

@app.route("/historico")
def historico():
    termo = request.args.get("busca", "")
    form = f'<form><label>Crachá: <input name="busca" value="{html.escape(termo)}"></label> <button>Buscar</button></form>'
    if not termo:
        return PAG.format(form)
    sql = ("SELECT data_hora, cracha, espaco, evento FROM legado.acessos "
           f"WHERE cracha LIKE '%{termo}%' ORDER BY data_hora DESC LIMIT 50")      # VULNERÁVEL
    try:
        with psycopg.connect(DSN, autocommit=True) as db:                          # superusuário
            cur = db.execute(sql)
            rows = cur.fetchall() if cur.description else []
    except Exception as e:
        return PAG.format(form + f"<pre>Erro: {html.escape(str(e))}\nSQL: {html.escape(sql)}</pre>"), 500   # vaza detalhes
    return PAG.format(form + tabela(rows))

@app.route("/agenda")
def agenda():
    with psycopg.connect(DSN) as db:
        rows = db.execute("SELECT espaco, janelas, versao, atualizado_em FROM agenda_bomba").fetchall()
    return PAG.format(tabela(rows))
