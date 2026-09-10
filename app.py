from flask import Flask, jsonify, render_template, request, redirect, url_for, flash
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from cryptography.fernet import Fernet, InvalidToken
from iqoptionapi.stable_api import IQ_Option
import time
import os
import threading

app = Flask(__name__)
app.config["SECRET_KEY"] = os.environ.get("SECRET_KEY", "troque-esta-chave-em-producao")

# ---------------------------------------------------------------------------
# Criptografia das senhas da IQ Option de cada usuário — a senha do
# dashboard (Usuario.senha_hash) usa hash (não dá pra reverter, só compara).
# Já a senha da IQ Option de cada um precisa ser RECUPERÁVEL (a gente
# precisa da senha de verdade pra logar na IQ Option toda vez que a pessoa
# for comprar/vender), então usa criptografia reversível (Fernet) em vez de
# hash. A chave PRECISA vir de uma variável de ambiente fixa (IQ_CRED_KEY) —
# se ela mudar ou sumir, todas as senhas já guardadas ficam ilegíveis pra
# sempre (a pessoa precisaria cadastrar de novo).
_IQ_CRED_KEY = os.environ.get("IQ_CRED_KEY")
if not _IQ_CRED_KEY:
    _IQ_CRED_KEY = Fernet.generate_key().decode()
    print("AVISO: variável de ambiente IQ_CRED_KEY não definida — gerei uma "
          "chave temporária só pra essa execução. Defina IQ_CRED_KEY no "
          "Render com um valor fixo, senão toda vez que o servidor reiniciar "
          "as senhas da IQ Option já cadastradas por cada usuário deixam de "
          "funcionar (a pessoa precisa cadastrar de novo). Gere uma chave "
          "com: python3 -c \"from cryptography.fernet import Fernet; "
          "print(Fernet.generate_key().decode())\"")
_fernet = Fernet(_IQ_CRED_KEY.encode() if isinstance(_IQ_CRED_KEY, str) else _IQ_CRED_KEY)


def criptografar_senha_iq(senha_plana):
    return _fernet.encrypt(senha_plana.encode()).decode()


def descriptografar_senha_iq(senha_criptografada):
    return _fernet.decrypt(senha_criptografada.encode()).decode()

# ---------------------------------------------------------------------------
# Banco de dados (Postgres via Neon, ou SQLite local como fallback pra testes)
# ---------------------------------------------------------------------------
database_url = os.environ.get("DATABASE_URL", "sqlite:///usuarios.db")
# Neon/Render às vezes fornecem a URL como "postgres://" — SQLAlchemy mais novo
# exige "postgresql://"
if database_url.startswith("postgres://"):
    database_url = database_url.replace("postgres://", "postgresql://", 1)

app.config["SQLALCHEMY_DATABASE_URI"] = database_url
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
db = SQLAlchemy(app)

login_manager = LoginManager(app)
login_manager.login_view = "login"


class Usuario(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(255), unique=True, nullable=False)
    senha_hash = db.Column(db.String(255), nullable=False)
    # conta IQ Option PRÓPRIA de cada usuário — separada da conta padrão
    # (IQ_EMAIL/IQ_SENHA) usada só pra puxar as velas do gráfico. Fica vazio
    # até a pessoa cadastrar a própria conta em "Minha Conta IQ Option".
    iq_email = db.Column(db.String(255), nullable=True)
    iq_senha_cripto = db.Column(db.String(500), nullable=True)
    iq_conta_tipo = db.Column(db.String(20), nullable=True, default="PRACTICE")  # PRACTICE ou REAL

    def set_senha(self, senha):
        self.senha_hash = generate_password_hash(senha)

    def checar_senha(self, senha):
        return check_password_hash(self.senha_hash, senha)

    def set_senha_iq(self, senha_plana):
        self.iq_senha_cripto = criptografar_senha_iq(senha_plana) if senha_plana else None

    def get_senha_iq(self):
        if not self.iq_senha_cripto:
            return None
        try:
            return descriptografar_senha_iq(self.iq_senha_cripto)
        except InvalidToken:
            # a chave de criptografia mudou desde que essa senha foi salva —
            # não dá pra recuperar, a pessoa precisa cadastrar de novo
            return None

    def tem_conta_iq_cadastrada(self):
        return bool(self.iq_email and self.iq_senha_cripto)


@login_manager.user_loader
def load_user(user_id):
    return Usuario.query.get(int(user_id))


with app.app_context():
    db.create_all()
    # migração leve: db.create_all() só cria tabelas que ainda não existem —
    # como o banco Neon já tinha a tabela "usuario" de antes (sem essas 3
    # colunas novas), precisa adicionar elas manualmente. Cada ALTER TABLE
    # fica num try/except próprio porque, se a coluna já existir (ex: depois
    # do 1º deploy com essa mudança), o comando dá erro — e isso é esperado,
    # não deve travar o boot do servidor.
    colunas_novas = [
        "ALTER TABLE usuario ADD COLUMN iq_email VARCHAR(255)",
        "ALTER TABLE usuario ADD COLUMN iq_senha_cripto VARCHAR(500)",
        "ALTER TABLE usuario ADD COLUMN iq_conta_tipo VARCHAR(20)",
    ]
    for comando in colunas_novas:
        try:
            db.session.execute(db.text(comando))
            db.session.commit()
        except Exception:
            db.session.rollback()  # coluna já existe (ou outro erro) — segue a vida

# ---------------------------------------------------------------------------
# Conexão com a IQ Option
# ---------------------------------------------------------------------------
EMAIL_IQ = os.environ.get("IQ_EMAIL")
SENHA_IQ = os.environ.get("IQ_SENHA")

iq = IQ_Option(EMAIL_IQ, SENHA_IQ)

# o objeto `iq` é compartilhado por toda requisição que chega no servidor —
# se o Render/gunicorn processar mais de uma requisição ao mesmo tempo (mais
# de 1 thread), duas chamadas simultâneas na biblioteca da IQ Option podem
# corromper o estado interno dela (ela não foi feita pra ser usada de vários
# lugares ao mesmo tempo). Esse lock garante que só uma requisição por vez
# fala com a IQ Option — as outras esperam a vez, mas ninguém pisa no
# estado da outra.
iq_lock = threading.Lock()


def iq_conectar():
    """Conecta (ou reconecta) na IQ Option. Chamado no boot e sempre que uma
    chamada à API falhar por sessão expirada/caída."""
    check, reason = iq.connect()
    if check:
        iq.change_balance("PRACTICE")
        print("Conectado com sucesso na IQ Option!")
    else:
        print("Erro ao conectar:", reason)
    return check


iq_conectar()


# ---------------------------------------------------------------------------
# Conexões IQ Option POR USUÁRIO — usadas só na hora de comprar/vender.
# A conexão padrão (`iq`, lá em cima) continua servindo as velas do gráfico
# pra todo mundo, não muda. Cada usuário logado que cadastrou a própria
# conta ganha sua PRÓPRIA conexão aqui, guardada em memória enquanto o
# servidor estiver de pé (cai se o servidor reiniciar — a pessoa só precisa
# comprar/vender de novo, não precisa recadastrar a conta).
conexoes_iq_usuarios = {}  # { usuario_id: instancia IQ_Option já conectada }
conexoes_iq_lock = threading.Lock()


def obter_conexao_iq_do_usuario(usuario):
    """Retorna a conexão IQ Option do usuário, conectando na hora se ainda
    não existir ou se caiu. Levanta Exception com mensagem amigável se o
    usuário não tem conta cadastrada ou se o login na IQ Option falhar."""
    if not usuario.tem_conta_iq_cadastrada():
        raise Exception("Você ainda não cadastrou sua conta IQ Option. Vá em \"Minha Conta IQ Option\" primeiro.")

    senha = usuario.get_senha_iq()
    if not senha:
        raise Exception("Não consegui recuperar sua senha salva (a chave de criptografia do servidor mudou). Cadastre sua conta de novo.")

    with conexoes_iq_lock:
        conexao = conexoes_iq_usuarios.get(usuario.id)
        if conexao is None or not conexao.check_connect():
            conexao = IQ_Option(usuario.iq_email, senha)
            check, motivo = conexao.connect()
            if not check:
                raise Exception("Não consegui logar na sua conta IQ Option: " + str(motivo))
            conexao.change_balance(usuario.iq_conta_tipo or "PRACTICE")
            conexoes_iq_usuarios[usuario.id] = conexao
        return conexao


def iq_get_candles_seguro(ativo, timeframe, qtd, fim):
    """
    Wrapper em volta de iq.get_candles() com duas proteções:
    1. Lock — evita duas requisições mexendo na conexão ao mesmo tempo.
    2. Reconexão automática — se a sessão da IQ Option caiu (comum depois de
       várias horas rodando), detecta que a chamada falhou/voltou vazia,
       tenta reconectar, e refaz a chamada UMA vez antes de desistir. Sem
       isso, depois que a sessão cai, o app fica servindo lista vazia pra
       sempre até alguém reiniciar o servidor manualmente no Render.
    """
    with iq_lock:
        try:
            if not iq.check_connect():
                iq_conectar()
            velas = iq.get_candles(ativo, timeframe, qtd, fim)
            if velas:
                return velas
        except Exception as e:
            print("get_candles falhou, tentando reconectar:", e)

        # não veio nada (ou deu exceção) — tenta reconectar e refazer 1 vez
        try:
            if iq_conectar():
                return iq.get_candles(ativo, timeframe, qtd, fim)
        except Exception as e:
            print("get_candles falhou de novo mesmo após reconectar:", e)
        return []


TIMEFRAME = 60
QTD_VELAS_POLL = 100          # atualização ao vivo (rápido, chamado a cada poucos segundos)
QTD_VELAS_MAX = 35000         # trava de segurança — cobre até 500 velas de H1 (30000min)
QTD_VELAS_MAX_OTC = 1500      # pares OTC são sintéticos — só as velas recentes são confiáveis
LOTE_POR_CHAMADA = 1000       # a IQ Option limita quantas velas vêm numa única chamada

# ---------------------------------------------------------------------------
# Autenticação
# ---------------------------------------------------------------------------
@app.route("/registrar", methods=["GET", "POST"])
def registrar():
    if request.method == "POST":
        email = request.form.get("email", "").strip().lower()
        senha = request.form.get("senha", "")
        confirmar = request.form.get("confirmar", "")

        if not email or not senha:
            flash("Preencha email e senha.")
            return redirect(url_for("registrar"))
        if senha != confirmar:
            flash("As senhas não são iguais.")
            return redirect(url_for("registrar"))
        if len(senha) < 6:
            flash("A senha precisa ter pelo menos 6 caracteres.")
            return redirect(url_for("registrar"))
        if Usuario.query.filter_by(email=email).first():
            flash("Já existe uma conta com esse email.")
            return redirect(url_for("registrar"))

        novo = Usuario(email=email)
        novo.set_senha(senha)
        db.session.add(novo)
        db.session.commit()

        login_user(novo)
        return redirect(url_for("home"))

    return render_template("registrar.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        email = request.form.get("email", "").strip().lower()
        senha = request.form.get("senha", "")

        usuario = Usuario.query.filter_by(email=email).first()
        if usuario and usuario.checar_senha(senha):
            login_user(usuario)
            return redirect(url_for("home"))

        flash("Email ou senha incorretos.")
        return redirect(url_for("login"))

    return render_template("login.html")


@app.route("/logout")
@login_required
def logout():
    logout_user()
    return redirect(url_for("login"))


@app.route("/minha-conta-iq", methods=["GET", "POST"])
@login_required
def minha_conta_iq():
    if request.method == "POST":
        iq_email = request.form.get("iq_email", "").strip()
        iq_senha = request.form.get("iq_senha", "")
        iq_tipo = request.form.get("iq_conta_tipo", "PRACTICE")
        if iq_tipo not in ("PRACTICE", "REAL"):
            iq_tipo = "PRACTICE"

        if not iq_email or not iq_senha:
            flash("Preencha o email e a senha da sua conta IQ Option.")
            return redirect(url_for("minha_conta_iq"))

        current_user.iq_email = iq_email
        current_user.set_senha_iq(iq_senha)
        current_user.iq_conta_tipo = iq_tipo
        db.session.commit()

        # já invalida qualquer conexão antiga em memória, pra próxima compra/
        # venda usar a conta/senha recém cadastrada, não uma versão antiga
        with conexoes_iq_lock:
            conexoes_iq_usuarios.pop(current_user.id, None)

        flash("Conta IQ Option salva com sucesso.")
        return redirect(url_for("minha_conta_iq"))

    return render_template("minha_conta_iq.html", usuario=current_user)


@app.route("/ordem", methods=["POST"])
@login_required
def ordem():
    """Executa uma ordem de compra/venda (binária) na conta IQ Option DO
    USUÁRIO LOGADO — nunca na conta padrão do servidor. Esperado no corpo
    (JSON): { ativo, direcao ('call'|'put'), valor, expiracao_min }."""
    dados = request.get_json(silent=True) or {}
    ativo = dados.get("ativo", "")
    direcao = dados.get("direcao", "")
    valor = dados.get("valor")
    expiracao_min = dados.get("expiracao_min", 1)

    if direcao not in ("call", "put"):
        return jsonify({"sucesso": False, "erro": "direção inválida (use 'call' ou 'put')"}), 400
    try:
        valor = float(valor)
        if valor <= 0:
            raise ValueError()
    except (TypeError, ValueError):
        return jsonify({"sucesso": False, "erro": "valor de entrada inválido"}), 400
    if not ativo:
        return jsonify({"sucesso": False, "erro": "ativo não informado"}), 400

    try:
        conexao = obter_conexao_iq_do_usuario(current_user)
    except Exception as e:
        return jsonify({"sucesso": False, "erro": str(e)}), 400

    try:
        check, id_ordem = conexao.buy(valor, ativo, direcao, int(expiracao_min))
    except Exception as e:
        return jsonify({"sucesso": False, "erro": "Erro ao enviar ordem pra IQ Option: " + str(e)}), 500

    if not check:
        return jsonify({"sucesso": False, "erro": "A IQ Option recusou a ordem (ativo fechado, saldo insuficiente, ou fora do horário de operação)."}), 400

    return jsonify({"sucesso": True, "id_ordem": id_ordem, "conta": current_user.iq_conta_tipo})


# ---------------------------------------------------------------------------
# Rotas do app (protegidas por login)
# ---------------------------------------------------------------------------
@app.route("/")
@login_required
def home():
    return render_template("index.html")


def buscar_velas_em_blocos(ativo, qtd_total):
    """
    A IQ Option limita quantas velas vêm numa única chamada de get_candles
    (na prática, ~1000 por vez). Pra buscar um histórico maior (ex: 12000,
    pro app abrir com bastante vela em qualquer timeframe), busca em vários
    blocos de LOTE_POR_CHAMADA, andando pra trás no tempo a cada chamada
    (usando o timestamp da vela mais antiga já recebida como novo "fim").

    Se algum bloco no meio do caminho falhar (timeout, reconexão da IQ
    Option, etc.), NÃO derruba a busca inteira — devolve o que já
    conseguiu buscar até ali, pra pelo menos aparecer alguma vela em vez
    do gráfico ficar totalmente vazio.
    """
    todas = []
    fim = time.time()
    while len(todas) < qtd_total:
        restante = qtd_total - len(todas)
        lote = min(LOTE_POR_CHAMADA, restante)
        velas = iq_get_candles_seguro(ativo, TIMEFRAME, lote, fim)
        if not velas:
            break  # IQ Option não tem mais histórico pra trás (ou falhou de vez)
        todas = velas + todas
        mais_antiga = velas[0]["from"]
        if fim <= mais_antiga:
            break  # não avançou pra trás, evita loop infinito
        fim = mais_antiga - 1

    # blinda contra blocos sobrepostos ou fora de ordem (a lib do gráfico no
    # frontend se recusa a desenhar — fica tudo em branco, sem erro visível —
    # se receber velas com tempo repetido ou fora de ordem crescente)
    unicas = {}
    for v in todas:
        unicas[v["from"]] = v
    return [unicas[t] for t in sorted(unicas.keys())]


@app.route("/candles")
@login_required
def candles():
    ativo = request.args.get("ativo", "EURUSD-OTC")
    qtd = request.args.get("qtd", type=int) or QTD_VELAS_POLL
    qtd = min(max(qtd, 1), QTD_VELAS_MAX)

    # Pares OTC são sintéticos (a IQ Option gera o movimento artificialmente
    # pra manter o ativo negociável fora do horário real de mercado) — buscar
    # muito histórico passado desses pares às vezes vem "regenerado" de forma
    # diferente do que realmente foi mostrado ao vivo, fazendo o gráfico não
    # bater com a plataforma oficial. Pra OTC, trava a profundidade de
    # histórico num valor bem mais raso (só as velas recentes são confiáveis).
    if "OTC" in ativo.upper():
        qtd = min(qtd, QTD_VELAS_MAX_OTC)

    if qtd <= LOTE_POR_CHAMADA:
        velas = iq_get_candles_seguro(ativo, TIMEFRAME, qtd, time.time())
    else:
        velas = buscar_velas_em_blocos(ativo, qtd)

    dados = []
    for v in velas:
        dados.append({
            "time": v["from"],
            "open": v["open"],
            "high": v["max"],
            "low": v["min"],
            "close": v["close"],
            "volume": v.get("volume", 0),
        })
    return jsonify(dados)


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port)
