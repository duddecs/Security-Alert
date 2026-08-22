"""
Security Alert - Plataforma de Treinamento em Ciberseguranca
Challenge Leroy Merlin 2026 - FIAP Defesa Cibernetica
Grupo: Ana Luiza, Maria Eduarda (Duda), Pedro Henrique, Thalia
"""

import os
import re
import sqlite3
import secrets
from datetime import datetime, timedelta
from functools import wraps
from flask import (
    Flask, render_template, request, redirect, url_for,
    session, flash, jsonify, g
)
from werkzeug.security import generate_password_hash, check_password_hash

# ─── Configuracao ────────────────────────────────────────────
app = Flask(__name__)
app.secret_key = secrets.token_hex(32)
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(days=7)
DATABASE = os.path.join(app.instance_path, 'security_alert.db')

# ─── Banco de Dados ──────────────────────────────────────────
def get_db():
    if 'db' not in g:
        os.makedirs(app.instance_path, exist_ok=True)
        g.db = sqlite3.connect(DATABASE)
        g.db.row_factory = sqlite3.Row
        g.db.execute("PRAGMA journal_mode=WAL")
        g.db.execute("PRAGMA foreign_keys=ON")
    return g.db

@app.teardown_appcontext
def close_db(exception):
    db = g.pop('db', None)
    if db is not None:
        db.close()

def init_db():
    db = get_db()
    db.executescript("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            email TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            show_in_ranking BOOLEAN DEFAULT 1,
            reset_token TEXT,
            reset_token_expires TIMESTAMP,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );

        CREATE TABLE IF NOT EXISTS game_sessions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            score INTEGER DEFAULT 0,
            max_score INTEGER DEFAULT 0,
            current_phase INTEGER DEFAULT 1,
            current_subphase INTEGER DEFAULT 1,
            completed BOOLEAN DEFAULT 0,
            started_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            finished_at TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users(id)
        );

        CREATE TABLE IF NOT EXISTS phase_answers (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            session_id INTEGER NOT NULL,
            phase INTEGER NOT NULL,
            subphase INTEGER NOT NULL,
            correct BOOLEAN NOT NULL,
            answered_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (session_id) REFERENCES game_sessions(id)
        );
    """)
    # Migra banco existente (caso ja exista sem a coluna)
    cols = [r["name"] for r in db.execute("PRAGMA table_info(users)").fetchall()]
    if "show_in_ranking" not in cols:
        db.execute("ALTER TABLE users ADD COLUMN show_in_ranking BOOLEAN DEFAULT 1")
    db.commit()

# ─── Decorator de Autenticacao ────────────────────────────────
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash('Voce precisa fazer login para acessar essa pagina.', 'warning')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

# ─── Dados do Jogo ───────────────────────────────────────────
GAME_PHASES = {
    1: {
        "title": "Fase 1: Senhas Seguras",
        "icon": "🔑",
        "color": "#f8bce4",
        "boss_name": "Chefe Carlos",
        "explanation": (
            "Bem-vindo(a) ao seu primeiro dia de treinamento! "
            "Sou seu chefe, Carlos, e vou te ensinar sobre a importância de senhas fortes no seu dia a dia! Sabia que senhas fracas são a principal porta de entrada para hackers? "
            "Vamos aprender a criar senhas que são verdadeiras fortalezas digitais!"
        ),
        "subphases": [
            {
                "id": 1,
                "title": "Construtor de senha com dados",
                "mode": "password_builder",
                "question": (
                    "Digite dados fictícios e veja que senhas fracas um "
                    "atacante poderia montar com eles."
                )
            },
            {
                "id": 2,
                "title": "Criar senha forte",
                "question": "Crie uma senha forte usando o teclado virtual abaixo.",
                "options": []
            },
            {
                "id": 3,
                "title": "Classificar senhas",
                "mode": "password_dnd",
                "question": (
                    "Arraste cada cartão para a coluna correta: Senha Fácil (fraca, "
                    "fácil de adivinhar) ou Senha Difícil (forte, bem protegida)."
                )
            }
        ]
    },
    2: {
        "title": "Fase 2: Negligência e Atenção",
        "icon": "⚠️",
        "color": "#a8d89e",
        "boss_name": "Chefe Carlos",
        "explanation": (
            "Ótimo trabalho na primeira fase! Agora Carlos vai falar sobre algo muito comum: "
            "a negligência. Muitos ataques acontecem por simples falta de atenção. "
            "Vamos aprender a evitar esses vacilos!"
        ),
        "subphases": [
            {
                "id": 1,
                "title": "Estação de trabalho",
                "question": "Você vai ao banheiro e deixa seu computador...",
                "options": [
                    "Desbloqueado, volto rápido mesmo",
                    "So coloco a tela um pouco abaixada",
                    "Bloqueio a tela (Windows + L) antes de sair",
                    "Peço para o colega do lado dar uma olhada"
                ],
                "correct": 2,
                "explanation_correct": (
                    "Muito bem! Sempre bloqueie sua estação ao se ausentar, mesmo que seja por 1 minuto. "
                    "Windows + L é seu melhor amigo no escritório!"
                ),
                "explanation_wrong": (
                    "Perigoso! Uma estação desbloqueada 'r um convite para que qualquer pessoa "
                    "acesse informações sigilosas. Bloqueie SEMPRE, sem exceçao!"
                )
            },
            {
                "id": 2,
                "title": "Dispositivos móveis",
                "question": "Você está no ônibus e percebe que seu celular corporativo sumiu da mochila. O que você deve fazer PRIMEIRO?",
                "options": [
                    "Esperar chegar em casa pra ver se está la",
                    "Procurar no chão do ônibus",
                    "Avisar IMEDIATAMENTE o TI e seu gestor",
                    "Comprar outro e fingir que nada aconteceu"
                ],
                "correct": 2,
                "explanation_correct": (
                    "Exato! Tempo é crucial. Quanto antes o TI souber, mais rápido podem "
                    "bloquear o dispositivo remotamente, revogar seus acessos e proteger os dados da empresa."
                ),
                "explanation_wrong": (
                    "Não espere! Cada minuto conta quando um dispositivo corporativo é perdido. "
                    "O TI pode bloquear e rastrear o aparelho remotamente, mas precisa ser avisado IMEDIATAMENTE."
                )
            },
            {
                "id": 3,
                "title": "Informações sigilosas",
                "question": "Em uma ligação, alguem se passando pelo RH pede seu CPF e data de admissão para 'confirmar seu cadastro'. Você...",
                "options": [
                    "Passo os dados, parece oficial",
                    "Desconfio, desligo e verifico com o RH pelos canais oficiais",
                    "Peco pra pessoa me mandar um e-mail",
                    "Dou os dados, mas só o CPF"
                ],
                "correct": 1,
                "explanation_correct": (
                    "Perfeito! SEMPRE desconfie de solicitações de dados pessoais por telefone. "
                    "Desligue e confirme pelos canais oficiais da empresa."
                ),
                "explanation_wrong": (
                    "Caiu no golpe! Isso é engenharia social: o atacante se passa por alguem de confiança "
                    "para conseguir informações. Nunca passe dados pessoais em ligações não solicitadas."
                )
            }
        ]
    },
    3: {
        "title": "Fase 3: Phishing",
        "icon": "🎣",
        "color": "#5a8581",
        "boss_name": "Chefe Carlos",
        "explanation": (
            "Voce esta indo muito bem! Agora chegamos ao ataque mais comum no mundo corporativo: "
            "o Phishing. Ele pode vir por e-mail, telefone, SMS ou ate WhatsApp. "
            "Seu objetivo é aprender a identificar essas tentativas antes de cair nelas!"
        ),
        "subphases": [
            {
                "id": 1,
                "title": "E-mail suspeito",
                "mode": "email_compare",
                "question": (
                    "Você recebeu DOIS e-mails no seu correio corporativo. Um deles é falso e está "
                    "tentando enganar você. Compare os dois e REPORTE ao TI o e-mail que você "
                    "acredita ser o FALSO."
                ),
                "emails": [
                    {
                        "label": "E-mail 1",
                        "from_name": "Recursos Humanos",
                        "from_email": "rh@leroymerlin.com.br",
                        "time": "09:14",
                        "subject": "🎓 Treinamento Security Alert - Certificado disponível",
                        "body": [
                            "Prezado(a) colaborador(a),",
                            "Parabéns por concluir o treinamento de cibersegurança Security Alert! Seu certificado já está disponível no Portal do Colaborador. Acesse https://portal.leroymerlin.com.br e procure por 'Meus Treinamentos'.",
                            "Em caso de dúvidas, fale com a equipe de RH",
                            "Atenciosamente, Equipe de RH."
                        ],
                        "is_fake": False
                    },
                    {
                        "label": "E-mail 2",
                        "from_name": "Departamento de TI",
                        "from_email": "ti@ler0y-merlin.com.br",
                        "time": "09:30",
                        "subject": "⚠️ AÇÃO NECESSÁRIA: atualize sua senha hoje!!",
                        "body": [
                            "Prezado(a) colaborador(a),",
                            "Detectamos atividade suspeita na sua conta. Para manter seus dados seguros, atualize sua senha imediatamente clicando no link abaixo.",
                            "https://portall.ler0ymerIin.com.br/atualizar-senha",
                            "Caso não faça isso em até 24 horas, seu acesso será suspenso.",
                            "Departamento de Segurança da Informação."
                        ],
                        "is_fake": True
                    }
                ],
                "correct": 1,
                "explanation_correct": (
                    "🎉 Parabéns! Você identificou e reportou o e-mail FALSO corretamente! "
                    "O e-mail 2 vinha de 'ti@ler0y-merlin.com.br' — repare no HÍFEN e no número 0 do domínio. "
                    "O domínio oficial da Leroy Merlin é @leroymerlin.com.br (sem hífen). "
                    "Além disso, ele usava um link suspeito ('portall...') e tom de urgência, "
                    "sinais clássicos de phishing. Reportar ao TI foi a atitude correta!"
                ),
                "explanation_wrong": (
                    "😔 Que Pena! Você reportou o e-mail VERDADEIRO! Comparando os dois: o e-mail 2 era o falso. "
                    "Ele vinha de 'ti@ler0y-merlin.com.br' — repare que ele possui um número 0 e um HÍFEN do domínio. "
                    "O domínio oficial é @leroymerlin.com.br (sem hífen). O e-mail falso também tinha "
                    "um link suspeito ('portall.leroymerIin.com.br') e pressionava com urgência "
                    "('seu acesso será suspenso'). Esses são os sinais de phishing que você deve observar!"
                )
            },
            {
                "id": 2,
                "title": "SMS falso",
                "mode": "sms_sim",
                "question": (
                    "Você recebeu este SMS no seu celular corporativo. "
                    "Por que essa mensagem NÃO é legítima?"
                ),
                "options": [
                    "Porque a Leroy Merlin nunca envia SMS aos colaboradores - Sinal de phishing",
                    "Porque usa tom de urgência, link encurtado (bit.ly) e tem erros ortográficos - sinais clássicos de phishing",
                    "Porque erros de ortografia não acontecem em mensagens de golpe",
                    "Porque vazamento de dados não é um tema real de segurança"
                ],
                "correct": 1,
                "explanation_correct": (
                    "Excelente! 🎉 Você identificou os sinais de phishing: tom de urgência, "
                    "link encurtado (bit.ly) e vários erros ortográficos ('forão', 'pessuais', 'SEGURANSA'). "
                    "Mensagens oficiais da Leroy Merlin são revisadas e nunca pedem ação urgente por SMS. "
                    "Exclua a mensagem e reporte ao TI!"
                ),
                "explanation_wrong": (
                    "Quase lá! Os sinais de golpe eram: tom de urgência ('URGENTE', 'será bloqueado'), "
                    "link encurtado (bit.ly) e vários erros ortográficos ('forão', 'pessuais', 'SEGURANSA'). "
                    "Mensagens legítimas da empresa não usam links encurtados nem pedem ação imediata por SMS."
                )
            },
            {
                "id": 3,
                "title": "Site clonado",
                "mode": "site_sim",
                "question": (
                    "Você clicou em um link e caiu neste site, que se parece com o portal da "
                    "Leroy Merlin. Por que este site é FALSO?"
                ),
                "options": [
                    "Porque a URL tem hífen (leroymerlin-seguranca.com) e não é o domínio oficial leroymerlin.com.br",
                    "Porque a página é muito bonita para ser um site falso",
                    "Porque promoções com 90% de desconto sempre são reais",
                    "Porque pedir login é algo que nenhum site legítimo faz"
                ],
                "correct": 0,
                "explanation_correct": (
                    "Excelente! 🎉 O domínio oficial da Leroy Merlin é leroymerlin.com.br. "
                    "Este site usava 'leroymerlin-seguranca.com' (com hífen), um domínio falso criado "
                    "para enganar. Além disso, o alerta de 'site não seguro' e a promoção absurda "
                    "de 90% de desconto são fortes sinais de golpe. Feche a página e reporte ao TI!"
                ),
                "explanation_wrong": (
                    "Cuidado! 🚨 O site era falso porque a URL tinha um hífen: "
                    "'leroymerlin-seguranca.com' em vez do domínio oficial 'leroymerlin.com.br'. "
                    "Promoções exageradas, alertas de 'site não seguro' e pedidos de login fora do "
                    "site oficial são sinais clássicos de phishing. NUNCA digite suas credenciais em "
                    "sites com URLs suspeitas."
                )
            }
        ]
    },
    4: {
        "title": "Fase 4: Engenharia Social",
        "icon": "📞",
        "color": "#f2d38b",
        "boss_name": "Chefe Carlos",
        "explanation": (
            "Você chegou à última fase do treinamento! Agora vamos falar sobre engenharia social: "
            "golpistas que usam a confiança e o medo para enganar. Vou simular uma ligação de um "
            "farsante e você precisa decidir como agir com segurança."
        ),
        "subphases": [
            {
                "id": 1,
                "title": "Ligação do farsante",
                "mode": "call_sim",
                "question": (
                    "Você recebeu esta ligação de alguém se passando pelo setor de segurança da "
                    "Leroy Merlin e pedindo seus dados. Como você deve proceder?"
                ),
                "options": [
                    "Passo meu CPF completo, parece ser legítimo",
                    "Desligo a ligação e confirmo com o TI pelos canais oficiais da empresa",
                    "Informo meus dados, mas peço para a pessoa confirmar o nome dela primeiro",
                    "Dou só a data de admissão, não é tão grave"
                ],
                "correct": 1,
                "explanation_correct": (
                    "Perfeito! 🎉 Você concluiu o treinamento com maestria! Desligar e confirmar "
                    "pelos canais oficiais é a atitude certa. Empresas legítimas NUNCA pedem dados "
                    "sensíveis por telefone. O golpista usava engenharia social, e você não caiu!"
                ),
                "explanation_wrong": (
                    "Cuidado! 🚨 Isso é engenharia social: o golpista se passa por alguém de "
                    "confiança para roubar seus dados. Nunca informe CPF, senha ou dados pessoais "
                    "por telefone. Desligue e confirme com o TI pelos canais oficiais da empresa."
                )
            }
        ]
    }
}

# ─── Rotas de Autenticacao ───────────────────────────────────
@app.route('/')
def index():
    if 'user_id' in session:
        return redirect(url_for('dashboard'))
    # Busca ranking nacional (somente quem ativou a opcao)
    db = get_db()
    ranking = db.execute("""
        SELECT u.username, MAX(gs.score) as best_score, MAX(gs.max_score) as max_score
        FROM game_sessions gs
        JOIN users u ON gs.user_id = u.id
        WHERE gs.completed = 1 AND u.show_in_ranking = 1
        GROUP BY u.id
        ORDER BY best_score DESC
        LIMIT 10
    """).fetchall()
    return render_template('index.html', ranking=ranking)

@app.route('/about')
def about():
    return render_template('about.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        email = request.form.get('email', '').strip().lower()
        password = request.form.get('password', '')
        confirm = request.form.get('confirm', '')

        errors = []
        if len(username) < 3:
            errors.append('Nome de usuario deve ter pelo menos 3 caracteres.')
        if len(email) < 5 or '@' not in email:
            errors.append('Email invalido.')
        if len(password) < 6:
            errors.append('Senha deve ter pelo menos 6 caracteres.')
        if password != confirm:
            errors.append('As senhas nao conferem.')

        if errors:
            for e in errors:
                flash(e, 'danger')
            return render_template('register.html')

        db = get_db()
        existing = db.execute(
            "SELECT id FROM users WHERE username = ? OR email = ?",
            (username, email)
        ).fetchone()

        if existing:
            flash('Usuario ou email ja cadastrado.', 'warning')
            return render_template('register.html')

        password_hash = generate_password_hash(password)
        show_in_ranking = 1 if request.form.get('show_in_ranking') else 0
        db.execute(
            "INSERT INTO users (username, email, password_hash, show_in_ranking) VALUES (?, ?, ?, ?)",
            (username, email, password_hash, show_in_ranking)
        )
        db.commit()

        flash('Conta criada com sucesso! Faca login para comecar.', 'success')
        return redirect(url_for('login'))

    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        login_field = request.form.get('login', '').strip().lower()
        password = request.form.get('password', '')

        db = get_db()
        user = db.execute(
            "SELECT * FROM users WHERE username = ? OR email = ?",
            (login_field, login_field)
        ).fetchone()

        if user and check_password_hash(user['password_hash'], password):
            session.permanent = True
            session['user_id'] = user['id']
            session['username'] = user['username']
            flash(f'Bem-vindo(a) de volta, {user["username"]}! 🛡️', 'success')
            return redirect(url_for('dashboard'))
        else:
            flash('Usuario/email ou senha incorretos.', 'danger')

    return render_template('login.html')

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('index'))

@app.route('/reset-password', methods=['GET', 'POST'])
def reset_password():
    if request.method == 'POST':
        email = request.form.get('email', '').strip().lower()
        new_password = request.form.get('new_password', '')
        confirm = request.form.get('confirm', '')

        db = get_db()
        user = db.execute("SELECT * FROM users WHERE email = ?", (email,)).fetchone()

        if not user:
            flash('Email nao encontrado.', 'danger')
            return render_template('reset_password.html')

        if len(new_password) < 6:
            flash('Senha deve ter pelo menos 6 caracteres.', 'danger')
            return render_template('reset_password.html')

        if new_password != confirm:
            flash('As senhas nao conferem.', 'danger')
            return render_template('reset_password.html')

        password_hash = generate_password_hash(new_password)
        db.execute(
            "UPDATE users SET password_hash = ?, reset_token = NULL, reset_token_expires = NULL WHERE id = ?",
            (password_hash, user['id'])
        )
        db.commit()

        flash('Senha redefinida com sucesso! Faca login.', 'success')
        return redirect(url_for('login'))

    return render_template('reset_password.html')

# ─── Rotas do Jogo ───────────────────────────────────────────
@app.route('/dashboard')
@login_required
def dashboard():
    db = get_db()
    sessions = db.execute(
        "SELECT * FROM game_sessions WHERE user_id = ? ORDER BY started_at DESC",
        (session['user_id'],)
    ).fetchall()

    # Calcular estatisticas
    total_games = len(sessions)
    completed_games = [s for s in sessions if s['completed']]
    best_score = max((s['score'] for s in completed_games), default=0)
    best_max = max((s['max_score'] for s in completed_games), default=30)

    # Busca status de show_in_ranking do usuario
    user_data = db.execute(
        "SELECT show_in_ranking FROM users WHERE id = ?",
        (session['user_id'],)
    ).fetchone()
    show_in_ranking = bool(user_data['show_in_ranking']) if user_data else True

    # Ranking nacional (somente quem ativou a opcao)
    ranking = db.execute("""
        SELECT u.username, MAX(gs.score) as best_score, MAX(gs.max_score) as max_score
        FROM game_sessions gs
        JOIN users u ON gs.user_id = u.id
        WHERE gs.completed = 1 AND u.show_in_ranking = 1
        GROUP BY u.id
        ORDER BY best_score DESC
        LIMIT 10
    """).fetchall()

    return render_template('dashboard.html',
                         sessions=sessions,
                         total_games=total_games,
                         completed_count=len(completed_games),
                         best_score=best_score,
                         best_max=best_max,
                         show_in_ranking=show_in_ranking,
                         ranking=ranking)

@app.route('/toggle-ranking', methods=['POST'])
@login_required
def toggle_ranking():
    db = get_db()
    current = db.execute(
        "SELECT show_in_ranking FROM users WHERE id = ?",
        (session['user_id'],)
    ).fetchone()
    new_value = 0 if current['show_in_ranking'] else 1
    db.execute(
        "UPDATE users SET show_in_ranking = ? WHERE id = ?",
        (new_value, session['user_id'])
    )
    db.commit()
    return redirect(url_for('dashboard'))

@app.route('/game/start')
@login_required
def game_start():
    db = get_db()
    # Criar uma nova sessao de jogo
    cursor = db.execute(
        "INSERT INTO game_sessions (user_id, max_score) VALUES (?, ?)",
        (session['user_id'], 100)  # 10 questoes x 10 pontos
    )
    db.commit()
    game_id = cursor.lastrowid

    # Corrigir max_score
    db.execute("UPDATE game_sessions SET max_score = 100 WHERE id = ?", (game_id,))
    db.commit()

    return redirect(url_for('game_play', game_id=game_id, phase=1, sub=1))

@app.route('/game/<int:game_id>/phase/<int:phase>/sub/<int:sub>')
@login_required
def game_play(game_id, phase, sub):
    db = get_db()
    game = db.execute(
        "SELECT * FROM game_sessions WHERE id = ? AND user_id = ?",
        (game_id, session['user_id'])
    ).fetchone()

    if not game:
        flash('Sessao de jogo nao encontrada.', 'danger')
        return redirect(url_for('dashboard'))

    if game['completed']:
        return redirect(url_for('game_feedback', game_id=game_id))

    if phase not in GAME_PHASES:
        return redirect(url_for('game_feedback', game_id=game_id))

    # A Fase 1 tem layout customizado (teclado virtual in-page),
    # mas é renderizado dentro do proprio game.html quando phase == 1.

    phase_data = GAME_PHASES[phase]
    if sub > len(phase_data['subphases']):
        # Proxima fase
        next_phase = phase + 1
        if next_phase in GAME_PHASES:
            return redirect(url_for('game_play', game_id=game_id, phase=next_phase, sub=1))
        else:
            # Jogo concluido!
            db.execute(
                "UPDATE game_sessions SET completed = 1, finished_at = CURRENT_TIMESTAMP WHERE id = ?",
                (game_id,)
            )
            db.commit()
            return redirect(url_for('game_feedback', game_id=game_id))

    subphase_data = phase_data['subphases'][sub - 1]

    # Verificar se ja respondeu
    already_answered = db.execute(
        "SELECT * FROM phase_answers WHERE session_id = ? AND phase = ? AND subphase = ?",
        (game_id, phase, sub)
    ).fetchone()

    # Email cadastrado pelo usuario (usado como destinatario na simulacao de e-mail)
    user_email = db.execute(
        "SELECT email FROM users WHERE id = ?",
        (session['user_id'],)
    ).fetchone()['email']

    return render_template('game.html',
                         game=game,
                         phase=phase,
                         sub=sub,
                         phase_data=phase_data,
                         subphase_data=subphase_data,
                         already_answered=already_answered,
                         user_email=user_email,
                         total_phases=len(GAME_PHASES),
                         total_subs_in_phase=len(phase_data['subphases']))

# ═══════════════════════════════════════════════════════════════════════════
# 🎮 FASE 1 — CRIADOR DE SENHA (point-and-click)
# Rotas dedicadas: /game/<id>/phase/1/play e /game/<id>/phase/1/submit
# ═══════════════════════════════════════════════════════════════════════════

COMMON_PATTERNS = [
    r'123', r'234', r'345', r'456', r'567', r'678', r'789', r'890',
    r'abc', r'bcd', r'cde', r'def', r'qwerty', r'asdf', r'zxcv',
    r'111', r'222', r'333', r'444', r'555', r'666', r'777', r'888', r'999', r'000',
    r'password', r'senha', r'admin', r'login', r'user',
]

def check_password_strength(password):
    """Avalia a força de uma senha."""
    if not password:
        return {"score": 0, "max_score": 18, "strength": "vazia", "label": "Digite uma senha...", "color": "#888", "percent": 0, "time": "—", "feedback": [], "bonuses": [], "length": 0}

    score = 0
    feedback = []
    bonuses = []
    length = len(password)

    if length >= 8:
        score += 2; feedback.append("✅ Pelo menos 8 caracteres")
    elif length >= 6:
        score += 1; feedback.append("⚠️ Senha curta — tente pelo menos 8 caracteres")
    else:
        feedback.append("❌ Senha muito curta (mínimo 6 caracteres)")

    if length >= 12: score += 3; bonuses.append("🌟 12+ caracteres (+3)")
    if length >= 16: score += 2; bonuses.append("🏆 16+ caracteres (+2)")

    if re.search(r'[a-z]', password): score += 2; feedback.append("✅ Tem letras minúsculas")
    else: feedback.append("❌ Falta letra minúscula")
    if re.search(r'[A-Z]', password): score += 2; feedback.append("✅ Tem letras maiúsculas")
    else: feedback.append("❌ Falta letra maiúscula")
    if re.search(r'[0-9]', password): score += 2; feedback.append("✅ Tem números")
    else: feedback.append("❌ Falta número")
    if re.search(r'[^a-zA-Z0-9]', password): score += 3; feedback.append("✅ Tem caracteres especiais")
    else: feedback.append("❌ Falta caractere especial (!@#$%)")

    pwd_lower = password.lower()
    has_pattern = any(re.search(pat, pwd_lower) for pat in COMMON_PATTERNS)
    if has_pattern:
        feedback.append("⚠️ Contém padrão comum (123, abc, qwerty...)")
    else:
        score += 2; feedback.append("✅ Sem padrões óbvios")

    if re.search(r'(.)\1\1', password):
        score -= 2; feedback.append("⚠️ Caracteres repetidos em sequência (aaa, 111)")
    else:
        score += 1; feedback.append("✅ Sem repetições em sequência")

    score = max(0, score)
    percent = int((score / 18) * 100)

    if score <= 6: strength, label, color = "fraca", "❌ Fraca", "#FF6B6B"
    elif score <= 10: strength, label, color = "media", "⚠️ Média", "#FFC98A"
    elif score <= 14: strength, label, color = "forte", "✅ Forte", "#A8D5BA"
    else: strength, label, color = "epica", "⭐ Épica", "#F29DBF"

    if length < 6: time_str = "instantâneo"
    elif length < 8 and not has_pattern: time_str = "algumas horas"
    elif length < 10: time_str = "dias"
    elif length < 12: time_str = "anos"
    elif length < 16: time_str = "séculos"
    else: time_str = "mais que a idade do universo 🌌"

    return {"score": score, "max_score": 18, "strength": strength, "label": label, "color": color, "percent": percent, "time": time_str, "feedback": feedback, "bonuses": bonuses, "length": length}


@app.route('/game/<int:game_id>/phase/1/sub/0/submit', methods=['POST'])
@login_required
def phase1_sub0_submit(game_id):
    """Mini drag-and-drop de aquecimento (sub 0 da Fase 1). 4 cards:
    2 faceis + 2 dificeis. Avanca para a sub 1 (teclado virtual)."""
    db = get_db()
    game = db.execute(
        "SELECT * FROM game_sessions WHERE id = ? AND user_id = ? AND completed = 0",
        (game_id, session['user_id'])
    ).fetchone()
    if not game:
        return jsonify({"error": "Sessao invalida"}), 400

    try:
        data = request.get_json(force=True, silent=False) or {}
    except Exception:
        data = {}

    score = int(data.get('score', 0))
    correct = int(data.get('correct', 0))
    wrong = int(data.get('wrong', 0))

    existing = db.execute(
        "SELECT * FROM phase_answers WHERE session_id = ? AND phase = 1 AND subphase = 0",
        (game_id,)
    ).fetchone()
    if existing:
        return jsonify({"error": "Voce ja completou essa fase"}), 400

    # Pontuacao: 4 cards, escala igual a sub 2 (>=100: 10pts, >=60: 7pts, ...)
    # Como o score maximo possivel aqui e 4 acertos * 10 = 40, mantemos a
    # mesma logica mas com piso mais alto para reconhecer o aquecimento.
    if correct >= 4: points = 7        # gabaritou
    elif correct >= 3: points = 5
    elif correct >= 2: points = 3
    else: points = 1

    is_strong = correct >= 3

    db.execute(
        "INSERT INTO phase_answers (session_id, phase, subphase, correct) VALUES (?, 1, 0, ?)",
        (game_id, is_strong)
    )
    if points > 0:
        db.execute(
            "UPDATE game_sessions SET score = score + ? WHERE id = ?",
            (points, game_id)
        )
    db.commit()

    next_url = url_for('game_play', game_id=game_id, phase=1, sub=1)

    return jsonify({
        "success": True,
        "score": score,
        "points_earned": points,
        "is_strong": is_strong,
        "correct": correct,
        "wrong": wrong,
        "next_url": next_url
    })


@app.route('/game/<int:game_id>/phase/1/submit', methods=['POST'])
@login_required
def phase1_submit(game_id):
    """Teclado virtual (sub 2). Avança para a sub 3 (drag and drop)."""
    db = get_db()
    game = db.execute(
        "SELECT * FROM game_sessions WHERE id = ? AND user_id = ? AND completed = 0",
        (game_id, session['user_id'])
    ).fetchone()
    if not game:
        return jsonify({"error": "Sessao invalida"}), 400

    password = request.form.get('password', '')
    result = check_password_strength(password)

    existing = db.execute(
        "SELECT * FROM phase_answers WHERE session_id = ? AND phase = 1 AND subphase = 2",
        (game_id,)
    ).fetchone()
    if existing:
        return jsonify({"error": "Voce ja completou essa fase"}), 400

    is_strong = all([
        len(password) >= 10,
        re.search(r'[a-z]', password),
        re.search(r'[A-Z]', password),
        re.search(r'[0-9]', password),
        re.search(r'[^a-zA-Z0-9]', password),
    ])
    points = 10 if is_strong else 0

    db.execute(
        "INSERT INTO phase_answers (session_id, phase, subphase, correct) VALUES (?, 1, 2, ?)",
        (game_id, is_strong)
    )
    if points > 0:
        db.execute(
            "UPDATE game_sessions SET score = score + ? WHERE id = ?",
            (points, game_id)
        )
    db.commit()

    next_url = url_for('game_play', game_id=game_id, phase=1, sub=3)

    return jsonify({
        "success": True,
        "score": result['score'], "max_score": result['max_score'],
        "is_strong": is_strong, "points_earned": points,
        "strength": result['strength'], "label": result['label'],
        "color": result['color'], "percent": result['percent'],
        "time": result['time'], "feedback": result['feedback'],
        "bonuses": result['bonuses'], "next_url": next_url
    })


@app.route('/game/<int:game_id>/phase/1/sub/2/submit', methods=['POST'])
@login_required
def phase1_sub2_submit(game_id):
    """Valida o resultado do jogo de classificar senhas (drag and drop).
    Mora dentro da Fase 1 (subfase 3) e empurra o jogador para a Fase 2.
    """
    db = get_db()
    game = db.execute(
        "SELECT * FROM game_sessions WHERE id = ? AND user_id = ? AND completed = 0",
        (game_id, session['user_id'])
    ).fetchone()
    if not game:
        return jsonify({"error": "Sessao invalida"}), 400

    # Pega dados do JSON (frontend envia JSON)
    try:
        data = request.get_json(force=True, silent=False) or {}
    except Exception:
        data = {}

    score = int(data.get('score', 0))
    correct = int(data.get('correct', 0))
    wrong = int(data.get('wrong', 0))

    # Verifica se ja respondeu essa fase
    existing = db.execute(
        "SELECT * FROM phase_answers WHERE session_id = ? AND phase = 1 AND subphase = 3",
        (game_id,)
    ).fetchone()
    if existing:
        return jsonify({"error": "Voce ja completou essa fase"}), 400

    # Pontos baseados em performance
    # 0 vidas = 0pts, 1 vida = 3pts, 2 vidas = 7pts, 3 vidas = 10pts
    # Bonus: cada acerto extra alem de 5 = +1pt
    if score >= 100: points = 10
    elif score >= 60: points = 7
    elif score >= 30: points = 5
    else: points = 2

    is_strong = points >= 7

    db.execute(
        "INSERT INTO phase_answers (session_id, phase, subphase, correct) VALUES (?, 1, 3, ?)",
        (game_id, is_strong)
    )
    db.execute(
        "UPDATE game_sessions SET score = score + ? WHERE id = ?",
        (points, game_id)
    )
    db.commit()

    next_url = url_for('game_play', game_id=game_id, phase=2, sub=1)

    return jsonify({
        "success": True,
        "score": score,
        "points_earned": points,
        "is_strong": is_strong,
        "correct": correct,
        "wrong": wrong,
        "next_url": next_url
    })


@app.route('/game/<int:game_id>/phase/1/sub/3/save-data', methods=['POST'])
@login_required
def phase1_sub3_save_data(game_id):
    """Salva os 5 dados ficticios do Construtor de Senha com Dados na sessao.
    O frontend usa isso pra construir o passo 2 (mostra senhas fracas).
    Os dados nao sao persistidos no banco — sao temporarios e vivem
    apenas na sessao do Flask."""
    db = get_db()
    game = db.execute(
        "SELECT * FROM game_sessions WHERE id = ? AND user_id = ? AND completed = 0",
        (game_id, session['user_id'])
    ).fetchone()
    if not game:
        return jsonify({"error": "Sessao invalida"}), 400

    try:
        data = request.get_json(force=True, silent=False) or {}
    except Exception:
        data = {}

    # Salva os 5 campos na sessao (so pra esse usuario + esse game)
    session[f'p1s3_personal_{game_id}'] = {
        'pet':    (data.get('pet')    or '').strip()[:40],
        'dob':    (data.get('dob')    or '').strip()[:10],
        'team':   (data.get('team')   or '').strip()[:40],
        'city':   (data.get('city')   or '').strip()[:40],
        'mother': (data.get('mother') or '').strip()[:40],
    }

    # Pre-calcula as 5 senhas fracas com base nos dados, pra o frontend
    # renderizar no passo 2. Se algum campo estiver vazio, usa placeholder.
    d = session[f'p1s3_personal_{game_id}']
    pet = d['pet'] or 'pet'
    dob = d['dob'] or '15051998'
    team = d['team'] or 'time'
    city = d['city'] or 'cidade'
    mother = d['mother'] or 'mae'

    # Extrai o ano da data (4 ultimos digitos, ou usa tudo se nao for data)
    year = dob[-4:] if len(dob) >= 4 and dob[-4:].isdigit() else '1990'
    # Pega a primeira letra do pet
    pet_initial = pet[0].lower() if pet else 'p'
    team_initial = team[0].lower() if team else 't'

    weak_passwords = [
        (f'{pet_initial}123',       f'pet + sequencia numerica (seu pet e {pet})'),
        (f'{team_initial}2024',     f'time + ano (seu time e {team})'),
        (mother.lower(),            f'nome da mae (sua mae e {mother})'),
        (f'{city}{year}',           f'cidade + ano de nascimento (voce nasceu em {city} em {year})'),
        (f'{pet}{year}',            f'pet + ano (combinacao classica)'),
    ]

    return jsonify({
        "success": True,
        "weak_passwords": weak_passwords
    })


@app.route('/game/<int:game_id>/phase/1/sub/3/submit', methods=['POST'])
@login_required
def phase1_sub3_submit(game_id):
    """Fecha a subfase 1 (Construtor de Senha) e avanca para o teclado virtual.
    Nao soma pontos: a subfase 1 e educativa, nao pontuavel."""
    db = get_db()
    game = db.execute(
        "SELECT * FROM game_sessions WHERE id = ? AND user_id = ? AND completed = 0",
        (game_id, session['user_id'])
    ).fetchone()
    if not game:
        return jsonify({"error": "Sessao invalida"}), 400

    existing = db.execute(
        "SELECT * FROM phase_answers WHERE session_id = ? AND phase = 1 AND subphase = 1",
        (game_id,)
    ).fetchone()
    if existing:
        return jsonify({"error": "Voce ja completou essa fase"}), 400

    db.execute(
        "INSERT INTO phase_answers (session_id, phase, subphase, correct) VALUES (?, 1, 1, ?)",
        (game_id, True)
    )
    db.commit()

    next_url = url_for('game_play', game_id=game_id, phase=1, sub=2)

    return jsonify({
        "success": True,
        "next_url": next_url
    })


@app.route('/game/<int:game_id>/answer', methods=['POST'])
@login_required
def game_answer(game_id):
    db = get_db()
    game = db.execute(
        "SELECT * FROM game_sessions WHERE id = ? AND user_id = ? AND completed = 0",
        (game_id, session['user_id'])
    ).fetchone()

    if not game:
        return jsonify({"error": "Sessao invalida"}), 400

    phase = int(request.form.get('phase', 1))
    sub = int(request.form.get('sub', 1))
    answer = int(request.form.get('answer', -1))

    if phase not in GAME_PHASES:
        return jsonify({"error": "Fase invalida"}), 400

    phase_data = GAME_PHASES[phase]
    if sub > len(phase_data['subphases']):
        return jsonify({"error": "Sub-fase invalida"}), 400

    subphase_data = phase_data['subphases'][sub - 1]

    # Verificar se ja respondeu
    existing = db.execute(
        "SELECT * FROM phase_answers WHERE session_id = ? AND phase = ? AND subphase = ?",
        (game_id, phase, sub)
    ).fetchone()

    if existing:
        return jsonify({"error": "Voce ja respondeu essa pergunta"}), 400

    correct = (answer == subphase_data['correct'])
    points = 10 if correct else 0

    db.execute(
        "INSERT INTO phase_answers (session_id, phase, subphase, correct) VALUES (?, ?, ?, ?)",
        (game_id, phase, sub, correct)
    )

    if correct:
        db.execute(
            "UPDATE game_sessions SET score = score + ? WHERE id = ?",
            (points, game_id)
        )

    db.commit()

    # Determinar proximo destino
    next_sub = sub + 1
    next_phase = phase
    if next_sub > len(phase_data['subphases']):
        next_phase = phase + 1
        next_sub = 1

    is_final = (next_phase not in GAME_PHASES)

    if is_final:
        db.execute(
            "UPDATE game_sessions SET completed = 1, finished_at = CURRENT_TIMESTAMP WHERE id = ?",
            (game_id,)
        )
        db.commit()

    return jsonify({
        "correct": correct,
        "explanation": subphase_data['explanation_correct'] if correct else subphase_data['explanation_wrong'],
        "points_earned": points,
        "explanation_title": "Acertou! +10 pontos" if correct else "Que pena... 0 pontos",
        "next_phase": next_phase,
        "next_sub": next_sub,
        "is_final": is_final,
        "next_url": url_for('game_feedback', game_id=game_id) if is_final
                   else url_for('game_play', game_id=game_id, phase=next_phase, sub=next_sub)
    })

@app.route('/game/<int:game_id>/feedback')
@login_required
def game_feedback(game_id):
    db = get_db()
    game = db.execute(
        "SELECT * FROM game_sessions WHERE id = ? AND user_id = ?",
        (game_id, session['user_id'])
    ).fetchone()

    if not game:
        flash('Sessao nao encontrada.', 'danger')
        return redirect(url_for('dashboard'))

    answers = db.execute(
        "SELECT * FROM phase_answers WHERE session_id = ? ORDER BY phase, subphase",
        (game_id,)
    ).fetchall()

    score = game['score']
    max_score = game['max_score']
    percentage = (score / max_score * 100) if max_score > 0 else 0

    # Gerar feedback personalizado
    if percentage >= 90:
        feedback_level = "excelente"
        feedback_emoji = "🏆"
        feedback_msg = (
            "Voce e um verdadeiro guardiao digital! Seu conhecimento em ciberseguranca "
            "e impressionante. Continue assim e ajude seus colegas a se protegerem tambem!"
        )
    elif percentage >= 60:
        feedback_level = "bom"
        feedback_emoji = "👍"
        feedback_msg = (
            "Bom trabalho! Voce tem uma base solida, mas ainda pode melhorar. "
            "Revise os topicos onde errou e tente novamente para alcancar a pontuacao maxima!"
        )
    elif percentage >= 30:
        feedback_level = "regular"
        feedback_emoji = "📚"
        feedback_msg = (
            "Voce esta no caminho certo, mas precisa de mais atencao. "
            "A ciberseguranca e essencial no dia a dia. Que tal jogar novamente "
            "para reforcar o aprendizado?"
        )
    else:
        feedback_level = "iniciante"
        feedback_emoji = "🌱"
        feedback_msg = (
            "Todo expert ja foi iniciante! Nao desanime. "
            "A ciberseguranca e uma habilidade que se desenvolve com pratica. "
            "Jogue novamente e preste atencao nas explicacoes!"
        )

    # Detalhamento por fase
    phase_details = []
    for p_num, p_data in GAME_PHASES.items():
        phase_answers = [a for a in answers if a['phase'] == p_num]
        correct_count = sum(1 for a in phase_answers if a['correct'])
        total_count = len(p_data['subphases'])
        phase_details.append({
            "num": p_num,
            "title": p_data['title'],
            "icon": p_data['icon'],
            "correct": correct_count,
            "total": total_count,
            "percentage": (correct_count / total_count * 100) if total_count > 0 else 0
        })

    return render_template('feedback.html',
                         game=game,
                         score=score,
                         max_score=max_score,
                         percentage=percentage,
                         feedback_level=feedback_level,
                         feedback_emoji=feedback_emoji,
                         feedback_msg=feedback_msg,
                         phase_details=phase_details,
                         answers=answers)

# ─── Inicializacao ───────────────────────────────────────────
@app.before_request
def before_request():
    init_db()

if __name__ == '__main__':
    print("=" * 55)
    print("🛡️  SECURITY ALERT - Plataforma de Treinamento")
    print("   Challenge Leroy Merlin 2026 - FIAP")
    print("=" * 55)
    print()
    print("🌐 Acesse: http://localhost:5000")
    print("📋 Para parar: pressione Ctrl+C")
    print()
    app.run(debug=True, host='0.0.0.0', port=5000)
