"""
Security Alert - Plataforma de Treinamento em Ciberseguranca
Challenge Leroy Merlin 2026 - FIAP Defesa Cibernetica
Grupo: Ana Luiza, Maria Eduarda (Duda), Pedro Henrique, Thalia
"""

import os
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
            character TEXT DEFAULT 'ana',
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
            timed_out BOOLEAN DEFAULT 0,
            answered_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (session_id) REFERENCES game_sessions(id)
        );
    """)
    # Migra banco existente (caso ja exista sem as colunas)
    cols = [r["name"] for r in db.execute("PRAGMA table_info(users)").fetchall()]
    if "show_in_ranking" not in cols:
        db.execute("ALTER TABLE users ADD COLUMN show_in_ranking BOOLEAN DEFAULT 1")
    if "character" not in cols:
        db.execute(f"ALTER TABLE users ADD COLUMN character TEXT DEFAULT '{DEFAULT_CHARACTER}'")
    answer_cols = [r["name"] for r in db.execute("PRAGMA table_info(phase_answers)").fetchall()]
    if "timed_out" not in answer_cols:
        db.execute("ALTER TABLE phase_answers ADD COLUMN timed_out BOOLEAN DEFAULT 0")
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
CHARACTERS = {
    "ana":       {"name": "Ana",    "sprite": "img/personagens/ana.png"},
    "donoleroy": {"name": "Patrão", "sprite": "img/personagens/donoleroy.png"},
    "fabi":      {"name": "Fabi",   "sprite": "img/personagens/fabi.png"},
    "pedro":     {"name": "Pedro",  "sprite": "img/personagens/pedro.png"},
    "silvio":    {"name": "Silvio", "sprite": "img/personagens/silvio.png"},
}
DEFAULT_CHARACTER = "ana"

# Ordem de giro (volta completa) para a animacao na tela de selecao
SPIN_ORDER = ["south", "south-west", "west", "north-west",
              "north", "north-east", "east", "south-east"]

def get_spin_frames(char_key):
    """Lista de URLs dos sprites de rotacao existentes para o personagem girar."""
    frames = []
    for direction in SPIN_ORDER:
        rel = f"img/personagens/spin/{char_key}/{direction}.png"
        if os.path.exists(os.path.join(app.static_folder, *rel.split('/'))):
            frames.append(f"{app.static_url_path}/{rel}")
    return frames

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
                "title": "Qual é a senha mais forte?",
                "question": "Entre as opções abaixo, qual é a senha MAIS SEGURA?",
                "options": [
                    "123456merlin",
                    "leroy2026",
                    "^t4$K&$FW5L2",
                    "passwd123"
                ],
                "correct": 2,
                "explanation_correct": (
                    "Excelente! Senhas fortes misturam letras maiúsculas, minúsculas, "
                    "números e caractéres especiais. Quanto mais longa e aleatoria, melhor!"
                ),
                "explanation_wrong": (
                    "Ops! Senhas como '123456merlin', 'leroy2026' e 'passwd123' são extremamente fáceis de adivinhar. "
                    "Use sempre combinações complexas com maiúsculas, minúsculas, números e simbolos!"
                )
            },
            {
                "id": 2,
                "title": "Compartilhar senhas?",
                "question": "Um colega pede sua senha emprestada para acessar um sistema rapidamente. O que voce faz?",
                "options": [
                    "Compartilho, é so uma vez mesmo!",
                    "Não compartilho e aviso que ele deve pedir acesso ao TI",
                    "Mando por WhatsApp, é mais rapido",
                    "Anoto em um post-it e entrego pra ele"
                ],
                "correct": 1,
                "explanation_correct": (
                    "Perfeito! Nunca compartilhe suas senhas com ninguem. "
                    "Cada colaborador deve ter suas próprias credenciais. O TI pode criar acessos quando necessário."
                ),
                "explanation_wrong": (
                    "Cuidado! Compartilhar senhas é um risco enorme. Se o colega precisar de acesso, "
                    "ele deve solicitar formalmente ao departamento de TI. Sua senha é só sua!"
                )
            },
            {
                "id": 3,
                "title": "Reutilização de senhas",
                "question": "Voce usa a mesma senha no sistema da Leroy Merlin e no seu Instagram pessoal. Isso e...",
                "options": [
                    "Prático e inteligente",
                    "Perigoso! Se uma conta vazar, todas estão comprometidas",
                    "Não tem problema, ninguem vai descobrir",
                    "Recomendado pela empresa"
                ],
                "correct": 1,
                "explanation_correct": (
                    "Isso mesmo! Nunca reuse senhas entre sistemas pessoais e corporativos. "
                    "Se seu Instagram for hackeado, o atacante terá acesso ao sistema da empresa tambem!"
                ),
                "explanation_wrong": (
                    "Cuidado! Reutilizar senhas é um erro classico. Se um site que voce usa sofrer "
                    "um vazamento, suas credenciais da empresa ficam expostas. Use senhas únicas!"
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
    },
    5: {
        "title": "Fase 5: Uso de dispositivos pessoais",
        "icon": "📱",
        "color": "#b8a8d8",
        "boss_name": "Chefe Carlos",
        "explanation": (
            "Mandou muito bem até aqui! Agora vamos falar sobre os dispositivos pessoais: celular, pen drive, "
            "computador de casa... Eles facilitam o seu trabalho, mas também podem abrir portas para os hackers. "
            "Quando você usa tecnologia própria para acessar o sistema da empresa, a segurança depende das SUAS escolhas. "
            "E atenção: na última questão o tempo é seu inimigo. Um ataque não espera você pensar!"
        ),
        "subphases": [
            {
                "id": 1,
                "title": "Senha anotada no post-it",
                "question": (
                    "Você anotou a senha do sistema da empresa em um post-it para não esquecer. Depois de decorar, "
                    "jogou o papel no lixo da sala. Qual é o problema?"
                ),
                "options": [
                    "Só seria perigoso se o papel tivesse também o nome do sistema, não apenas a senha.",
                    "O problema é apenas ambiental, pelo desperdício de papel.",
                    "O papel pode ser encontrado no lixo por alguém mal-intencionado, que poderá usar a senha para entrar no sistema da empresa.",
                    "Nenhum, porque senhas em papel não servem para ataques pela internet."
                ],
                "correct": 2,
                "explanation_correct": (
                    "Excelente! ✅ Alguém pode revirar o lixo procurando exatamente esse tipo de informação — senhas, "
                    "documentos, anotações. Basta digitar a senha no sistema para entrar."
                ),
                "explanation_wrong": (
                    "❌ A senha escrita em papel funciona perfeitamente quando digitada — o criminoso não precisa invadir nada, "
                    "é só ler e usar (D). O desperdício de papel (B) é o menor dos problemas: o risco real é de segurança da informação, "
                    "com vazamento de dados da empresa. E a senha por si só já é suficiente para o ataque (A) — saber o nome do sistema "
                    "é um detalhe, já que muitas vezes é óbvio qual sistema a empresa usa."
                )
            },
            {
                "id": 2,
                "title": "Pen drive de banca de rua",
                "question": (
                    "Você comprou um pen drive baratinho em uma banca de rua. Precisa levar arquivos do trabalho para casa. "
                    "O que você deve fazer?"
                ),
                "options": [
                    "Formatar o pen drive antes de usar, pois isso elimina qualquer ameaça.",
                    "Não usar esse pen drive para arquivos da empresa. Utilize apenas dispositivos fornecidos ou aprovados pela TI.",
                    "Passar o antivírus no pen drive uma vez e depois usar sem preocupação.",
                    "Usar o pen drive normalmente, já que ele é novo e custou pouco."
                ],
                "correct": 1,
                "explanation_correct": (
                    "Exato! ✅ Pen drives de origem duvidosa podem vir com programas escondidos que infectam o computador ao serem "
                    "conectados. Para arquivos da empresa, use apenas dispositivos confiáveis."
                ),
                "explanation_wrong": (
                    "❌ 'Novo e barato' não significa seguro — o dispositivo pode ter sido preparado para parecer normal, mas conter "
                    "ameaças invisíveis (D). O antivírus (C) não detecta tudo, especialmente ameaças escondidas no firmware do pen drive; "
                    "quando você conecta para escanear, o ataque pode já ter acontecido. E formatar (A) limpa os arquivos, mas não remove "
                    "ameaças que estão no firmware do dispositivo."
                )
            },
            {
                "id": 3,
                "title": "Celular pessoal no trabalho",
                "question": "Você usa seu celular pessoal para acessar o e-mail da empresa. Qual atitude é a mais segura?",
                "options": [
                    "Instalar o e-mail da empresa e os apps pessoais (jogos, redes sociais) no mesmo espaço, sem separação.",
                    "Usar a mesma senha do e-mail pessoal no e-mail corporativo para não esquecer.",
                    "Manter o celular atualizado, com bloqueio de tela por biometria ou PIN forte, e usar o perfil de trabalho para separar dados pessoais dos corporativos.",
                    "Deixar o celular sem bloqueio de tela para responder e-mails mais rápido."
                ],
                "correct": 2,
                "explanation_correct": (
                    "Perfeito! ✅ Celular atualizado fecha brechas conhecidas, bloqueio de tela protege contra acesso de estranhos e a "
                    "separação de perfis impede que um app pessoal infectado alcance os dados da empresa."
                ),
                "explanation_wrong": (
                    "❌ Sem bloqueio de tela (D), qualquer pessoa que pegue seu celular terá acesso livre aos e-mails e documentos da empresa — "
                    "é como deixar a porta de casa aberta. Se sua conta pessoal for invadida (B), o atacante terá automaticamente a senha da "
                    "empresa também: cada conta deve ter senha diferente. E misturar tudo no mesmo espaço (A) faz com que um app pessoal com "
                    "problema possa acessar dados corporativos — a separação é essencial para isolar os riscos."
                )
            },
            {
                "id": 4,
                "title": "Computador compartilhado em casa",
                "question": (
                    "Você trabalha em home office e seu filho usa o mesmo computador para jogar e acessar sites na internet. "
                    "Qual é o risco para a empresa?"
                ),
                "options": [
                    "Só há risco se o filho usar a conta de usuário que você usa para trabalhar.",
                    "Nenhum, porque o computador separa totalmente as contas de usuário diferentes.",
                    "O único problema é o computador ficar lento para trabalhar.",
                    "O filho pode, sem querer, instalar programas ou acessar sites que infectem o computador, comprometendo os dados da empresa que estão no mesmo aparelho."
                ],
                "correct": 3,
                "explanation_correct": (
                    "Isso mesmo! ✅ Mesmo com contas separadas, o computador compartilha o mesmo sistema e a mesma rede. Um vírus instalado "
                    "pelo filho pode se espalhar e alcançar os dados da empresa."
                ),
                "explanation_wrong": (
                    "❌ A separação entre contas (B) não é total: um vírus bem feito consegue atravessar essa barreira e acessar tudo no "
                    "computador, inclusive arquivos da empresa. Lentidão (C) é o menor dos problemas — o risco real é roubo de senhas e "
                    "vazamento de dados corporativos sem ninguém perceber. E o risco existe independente da conta usada (A): um vírus instalado "
                    "na conta do filho pode infectar o sistema inteiro e afetar também a sua conta de trabalho."
                )
            },
            {
                "id": 5,
                "title": "Descarte de computador",
                "question": (
                    "Você vai descartar um computador pessoal que usava para acessar o sistema da empresa. O que você deve fazer antes "
                    "de doá-lo ou vendê-lo?"
                ),
                "options": [
                    "Apenas esvaziar a lixeira do sistema operacional antes de entregar o computador.",
                    "Doar para uma instituição de caridade, pois eles não terão interesse nos dados da empresa.",
                    "Garantir que os dados sejam totalmente destruídos — por sobrescrita, criptografia ou destruição física — para que ninguém consiga recuperá-los.",
                    "Apagar os arquivos visíveis e formatar o computador. Pronto para doar."
                ],
                "correct": 2,
                "explanation_correct": (
                    "Correto! ✅ Apagar arquivos ou formatar não destrói os dados de verdade — eles continuam no disco até serem sobrescritos. "
                    "Só técnicas especiais ou destruição física garantem que ninguém recupere nada."
                ),
                "explanation_wrong": (
                    "❌ Formatar (D) só apaga a 'lista' de arquivos, mas os dados continuam lá — ferramentas gratuitas conseguem recuperar tudo "
                    "facilmente. O computador doado (B) pode ser revendido, perdido ou roubado: a responsabilidade pelos dados da empresa continua "
                    "sendo sua, não importa para quem você doou. E esvaziar a lixeira (A) só remove a referência ao arquivo — os dados continuam no "
                    "disco e podem ser recuperados por qualquer pessoa com ferramentas simples."
                )
            },
            {
                "id": 6,
                "title": "HD externo suspeito",
                "question": (
                    "Você encontrou um HD externo à venda na internet por um preço muito abaixo do mercado. Precisa de espaço extra para "
                    "guardar arquivos do trabalho. O que você faz?"
                ),
                "options": [
                    "Comprar e usar apenas se o vendedor tiver boa avaliação na plataforma.",
                    "Comprar e usar, pois é uma boa oportunidade e HDs são só armazenamento.",
                    "Não usar para arquivos da empresa. Dispositivos de procedência duvidosa podem conter ameaças escondidas que infectam o computador ao serem conectados.",
                    "Comprar, passar o antivírus e depois usar sem problemas."
                ],
                "correct": 2,
                "explanation_correct": (
                    "Exato! ✅ HDs de origem duvidosa podem vir com programas escondidos que instalam vírus assim que você conecta. Para arquivos "
                    "da empresa, só use dispositivos confiáveis."
                ),
                "explanation_wrong": (
                    "❌ HD não é 'só armazenamento' (B): ele pode conter ameaças no próprio firmware, que ativam assim que é conectado ao "
                    "computador. O antivírus (D) não detecta tudo — e quando você conecta o HD para escanear, o ataque pode já ter acontecido, "
                    "antes mesmo do antivírus terminar. Boa avaliação do vendedor (A) também não garante segurança: o vendedor pode nem saber que "
                    "o dispositivo está comprometido. Procedência duvidosa é risco, não importa a avaliação."
                )
            },
            {
                "id": 7,
                "title": "Jogo de site não oficial",
                "question": (
                    "Você baixou um jogo de um site não oficial no mesmo computador que usa para acessar o sistema da empresa. Qual é o problema?"
                ),
                "options": [
                    "O problema é só que o jogo pode deixar o computador lento.",
                    "Jogos de sites não oficiais podem vir com vírus escondidos que infectam o computador e podem roubar senhas e dados da empresa acessados no mesmo aparelho.",
                    "Nenhum, desde que o jogo seja gratuito.",
                    "O único problema é que a empresa pode multar você por usar o computador para coisas pessoais."
                ],
                "correct": 1,
                "explanation_correct": (
                    "Correto! ✅ Programas de sites não oficiais costumam trazer vírus escondidos que podem capturar senhas, roubar arquivos e usar "
                    "o computador como ponte para atacar a empresa."
                ),
                "explanation_wrong": (
                    "❌ Ser gratuito (C) não significa seguro — muitos vírus são distribuídos justamente em programas 'gratuitos' para atrair "
                    "usuários desavisados. O problema vai muito além de punição administrativa (D): há um risco técnico real de vazamento de dados "
                    "e comprometimento dos sistemas da empresa. E lentidão (A) é o menor dos problemas — o perigo é invisível e silencioso: o vírus "
                    "pode agir por meses sem que você perceba nada de errado."
                )
            },
            {
                "id": 8,
                "title": "Protegendo a empresa",
                "question": "Qual destas atitudes ajuda a proteger a empresa quando você usa seu equipamento pessoal para trabalhar?",
                "options": [
                    "Desativar o firewall do computador quando o sistema da empresa estiver lento.",
                    "Usar a mesma senha para tudo, desde que seja uma senha muito forte.",
                    "Ativar a autenticação em duas etapas (MFA) nos sistemas da empresa e manter o computador com antivírus e sistema operacional atualizados.",
                    "Deixar o antivírus desligado para o computador ficar mais rápido."
                ],
                "correct": 2,
                "explanation_correct": (
                    "Perfeito! ✅ A autenticação em duas etapas exige um segundo passo para entrar (como um código no celular). Mesmo que alguém "
                    "descubra sua senha, não consegue acessar sem o segundo fator. Antivírus e atualizações fecham brechas conhecidas."
                ),
                "explanation_wrong": (
                    "❌ Antivírus desligado (D) deixa o computador desprotegido — a perda de performance é mínima perto do risco de comprometer "
                    "dados da empresa. Mesmo a senha mais forte, se reutilizada em vários lugares (B), vira ponto único de falha: se uma conta for "
                    "invadida, todas as outras com a mesma senha também estarão comprometidas. E o firewall (A) bloqueia conexões perigosas de fora "
                    "para dentro — desligá-lo deixa o computador exposto a invasões e a vírus se comunicando com criminosos pela internet."
                )
            },
            {
                "id": 9,
                "title": "Pen drive infectado — ataque em andamento!",
                "question": (
                    "🚨 AMEAÇA ATIVA! Você conectou um pen drive infectado ao computador da empresa e percebeu que ele pode estar comprometido. "
                    "O ataque já começou — decida rápido, antes que o hacker complete a invasão!"
                ),
                "options": [
                    "Continuar usando o computador normalmente e avisar a TI apenas se aparecer algum problema.",
                    "Formatar o pen drive e conectá-lo novamente para verificar se o problema foi resolvido.",
                    "Desconectar o pen drive, não abrir nem executar arquivos dele e comunicar imediatamente a TI ou o responsável pela segurança da empresa.",
                    "Passar o antivírus no pen drive e, se não encontrar nada, continuar usando normalmente."
                ],
                "correct": 2,
                "timer_seconds": 30,
                "hacked_title": "Você foi hackeado(a)",
                "hacked_text": (
                    "💀 O tempo acabou e o malware se espalhou pelo computador antes de você reagir. Todos os pontos desta fase foram perdidos. "
                    "No mundo real, a atitude correta era: desconectar o pen drive, não abrir nem executar arquivos dele e comunicar IMEDIATAMENTE "
                    "a TI ou o responsável pela segurança — isso permite analisar a máquina e evita que a infecção se espalhe."
                ),
                "saved_title": "Você salvou a empresa.",
                "explanation_correct": (
                    "🌱 Você salvou a empresa! Ao desconectar o pen drive, não abrir nenhum arquivo dele e comunicar imediatamente a TI ou o "
                    "responsável pela segurança, você interrompeu o ataque na hora certa. Isso permite que o computador seja analisado e evita que "
                    "uma possível infecção se espalhe pela rede."
                ),
                "explanation_wrong": (
                    "❌ A atitude correta era desconectar o pen drive, não abrir nem executar arquivos dele e comunicar imediatamente a TI ou o "
                    "responsável pela segurança (C). Continuar usando o computador (A) permite que o malware se espalhe ou roube informações antes "
                    "que alguém perceba. Formatar e reconectar o pen drive (B) não garante que a ameaça foi eliminada — e ainda coloca o computador "
                    "em risco outra vez. E o antivírus (D) pode não detectar todas as ameaças: a análise deve ficar com a equipe responsável pela segurança."
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

# ─── Selecao de Personagem ───────────────────────────────────
def get_user_character():
    """Retorna os dados do personagem escolhido pelo usuario logado."""
    db = get_db()
    row = db.execute(
        "SELECT character FROM users WHERE id = ?",
        (session['user_id'],)
    ).fetchone()
    key = row['character'] if row and row['character'] in CHARACTERS else DEFAULT_CHARACTER
    return key, CHARACTERS[key]

@app.route('/personagem', methods=['GET', 'POST'])
@login_required
def personagem():
    db = get_db()
    if request.method == 'POST':
        chosen = request.form.get('character', '')
        if chosen not in CHARACTERS:
            flash('Personagem invalido.', 'danger')
            return redirect(url_for('personagem'))
        db.execute(
            "UPDATE users SET character = ? WHERE id = ?",
            (chosen, session['user_id'])
        )
        db.commit()
        flash(f'{CHARACTERS[chosen]["name"]} agora e o seu personagem! 🎮', 'success')
        return redirect(url_for('personagem'))
    current, _ = get_user_character()
    return render_template('personagem.html',
                         characters=CHARACTERS,
                         current=current,
                         spin_frames={k: get_spin_frames(k) for k in CHARACTERS})

@app.route('/game/start')
@login_required
def game_start():
    db = get_db()
    # Pontuacao maxima dinamica: 10 pontos por questao
    total_questions = sum(len(p['subphases']) for p in GAME_PHASES.values())
    cursor = db.execute(
        "INSERT INTO game_sessions (user_id, max_score) VALUES (?, ?)",
        (session['user_id'], total_questions * 10)
    )
    db.commit()
    game_id = cursor.lastrowid

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

    # Personagem escolhido pelo jogador (exibido no canto da fase)
    char_key, char_data = get_user_character()

    return render_template('game.html',
                         game=game,
                         phase=phase,
                         sub=sub,
                         phase_data=phase_data,
                         subphase_data=subphase_data,
                         already_answered=already_answered,
                         user_email=user_email,
                         player_char=char_data,
                         total_phases=len(GAME_PHASES),
                         total_subs_in_phase=len(phase_data['subphases']))

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

@app.route('/game/<int:game_id>/hacked', methods=['POST'])
@login_required
def game_hacked(game_id):
    """Tempo esgotado em questao com timer: o jogador foi hackeado.
    Os pontos da fase inteira sao descartados (zerados)."""
    db = get_db()
    game = db.execute(
        "SELECT * FROM game_sessions WHERE id = ? AND user_id = ? AND completed = 0",
        (game_id, session['user_id'])
    ).fetchone()

    if not game:
        return jsonify({"error": "Sessao invalida"}), 400

    phase = int(request.form.get('phase', 0))
    sub = int(request.form.get('sub', 0))

    if phase not in GAME_PHASES:
        return jsonify({"error": "Fase invalida"}), 400

    phase_data = GAME_PHASES[phase]
    if sub > len(phase_data['subphases']):
        return jsonify({"error": "Sub-fase invalida"}), 400

    # Zera as respostas corretas dessa fase e desconta os pontos ganhos nela
    lost = 0
    row = db.execute(
        "SELECT COUNT(*) AS n FROM phase_answers WHERE session_id = ? AND phase = ? AND correct = 1",
        (game_id, phase)
    ).fetchone()
    lost = row['n'] * 10
    if lost:
        db.execute(
            "UPDATE phase_answers SET correct = 0 WHERE session_id = ? AND phase = ? AND correct = 1",
            (game_id, phase)
        )
        db.execute(
            "UPDATE game_sessions SET score = MAX(0, score - ?) WHERE id = ?",
            (lost, game_id)
        )

    # Registra a questao atual como nao respondida a tempo (timeout)
    existing = db.execute(
        "SELECT id FROM phase_answers WHERE session_id = ? AND phase = ? AND subphase = ?",
        (game_id, phase, sub)
    ).fetchone()
    if not existing:
        db.execute(
            "INSERT INTO phase_answers (session_id, phase, subphase, correct, timed_out) VALUES (?, ?, ?, 0, 1)",
            (game_id, phase, sub)
        )

    # Se era a ultima questao do jogo, finaliza a sessao
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
        "ok": True,
        "hacked": True,
        "points_lost": lost,
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
