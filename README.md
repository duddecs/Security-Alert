# 🛡️ Security Alert

> Plataforma corporativa de capacitação em cibersegurança para colaboradores da Leroy Merlin.
> Challenge Leroy Merlin 2026 — FIAP Defesa Cibernética.

[![Status](https://img.shields.io/badge/status-active-success.svg)]()
[![Python](https://img.shields.io/badge/python-3.11+-blue.svg)]()
[![Flask](https://img.shields.io/badge/flask-3.1-green.svg)]()

---

## 📖 Sobre o Projeto

A **Security Alert** é uma plataforma de treinamento gamificado que ensina colaboradores a identificar e responder a três das principais ameaças cibernéticas enfrentadas no ambiente corporativo:

- 🔑 **Senhas seguras** — criação, gestão e não compartilhamento
- ⚠️ **Negligência operacional** — bloqueios de tela, dispositivos perdidos, informações sigilosas
- 🎣 **Phishing** — identificação de tentativas por e-mail, SMS, telefone e web

Cada fase possui sub-fases que valem pontos. O jogador recebe feedback imediato sobre suas escolhas e, ao final, uma avaliação personalizada de seu desempenho.

---

## 🛠️ Tecnologias Utilizadas

| Camada       | Tecnologia            |
|--------------|-----------------------|
| **Backend**  | Python 3.11 + Flask 3.1 |
| **Banco**    | SQLite (via Python stdlib) |
| **Frontend** | HTML5 + CSS3 + JavaScript |
| **Fontes**   | Aurora, Floraless, Alte Haas Grotesk |
| **Hospedagem local** | Flask dev server (porta 5000) |

---

## 📂 Estrutura do Projeto

```
security-alert/
├── 📄 app.py                  # Backend Flask (rotas + lógica + banco)
├── 📄 requirements.txt         # Dependências Python
├── 📄 README.md                # Este arquivo
├── 📄 .gitignore               # Arquivos ignorados pelo Git
│
├── 📁 static/                  # Arquivos estáticos (servidos direto)
│   ├── 📁 css/
│   │   └── 🎨 style.css       # Estilos cyber-femininos
│   ├── 📁 js/
│   │   └── 📜 characters.js   # Personagens SVG (legado)
│   ├── 📁 fonts/              # Fontes customizadas
│   │   ├── Aurora.otf         # Cyber futurista
│   │   ├── Floraless.ttf      # Delicada (números)
│   │   └── AlteHaasGroteskRegular.ttf  # Corpo clean
│   └── 📁 img/                 # Imagens do projeto
│       ├── logo.png
│       ├── carlos.png          # Chefe Carlos (mentor)
│       └── ...
│
└── 📁 templates/               # Templates Jinja2 (HTML)
    ├── 🏠 base.html           # Estrutura base (todas as páginas)
    ├── 🏠 index.html          # Landing page (página inicial)
    ├── 🔐 login.html          # Tela de login
    ├── ✨ register.html        # Tela de cadastro
    ├── 🔑 reset_password.html # Recuperação de senha
    ├── 📊 dashboard.html      # Painel do usuário logado
    ├── 🎮 game.html           # O jogo em si (fases + questões)
    ├── 🏆 feedback.html       # Resultado final do treinamento
    └── ℹ️ about.html           # "Por que" e "Quem somos"
```

---

## 📄 O que cada página HTML faz

### 🏠 `base.html` — O esqueleto de tudo
Estrutura base usada por **todas** as outras páginas. Contém:
- Navbar com logo + nome do site + links
- Área onde o conteúdo de cada página é injetado (`{% block content %}`)
- Rodapé com créditos do grupo

### 🏠 `index.html` — Landing page
Primeira página vista por quem **não está logado**. Mostra:
- Hero com logo grande + slogan corporativo
- Botões "Entrar" e "Criar Conta"
- 3 cards de features (módulos de treinamento)
- Ranking Nacional (só aparece com usuários que autorizaram)
- Links "Por que a Security Alert?" e "Quem somos"

### 🔐 `login.html` — Tela de login
Formulário para usuário entrar com **username ou email** + senha.
Possui link para cadastro e para recuperação de senha.

### ✨ `register.html` — Tela de cadastro
Formulário para criar conta nova:
- Nome de usuário (mínimo 3 caracteres)
- Email
- Senha (mínimo 6 caracteres)
- Checkbox "Aparecer em Ranking Nacional?" (marcado por padrão)

### 🔑 `reset_password.html` — Recuperação de senha
Permite redefinir senha informando email + nova senha (sem token, validação direta).

### 📊 `dashboard.html` — Painel do usuário
Primeira página vista após login. Mostra:
- Saudação "Bem-vindo(a), [usuário]!"
- Botão "Iniciar Novo Treinamento"
- 3 cards de estatísticas (treinamentos, concluídos, melhor pontuação)
- Ranking Nacional com toggle para aparecer/sair
- Histórico de treinamentos anteriores

### 🎮 `game.html` — O jogo em si
A página principal do treinamento. Mostra:
- Barra de progresso das 3 fases (🔑 ⚠️ 🎣)
- Tela de introdução da fase com personagem do **Chefe Carlos** (PNG)
- Fala do chefe rolando letra por letra (efeito typewriter)
- Perguntas com 4 opções (A, B, C, D)
- Feedback imediato após resposta (acerto/erro com explicação)
- Botão para próxima fase

### 🏆 `feedback.html` — Resultado final
Mostrado após completar as 3 fases. Exibe:
- Emoji grande baseado no desempenho (🏆 / 👍 / 📚 / 🌱)
- Pontuação final em círculo com anel animado
- Mensagem personalizada de acordo com a performance
- Detalhamento por fase (acertos / total)
- Botões para jogar novamente ou voltar ao dashboard

### ℹ️ `about.html` — Sobre
Página estática com:
- Seção "Por que a Security Alert?" (texto explicativo)
- Seção "Quem somos" (cartões do grupo)

---

## 🚀 Como rodar localmente

### Pré-requisitos

- Python 3.11 ou superior
- pip ou uv (gerenciador de pacotes)

### Instalação

```bash
# Clone o repositório
git clone https://github.com/duddecs/security-alert.git
cd security-alert

# Instale as dependências
pip install -r requirements.txt
# ou
uv pip install -r requirements.txt
```

### Executando

```bash
python app.py
```

Acesse no navegador: **http://localhost:5000**

---

## 👥 Equipe

| Membro | RM |
|--------|-----|
| Ana Luiza Azevedo Morais | 565711 |
| Maria Eduarda de Lucena Alves | 565184 |
| Pedro Henrique Copertino | 564771 |
| Thalia Aiko Yamamoto | 561758 |

**Orientador:** Prof. Silvio César Roxo Giavaroto

**Instituição:** FIAP — Curso de Defesa Cibernética (Paulista, 2026)

---

## 📜 Licença

Projeto acadêmico desenvolvido para o Challenge Leroy Merlin 2026.
Todos os direitos reservados ao grupo Security Alert.
