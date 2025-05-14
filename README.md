# 🔐 Envelope Digital - AES + RSA com Interface Gráfica

Este projeto implementa um sistema de **criptografia híbrida** (AES + RSA), permitindo **criar** e **abrir envelopes digitais** com uma interface gráfica simples feita em `Tkinter` e **compatível com o site [CyberChef](https://gchq.github.io/CyberChef/)** para cifragem/decifragem manual de mensagens.

## 🔐 Conceito de envelope digital

> Um **envelope digital** utiliza uma chave simétrica (AES) para criptografar a mensagem e uma chave pública (RSA) para criptografar a chave AES. Assim, combina **eficiência** e **segurança** em um único processo.

## ✨ Funcionalidades

- 🔑 **Geração de chaves RSA** (1024 ou 2048 bits)  
- 🛡️ **Criptografia de arquivos com AES** (ECB ou CBC) e chave AES cifrada com RSA  
- 📦 **Criação de envelope digital** contendo:
  - Mensagem cifrada
  - Chave AES cifrada
  - (Opcional) IV no modo CBC  
- 🔓 **Abertura do envelope** com chave privada e descriptografia da mensagem
- 🌐 **Compatível com o site 

## 🖼️ Interface gráfica

A interface oferece:
- Navegação entre etapas (menu → gerar chaves → criar envelope → abrir envelope)
- Seleção de arquivos por janela
- Escolha entre codificação Base64 ou Hex
- Registro de ações em um log automático

## ⚙️ Tecnologias usadas

- Python 3
- [`pycryptodome`](https://pypi.org/project/pycryptodome/) – Criptografia AES e RSA
- `Tkinter` – Interface gráfica
- `Base64` e `Hex` – Codificações de saída

## 🚀 Como executar

1. Instale as dependências:
```bash
pip install pycryptodome
```

2. Rode o programa:
```bash
python gui.py
```

## 📁 Estrutura do projeto

```
├── gui.py              # Interface gráfica
├── main.py             # Funções de criptografia e descriptografia
├── output/             # Arquivos gerados (chaves, mensagens cifradas, etc.)
└── log.txt             # Registro das ações realizadas
```
