<h1 align="center">🔎 Vestigium</h1>

<p align="center">
  <b>Agente autônomo de análise forense, CTF e pentest.</b><br>
  Ingere evidências ou avalia um alvo autorizado, detecta e correlaciona riscos, e gera um relatório profissional completo.
</p>

<p align="center">
  <a href="https://elevbit-ai.github.io/vestigium/">Website</a> ·
  <a href="#instalação">Instalação</a> ·
  <a href="#uso">Uso</a> ·
  <a href="#como-o-agente-funciona">Como funciona</a> ·
  <a href="#categorias-de-detecção">Categorias</a>
</p>

<p align="center">
  <img alt="Python" src="https://img.shields.io/badge/python-3.9%2B-blue">
  <img alt="Licença" src="https://img.shields.io/badge/licen%C3%A7a-MIT-green">
  <img alt="Dependências" src="https://img.shields.io/badge/depend%C3%AAncias-zero-brightgreen">
  <img alt="Status" src="https://img.shields.io/badge/status-est%C3%A1vel-success">
</p>

---

## Visão geral

**Vestigium** (do latim *vestígio, rastro*) é um agente que automatiza a triagem
forense de um conjunto de evidências. Você aponta para um arquivo ou uma pasta;
o agente **identifica cada artefato**, **roteia** para os analisadores certos,
**executa as detecções**, **correlaciona** os achados para reconstruir a cadeia
do ataque e entrega um **relatório profissional** em HTML, Markdown e JSON.

Ele foi pensado para os cenários clássicos de **CTF de forense**, **DFIR** (resposta
a incidentes) e **triagem em pentest** — cobrindo nove categorias:

> **PCAP · LOG · SQLite · Stego · Crypto · Warmup · Phishing · Cadeia · Dropper**

O núcleo usa **somente a biblioteca padrão do Python** — sem dependências, sem
instalar nada além do próprio pacote.

> 🎬 **Veja o sistema inteiro em ~1 minuto:** [vídeo de demonstração](https://elevbit-ai.github.io/vestigium/#video) no website.

---

## Destaques

- 🤖 **Funciona como agente**: ciclo *percepção → roteamento → análise → correlação → síntese*, com uma **trilha de decisão auditável** registrada no relatório.
- 🧩 **9 analisadores** especializados, cada um mapeado a técnicas **MITRE ATT&CK**.
- 🔗 **Correlação de cadeia**: liga IOCs entre evidências e reconstrói as fases da *kill chain*.
- 📄 **Relatório profissional**: HTML autocontido e imprimível, além de Markdown e JSON para automação.
- 🚩 **Recupera bandeiras (flags)** automaticamente após decodificação/desofuscação.
- 🧮 **Índice de risco** de 0 a 100 e sumário executivo.
- 🪶 **Zero dependências** e multiplataforma (Windows, Linux, macOS).

---

## Instalação

```bash
git clone https://github.com/elevbit-ai/vestigium.git
cd vestigium
pip install -e .
```

Ou, sem instalar, direto do código-fonte:

```bash
# a partir da raiz do repositório
python -m vestigium scan <caminho>   # (com src no PYTHONPATH)
```

Requisito: **Python 3.9+**. Nenhuma dependência externa.

---

## Uso

```bash
# analisa uma pasta de evidências e gera o relatório
vestigium scan ./evidencias -o relatorio/

# escolhe os formatos de saída
vestigium scan captura.pcap --formats html,json

# modo CI: falha (exit 1) se houver achado de severidade alta ou superior
vestigium scan ./evidencias --fail-on high
```

Gerar e analisar o conjunto de demonstração:

```bash
python examples/generate_samples.py
vestigium scan examples/samples -o examples/demo-report
```

Saída típica:

```
  RISCO: Critico (100/100)
  Evidencias: 8 | Achados: 47 | Tempo: 3.1s
  Severidade: Alta=26 | Critica=4 | Media=5 | Baixa=2 | Informativo=10
  Bandeiras: flag{rot_treze}, flag{base64_aninhado}, flag{apos_o_eof}, ...
```

O relatório HTML (`relatorio.html`) é autocontido — basta abrir no navegador ou
imprimir em PDF.

---

## Modo Pentest (reconhecimento)

Além da análise forense (que recebe evidências já coletadas), o Vestigium tem um
**modo ofensivo de reconhecimento** para testes de intrusão **autorizados**. Ele
executa as fases seguras e **não destrutivas** de um pentest contra **um único
alvo** e alimenta o mesmo relatório profissional.

```bash
# reconhecimento de um alvo autorizado (exige --authorize)
vestigium recon exemplo.com --authorize -o pentest/

# alvo com porta e formatos específicos
vestigium recon 10.0.0.5:8080 --authorize --formats html,json

# varredura ampla de portas (1-1024 + comuns)
vestigium recon exemplo.com --authorize --full-ports
```

O que o `recon` faz:

| Fase | Verificação |
|------|-------------|
| **Portas** | Varredura TCP *connect* das portas comuns (ou 1–1024 com `--full-ports`); destaca serviços sensíveis expostos. |
| **Serviços** | Coleta de banner e identificação de serviço/versão. |
| **HTTP** | Cabeçalhos de segurança ausentes (HSTS, CSP, X-Frame-Options…), divulgação de versão e cookies sem flags. |
| **Tecnologias** | Identificação de CMS e stack (WordPress, Drupal, Laravel, Django, ASP.NET, React/Angular…) por cabeçalhos, cookies e HTML. |
| **WAF/CDN** | Detecção de WAF/CDN (Cloudflare, Akamai, Imperva, AWS, F5, Fortinet, ModSecurity…). |
| **TLS** | Protocolo negociado (alerta TLS < 1.2) e validade do certificado. |
| **DNS** | Enumeração de registros (A/MX/NS/TXT) e higiene de e-mail — alerta para MX sem SPF/DMARC. |
| **SNMP** | Verifica exposição de SNMP com a *community* padrão `public` (somente leitura, sem força bruta). |
| **Descoberta** | GET não destrutivo de caminhos sensíveis (`.git`, `.env`, `server-status`, backups, painéis…). |

**Salvaguardas de segurança embutidas** — este modo **não** é uma ferramenta de ataque:

- 🔒 Exige `--authorize` (confirmação explícita de permissão).
- 🎯 Aceita **apenas um alvo** — **faixas CIDR e listas são rejeitadas** (sem alvo em massa).
- 🚫 **Sem exploração**, sem força bruta de credenciais e **sem negação de serviço**.
- 📋 Registra o escopo autorizado e toda a trilha de decisão no relatório.

---

## Como o agente funciona

O agente executa um ciclo determinístico e **registra cada decisão**:

```
  ┌─────────────┐   ┌──────────────┐   ┌───────────┐   ┌─────────────┐   ┌──────────┐
  │ 1. Percepção │──▶│ 2. Roteamento │──▶│ 3. Análise │──▶│ 4.Correlação│──▶│ 5.Síntese │
  └─────────────┘   └──────────────┘   └───────────┘   └─────────────┘   └──────────┘
   coleta e            escolhe os        executa os       liga IOCs e        pontua o risco
   identifica          analisadores      analisadores     reconstrói a       e gera o
   evidências          por evidência     e coleta         cadeia de ataque   relatório
   (magic bytes)                         achados
```

1. **Percepção** — varre o alvo, calcula SHA-256/MD5 e entropia, e identifica o tipo real de cada arquivo por *magic bytes* (não pela extensão).
2. **Roteamento** — decide quais analisadores se aplicam a cada evidência.
3. **Análise** — cada analisador produz *findings* com severidade, evidência, IOCs, técnica MITRE e recomendação.
4. **Correlação** — o analisador **Cadeia** cruza IOCs entre evidências e mapeia as fases da *kill chain*.
5. **Síntese** — calcula o índice de risco e emite o relatório (HTML/MD/JSON).

Toda a trilha (`trace`) fica no relatório, tornando o comportamento do agente
**auditável e reproduzível**.

---

## Categorias de detecção

| Categoria    | O que detecta |
|--------------|---------------|
| **Warmup**   | Triagem genérica: strings, bandeiras em claro, IOCs, extensão incompatível com o conteúdo, blocos base64/hex embutidos. |
| **PCAP**     | Parser próprio de pcap/pcapng: protocolos, DNS (e tunelamento), HTTP em claro, **credenciais em claro**, bandeiras em payload e **beaconing** (C2). |
| **LOG**      | SQLi, XSS, path traversal, LFI/RFI, injeção de comando, Log4Shell, varredura (404 em massa), **força bruta** e User-Agents de ferramentas. |
| **SQLite**   | Esquema, tabelas sensíveis/PII, hashes de senha, bandeiras e **carving** de registros apagados nas páginas/freelist. |
| **Stego**    | Dados após o EOF da imagem, **arquivos embutidos/polyglot**, metadados, LSB e assinaturas de ferramentas (steghide/OpenStego). |
| **Crypto**   | base64/base32/hex (inclusive aninhado), ROT/Caesar (todos os shifts), Atbash, **XOR byte único**, Morse, chaves PEM e identificação de hashes. |
| **Phishing** | SPF/DKIM/DMARC, spoofing de remetente, domínios sósia (typosquat), links mascarados, encurtadores, formulários de captura de credenciais e anexos perigosos. |
| **Dropper**  | PowerShell/JS/VBS/macros ofuscados, download de estágios, LOLBins, execução em memória, **desofuscação** de `-EncodedCommand`/base64 e seções PE de alta entropia. |
| **Cadeia**   | Correlaciona IOCs entre evidências e **reconstrói a cadeia de ataque** (kill chain / MITRE ATT&CK). |

---

## Saída para automação (JSON)

```json
{
  "tool": "Vestigium",
  "risk_score": 100,
  "risk_label": "Critico",
  "stats": { "by_severity": {"CRITICAL": 4, "HIGH": 26}, "flags": ["flag{...}"] },
  "findings": [
    { "analyzer": "pcap", "category": "pcap", "severity": "CRITICAL",
      "title": "Credenciais em texto claro na rede",
      "mitre": ["T1040"], "iocs": {"ipv4": ["10.0.0.9"]} }
  ]
}
```

---

## Estrutura do projeto

```
vestigium/
├── src/vestigium/
│   ├── agent.py          # orquestrador (o "agente")
│   ├── evidence.py       # ingestão e identificação por magic bytes
│   ├── findings.py       # modelo de achados e severidade
│   ├── patterns.py       # regex de IOCs, flags e decodificadores
│   ├── report.py         # relatório HTML / Markdown / JSON
│   ├── cli.py            # linha de comando (scan + recon)
│   ├── analyzers/        # os 9 analisadores forenses
│   └── offensive/        # modo pentest (reconhecimento)
├── examples/             # gerador de amostras + demo
├── tests/                # testes de fumaça
└── docs/                 # website (GitHub Pages)
```

---

## Ética e uso responsável

O Vestigium é uma ferramenta para **análise forense, CTF e testes de intrusão
autorizados**. A análise forense é defensiva (opera sobre evidências já
coletadas). O **modo pentest (`recon`) é ativo** e deve ser usado **somente**
contra sistemas para os quais você tem **autorização explícita por escrito** —
por isso ele exige `--authorize`, aceita apenas um alvo e não executa exploração,
força bruta ou negação de serviço. Testar sistemas de terceiros sem permissão é
ilegal. O autor não se responsabiliza por uso indevido.

---

## Autor

**Joaquim Pedro de Morais Filho**
✉️ j360074@hotmail.com

Licenciado sob a [MIT License](LICENSE).
