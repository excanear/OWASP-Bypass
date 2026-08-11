<div align="center">

# 🛡️ OWASP Bypass

### Motor autônomo de exploits para o [OWASP Juice Shop](https://github.com/juice-shop/juice-shop)

**107 exploits registrados · verificação ao vivo contra o scoreboard real · zero mocking**

[![Python](https://img.shields.io/badge/python-3.11%2B-3776AB?style=for-the-badge&logo=python&logoColor=white)](https://www.python.org/)
[![Node.js](https://img.shields.io/badge/node.js-18%2B-339933?style=for-the-badge&logo=node.js&logoColor=white)](https://nodejs.org/)
[![Juice Shop](https://img.shields.io/badge/juice--shop-20.1.1-FF6B00?style=for-the-badge&logo=owasp&logoColor=white)](https://github.com/juice-shop/juice-shop)
[![Resultado](https://img.shields.io/badge/desafios-106%2F107-brightgreen?style=for-the-badge)](#-resultados)
[![Documentação](https://img.shields.io/badge/📘_documentação-técnica_completa-6E56CF?style=for-the-badge)](docs/documentacao/README.md)

<br>

```
╭──────────────────────────────────────────────╮
│                                                │
│   TOTAL: 106/107 desafios resolvidos          │
│                                                │
╰──────────────────────────────────────────────╯
```

</div>

<br>

> [!NOTE]
> O Juice Shop é a aplicação **intencionalmente vulnerável** mantida pela própria OWASP para treinamento de segurança. Esta ferramenta pilota uma instância local dele de ponta a ponta — registra contas, forja tokens, corre contra o servidor em condições de corrida, contrabandeia payloads — e confirma cada vitória consultando o **scoreboard real da aplicação** (`/api/Challenges/`). Nada aqui é simulado: se um solver reporta sucesso, é porque o próprio Juice Shop já marcou aquele desafio como resolvido.

<br>

## 📑 Sumário

<table>
<tr><td width="50%" valign="top">

- [🎯 O que é isto](#-o-que-é-isto)
- [📊 Resultados](#-resultados)
- [🚀 Início rápido](#-início-rápido)
- [📋 Requisitos](#-requisitos)
- [⚙️ Instalação](#️-instalação)
- [🖥️ Uso](#️-uso)

</td><td width="50%" valign="top">

- [🧠 Como funciona](#-como-funciona)
- [📁 Estrutura do projeto](#-estrutura-do-projeto)
- [🧩 Criando um novo solver](#-criando-um-novo-solver)
- [🧪 Filosofia de testes](#-filosofia-de-testes)
- [🎓 Técnicas em destaque](#-técnicas-em-destaque)
- [🚫 Desafios adiados](#-desafios-adiados) · [⚖️ Uso responsável](#️-uso-responsável)

</td></tr>
</table>

<br>

## 🎯 O que é isto

**OWASP Bypass** é uma CLI em Python que **resolve automaticamente** os desafios de segurança embutidos no OWASP Juice Shop — SQL/NoSQL injection, XSS, forja de JWT, IDOR, SSRF, XXE, escrita arbitrária de arquivo via zip-slip, condições de corrida e muito mais — pilotando a API HTTP/WebSocket real da aplicação exatamente como um atacante humano faria, e confirmando cada solução contra o **scoreboard ao vivo** do próprio Juice Shop. Nunca confiando no "provavelmente funcionou" do script.

Cada um dos 107 solvers registrados foi construído da mesma forma, sem exceção:

<table>
<tr><td width="8%" align="center"><b>1</b></td><td>Ler o <b>código-fonte TypeScript real</b> do Juice Shop para encontrar o caminho vulnerável exato — nunca chutado.</td></tr>
<tr><td align="center"><b>2</b></td><td>Construir o payload <b>a partir desse código-fonte</b> — um comentário SQL específico, um JWT forjado, um caminho de zip-slip, uma janela de timing para condição de corrida.</td></tr>
<tr><td align="center"><b>3</b></td><td>Rodar contra uma <b>instância local ao vivo</b> e observar o scoreboard virar.</td></tr>
<tr><td align="center"><b>4</b></td><td>Se não virou, <b>ler o código-fonte de novo</b> — nunca afrouxar a verificação para aceitar um falso positivo.</td></tr>
</table>

O resultado é um corpus de funções de exploit pequenas, de responsabilidade única e fartamente comentadas, que funcionam também como um **writeup vivo e verificado** de quase todos os desafios do Juice Shop — útil como referência de estudo mesmo que você nunca rode a CLI.

<br>

## 📊 Resultados

| Categoria | Resolvidos | Destaques |
|:--|:--:|:--|
| Sensitive Data Exposure | `16/16` | |
| Injection | `11/11` | SQLi, NoSQLi, SSTI |
| Improper Input Validation | `11/11` | |
| Broken Access Control | `11/11` | |
| XSS | `9/9` | inclui XSS na legenda do vídeo via zip-slip |
| Broken Authentication | `9/9` | |
| Vulnerable Components | `8/8` | escrita arbitrária de arquivo, forja de JWT |
| Miscellaneous | `5/5` | |
| Cryptographic Issues | `5/5` | forja de cupom Z85, continue-code Hashids |
| Security Misconfiguration | `4/4` | |
| Observability Failures | `4/4` | |
| Broken Anti Automation | `4/4` | inclui uma condição de corrida (TOCTOU) real |
| Security through Obscurity | `3/3` | |
| Insecure Deserialization | `3/3` | par RCE/DoS por timing em interpretador JS isolado |
| XXE | `1/2` | ver [Desafios adiados](#-desafios-adiados) |
| Unvalidated Redirects | `2/2` | |
| **Total** | **`106/107`** | **110 no escopo · 3 excluídos de saída · 1 bloqueado pelo ambiente** |

<sub>Reproduza este número você mesmo: `python main.py --setup`</sub>

<br>

## 🚀 Início rápido

```bash
git clone https://github.com/excanear/OWASP-Bypass.git
cd OWASP-Bypass
pip install -r requirements.txt
python main.py --setup
```

`--setup` clona o Juice Shop em `./juice-shop`, roda `npm install`, sobe o servidor com `npm start`, espera ele ficar pronto e então executa todos os solvers, imprimindo um relatório agrupado por categoria. A primeira execução leva alguns minutos (instalação do Node + build do Angular); as seguintes são rápidas.

<br>

## 📋 Requisitos

| | |
|:--|:--|
| 🐍 **Python** | 3.11 ou superior |
| 🟢 **Node.js** | 18+ e npm — só necessário se usar `--setup` para provisionar o Juice Shop você mesmo (aponte `--base-url` para uma instância que já esteja rodando e pule isso completamente) |
| 🎯 **Instância do Juice Shop** | iniciada via `npm start`, **nunca via Docker** — 17 desafios declaram `disabledEnv: [Docker, Heroku]` e são simplesmente inalcançáveis em container |
| 🪟 **Testado em** | Windows (git-bash/PowerShell) contra Juice Shop `20.1.1`. Os solvers são HTTP/WebSocket puro e não têm dependência específica de Windows, exceto um payload (`xxeFileDisclosureChallenge` lê `C:\Windows\win.ini` em vez de `/etc/passwd`) |

<br>

## ⚙️ Instalação

```bash
pip install -r requirements.txt
```

Nenhuma dependência de sistema além do Python — os esquemas de codificação Z85 e Hashids usados por dois solvers são implementados diretamente neste repositório em vez de importados como pacotes extras (veja [Técnicas em destaque](#-técnicas-em-destaque)).

Se preferir provisionar o Juice Shop manualmente:

```bash
git clone --depth 1 https://github.com/juice-shop/juice-shop.git
cd juice-shop && npm install && npm start
```

> [!IMPORTANT]
> Uma categoria só fica alcançável com uma flag específica no servidor — `jwtForgedChallenge` vem desabilitado por padrão no Windows a menos que o modo de segurança do Juice Shop seja desligado:
> ```bash
> NODE_CONFIG='{"challenges":{"safetyMode":"disabled"}}' npm start
> ```
> `python main.py --setup` já faz isso por você.

<br>

## 🖥️ Uso

```bash
# Execução completa: provisiona o Juice Shop e resolve tudo
python main.py --setup

# Rodar contra uma instância que você já tem no ar
python main.py --base-url http://localhost:3000

# Rodar apenas categorias específicas (repetível)
python main.py --category Injection --category XSS

# Apenas conferir o scoreboard ao vivo, sem rodar nenhum solver
pytest tests/test_framework.py -v
```

### Referência da CLI

| Flag | Descrição |
|:--|:--|
| `--setup` | Clona/instala/inicia um Juice Shop local antes de rodar os solvers |
| `--base-url URL` | Instância alvo (padrão `http://localhost:3000`) |
| `--category NOME` | Restringe a execução a uma categoria; repita a flag para várias |

O processo sai com código `1` se algum desafio tentado ficar sem solução — ou seja, `python main.py` é amigável para pipelines de CI.

<details>
<summary><b>📄 Ver exemplo de saída</b></summary>

```
Injection (11/11)
  [OK  ] loginAdminChallenge (0.04s)
  [OK  ] unionSqlInjectionChallenge (0.07s)
  [OK  ] sstiChallenge (0.36s)
  ...

Insecure Deserialization (3/3)
  [OK  ] rceChallenge (0.24s)
  [OK  ] rceOccupyChallenge (2.07s)
  [OK  ] yamlBombChallenge (2.27s)

XXE (1/2)
  [OK  ] xxeFileDisclosureChallenge (0.05s)
  [FAIL] xxeDosChallenge (0.13s)

TOTAL: 106/107 solved
```

</details>

<br>

## 🧠 Como funciona

```
┌───────────────┐   register()   ┌────────────────────┐
│  solvers/*.py │ ─────────────► │  registro global    │
└───────────────┘                └──────────┬──────────┘
                                             │ all_solvers()
                                             ▼
┌───────────────┐   HTTP/WS      ┌────────────────────┐   /api/Challenges/   ┌────────────────┐
│ JuiceShop     │ ◄───────────── │  core/runner.py     │ ────────────────────► │  servidor real  │
│ Client        │ ─────────────► │      run_all()       │ ◄──────────────────── │  Juice Shop     │
└───────────────┘   solve(ctx)   └──────────┬──────────┘   solved: true/false  └────────────────┘
                                             ▼
                                    ┌────────────────────┐
                                    │    report.py         │
                                    │  resumo por categoria │
                                    └────────────────────┘
```

Cada solver é uma **função simples**, registrada com um decorator:

```python
@register("loginAdminChallenge", "Injection", 2)
def solve_login_admin(ctx: SolverContext) -> None:
    ctx.client.login("admin@juice-sh.op'--", "irrelevant")
```

`core/runner.run_all()` entrega a cada solver um **`JuiceShopClient` novo em folha** (cookie jar e token de autenticação próprios — nenhum estado vaza entre desafios), executa a função, captura o que ela lançar e, **independentemente de ter havido exceção**, reconsulta o endpoint real `/api/Challenges/` para verificar se a flag realmente virou. É essa reconsulta ao vivo — e não o retorno do solver nem a ausência de exceção — a única coisa que conta como "resolvido". Um solver que retorna normalmente mas não disparou a verificação do lado servidor é reportado como falho; um solver que lança exceção *depois* de o servidor já ter registrado a solução ainda é reportado como resolvido.

Essa é a única regra arquitetural que o projeto inteiro segue à risca: o Juice Shop, às vezes, vira a flag de um desafio dentro de uma continuação assíncrona que chega um instante depois da resposta HTTP que você já recebeu — por isso `run_all` faz um polling curto (até 5 tentativas, 300ms entre elas) para absorver essa corrida em vez de reportar um falso negativo.

<br>

## 📁 Estrutura do projeto

<details open>
<summary><b>Ver árvore completa</b></summary>

```
main.py                     ponto de entrada da CLI — importa todos os solvers, executa, reporta
setup.py                    clona/instala/inicia o Juice Shop para você
report.py                   relatório no console, agrupado por categoria

core/
  client.py                 JuiceShopClient — wrapper fino sobre requests.Session (login, registro, verbos)
  runner.py                 run_all() — o loop de verificação ao vivo descrito acima
  challenge_api.py          lê o scoreboard real em /api/Challenges/

solvers/
  base.py                        o decorator @register + o registro de solvers
  injection.py                    11 solvers — SQLi, NoSQLi, SSTI
  xss.py                           9 solvers — XSS refletido/persistido/DOM, disparado via WebSocket
  broken_auth.py                   9 solvers — senhas fracas, vazamento de segredo 2FA, respostas de recuperação
  sensitive_data.py               16 solvers — IDOR, vazamento de JWT/cupom, metadados de geolocalização
  broken_access_control.py        11 solvers — CSRF, SSRF, adulteração de carrinho/avaliação
  improper_input_validation.py    11 solvers
  vulnerable_components.py         9 solvers — escrita de arquivo via zip-slip, JWT não assinado/forjado
  cryptographic_issues.py          5 solvers — forja de cupom Z85, continue-code Hashids
  security_misconfiguration.py     4 solvers
  observability_failures.py        4 solvers
  miscellaneous.py                 5 solvers
  broken_anti_automation.py        4 solvers — bypass de CAPTCHA, uma condição de corrida real
  security_through_obscurity.py    3 solvers
  insecure_deserialization.py      3 solvers — par RCE/DoS por timing, bomba YAML
  unvalidated_redirects.py         2 solvers — bypass de allowlist por substring vs. prefixo
  xxe.py                           2 solvers — leitura de arquivo via entidade externa, DoS por expansão

tests/
  test_framework.py          smoke tests do próprio framework
  test_<categoria>_live.py   uma suíte de verificação ao vivo por categoria, sem mocking, jamais

docs/superpowers/
  specs/                     documento original de escopo e arquitetura
  plans/                     os 5 planos de implementação, fase a fase, que originaram este projeto
```

</details>

<br>

## 🧩 Criando um novo solver

Todo solver segue a mesma forma de três linhas:

```python
# solvers/minha_categoria.py
from solvers.base import SolverContext, register

@register("algumaChaveDoDesafio", "Nome da Categoria", difficulty=3)
def solve_alguma_coisa(ctx: SolverContext) -> None:
    ctx.client.post("/algum/endpoint", json={"payload": "..."})
```

- `ctx.client` é um `JuiceShopClient` — `.get/.post/.put/.patch(path, **kwargs)` encapsulam o `requests` diretamente, além dos helpers `.register(email, senha)` e `.login(email, senha)`, que já cuidam do cookie/header de autenticação.
- Você nunca consulta o scoreboard manualmente — `run_all()` faz isso depois que sua função retorna (ou lança exceção).
- Registre o import do módulo em `main.py` (`try: import solvers.minha_categoria`) para que ele seja carregado.
- Adicione um `tests/test_minha_categoria_live.py` seguindo o padrão existente — HTTP real contra uma instância real, verificando que cada chave da sua categoria aparece como `solved: true`.

<br>

## 🧪 Filosofia de testes

> [!TIP]
> **Sem mocking. Em lugar nenhum. Nunca.** Todo teste em `tests/` roda os solvers de verdade contra uma instância real do Juice Shop e verifica contra o scoreboard real. Isso é deliberado: um teste mockado pode passar enquanto o exploit de verdade está quebrado — o que, para uma ferramenta de segurança, é pior do que não ter teste nenhum.

```bash
pytest tests/ -v
```

Cada `test_*_live.py` faz *skip* (não falha) quando nenhuma instância está acessível em `http://localhost:3000`, então a suíte é segura de rodar mesmo sem o Juice Shop no ar — ela só reporta zero asserções coletadas nos arquivos ao vivo.

<br>

## 🎓 Técnicas em destaque

Alguns solvers que vão bem além de um payload de uma linha:

<table>
<tr>
<td width="30%"><b>📦 Zip-slip → escrita arbitrária de arquivo</b><br><sub><a href="solvers/vulnerable_components.py">vulnerable_components.py</a></sub></td>
<td>Um upload <code>.zip</code> forjado com entradas como <code>../../ftp/legal.md</code> escapa do diretório pretendido <code>uploads/complaints/</code>. A mesma técnica sobrescreve a legenda do vídeo promocional com um payload de XSS, resolvendo de brinde um segundo desafio — de XSS — sem relação direta.</td>
</tr>
<tr>
<td><b>🔑 Confusão de algoritmo JWT (RS256→HS256)</b><br><sub><a href="solvers/vulnerable_components.py">vulnerable_components.py</a></sub></td>
<td>Busca a chave <b>pública</b> RSA do próprio servidor em seu endpoint público, depois assina um token forjado com <b>HS256</b>, usando os bytes brutos da chave pública como segredo HMAC — o clássico ataque de confusão de algoritmo contra bibliotecas JWT que não fixam o algoritmo esperado. (O PyJWT moderno bloqueia isso ativamente como defesa em profundidade, então este solver monta o HMAC manualmente com a biblioteca padrão em vez de <code>pyjwt.encode()</code>.)</td>
</tr>
<tr>
<td><b>💳 Forja de cupom Z85</b><br><sub><a href="solvers/cryptographic_issues.py">cryptographic_issues.py</a></sub></td>
<td>O Juice Shop codifica cupons de desconto com o esquema Z85 (RFC 32) do ZeroMQ. Este repositório porta manualmente o codificador de ~15 linhas direto do pacote npm real (verificado byte a byte contra o registry, nunca chutado) em vez de confiar em um pacote PyPI homônimo sem relação alguma.</td>
</tr>
<tr>
<td><b>🎮 Forja de continue-code Hashids</b><br><sub><a href="solvers/cryptographic_issues.py">cryptographic_issues.py</a></sub></td>
<td>Reproduz o "código de continuação" de save-game do Juice Shop usando o mesmo salt/alfabeto/tamanho mínimo do servidor, de forma determinística — sem nunca ter jogado.</td>
</tr>
<tr>
<td><b>⚡ Condição de corrida real (TOCTOU)</b><br><sub><a href="solvers/broken_anti_automation.py">broken_anti_automation.py</a></sub></td>
<td>Dispara oito requisições concorrentes de "curtir esta avaliação" via <code>concurrent.futures.ThreadPoolExecutor</code> para vencer uma janela TOCTOU real: o servidor verifica "você já curtiu isso?" antes de um atraso artificial de 150ms e só grava a curtida <i>depois</i> dele — requisições concorrentes o suficiente escapam da verificação antes que qualquer uma delas seja confirmada.</td>
</tr>
<tr>
<td><b>💣 Par DoS/RCE por timing</b><br><sub><a href="solvers/insecure_deserialization.py">insecure_deserialization.py</a></sub></td>
<td>O Juice Shop avalia JS não confiável num interpretador isolado com dois limites independentes: o contador de 1.000.000 de iterações do próprio interpretador, e o timeout de 2 segundos da VM hospedeira. Um solver usa um <code>while(true){}</code> leve o bastante para disparar primeiro o contador do interpretador; o outro aninha um loop pesado para que o timeout da <i>VM</i> vença a corrida — dois desfechos opostos do mesmo endpoint vulnerável, de propósito.</td>
</tr>
<tr>
<td><b>🔀 Bypass de allowlist por substring vs. prefixo</b><br><sub><a href="solvers/unvalidated_redirects.py">unvalidated_redirects.py</a></sub></td>
<td>A verificação de allowlist de redirecionamento do servidor usa <code>.includes()</code> (substring em qualquer posição), enquanto a verificação de "isso era um redirecionamento pretendido" usa <code>.startsWith()</code> (só prefixo) — uma URL que <i>contém</i> uma URL permitida sem <i>começar</i> com ela satisfaz a primeira verificação e falha a segunda ao mesmo tempo.</td>
</tr>
</table>

<br>

## 🚫 Desafios adiados

107 dos 110 desafios do Juice Shop no escopo são resolvidos automaticamente. Quatro permanecem permanentemente fora de alcance para esta ferramenta, todos pelo mesmo motivo raiz: exigem um serviço externo real que este ambiente não tem acesso, ou um comportamento de dependência não corrigido que a versão exata da biblioteca aqui não apresenta. Nenhum é resolvível trocando o payload.

| Desafio | Categoria | Por que está excluído |
|:--|:--|:--|
| `chatbotPromptInjectionChallenge`, `chatbotGreedyInjectionChallenge`, `systemPromptExtractionChallenge` | Injection | Exigem um LLM real configurado por trás do chatbot embutido no Juice Shop |
| `aiDebuggingChallenge` | Broken Access Control | Exige que o chatbot invoque uma chamada de ferramenta via LLM real |
| `nftMintChallenge` | Improper Input Validation | Exige uma carteira Ethereum real e financiada na testnet Sepolia + uma chave de API paga da Alchemy |
| `web3WalletChallenge` | Miscellaneous | Mesma dependência on-chain/Alchemy acima |
| `xxeDosChallenge` | XXE | Uma bomba clássica de expansão de entidades ("billion laughs") é rejeitada de imediato pelo guard `xmlCtxtSetMaxAmplification` do libxml2, combinado com o limite de 200KB de upload do Juice Shop, na versão do libxml2-wasm fixada neste checkout — o payload que dispararia o timeout pretendido nunca chega a rodar por tempo suficiente antes de ser rejeitado em milissegundos. Verificado em seis variações de payload ajustadas independentemente; o solver permanece registrado e é tentado normalmente, sendo reportado honestamente como não resolvido em vez de removido. |

<sub>O solver de <code>xxeDosChallenge</code> permanece em <code>solvers/xxe.py</code> de propósito — uma tentativa genuína e documentada que falha é mais útil do que fingir que o desafio não existe.</sub>

<br>

## 📚 Documentação de design

> [!IMPORTANT]
> **Documentação técnica completa:** este README é a introdução rápida. Para arquitetura em profundidade, referência de API, o catálogo técnico detalhado dos 107 exploits, guia de extensão e o registro de decisões de design, veja a **[📘 Documentação Técnica Oficial](docs/documentacao/README.md)**.

Este projeto foi construído fase a fase, cada uma com um plano de implementação escrito e revisado contra o código-fonte real do Juice Shop antes de qualquer linha de solver ser escrita:

- [`docs/superpowers/specs/`](docs/superpowers/specs/2026-08-09-juice-shop-automator-design.md) — escopo e arquitetura originais
- [`docs/superpowers/plans/`](docs/superpowers/plans/) — cinco planos de fase, um por entrega, cada um listando os arquivos-fonte exatos consultados e o raciocínio por trás de cada payload não óbvio

<br>

## ⚖️ Uso responsável

> [!WARNING]
> Este projeto tem como alvo o **OWASP Juice Shop**, uma aplicação construída e mantida pela própria OWASP especificamente para ser atacada em treinamentos de segurança. Rodar estes solvers contra sua própria instância local do Juice Shop é exatamente para isso que o projeto existe.
>
> **Não aponte `--base-url` para nenhuma instância que você não possua ou não tenha autorização explícita para testar.** Nada neste repositório é destinado a, ou deve ser usado contra, infraestrutura de terceiros.

<br>

<div align="center">
<sub>Construído com verificação ao vivo, sem mocking, contra o código-fonte real do Juice Shop.</sub>
</div>
