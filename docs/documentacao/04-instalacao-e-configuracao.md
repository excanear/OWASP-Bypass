[← Índice](README.md)

# ⚙️ Instalação e Configuração

## Requisitos

| Componente | Versão mínima | Necessário quando |
|:--|:--|:--|
| Python | 3.11+ | Sempre |
| Node.js | 18+ | Só se usar `--setup` para provisionar o Juice Shop você mesmo |
| npm | (vem com o Node) | Idem |
| Git | qualquer versão recente | Idem (clonagem do Juice Shop) |

Se você já tem uma instância do Juice Shop rodando em outro lugar, Node/npm/Git nem precisam estar instalados na máquina que roda a ferramenta — basta apontar `--base-url` para ela.

<br>

## Instalação da ferramenta

```bash
git clone https://github.com/excanear/OWASP-Bypass.git
cd OWASP-Bypass
pip install -r requirements.txt
```

Nenhuma dependência de sistema além das listadas em `requirements.txt`:

| Pacote | Uso |
|:--|:--|
| `requests` | cliente HTTP base (`core/client.py`) |
| `python-socketio[client]` | eventos WebSocket (`localXssChallenge`, `svgInjectionChallenge`, `closeNotificationsChallenge`, etc.) |
| `pyotp` | geração de código TOTP (`twoFactorAuthUnsafeSecretStorageChallenge`) |
| `pyyaml` | usado internamente pelo `setup.py` |
| `eth-account` | derivação de carteira Ethereum (`nftUnlockChallenge`) |
| `hashids` | forja de continue-code (`continueCodeChallenge`) |

O codificador Z85 (`forgedCouponChallenge`) **não** é uma dependência externa — é portado manualmente dentro do próprio repositório (veja [Catálogo de Exploits](03-catalogo-de-exploits.md#cryptographic-issues) e [Decisões de Design](08-decisoes-de-design.md)).

<br>

## Provisionando o Juice Shop

### Opção A — automática (`--setup`)

```bash
python main.py --setup
```

Executa, em sequência: clonagem (`git clone --depth 1`), instalação (`npm install`, que também builda o frontend Angular via `postinstall`), inicialização do servidor (`npm start`) e espera ativa até a instância responder. Primeira execução leva alguns minutos; execuções seguintes reaproveitam `./juice-shop/node_modules` e são rápidas.

> [!WARNING]
> **Nunca use Docker para rodar o Juice Shop com esta ferramenta.** 17 dos desafios em escopo declaram `disabledEnv: [Docker, Heroku]` no próprio código-fonte do Juice Shop e ficam **inalcançáveis** dentro de um container. Use sempre `npm start` direto no host.

### Opção B — manual

```bash
git clone --depth 1 https://github.com/juice-shop/juice-shop.git
cd juice-shop
npm install
npm start
```

Depois, rode a ferramenta apontando para a instância:

```bash
python main.py --base-url http://localhost:3000
```

<br>

## Variável de ambiente obrigatória: `NODE_CONFIG`

Uma categoria inteira só fica alcançável com uma flag específica do lado do servidor. `jwtForgedChallenge` (categoria Vulnerable Components) é **desabilitado por padrão no Windows** pelo próprio Juice Shop (`disabledEnv: [Windows]` no dataset de desafios), a menos que o modo de segurança seja explicitamente desligado:

```bash
NODE_CONFIG='{"challenges":{"safetyMode":"disabled"}}' npm start
```

Se você usar `python main.py --setup`, isso já é feito automaticamente por `setup.py` (veja [Referência de API](02-referencia-api.md#setuppy)). Se você subir o Juice Shop manualmente, precisa incluir essa variável você mesmo — sem ela, `jwtForgedChallenge` falha permanentemente, não por bug do solver, mas porque o próprio servidor recusa o desafio na porta de entrada.

<br>

## Executando

```bash
# Tudo de uma vez, provisionando o Juice Shop primeiro
python main.py --setup

# Contra uma instância que já está no ar
python main.py --base-url http://localhost:3000

# Só algumas categorias (repita a flag quantas vezes precisar)
python main.py --category Injection --category XSS
```

Veja a [referência completa de flags](../../README.md#referência-da-cli) no README principal.

<br>

## Rodando em outro sistema operacional

O Windows é a plataforma testada e documentada para este projeto (a maioria dos solvers são HTTP/WebSocket puro e portáveis, mas dois pontos são específicos de Windows):

| Ponto | Comportamento no Windows | Comportamento esperado em Linux/macOS |
|:--|:--|:--|
| `xxeFileDisclosureChallenge` | Lê `file:///C:/Windows/win.ini` | Precisaria ser trocado para `file:///etc/passwd` |
| `jwtForgedChallenge` | Desabilitado sem `safetyMode: disabled` | Alcançável nativamente, sem flag extra |
| Resolução do `npm` em `setup.py` | Precisa de `shutil.which("npm")` (veja [Solução de Problemas](09-solucao-de-problemas.md)) | `subprocess.run(["npm", ...])` já funciona sem ajuste |

Se for adaptar para Linux/macOS, o único arquivo que provavelmente precisa de ajuste é `solvers/xxe.py` (o caminho do alvo de leitura de arquivo).

<br>

<div align="center">
<sub>← <a href="03-catalogo-de-exploits.md">Catálogo de Exploits</a> · <a href="README.md">Índice</a> · <a href="05-guia-de-extensao.md">Próximo: Guia de Extensão →</a></sub>
</div>
