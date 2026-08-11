[← Índice](README.md)

# 🔧 Solução de Problemas

Problemas conhecidos, causa raiz verificada e correção — em vez de sintomas genéricos, cada entrada aqui documenta exatamente o que foi investigado.

<br>

## `FileNotFoundError: [WinError 2]` ao rodar `python main.py --setup`

**Sintoma:**

```
File "...\setup.py", line 27, in npm_install
    subprocess.run(["npm", "install"], cwd=target_dir, check=True)
...
FileNotFoundError: [WinError 2] O sistema não pode encontrar o arquivo especificado
```

**Causa raiz:** no Windows, `npm` é na verdade `npm.cmd` (ou `npm.CMD`). `shutil.which("npm")` encontra esse arquivo sem problema, mas o `CreateProcess` do Windows — usado internamente por `subprocess` — não executa arquivos `.cmd` quando recebe a string literal `"npm"` como comando; ele precisa do caminho completo resolvido, ou da flag `shell=True`.

**Status:** ✅ **Já corrigido** neste repositório (commit `f2285ba`). `setup.py` agora resolve o caminho real via `shutil.which("npm")` antes de qualquer chamada de subprocesso — veja [ADR-08](08-decisoes-de-design.md#adr-08--resolução-explícita-do-caminho-do-npm-em-setuppy). Se você está numa versão antiga do repositório e vê este erro, atualize para a versão mais recente do `main`.

**Como foi encontrado:** rodando `python main.py --setup` de ponta a ponta pela primeira vez, contra uma clonagem 100% nova — em todas as fases de desenvolvimento anteriores, o Juice Shop tinha sido instalado manualmente via terminal bash, então esse caminho de código nunca tinha sido exercitado de verdade antes.

<br>

## `jwtForgedChallenge` nunca resolve, mesmo com o solver rodando sem erro

**Sintoma:** `[FAIL] jwtForgedChallenge` no relatório, sem mensagem de erro HTTP (a requisição em si teve sucesso).

**Causa raiz:** este desafio específico é desabilitado pelo **próprio Juice Shop** quando ele detecta que está rodando no Windows (`disabledEnv: [Windows]` no dataset de desafios), a menos que o modo de segurança do servidor esteja explicitamente desligado.

**Correção:** garanta que o Juice Shop foi iniciado com:

```bash
NODE_CONFIG='{"challenges":{"safetyMode":"disabled"}}' npm start
```

Se você usou `python main.py --setup`, isso já é automático. Se você subiu o Juice Shop manualmente, precisa incluir essa variável de ambiente você mesmo — veja [Instalação e Configuração](04-instalacao-e-configuracao.md#variável-de-ambiente-obrigatória-node_config).

<br>

## `ModuleNotFoundError: No module named 'solvers'` ao rodar `pytest`

**Sintoma:** `pytest tests/test_injection_live.py` falha na coleta, sem sequer tentar rodar o teste.

**Causa raiz:** dependendo do ambiente (observado no Windows durante o desenvolvimento), o comando `pytest` puro nem sempre adiciona o diretório raiz do projeto ao `sys.path` da forma esperada.

**Correção:** use `python -m pytest` no lugar de `pytest` diretamente:

```bash
python -m pytest tests/ -v
```

<br>

## Porta 3000 já em uso

**Sintoma:** `python main.py --setup` trava esperando o servidor ficar pronto, ou `npm start` falha ao subir.

**Causa raiz:** uma instância anterior do Juice Shop ainda está rodando em background (comum depois de uma sessão de desenvolvimento interrompida abruptamente).

**Correção (Windows/PowerShell):**

```powershell
$conn = Get-NetTCPConnection -LocalPort 3000 -ErrorAction SilentlyContinue | Where-Object State -eq 'Listen'
if ($conn) { Stop-Process -Id $conn[0].OwningProcess -Force }
```

**Correção (Linux/macOS):**

```bash
lsof -ti:3000 | xargs kill -9
```

<br>

## `timingAttackChallenge` falha intermitentemente

**Sintoma:** o desafio resolve na maioria das execuções, mas ocasionalmente aparece como `[FAIL]`.

**Causa raiz:** é uma condição de corrida real (ver [Catálogo de Exploits](03-catalogo-de-exploits.md#broken-anti-automation)) — depende de pelo menos 3 das 8 requisições concorrentes vencerem a janela de 150ms do servidor. Em máquinas sob carga pesada, ou com latência de rede/loopback anormal, isso pode ocasionalmente não acontecer.

**Correção:** normalmente basta rodar de novo. Se a falha for consistente, aumente `max_workers`/o número de requisições disparadas em `solvers/broken_anti_automation.py` (não adicione atraso artificial — isso derrotaria o propósito do exploit).

<br>

## Os solvers de RCE/XXE-DoS (`rceChallenge`, `rceOccupyChallenge`, `xxeDosChallenge`) se comportam diferente do documentado

**Causa raiz possível:** esses três dependem de uma corrida de timing contra limites internos específicos do Juice Shop (contador de iterações do interpretador `notevil`, timeout de 2s da VM, guard de amplificação do libxml2). Uma mudança de versão dessas dependências no `package.json` do Juice Shop pode alterar o comportamento.

**O que fazer:** leia a análise técnica completa em [Desafios Adiados](07-desafios-adiados.md) antes de assumir que é um bug de payload — dois desses três (`rceChallenge`/`rceOccupyChallenge`) são deliberadamente ajustados para ficar em lados opostos da mesma corrida, e um ajuste de peso errado nos faria trocar de lugar entre si, não simplesmente falhar.

<br>

## Nenhum dos problemas acima descreve o que você está vendo

Abra uma issue no repositório com:

1. O comando exato que rodou
2. A saída completa (stdout + stderr)
3. `python --version`, `node --version`, `npm --version`
4. Se possível, a linha de log correspondente no terminal onde o Juice Shop está rodando (ele geralmente imprime o erro do lado servidor no momento em que a requisição chega)

<br>

<div align="center">
<sub>← <a href="08-decisoes-de-design.md">Decisões de Design</a> · <a href="README.md">Índice</a></sub>
</div>
