[← Índice](README.md)

# 🧩 Guia de Extensão

Como adicionar suporte a um novo desafio (ou uma categoria inteira) do zero, seguindo exatamente a convenção usada nos 107 solvers existentes.

<br>

## O contrato de um solver

Todo solver é uma função com esta assinatura exata:

```python
def solve_algo(ctx: SolverContext) -> None:
    ...
```

- Recebe um único argumento: `ctx`, um `SolverContext` já pronto (`ctx.client` é um `JuiceShopClient` novo, sem autenticação prévia; `ctx.base_url` é a URL crua da instância).
- **Não retorna nada relevante.** O sistema nunca olha o valor de retorno — só reconsulta o placar depois (veja [Arquitetura](01-arquitetura.md)).
- **Pode lançar exceção sem medo.** `core.runner.run_all()` isola cada solver individualmente; uma exceção não derruba os outros 106.

<br>

## Passo a passo

### 1. Descubra a técnica lendo o código-fonte real do Juice Shop

Esta é a regra número um do projeto (veja [Decisões de Design](08-decisoes-de-design.md)): **nunca adivinhe um payload**. Antes de escrever qualquer código Python, leia o arquivo `.ts` correspondente no [repositório oficial do Juice Shop](https://github.com/juice-shop/juice-shop) para encontrar exatamente:

- Qual rota implementa o desafio
- Qual é a condição exata que marca `solved: true`
- Se existe alguma validação/middleware entre o seu payload e essa condição

### 2. Crie (ou reaproveite) o módulo da categoria

Cada categoria do Juice Shop mora em `solvers/<nome_da_categoria>.py`. Se a categoria já existe, adicione sua função lá; se não, crie um arquivo novo seguindo o padrão de cabeçalho já usado em todos os outros:

```python
"""<Nome da Categoria> category solvers (N de M). Verified against
routes/algumaCoisa.ts, lib/outraCoisa.ts (fetched YYYY-MM-DD)."""
from solvers.base import SolverContext, register

DOMAIN = "juice-sh.op"
```

### 3. Escreva o solver

```python
# --- routes/algumaCoisa.ts: explique aqui, em prosa, exatamente qual
# condição do servidor está sendo satisfeita e por quê o payload funciona.
# Esse comentário é o writeup técnico do exploit — trate-o como parte
# central da entrega, não como decoração. ---

@register("chaveExataDoDesafio", "Nome da Categoria", 3)
def solve_algo(ctx: SolverContext) -> None:
    email = f"prefixo.{uuid.uuid4().hex[:8]}@{DOMAIN}"
    ctx.client.register(email, "Test1234!")
    ctx.client.login(email, "Test1234!")
    ctx.client.post("/algum/endpoint", json={"campo": "payload"}).raise_for_status()
```

Convenções obrigatórias, extraídas dos 107 solvers já existentes:

- **A chave do desafio é sempre a chave real** de `data/static/challenges.yml` no repositório do Juice Shop — copie exatamente, incluindo capitalização.
- **A categoria é sempre a string oficial do Juice Shop**, não uma abreviação sua.
- **Contas de teste sempre usam e-mail único por execução** (`uuid.uuid4().hex[:8]`) para nunca colidir com uma conta de uma execução anterior contra a mesma instância.
- **`.raise_for_status()` é a norma, não a exceção** — só omita quando o próprio exploit depende de uma resposta de erro (documente por quê, com um comentário; veja `loginAdminChallenge` ou `basketManipulateChallenge` no [Catálogo de Exploits](03-catalogo-de-exploits.md)).
- **Um comentário `# --- ... ---` acima de cada solver (ou grupo de solvers relacionados)**, explicando a mecânica exata do exploit e citando o arquivo-fonte do Juice Shop consultado.

### 4. Registre o import em `main.py`

```python
try:
    import solvers.minha_categoria  # noqa: F401
except ImportError:
    pass
```

O `# noqa: F401` é intencional — o import existe só pelo efeito colateral do decorator `@register`, o linter não precisa reclamar que o módulo "não é usado".

### 5. Escreva o teste de verificação ao vivo

Todo módulo de solvers tem um arquivo de teste irmão, seguindo exatamente este molde (copie de qualquer `tests/test_*_live.py` existente e adapte):

```python
# tests/test_minha_categoria_live.py
"""No mocking, per project convention: runs the real solvers against a live
Juice Shop instance and checks the live score-board."""
import pytest

import solvers.minha_categoria  # noqa: F401 - registers the solvers
from core.client import JuiceShopClient
from core.runner import run_all


def _instance_reachable() -> bool:
    try:
        JuiceShopClient().get("/rest/admin/application-version", timeout=2).raise_for_status()
        return True
    except Exception:
        return False


pytestmark = pytest.mark.skipif(not _instance_reachable(), reason="Juice Shop not running on localhost:3000")

MINHA_CATEGORIA_KEYS = ["chaveExataDoDesafio"]  # todas as chaves da categoria


def test_all_minha_categoria_challenges_solved():
    results = run_all(categories=["Nome da Categoria"])
    by_key = {r["key"]: r for r in results}
    failures = [k for k in MINHA_CATEGORIA_KEYS if not by_key.get(k, {}).get("solved")]
    assert not failures, f"unsolved: {failures}; details={[by_key.get(k) for k in failures]}"
```

### 6. Verifique ao vivo, contra uma instância real

```bash
python main.py --setup           # instância nova, do zero
pytest tests/test_minha_categoria_live.py -v
```

Se não resolver de primeira: **volte ao passo 1**. Leia a resposta HTTP crua, leia o código-fonte de novo, ajuste o payload. Nunca afrouxe a asserção do teste para "aceitar parcial" — isso quebra a garantia central do projeto (ver [Filosofia de Testes](06-testes.md)).

<br>

## Checklist antes de considerar pronto

- [ ] A chave do desafio bate exatamente com `data/static/challenges.yml` do Juice Shop
- [ ] A categoria bate exatamente com a string oficial do Juice Shop
- [ ] O comentário acima do solver explica a mecânica e cita o(s) arquivo(s)-fonte consultado(s)
- [ ] `.raise_for_status()` está presente, ou sua ausência está documentada
- [ ] O import está registrado em `main.py` dentro de um bloco `try/except ImportError`
- [ ] Existe um `tests/test_<categoria>_live.py` cobrindo todas as chaves do módulo
- [ ] O teste passou de verdade, contra uma instância recém-provisionada (`python main.py --setup`)
- [ ] Nenhum framework file (`core/*.py`, `solvers/base.py`) foi modificado — se sua categoria exigir isso, é sinal de que talvez precise de discussão de design antes

<br>

<div align="center">
<sub>← <a href="04-instalacao-e-configuracao.md">Instalação e Configuração</a> · <a href="README.md">Índice</a> · <a href="06-testes.md">Próximo: Filosofia de Testes →</a></sub>
</div>
