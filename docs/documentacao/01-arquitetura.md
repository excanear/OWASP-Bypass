[← Índice](README.md)

# 🧠 Arquitetura

## Visão geral

O OWASP Bypass é organizado em três camadas independentes, cada uma com uma única responsabilidade:

```
┌─────────────────────────────────────────────────────────────────────┐
│                            CAMADA CLI                                │
│  main.py — importa todos os solvers, interpreta flags, orquestra     │
└──────────────────────────────┬────────────────────────────────────┘
                                 │
           ┌─────────────────────┼─────────────────────┐
           ▼                     ▼                     ▼
┌────────────────────┐ ┌──────────────────┐ ┌────────────────────┐
│   CAMADA SOLVERS    │ │   CAMADA CORE     │ │   CAMADA RELATÓRIO  │
│  solvers/*.py        │ │  core/*.py         │ │   report.py          │
│  107 funções de      │ │  runner, client,   │ │  formatação de       │
│  exploit registradas  │ │  challenge_api      │ │  saída no console    │
└────────────────────┘ └──────────────────┘ └────────────────────┘
```

- **Camada Solvers** — o conteúdo de segurança propriamente dito: 107 funções puras, cada uma resolvendo exatamente um desafio.
- **Camada Core** — a infraestrutura que executa, verifica e isola os solvers. Não sabe nada sobre exploits específicos.
- **Camada Relatório** — puramente cosmética, transforma a lista de resultados em texto legível.

Essa separação é deliberada: a camada Core nunca muda quando um novo solver é adicionado, e um solver nunca precisa saber como é verificado — só precisa tentar o exploit.

<br>

## Fluxo de execução completo

```
                          python main.py [--setup] [--category X]
                                          │
                                          ▼
                          ┌───────────────────────────┐
                          │  1. main.py importa cada    │
                          │     módulo solvers/*.py      │
                          │     (populando o registro     │
                          │     global via @register)     │
                          └─────────────┬─────────────┘
                                        │
                          ┌─────────────▼─────────────┐
                          │  2. (opcional) setup.py      │
                          │     clona/instala/sobe o       │
                          │     Juice Shop local            │
                          └─────────────┬─────────────┘
                                        │
                          ┌─────────────▼─────────────┐
                          │  3. core.runner.run_all()    │
                          │     itera solvers.base       │
                          │     .all_solvers()             │
                          └─────────────┬─────────────┘
                                        │
                    ┌───────────────────┼───────────────────┐
                    ▼                   ▼                   ▼
           ┌────────────────┐ ┌────────────────┐ ┌────────────────┐
           │ solver 1         │ │ solver 2         │ │ solver N         │
           │ JuiceShopClient  │ │ JuiceShopClient  │ │ JuiceShopClient  │
           │ novo              │ │ novo              │ │ novo              │
           └────────┬───────┘ └────────┬───────┘ └────────┬───────┘
                    │                   │                   │
                    ▼                   ▼                   ▼
           ┌─────────────────────────────────────────────────────┐
           │      4. Para cada solver: solver.run(ctx) roda,       │
           │         exceção (se houver) é capturada e isolada       │
           └───────────────────────┬─────────────────────────┘
                                    ▼
           ┌─────────────────────────────────────────────────────┐
           │  5. core.challenge_api.is_solved(client, key) —         │
           │     reconsulta GET /api/Challenges/ (até 5x, 300ms      │
           │     de intervalo) até ver solved:true OU esgotar        │
           └───────────────────────┬─────────────────────────┘
                                    ▼
           ┌─────────────────────────────────────────────────────┐
           │  6. report.print_report() imprime o resumo             │
           │     agrupado por categoria + total geral                │
           └─────────────────────────────────────────────────────┘
```

<br>

## Os componentes, um a um

### `main.py` — ponto de entrada

Responsável por três coisas apenas: **importar** todos os módulos de solvers (o efeito colateral do import é o que popula o registro — veja abaixo), **interpretar** os argumentos de linha de comando (`--setup`, `--base-url`, `--category`) e **orquestrar** a chamada de `full_setup()` (se pedido) seguida de `run_all()` e `print_report()`. Sai com código `1` se qualquer desafio tentado não tiver sido resolvido, tornando o comando apto para pipelines de CI.

Cada import de módulo é envolvido em `try/except ImportError: pass` — isso permite rodar a ferramenta mesmo que um módulo de categoria específico não exista ainda (útil durante desenvolvimento incremental) sem quebrar o restante.

### `solvers/base.py` — o registro global

O coração do mecanismo de extensibilidade. Três peças:

```python
@dataclass
class SolverContext:
    client: JuiceShopClient
    base_url: str

@dataclass
class Solver:
    key: str
    category: str
    difficulty: int
    run: Callable[[SolverContext], None]

def register(key: str, category: str, difficulty: int):
    def decorator(fn):
        _REGISTRY.append(Solver(key=key, category=category, difficulty=difficulty, run=fn))
        return fn
    return decorator
```

`register()` é um decorator factory: cada `@register("chave", "Categoria", dificuldade)` acima de uma função simplesmente a envolve num objeto `Solver` e o acrescenta a `_REGISTRY`, uma lista módulo-nível privada. `all_solvers()` devolve uma cópia dessa lista. Não existe nenhum tipo de descoberta automática de arquivo — um solver só existe para o sistema se seu módulo foi de fato importado (por isso `main.py` precisa importar cada `solvers/*.py` explicitamente).

### `core/client.py` — `JuiceShopClient`

Um wrapper fino sobre `requests.Session`. Mantém o cookie jar e o header `Authorization` daquela sessão específica, e expõe:

- `.register(email, senha, ...)` — `POST /api/Users`
- `.login(email, senha)` — `POST /rest/user/login`, extrai o token da resposta e chama `_set_token()` internamente
- `.verify_2fa(tmp_token, totp_token)` — segunda etapa de login para contas com 2FA
- `.get/.post/.put/.patch(path, **kwargs)` — repassam diretamente para `self.session.<verbo>()`, então qualquer kwarg que `requests` aceita (`json=`, `params=`, `headers=`, `files=`, `timeout=`, `allow_redirects=`) funciona sem adaptação

Não há abstração de "resposta padronizada" — os solvers recebem o `requests.Response` cru e decidem se chamam `.raise_for_status()` ou não (alguns exploits *esperam* um erro HTTP como parte do fluxo — veja o [Catálogo de Exploits](03-catalogo-de-exploits.md)).

### `core/challenge_api.py` — a fonte da verdade

Duas funções, sem estado:

```python
def get_challenges(client) -> list[dict]:
    resp = client.get("/api/Challenges/")
    resp.raise_for_status()
    return resp.json()["data"]

def is_solved(client, key: str) -> bool:
    for challenge in get_challenges(client):
        if challenge["key"] == key:
            return bool(challenge["solved"])
    raise KeyError(f"unknown challenge key: {key}")
```

Este módulo nunca é chamado por um solver — só pelo runner, depois que o solver já terminou de rodar. É deliberadamente burro: consulta o placar real e retorna exatamente o que o Juice Shop diz.

### `core/runner.py` — `run_all()`, o orquestrador

A única peça arquitetural que o projeto trata como regra inegociável:

> **O retorno de um solver nunca é a fonte da verdade. Só a reconsulta ao `/api/Challenges/` conta.**

```python
def run_all(base_url="http://localhost:3000", categories=None, timeout=15.0) -> list[dict]:
    results = []
    for solver in all_solvers():
        if categories and solver.category not in categories:
            continue
        client = JuiceShopClient(base_url)          # cliente NOVO por solver
        ctx = SolverContext(client=client, base_url=base_url)
        error = None
        try:
            solver.run(ctx)
        except Exception as exc:
            error = f"{type(exc).__name__}: {exc}"   # captura, não propaga

        solved = False
        for attempt in range(5):                      # poll de até 5x, 300ms
            try:
                solved = is_solved(client, solver.key)
            except Exception as exc:
                error = error or f"{type(exc).__name__}: {exc}"
                break
            if solved:
                break
            time.sleep(0.3)

        results.append({"key": ..., "category": ..., "solved": solved, "duration": ..., "error": error})
    return results
```

Duas garantias arquiteturais importantes aqui:

1. **Isolamento total entre solvers.** Cada iteração cria um `JuiceShopClient` novo — cookie jar e token próprios. Um solver que faz login como usuário X nunca contamina o próximo solver, que começa deslogado. Uma exceção lançada por um solver é capturada e registrada como `error`, mas **não interrompe o loop** — os 106 restantes continuam rodando normalmente mesmo que um exploit específico falhe.
2. **Poll com retry absorve corridas assíncronas do próprio Juice Shop.** Em vários pontos do código-fonte do Juice Shop, a flag de "resolvido" é setada dentro de uma continuação assíncrona (uma promise `.then()` que roda depois da resposta HTTP já ter sido enviada). Uma checagem única e imediata depois da resposta pode chegar cedo demais e reportar um falso negativo. O `run_all` tenta até 5 vezes, com 300ms de intervalo, antes de desistir — o que na prática absorve essa janela sem introduzir espera desnecessária nos ~95% dos casos que já resolvem na primeira tentativa.

### `report.py` — apresentação

Agrupa a lista de resultados por categoria, calcula subtotais e imprime o formato `[OK  ] chave (0.04s)` / `[FAIL] chave (0.13s) - mensagem de erro`, terminando com o total geral. Sem lógica de negócio — puramente formatação.

### `setup.py` — provisionamento

`full_setup()` executa, em sequência: `ensure_node()` (valida que `node`/`npm` existem no PATH), `clone_if_missing()` (`git clone --depth 1` do Juice Shop oficial), `npm_install()` (só roda se `node_modules/` ainda não existir), `start_server()` (sobe `npm start` com `NODE_CONFIG` setando `challenges.safetyMode: disabled` — necessário para o `jwtForgedChallenge` ficar alcançável no Windows) e `wait_ready()` (polling em `/rest/admin/application-version` até `200 OK` ou timeout de 180s).

Todo o disparo de processos usa `shutil.which("npm")` para resolver o caminho real do executável em vez da string literal `"npm"` — detalhe crítico no Windows, coberto em [Solução de Problemas](09-solucao-de-problemas.md).

<br>

## Garantias que a arquitetura oferece

| Garantia | Como é obtida |
|:--|:--|
| Um solver quebrado nunca derruba a suíte inteira | `try/except` isolado por solver dentro de `run_all` |
| Nenhum estado de autenticação vaza entre desafios | `JuiceShopClient` novo a cada iteração do loop |
| "Resolvido" sempre significa "o Juice Shop concorda" | `is_solved()` consulta `/api/Challenges/` diretamente, nunca confia no valor de retorno do solver |
| Falsos negativos por corrida assíncrona são raros | poll de até 5 tentativas / 300ms em `run_all` |
| Rodar uma categoria não afeta as outras | `run_all(categories=[...])` filtra antes de instanciar qualquer cliente |
| A suíte de testes reflete exatamente o comportamento real | `tests/test_*_live.py` chama exatamente o mesmo `run_all()` |

<br>

<div align="center">
<sub>← <a href="README.md">Índice</a> · <a href="02-referencia-api.md">Próximo: Referência de API →</a></sub>
</div>
