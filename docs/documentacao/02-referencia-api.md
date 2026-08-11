[← Índice](README.md)

# 📖 Referência de API

Assinatura completa e comportamento de cada classe/função pública do projeto. Para o contexto arquitetural de como essas peças se encaixam, veja [Arquitetura](01-arquitetura.md).

<br>

## `core/client.py`

### `class JuiceShopClient`

Wrapper fino sobre `requests.Session`, uma instância por sessão de autenticação.

```python
JuiceShopClient(base_url: str = "http://localhost:3000")
```

| Atributo | Tipo | Descrição |
|:--|:--|:--|
| `.base_url` | `str` | URL base, sem barra final (normalizada no `__init__`) |
| `.session` | `requests.Session` | sessão HTTP subjacente — cookie jar e headers persistem entre chamadas |
| `.token` | `str \| None` | token JWT atual, populado após `.login()`/`.verify_2fa()` bem-sucedidos |

#### `.register(email: str, password: str, security_question_id: int = 1, security_answer: str = "n/a") -> requests.Response`

`POST /api/Users`. Não faz login automaticamente — devolve a resposta crua para o solver decidir se checa o status.

#### `.login(email: str, password: str) -> requests.Response`

`POST /rest/user/login`.

- Em sucesso (`2xx`): extrai `authentication.token` do corpo JSON, chama `_set_token()` internamente (seta `Authorization` header + cookie `token`), retorna a resposta.
- Em `401` com `status: "totp_token_required"` no corpo: **não lança exceção** — devolve a resposta crua para o chamador tratar o segundo fator (ver `usernameXssChallenge`-style flows e `twoFactorAuthUnsafeSecretStorageChallenge`).
- Em qualquer outro `401`: lança `RuntimeError` com a mensagem crua do servidor.
- Em qualquer outro erro HTTP: propaga via `resp.raise_for_status()`.

> [!IMPORTANT]
> Vários solvers de injection (`loginAdminChallenge`, `ghostLoginChallenge`, etc.) chamam `.login()` com um email contendo `'--` proposital — a resposta pode legitimamente ser um erro HTTP mesmo quando o exploit já funcionou do lado do servidor (a flag de "resolvido" é setada antes da falha subsequente). Por isso muitos solvers não chamam `.raise_for_status()` — veja o padrão em [Catálogo de Exploits](03-catalogo-de-exploits.md).

#### `.verify_2fa(tmp_token: str, totp_token: str) -> requests.Response`

`POST /rest/2fa/verify`. Segunda etapa de autenticação; em sucesso, também chama `_set_token()`.

#### `.get/.post/.put/.patch(path: str, **kwargs) -> requests.Response`

Repassam diretamente para o verbo correspondente de `self.session`, prefixando `path` com `base_url`. Qualquer kwarg de `requests` funciona sem adaptação: `json=`, `params=`, `headers=`, `files=`, `data=`, `timeout=`, `allow_redirects=`.

#### `._url(path: str) -> str`

Helper interno (`base_url + path`) — exposto porque alguns solvers precisam de verbos que o client não encapsula (ex.: `DELETE`, usado por `feedbackChallenge` via `ctx.client.session.delete(ctx.client._url(...))`).

<br>

## `core/challenge_api.py`

#### `get_challenges(client: JuiceShopClient) -> list[dict]`

`GET /api/Challenges/`. Devolve a lista crua de desafios da API do Juice Shop (cada item tem, entre outros campos, `key` e `solved`).

#### `is_solved(client: JuiceShopClient, key: str) -> bool`

Itera `get_challenges()` procurando `key`. Lança `KeyError` se a chave não existir no placar do Juice Shop (proteção contra erro de digitação numa chave de desafio ao escrever um novo solver).

<br>

## `core/runner.py`

#### `run_all(base_url: str = "http://localhost:3000", categories: list[str] | None = None, timeout: float = 15.0) -> list[dict]`

Executa todo solver registrado (ou só os das categorias em `categories`, se informado), cada um com um `JuiceShopClient` novo. Devolve uma lista de dicionários:

```python
{
    "key": str,        # chave do desafio
    "category": str,    # categoria
    "solved": bool,      # resultado da reconsulta ao placar — nunca do retorno do solver
    "duration": float,   # segundos, arredondado a 2 casas
    "error": str | None, # repr da exceção, se houve alguma (mesmo que solved=True)
}
```

> [!NOTE]
> O parâmetro `timeout` existe na assinatura mas atualmente não é repassado a nenhuma chamada HTTP interna — cada solver controla seu próprio timeout de requisição individualmente (a maioria usa o default do `requests`; os solvers de RCE/DoS por timing passam `timeout=10` explicitamente).

<br>

## `solvers/base.py`

#### `class SolverContext` *(dataclass)*

```python
@dataclass
class SolverContext:
    client: JuiceShopClient
    base_url: str
```

O único argumento que toda função de solver recebe. `client` já vem pronto para uso (sessão limpa, sem autenticação); `base_url` é útil para solvers que precisam da URL crua (ex.: conectar um cliente WebSocket via `python-socketio`, que não aceita um objeto `requests.Session`).

#### `class Solver` *(dataclass)*

```python
@dataclass
class Solver:
    key: str
    category: str
    difficulty: int
    run: Callable[[SolverContext], None]
```

Representação interna de um solver registrado. Não é instanciado diretamente — é criado pelo decorator `register()`.

#### `register(key: str, category: str, difficulty: int) -> Callable`

Decorator factory. Uso:

```python
@register("chaveDoDesafio", "Nome da Categoria", 3)
def solve_algo(ctx: SolverContext) -> None:
    ...
```

Anexa um `Solver` ao registro global module-level. `difficulty` é informativo (espelha o número de estrelas do Juice Shop) — não afeta a execução.

#### `all_solvers() -> list[Solver]`

Devolve uma **cópia** da lista de registro (`list(_REGISTRY)`), consumida por `core.runner.run_all()`.

<br>

## `report.py`

#### `print_report(results: list[dict]) -> None`

Recebe exatamente a lista devolvida por `run_all()`, agrupa por `category`, imprime um bloco por categoria (`Categoria (N/M)` seguido de uma linha `[OK  ]`/`[FAIL]` por item) e uma linha final `TOTAL: X/Y solved`. Sem valor de retorno — efeito colateral é somente `print()` no console.

<br>

## `setup.py`

#### `_npm_path() -> str`

Resolve o caminho real do executável `npm` via `shutil.which("npm")`. Existe porque, no Windows, `subprocess` não consegue executar a string literal `"npm"` diretamente (ela resolve para `npm.cmd`, que `CreateProcess` não invoca sem o caminho completo ou `shell=True`) — veja [Solução de Problemas](09-solucao-de-problemas.md). Lança `RuntimeError` se `npm` não estiver no `PATH`.

#### `ensure_node() -> None`

Valida que `node` e `npm` (via `_npm_path()`) estão disponíveis. Lança `RuntimeError` com mensagem explicativa caso contrário.

#### `clone_if_missing(target_dir: str) -> None`

`git clone --depth 1 <repo-oficial-do-juice-shop> <target_dir>`, só se `target_dir` ainda não existir.

#### `npm_install(target_dir: str) -> None`

`npm install` dentro de `target_dir`, só se `target_dir/node_modules` ainda não existir. O `postinstall` script do próprio Juice Shop cuida de instalar e buildar o frontend Angular como parte desse único comando.

#### `start_server(target_dir: str) -> subprocess.Popen`

Sobe `npm start` em `target_dir` com a variável de ambiente `NODE_CONFIG='{"challenges":{"safetyMode":"disabled"}}'` injetada — necessária para que `jwtForgedChallenge` fique alcançável (ele é desabilitado por padrão no Windows pelo próprio Juice Shop). Devolve o objeto `Popen` do processo em background (não aguarda o servidor ficar pronto — isso é responsabilidade de `wait_ready()`).

#### `wait_ready(base_url: str = "http://localhost:3000", timeout: float = 180.0) -> None`

Faz polling em `GET {base_url}/rest/admin/application-version` a cada 2 segundos até receber `200 OK` ou estourar `timeout`. Lança `TimeoutError` no segundo caso.

#### `full_setup(target_dir: str = "./juice-shop", base_url: str = "http://localhost:3000") -> subprocess.Popen`

Orquestra as cinco funções acima em sequência. É o que `main.py --setup` chama.

<br>

<div align="center">
<sub>← <a href="01-arquitetura.md">Arquitetura</a> · <a href="README.md">Índice</a> · <a href="03-catalogo-de-exploits.md">Próximo: Catálogo de Exploits →</a></sub>
</div>
