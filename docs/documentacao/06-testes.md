[← Índice](README.md)

# 🧪 Filosofia e Guia de Testes

## A regra central

> [!TIP]
> **Zero mocking. Em nenhum arquivo. Nunca.**

Todo teste em `tests/` executa os solvers reais contra uma instância real do Juice Shop e verifica o resultado contra o placar real (`/api/Challenges/`). Não existe um único `unittest.mock`, `Mock()` ou stub de resposta HTTP em todo o repositório.

**Por quê:** esta é uma ferramenta de segurança. Um teste mockado pode continuar verde mesmo depois de um exploit quebrar de verdade — a API do Juice Shop muda uma validação, um payload para de funcionar, e o mock nunca saberia. Para o tipo de garantia que este projeto se propõe a dar ("estes exploits funcionam, de verdade, agora"), um teste que passa sem provar isso é **pior que não ter teste nenhum** — ele cria falsa confiança.

<br>

## Estrutura dos testes

```
tests/
  test_framework.py                    smoke tests do framework em si (não depende de solvers)
  test_injection_live.py                 uma suíte por categoria de solver
  test_xss_live.py
  test_broken_auth_live.py
  test_sensitive_data_live.py
  ... (uma por categoria, 15 no total)
```

Cada `test_<categoria>_live.py` segue exatamente o mesmo molde:

```python
def _instance_reachable() -> bool:
    try:
        JuiceShopClient().get("/rest/admin/application-version", timeout=2).raise_for_status()
        return True
    except Exception:
        return False


pytestmark = pytest.mark.skipif(not _instance_reachable(), reason="Juice Shop not running on localhost:3000")

CATEGORIA_KEYS = [...]  # toda chave de desafio da categoria


def test_all_categoria_challenges_solved():
    results = run_all(categories=["Nome da Categoria"])
    by_key = {r["key"]: r for r in results}
    failures = [k for k in CATEGORIA_KEYS if not by_key.get(k, {}).get("solved")]
    assert not failures, f"unsolved: {failures}; details={[by_key.get(k) for k in failures]}"
```

Três características importantes:

1. **`pytest.mark.skipif` no lugar de `fail`.** Se nenhuma instância estiver acessível em `localhost:3000`, o teste faz *skip* — não falha. Rodar `pytest tests/` numa máquina sem Juice Shop no ar é seguro; só não valida nada de verdade.
2. **Uma única asserção por categoria, cobrindo todas as chaves de uma vez.** Se `unsolved` não estiver vazio, a mensagem de falha já lista exatamente quais chaves falharam e o dicionário de detalhes de cada uma (`error`, `duration`) — suficiente para debugar sem precisar reproduzir manualmente.
3. **Reaproveita `run_all()` — exatamente o mesmo caminho de código que `main.py` usa.** Não existe uma "versão de teste" separada do runner. O que passa em `pytest` é literalmente o que roda em produção.

<br>

## Como rodar

```bash
# Tudo
pytest tests/ -v

# Só uma categoria
pytest tests/test_injection_live.py -v

# Um desafio específico não é possível filtrar diretamente via pytest
# (a granularidade do teste é por categoria) — para depurar um único
# desafio, chame o solver diretamente:
python -c "
from core.client import JuiceShopClient
from solvers.base import SolverContext
import solvers.injection
ctx = SolverContext(client=JuiceShopClient(), base_url='http://localhost:3000')
solvers.injection.solve_login_admin(ctx)
"
```

> [!NOTE]
> Neste ambiente de desenvolvimento (Windows), `python -m pytest` é mais confiável que o comando `pytest` puro para garantir que o diretório do projeto entre no `sys.path` corretamente — se `pytest` reclamar de `ModuleNotFoundError: No module named 'solvers'`, use `python -m pytest tests/ -v` no lugar.

<br>

## Considerações de CI

- `python main.py` (sem `--category`) sai com código `1` se qualquer desafio tentado ficar sem solução — apto para uma pipeline de CI que trata "algo regrediu" como falha de build.
- `xxeDosChallenge` (ver [Desafios Adiados](07-desafios-adiados.md)) é **excluído deliberadamente** da lista `XXE_KEYS` em `tests/test_xxe_live.py`, mas o solver continua registrado e é tentado por `main.py` — ou seja, `pytest tests/` fica 100% verde, mas `python main.py` reporta `106/107` no relatório de texto. Essa distinção é proposital: o teste automatizado precisa de um veredito binário estável; o relatório legível por humano pode (e deve) mostrar a tentativa honesta que falhou.
- Uma pipeline de CI precisaria provisionar o Juice Shop antes de rodar os testes (`python main.py --setup` cobre isso, mas é lento na primeira execução — considere cachear `juice-shop/node_modules` entre execuções).

<br>

<div align="center">
<sub>← <a href="05-guia-de-extensao.md">Guia de Extensão</a> · <a href="README.md">Índice</a> · <a href="07-desafios-adiados.md">Próximo: Desafios Adiados →</a></sub>
</div>
