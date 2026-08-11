[← Índice](README.md)

# 🏛️ Decisões de Design

Registro estilo ADR (*Architecture Decision Record*) das escolhas arquiteturais mais importantes do projeto — o quê foi decidido, e por quê, para que decisões futuras não repitam o mesmo debate do zero.

<br>

## ADR-01 — Verificação sempre contra o placar ao vivo, nunca contra o retorno do solver

**Decisão:** `core.runner.run_all()` nunca trata o retorno (ou a ausência de exceção) de um solver como sinal de sucesso. A única fonte da verdade é uma reconsulta a `GET /api/Challenges/` depois que o solver termina de rodar.

**Motivo:** um solver pode "parecer" ter funcionado (código 200, sem exceção) e o exploit real não ter disparado a condição que o servidor verifica — ou o inverso, um solver pode lançar uma exceção *depois* que o servidor já registrou a solução (ver `ephemeralAccountantChallenge`, onde uma falha de criação de carrinho acontece depois do login malicioso já ter sido processado). Confiar no retorno do Python teria produzido tanto falsos positivos quanto falsos negativos.

**Consequência:** todo solver pode ser escrito de forma despreocupada em relação a tratamento de erro — não precisa "reportar sucesso" de nenhuma forma especial. Isso mantém cada solver curto e focado só na mecânica do exploit.

<br>

## ADR-02 — Um `JuiceShopClient` novo por solver

**Decisão:** `run_all()` instancia um cliente HTTP totalmente novo (sessão, cookies, token) para cada solver, nunca reaproveita entre eles.

**Motivo:** vários solvers autenticam como usuários diferentes, alguns deliberadamente como administradores forjados. Reaproveitar sessão entre solvers criaria dependência de ordem de execução (um solver "vazando" autenticação para o próximo) — um efeito colateral sutil e difícil de depurar que romperia a garantia de que cada solver é uma unidade independente e reordenável.

**Consequência:** a suíte inteira pode ser filtrada por categoria (`--category`) ou reordenada sem qualquer solver quebrar por causa de estado deixado por outro.

<br>

## ADR-03 — Poll com retry no runner, não em cada solver

**Decisão:** a lógica de "tentar de novo por até 5x com 300ms de intervalo" vive uma única vez, dentro de `run_all()` — não replicada solver por solver.

**Motivo:** o Juice Shop, em vários pontos do código, marca um desafio como resolvido dentro de uma continuação assíncrona (`.then()`) que roda **depois** da resposta HTTP já ter sido enviada ao cliente. Uma checagem imediata após receber a resposta pode chegar cedo demais. Isso é um comportamento do servidor, não de um solver específico — então a mitigação pertence à camada que verifica, não à camada que explora.

**Consequência:** nenhum solver individual precisa se preocupar com timing de verificação — mesmo o mais simples (uma única requisição GET) se beneficia da mesma proteção contra falso negativo que os mais complexos.

<br>

## ADR-04 — Zero mocking em qualquer teste

**Decisão:** nenhum teste do projeto usa `unittest.mock`, stub de resposta HTTP, ou qualquer simulação de comportamento do servidor. Todo teste roda contra uma instância real.

**Motivo:** ver [Filosofia de Testes](06-testes.md) — para uma ferramenta de segurança, um teste que passa sem exercitar o exploit de verdade é mais perigoso que a ausência de teste, porque cria confiança falsa.

**Consequência:** a suíte de testes exige uma instância do Juice Shop no ar para produzir sinal real (faz *skip*, não falha, sem uma). CI precisa provisionar a aplicação antes de rodar `pytest`.

<br>

## ADR-05 — Algoritmos criptográficos hand-portados em vez de dependências de terceiros de nome parecido

**Decisão:** o codificador Z85 usado por `forgedCouponChallenge` é reimplementado manualmente dentro do repositório (~15 linhas), copiado linha por linha do código-fonte real do pacote npm `z85@0.0.2` (baixado do registry para conferência), em vez de instalar um pacote PyPI qualquer chamado "z85".

**Motivo:** não existe garantia de que um pacote PyPI de nome similar implemente exatamente a mesma variante do algoritmo, o mesmo alfabeto, ou o mesmo comportamento de borda (como a exigência de múltiplo de 4 bytes que o `z85@0.0.2` tem). Uma discrepância sutil produziria bytes que o servidor Node.js não conseguiria decodificar corretamente — um bug silencioso e difícil de diagnosticar. Portar o algoritmo exato elimina essa incerteza inteiramente.

**Consequência:** o projeto tem zero dependências de criptografia de terceiros para esse caso específico — só `requests`-adjacent e bibliotecas amplamente auditadas (`eth-account`, `pyotp`, `hashids`) para os demais casos, onde a compatibilidade cross-linguagem já é uma garantia documentada da própria biblioteca.

<br>

## ADR-06 — Categoria como dado, não como hierarquia de classes

**Decisão:** `register(key, category, difficulty)` recebe a categoria como uma string simples, não como um enum ou uma classe base por categoria.

**Motivo:** a categoria de um desafio no Juice Shop é só um rótulo para agrupamento e filtro (`--category`) — não implica nenhum comportamento compartilhado entre desafios da mesma categoria. Modelar isso como hierarquia de classes adicionaria uma camada de abstração sem benefício real, e tornaria mover um desafio entre módulos (como aconteceu com `videoXssChallenge`, fisicamente em `vulnerable_components.py` mas registrado sob a categoria `"XSS"`) mais burocrático do que precisa ser.

**Consequência:** um solver pode morar fisicamente num arquivo diferente da sua categoria "oficial" sempre que fizer sentido técnico (compartilhar a mesma infraestrutura de exploit), sem forçar uma reorganização de arquivos.

<br>

## ADR-07 — Docker nunca é uma opção suportada

**Decisão:** a ferramenta e toda sua documentação assumem que o Juice Shop roda via `npm start` direto no host, nunca em container.

**Motivo:** 17 dos desafios em escopo declaram `disabledEnv: [Docker, Heroku]` no próprio dataset de desafios do Juice Shop — são desabilitados pelo próprio servidor quando ele detecta que está rodando em container. Suportar Docker significaria aceitar de saída que 17 desafios nunca seriam alcançáveis, contrariando o objetivo do projeto.

**Consequência:** `setup.py` nunca oferece um caminho de Docker, e a documentação avisa explicitamente contra usá-lo.

<br>

## ADR-08 — Resolução explícita do caminho do `npm` em `setup.py`

**Decisão:** todo disparo de subprocesso para `npm` usa `shutil.which("npm")` para obter o caminho real do executável, nunca a string literal `"npm"`.

**Motivo:** achado real durante a validação end-to-end do projeto (ver [Solução de Problemas](09-solucao-de-problemas.md)) — no Windows, `subprocess.run(["npm", ...])` falha com `FileNotFoundError`, porque `npm` resolve para `npm.cmd`, e o `CreateProcess` do Windows não executa arquivos `.cmd` a partir de uma string de comando crua sem `shell=True` ou o caminho completo. `shutil.which()` resolve esse caminho completo de forma multiplataforma.

**Consequência:** `python main.py --setup` funciona de forma idêntica em qualquer sistema operacional, sem precisar de `shell=True` (que introduziria riscos de injeção de shell desnecessários para este caso de uso).

<br>

<div align="center">
<sub>← <a href="07-desafios-adiados.md">Desafios Adiados</a> · <a href="README.md">Índice</a> · <a href="09-solucao-de-problemas.md">Próximo: Solução de Problemas →</a></sub>
</div>
