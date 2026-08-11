<div align="center">

# 📘 Documentação Técnica Oficial

### OWASP Bypass — motor autônomo de exploits para o OWASP Juice Shop

</div>

<br>

Esta é a documentação técnica completa da ferramenta — para uma introdução rápida e o quickstart, veja o [README principal](../../README.md) na raiz do repositório. Aqui você encontra a referência completa: arquitetura interna, API de cada módulo, o catálogo técnico de todos os 107 exploits registrados, guias operacionais e as decisões de design por trás do projeto.

<br>

## 🗂️ Índice

| # | Documento | Conteúdo |
|:-:|:--|:--|
| 1 | [**Arquitetura**](01-arquitetura.md) | Componentes internos, fluxo de dados, o loop de verificação ao vivo, garantias de isolamento |
| 2 | [**Referência de API**](02-referencia-api.md) | Assinatura completa de cada classe/função pública em `core/`, `solvers/base.py`, `setup.py` e `report.py` |
| 3 | [**Catálogo de Exploits**](03-catalogo-de-exploits.md) | Os 107 solvers, um por um, agrupados por categoria — endpoint, técnica e justificativa técnica de cada um |
| 4 | [**Instalação e Configuração**](04-instalacao-e-configuracao.md) | Requisitos, passo a passo por sistema operacional, variáveis de ambiente, execução contra instância existente |
| 5 | [**Guia de Extensão**](05-guia-de-extensao.md) | Como escrever, registrar e testar um novo solver do zero |
| 6 | [**Filosofia e Guia de Testes**](06-testes.md) | Por que zero mocking, convenção de nomes, como rodar subconjuntos, considerações de CI |
| 7 | [**Desafios Adiados**](07-desafios-adiados.md) | Os 4 desafios fora de alcance — investigação técnica completa, incluindo os 6 experimentos do `xxeDosChallenge`, e como fechar a lacuna de graça |
| 8 | [**Decisões de Design**](08-decisoes-de-design.md) | Registro estilo ADR das decisões arquiteturais e o porquê de cada uma |
| 9 | [**Solução de Problemas**](09-solucao-de-problemas.md) | Erros conhecidos, causa raiz e correção — incluindo o bug real do `npm.cmd` no Windows já corrigido |

<br>

## 🧭 Por onde começar

- **Quer só rodar a ferramenta?** → [README principal](../../README.md#-início-rápido)
- **Quer entender como ela funciona por dentro?** → [Arquitetura](01-arquitetura.md)
- **Quer saber exatamente o que cada exploit faz e por quê?** → [Catálogo de Exploits](03-catalogo-de-exploits.md)
- **Quer adicionar um novo desafio/categoria?** → [Guia de Extensão](05-guia-de-extensao.md)
- **Algo deu errado?** → [Solução de Problemas](09-solucao-de-problemas.md)

<br>

## 📐 Convenções usadas nesta documentação

- **Nomes de desafio** (`loginAdminChallenge`, `sstiChallenge`, etc.) são sempre as chaves reais do Juice Shop, exatamente como aparecem em `data/static/challenges.yml` daquele projeto — permitindo busca cruzada direta com o placar da aplicação.
- **Caminhos de arquivo-fonte do Juice Shop** (`routes/login.ts`, `lib/insecurity.ts`, etc.) referenciam o repositório oficial [`juice-shop/juice-shop`](https://github.com/juice-shop/juice-shop), versão `20.1.1` — a mesma auditada durante a construção desta ferramenta.
- Blocos marcados como `> [!NOTE]`, `> [!IMPORTANT]`, `> [!WARNING]` seguem a sintaxe de callout nativa do GitHub.

<br>

<div align="center">
<sub>← <a href="../../README.md">Voltar ao README principal</a></sub>
</div>
