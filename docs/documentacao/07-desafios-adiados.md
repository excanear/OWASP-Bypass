[← Índice](README.md)

# 🚫 Desafios Adiados

107 dos 110 desafios do Juice Shop no escopo deste projeto têm solver implementado; 106 deles resolvem de verdade contra uma instância ao vivo. Este documento detalha, com profundidade técnica total, os quatro desafios que ficam fora de alcance — três nem chegam a ter um solver registrado (dependem de um serviço externo real), e um está registrado, é tentado a cada execução, e falha por um motivo verificado e documentado.

Nenhum destes é resolvível trocando o payload.

<br>

## Tabela-resumo

| Desafio | Categoria | Status | Motivo raiz | Custo pra resolver de graça? |
|:--|:--|:--|:--|:-:|
| `chatbotPromptInjectionChallenge` | Injection | Não registrado | Chatbot precisa de um LLM real configurado | ✅ Sim (Ollama local) |
| `chatbotGreedyInjectionChallenge` | Injection | Não registrado | Idem | ✅ Sim (Ollama local) |
| `systemPromptExtractionChallenge` | Injection | Não registrado | Idem | ✅ Sim (Ollama local) |
| `aiDebuggingChallenge` | Broken Access Control | Não registrado | Chatbot precisa invocar uma *tool call* real via LLM | ✅ Sim (Ollama local) |
| `nftMintChallenge` | Improper Input Validation | Não registrado | Transação real na testnet Ethereum Sepolia + chave de API Alchemy | ⚠️ Tecnicamente sim, com trabalho de configuração |
| `web3WalletChallenge` | Miscellaneous | Não registrado | Mesma dependência on-chain acima | ⚠️ Idem |
| `xxeDosChallenge` | XXE | **Registrado, tentado, falha** | Limitação real do libxml2-wasm nesta versão — não é dinheiro nem configuração | ❌ Não é sobre dinheiro |

<br>

## Os quatro desafios de chatbot/LLM

`chatbotPromptInjectionChallenge`, `chatbotGreedyInjectionChallenge`, `systemPromptExtractionChallenge` (categoria Injection) e `aiDebuggingChallenge` (categoria Broken Access Control) dependem todos do chatbot embutido no Juice Shop, que por sua vez espera um backend de LLM compatível com a API da OpenAI. No log de inicialização do servidor, isso aparece explicitamente:

```
warn: Domain http://localhost:11434/v1 is not reachable
warn: "Chatbot Prompt Injection" challenge will not work as intended without access to http://localhost:11434/v1
warn: "Greedy Chatbot Manipulation" challenge will not work as intended without access to http://localhost:11434/v1
warn: "AI Debugging" challenge will not work as intended without access to http://localhost:11434/v1
warn: "System Prompt Extraction" challenge will not work as intended without access to http://localhost:11434/v1
```

> [!TIP]
> **`localhost:11434` é a porta padrão do [Ollama](https://ollama.com/)** — um runtime de LLM local, gratuito e open source. Não é preciso nenhuma API paga: instalar o Ollama e rodar um modelo pequeno localmente (`ollama run llama3.2`, por exemplo) já satisfaz esse requisito. **Esses quatro desafios são, tecnicamente, resolvíveis de graça** — a ferramenta atualmente não implementa solvers para eles porque isso exigiria desenvolvimento adicional (orquestrar uma conversa multi-turno com o chatbot via prompt injection é um problema qualitativamente diferente dos outros 107 solvers, que são requisições HTTP/WebSocket determinísticas), não porque exista uma barreira financeira.

<br>

## `nftMintChallenge` e `web3WalletChallenge`

Ambos exigem uma transação real on-chain na testnet Ethereum Sepolia, detectada pelo servidor via um listener WebSocket conectado a `wss://eth-sepolia.g.alchemy.com/v2/${ALCHEMY_API_KEY}` (`routes/nftMint.ts` e `routes/web3Wallet.ts` respectivamente):

```
warn: Environment variable ALCHEMY_API_KEY is not present
warn: "Mint the Honey Pot" challenge will not work as intended without a valid ALCHEMY_API_KEY
warn: "Wallet Depletion" challenge will not work as intended without a valid ALCHEMY_API_KEY
```

A [Alchemy](https://www.alchemy.com/) oferece um tier gratuito de API key, e ETH de testnet Sepolia é obtido de graça em faucets públicos — então **nenhum dinheiro real é necessário**, mas o setup é mais trabalhoso: criar conta na Alchemy, gerar a chave, obter uma carteira com ETH de testnet via faucet, e então de fato submeter uma transação on-chain que o listener do servidor detecte. Como os dois anteriores, isso não está implementado atualmente — não por custo, mas por escopo de desenvolvimento.

<br>

<a id="xxedoschallenge"></a>
## `xxeDosChallenge` — a única limitação genuinamente técnica

Diferente de todos os outros seis desafios listados acima, este **não é uma questão de dinheiro, API ou configuração de serviço externo**. O solver existe, está registrado em `solvers/xxe.py`, é executado a cada rodada — e falha por um motivo verificado com profundidade.

### O que o desafio pede

`routes/fileUpload.ts` só marca `xxeDosChallenge` como resolvido quando o parsing de um XML enviado via upload **trava por mais de 2 segundos**, capturado pela mensagem de erro `"Script execution timed out"` vinda do timeout da VM Node.js que envolve a chamada de parsing.

### Por que a técnica clássica não funciona aqui

Um "billion laughs" clássico (entidades XML aninhadas, cada uma referenciando a anterior múltiplas vezes, expandindo exponencialmente) precisa ser processado até ficar grande o bastante para realmente demorar. A versão do `libxml2-wasm` usada por este build do Juice Shop tem uma proteção chamada `xmlCtxtSetMaxAmplification`, que calcula a razão entre o tamanho do XML de entrada e o tamanho para o qual ele se expandiria — e **rejeita o payload instantaneamente** (em milissegundos) se essa razão for suspeita demais. Combinado com o limite de 200KB de upload que o próprio Juice Shop impõe, não existe payload que seja:

1. Grande/profundo o bastante para realmente demorar 2+ segundos processando, **e**
2. Pequeno/discreto o bastante para passar despercebido pelo guard de amplificação.

Toda vez que o payload é grande o suficiente para ser lento, ele também é grande o suficiente para ser rejeitado na hora.

### Os seis experimentos

Confirmando que essa conclusão não é preguiça de ajuste de payload, seis variantes independentes foram testadas ao vivo contra a instância real:

| # | Variante | Resultado |
|:-:|:--|:--|
| 1 | Payload original: 9 níveis de aninhamento, fan-out de 9 | Rejeitado em ~10–30ms com `"Maximum entity amplification factor exceeded"` |
| 2 | Bisseção de profundidade (3–30 níveis) × fan-out (2–10) | Acima de ~1e5 referências totais **ou** 20+ níveis de profundidade, rejeitado em <10ms — abaixo disso, o parse completa em milissegundos, longe dos 2000ms necessários. Não existe zona intermediária. |
| 3 | Entidades-folha vazias (valor final ≈ 0 bytes, mas ~1e10 operações de substituição nocionais) | Ainda rejeitado em ~30ms — a proteção conta *volume de substituição*, não só o tamanho final materializado |
| 4 | Folhas grandes (90–20.000 bytes) × ~1e4 referências (900KB–200MB de expansão nocional) | Mesma rejeição — o **lado de entrada** da razão de amplificação é limitado pelo teto de 200.000 bytes do multer, então nenhuma combinação de forma de payload consegue tornar a entrada "grande o bastante para licenciar" uma expansão realmente lenta |
| 5 | Entidades de parâmetro no subset interno do DTD | Rejeitado por regra de bem-formação de XML: `"PEReferences forbidden in internal subset"` — não é um canal alternativo viável sem um segundo DTD externo, e o resolvedor de entidades do sandbox só aceita `file://` |
| 6 | Probe de complexidade algorítmica não relacionada a entidade (10.000 atributos únicos num único elemento, testando comportamento O(n²) independente de expansão) | Parseado em ~17ms — nenhuma explosão observada nos tamanhos que o limite de 200.000 bytes permite |

### Conclusão

Com o teto de 200KB de upload combinado ao guard de razão de amplificação do libxml2 e seu limite de profundidade de aninhamento (~20 níveis), nenhum payload baseado em expansão de entidade consegue plausivelmente consumir perto de 2000ms de tempo de parse do libxml2 nesta versão específica da dependência. O caminho de código `"Script execution timed out"` em `routes/fileUpload.ts` parece **inalcançável** por esta técnica neste build — uma descoberta real sobre a versão da dependência, não uma lacuna de ajuste de payload.

O solver permanece em `solvers/xxe.py`, registrado e tentado a cada execução, propositalmente. Uma tentativa genuína e documentada que falha é mais útil, e mais honesta, do que fingir que o desafio não existe.

<br>

## Se você quiser tentar fechar a lacuna você mesmo

- **Os 4 desafios de LLM:** instale o [Ollama](https://ollama.com/) localmente, rode um modelo pequeno (`ollama run llama3.2` ou similar) na porta padrão `11434`, e implemente solvers que conversem com `/rest/chat` seguindo o mesmo padrão dos demais módulos em `solvers/` (veja o [Guia de Extensão](05-guia-de-extensao.md)). Não custa nada, mas é um problema de orquestração de conversa, não de payload único.
- **`nftMintChallenge` / `web3WalletChallenge`:** crie uma conta gratuita na Alchemy, gere uma API key, obtenha ETH de testnet Sepolia num faucet público, e implemente a submissão de transação on-chain via `web3.py` ou similar.
- **`xxeDosChallenge`:** provavelmente exigiria uma versão diferente (mais antiga, sem o guard de amplificação) do `libxml2-wasm` no `package.json` do próprio Juice Shop — o que sairia do escopo desta ferramenta (que só ataca a aplicação como ela é distribuída oficialmente) e entraria em "modificar o alvo para o ataque funcionar", quebrando a premissa do projeto.

<br>

<div align="center">
<sub>← <a href="06-testes.md">Filosofia de Testes</a> · <a href="README.md">Índice</a> · <a href="08-decisoes-de-design.md">Próximo: Decisões de Design →</a></sub>
</div>
