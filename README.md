# OWASP Bypass

**An autonomous exploit runner for [OWASP Juice Shop](https://github.com/juice-shop/juice-shop) — 107 registered exploits, live-verified against a real running instance, zero mocking.**

> Juice Shop is the intentionally-vulnerable training application maintained by OWASP. This tool drives a local instance of it end-to-end: registers accounts, forges tokens, races the server, smuggles payloads, and confirms every single win against the app's own scoreboard API. Nothing here is simulated — if a solver reports success, Juice Shop itself has already marked that challenge solved.

```
TOTAL: 106/107 solved
```

---

## Table of Contents

- [What this is](#what-this-is)
- [Results](#results)
- [Quickstart](#quickstart)
- [Requirements](#requirements)
- [Installation](#installation)
- [Usage](#usage)
- [How it works](#how-it-works)
- [Project layout](#project-layout)
- [Writing a new solver](#writing-a-new-solver)
- [Testing philosophy](#testing-philosophy)
- [Notable exploit techniques](#notable-exploit-techniques)
- [Deferred challenges](#deferred-challenges)
- [Design docs](#design-docs)
- [Responsible use](#responsible-use)

---

## What this is

OWASP Bypass is a Python CLI that automatically **solves** OWASP Juice Shop's built-in
security challenges — SQL/NoSQL injection, XSS, JWT forgery, IDOR, SSRF, XXE,
zip-slip file writes, race conditions, and more — by driving the application's
real HTTP/WebSocket API exactly the way a human attacker would, then confirming
every solve against Juice Shop's own live scoreboard (`/api/Challenges/`), never
by trusting a script's own "it probably worked."

Every one of the 107 registered solvers was built the same way:

1. **Read the real Juice Shop TypeScript source** for the exact vulnerable code
   path (never guessed).
2. **Craft the payload from that source** — a specific SQL comment, a forged JWT,
   a zip-slip path, a race-condition timing window.
3. **Run it against a live local instance** and watch the scoreboard flip.
4. **If it didn't flip, read the source again** — never weaken the check to
   accept a false positive.

The result is a corpus of small, single-purpose, heavily-commented exploit
functions that double as a **working, live-verified writeup for nearly every
challenge in Juice Shop** — useful as a learning reference even if you never run
the CLI.

## Results

| Category | Solved | Notes |
|---|---:|---|
| Sensitive Data Exposure | 16/16 | |
| Injection | 11/11 | SQLi, NoSQLi, SSTI |
| Improper Input Validation | 11/11 | |
| Broken Access Control | 11/11 | |
| XSS | 9/9 | incl. video-subtitle XSS via zip-slip |
| Broken Authentication | 9/9 | |
| Vulnerable Components | 8/8 | zip-slip RCE-class write, JWT forgery |
| Miscellaneous | 5/5 | |
| Cryptographic Issues | 5/5 | Z85 coupon forgery, Hashids continue-code |
| Security Misconfiguration | 4/4 | |
| Observability Failures | 4/4 | |
| Broken Anti Automation | 4/4 | incl. a real TOCTOU race condition |
| Security through Obscurity | 3/3 | |
| Insecure Deserialization | 3/3 | sandboxed-JS timing race (RCE + DoS pair) |
| XXE | 1/2 | see [Deferred challenges](#deferred-challenges) |
| Unvalidated Redirects | 2/2 | |
| **Total** | **106/107** | **110 in scope; 3 excluded up front, 1 environment-blocked** |

Reproduce this number yourself:

```bash
python main.py --setup
```

## Quickstart

```bash
git clone https://github.com/excanear/OWASP-Bypass.git
cd OWASP-Bypass
pip install -r requirements.txt
python main.py --setup
```

`--setup` clones Juice Shop into `./juice-shop`, runs `npm install`, starts it
with `npm start`, waits for it to come up, then runs every solver and prints a
category-grouped report. First run takes a few minutes (Node install + Angular
build); every run after that is fast.

## Requirements

- **Python 3.11+**
- **Node.js 18+** and npm (only needed if you use `--setup` to provision Juice
  Shop yourself — point `--base-url` at an instance you already have running
  and skip this entirely)
- **A Juice Shop instance started via `npm start`, not Docker.** 17 of Juice
  Shop's challenges declare `disabledEnv: [Docker, Heroku]` and are simply
  unreachable in a container. This project always targets a directly-run
  instance.
- Tested on **Windows** (git-bash/PowerShell) against Juice Shop `20.1.1`. The
  solvers are pure HTTP/WebSocket and have no Windows-specific dependency
  except one payload path (`xxeFileDisclosureChallenge` reads
  `C:\Windows\win.ini` instead of `/etc/passwd` — see below).

## Installation

```bash
pip install -r requirements.txt
```

No system-level dependencies beyond Python — the Z85 and Hashids encoding
schemes used by two solvers are implemented directly in this repo rather than
pulled in as extra packages (see [Notable exploit techniques](#notable-exploit-techniques)).

If you'd rather provision Juice Shop by hand:

```bash
git clone --depth 1 https://github.com/juice-shop/juice-shop.git
cd juice-shop && npm install && npm start
```

One category needs a specific server flag to be reachable at all —
`jwtForgedChallenge` is disabled by default on Windows unless Juice Shop's
safety mode is turned off:

```bash
NODE_CONFIG='{"challenges":{"safetyMode":"disabled"}}' npm start
```

(`python main.py --setup` already does this for you.)

## Usage

```bash
# Full run: provision Juice Shop, then solve everything
python main.py --setup

# Run against an instance you already have up
python main.py --base-url http://localhost:3000

# Run only specific categories (repeatable)
python main.py --category Injection --category XSS

# Just print the current live scoreboard without running any solver
pytest tests/test_framework.py -v
```

### CLI reference

| Flag | Description |
|---|---|
| `--setup` | Clone/install/start a local Juice Shop before running solvers |
| `--base-url URL` | Target instance (default `http://localhost:3000`) |
| `--category NAME` | Limit the run to one category; repeat the flag for several |

The process exits `1` if any attempted challenge is left unsolved, so
`python main.py` is CI-friendly.

### Sample output

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

## How it works

```
┌──────────────┐   register()   ┌──────────────────┐
│ solvers/*.py │ ─────────────► │  solver registry  │
└──────────────┘                └────────┬──────────┘
                                          │ all_solvers()
                                          ▼
┌──────────────┐   HTTP/WS      ┌──────────────────┐   /api/Challenges/   ┌───────────────┐
│ JuiceShop    │ ◄───────────── │  core/runner.py   │ ───────────────────► │  live Juice   │
│ Client       │ ─────────────► │     run_all()      │ ◄─────────────────── │  Shop server  │
└──────────────┘   solve(ctx)   └────────┬──────────┘   solved: true/false  └───────────────┘
                                          ▼
                                  ┌──────────────────┐
                                  │   report.py       │
                                  │  category summary  │
                                  └──────────────────┘
```

**Every solver is a plain function**, registered with a decorator:

```python
@register("loginAdminChallenge", "Injection", 2)
def solve_login_admin(ctx: SolverContext) -> None:
    ctx.client.login("admin@juice-sh.op'--", "irrelevant")
```

`core/runner.run_all()` gives each solver a **fresh `JuiceShopClient`** (its own
cookie jar and auth token — no state leaks between challenges), calls it,
catches whatever it throws, and then — regardless of whether the solver itself
raised — **re-queries Juice Shop's own `/api/Challenges/` endpoint** to see if
the flag actually flipped. That live re-check, not the solver's return value or
lack of an exception, is the only thing that counts as "solved." A solver that
returns cleanly but didn't actually trip the server-side check is reported as
failed; a solver that throws an exception *after* the server already recorded
the solve is still reported as solved. This is the one architectural rule the
whole project holds to strictly, because Juice Shop occasionally flips a
challenge's flag from an async continuation that lands a beat after the HTTP
response you already received — `run_all` polls briefly (up to five times,
300ms apart) to absorb that race rather than reporting a false failure.

## Project layout

```
main.py                     CLI entrypoint — wires every solver module, runs, reports
setup.py                    clone/install/start Juice Shop for you
report.py                   category-grouped console report

core/
  client.py                 JuiceShopClient — thin requests.Session wrapper (login, register, verbs)
  runner.py                 run_all() — the live-verification loop described above
  challenge_api.py          reads the real /api/Challenges/ scoreboard

solvers/
  base.py                   the @register decorator + solver registry
  injection.py               11 solvers — SQLi, NoSQLi, SSTI
  xss.py                     9 solvers  — reflected/persisted/DOM XSS, WebSocket-triggered
  broken_auth.py             9 solvers  — weak passwords, 2FA secret leak, reset-password answers
  sensitive_data.py         16 solvers  — IDOR, JWT/coupon leaks, geo-stalking metadata
  broken_access_control.py  11 solvers  — CSRF, SSRF, basket/review tampering
  improper_input_validation.py 11 solvers
  vulnerable_components.py   9 solvers  — zip-slip file write, unsigned/forged JWT
  cryptographic_issues.py    5 solvers  — Z85 coupon forgery, Hashids continue-code
  security_misconfiguration.py 4 solvers
  observability_failures.py  4 solvers
  miscellaneous.py           5 solvers
  broken_anti_automation.py  4 solvers  — CAPTCHA bypass, a real TOCTOU race
  security_through_obscurity.py 3 solvers
  insecure_deserialization.py 3 solvers — sandboxed-JS RCE/DoS timing pair, YAML bomb
  unvalidated_redirects.py   2 solvers  — allowlist substring-vs-prefix bypass
  xxe.py                     2 solvers  — external entity file read, entity-expansion DoS

tests/
  test_framework.py          smoke tests for the framework itself
  test_<category>_live.py    one live-verification suite per category, no mocking, ever

docs/superpowers/
  specs/                     original scope/design document
  plans/                     the 5 phase-by-phase implementation plans this project was built from
```

## Writing a new solver

Every solver follows the same three-line shape:

```python
# solvers/my_category.py
from solvers.base import SolverContext, register

@register("someChallengeKey", "Category Name", difficulty=3)
def solve_something(ctx: SolverContext) -> None:
    ctx.client.post("/some/endpoint", json={"payload": "..."})
```

- `ctx.client` is a `JuiceShopClient` — `.get/.post/.put/.patch(path, **kwargs)`
  wrap `requests` directly, plus `.register(email, password)` and
  `.login(email, password)` helpers that manage the auth cookie/header for you.
- You never call the scoreboard yourself — `run_all()` does that after your
  function returns (or raises).
- Register the module's import in `main.py` (`try: import solvers.my_category`)
  so it gets picked up.
- Add a `tests/test_my_category_live.py` following the existing pattern —
  live HTTP against a real instance, asserting every key in your category
  shows `solved: true`.

## Testing philosophy

**No mocking, anywhere, ever.** Every test in `tests/` runs the real solvers
against a real running Juice Shop instance and asserts against the real
scoreboard. This is deliberate: a mocked test can pass while the actual
exploit is broken, which for a security tool is worse than no test at all.

```bash
pytest tests/ -v
```

Every `test_*_live.py` skips cleanly (not fails) when no instance is
reachable at `http://localhost:3000`, so the suite is safe to run without
Juice Shop up — it just reports 0 collected assertions for the live files.

## Notable exploit techniques

A few solvers that are more than a one-line payload:

- **[`vulnerable_components.py`](solvers/vulnerable_components.py) — zip-slip arbitrary file write.**
  A crafted `.zip` upload with entry names like `../../ftp/legal.md` escapes
  the intended `uploads/complaints/` directory. The same technique overwrites
  the promo video's subtitle track with an XSS payload, solving a second,
  unrelated *XSS* challenge as a side effect.
- **[`vulnerable_components.py`](solvers/vulnerable_components.py) — RS256→HS256 JWT key confusion.**
  Fetches the server's own RSA **public** key from its public endpoint, then
  signs a forged token with **HS256**, using the public key's raw bytes as the
  HMAC secret — a classic algorithm-confusion attack against JWT libraries that
  don't pin the expected algorithm. (Note: modern PyJWT actively blocks this at
  the library level as a defense-in-depth measure, so this solver hand-rolls
  the HMAC construction with the standard library instead of `pyjwt.encode()`.)
- **[`cryptographic_issues.py`](solvers/cryptographic_issues.py) — Z85 coupon forgery.**
  Juice Shop encodes discount coupons with ZeroMQ's Z85 (RFC 32) scheme. This
  repo hand-ports the exact ~15-line encoder from the real npm package's
  source (verified byte-for-byte against the registry, not guessed) rather
  than trust an unrelated same-named PyPI package.
- **[`cryptographic_issues.py`](solvers/cryptographic_issues.py) — Hashids continue-code forgery.**
  Reproduces Juice Shop's save-game "continue code" using the same
  salt/alphabet/min-length as the server, deterministically, with no need to
  ever have played the game.
- **[`broken_anti_automation.py`](solvers/broken_anti_automation.py) — a genuine race condition.**
  Fires eight concurrent "like this review" requests through
  `concurrent.futures.ThreadPoolExecutor` to win a real TOCTOU window: the
  server checks "have you already liked this?" before an artificial 150ms
  delay and only records the like *after* it — enough concurrent requests slip
  through the check before any of them commit.
- **[`insecure_deserialization.py`](solvers/insecure_deserialization.py) — a matched DoS/RCE timing pair.**
  Juice Shop evaluates untrusted JS in a sandboxed interpreter with two
  independent limits: the interpreter's own 1,000,000-iteration loop guard,
  and the host VM's 2-second wall-clock timeout. One solver uses a
  featherweight `while(true){}` to trip the interpreter's own counter first;
  the other nests a heavy loop inside so the *VM* timeout wins the race
  instead — two opposite outcomes from the same vulnerable endpoint, on
  purpose.
- **[`unvalidated_redirects.py`](solvers/unvalidated_redirects.py) — allowlist substring vs. prefix bypass.**
  The server's redirect allowlist check uses `.includes()` (substring
  anywhere) while its "was this an intended redirect" check uses
  `.startsWith()` (prefix only) — a URL that *contains* an allowed URL without
  *starting with* it satisfies the first check and fails the second
  simultaneously.

## Deferred challenges

107 of Juice Shop's 110 in-scope challenges are solved automatically. Four are
permanently out of reach for this tool, each for the same reason: they require
a real external service this environment doesn't have access to, or an
un-patched dependency behavior this environment's exact library version
doesn't exhibit. None are solvable by writing a different payload.

| Challenge | Category | Why it's excluded |
|---|---|---|
| `chatbotPromptInjectionChallenge`, `chatbotGreedyInjectionChallenge`, `systemPromptExtractionChallenge` | Injection | Require a real configured LLM behind Juice Shop's in-app chatbot |
| `aiDebuggingChallenge` | Broken Access Control | Requires the chatbot to invoke a real LLM tool call |
| `nftMintChallenge` | Improper Input Validation | Requires a funded Ethereum Sepolia testnet wallet + a paid Alchemy API key |
| `web3WalletChallenge` | Miscellaneous | Same on-chain/Alchemy dependency as above |
| `xxeDosChallenge` | XXE | A classic "billion laughs" entity-expansion bomb is rejected outright by libxml2's built-in `xmlCtxtSetMaxAmplification` entity-ratio guard, combined with Juice Shop's 200KB upload cap, on the libxml2-wasm version this checkout pins — the payload that would trigger the intended timeout never gets big enough to run long before being rejected in milliseconds. Verified across six independently-tuned payload variants; the solver is still registered and attempted, and is reported honestly as unsolved rather than removed. |

`xxeDosChallenge`'s solver stays in `solvers/xxe.py` on purpose — a genuine,
documented attempt that fails is more useful than pretending the challenge
doesn't exist.

## Design docs

This project was built phase-by-phase, each with a written implementation
plan reviewed against the real Juice Shop source before a line of solver code
was written:

- [`docs/superpowers/specs/2026-08-09-juice-shop-automator-design.md`](docs/superpowers/specs/2026-08-09-juice-shop-automator-design.md) — original scope and architecture
- [`docs/superpowers/plans/`](docs/superpowers/plans/) — five phase plans, one per delivery, each listing the exact source files consulted and the reasoning behind every non-obvious payload

## Responsible use

This project targets **OWASP Juice Shop**, an application built and
maintained by OWASP specifically to be attacked for security training. Running
these solvers against your own local Juice Shop instance is exactly what the
project exists for.

**Do not point `--base-url` at any instance you don't own or don't have
explicit authorization to test.** Nothing in this repository is intended for,
or should be used against, a third party's infrastructure.
