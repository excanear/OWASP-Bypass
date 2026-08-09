# OWASP Juice Shop Challenge Automator — Design

Date: 2026-08-09
Status: Approved

## Purpose

A Python tool that automatically solves the OWASP Juice Shop's built-in challenges
(SQLi, XSS, broken auth, IDOR, coding challenges, etc.) against a local instance,
for personal security-training / CTF practice. Not intended for use against any
instance the user does not own or have explicit authorization to test.

## Scope

- **Target: all 113 challenges** listed in the project's official
  `data/static/challenges.yml` (fetched from `juice-shop/juice-shop` master branch
  on 2026-08-09). This is the authoritative source of truth for challenge keys,
  categories, and difficulty — not a hardcoded guess.
- The instance must run via `npm start` (Node.js directly), **not Docker** — 17 of
  the 113 challenges declare `disabledEnv: [Docker, Heroku]` and are unreachable
  under Docker.
- Category breakdown (from the official list):

  | Category | Count |
  |---|---|
  | Sensitive Data Exposure | 16 |
  | Injection | 14 |
  | Improper Input Validation | 12 |
  | Broken Access Control | 12 |
  | XSS | 9 |
  | Broken Authentication | 9 |
  | Vulnerable Components | 8 |
  | Miscellaneous | 6 |
  | Cryptographic Issues | 5 |
  | Observability Failures | 4 |
  | Broken Anti Automation | 4 |
  | Security Misconfiguration | 4 |
  | Security through Obscurity | 3 |
  | Insecure Deserialization | 3 |
  | Unvalidated Redirects | 2 |
  | XXE | 2 |
  | **Total** | **113** |

- 13 of the 113 challenges are also tagged `tutorial:` in the source data — these
  are **not a separate category**, they're a subset already counted within their
  own category (e.g. "Login Admin" is Injection, "Admin Section" is Broken Access
  Control). Besides being solved as a normal exploit, each also has a "Find it /
  Fix it" coding-challenge UI variant, which the relevant category's solver will
  additionally complete via a static answer map — this is a bonus step on those
  13 solvers, not extra items added to the 113 total.
- Delivered incrementally within this engagement, category group by category
  group, each group validated against a live running instance via the score-board
  API before moving to the next.

## Non-goals

- No support for attacking a remote/third-party instance without explicit
  authorization (this is a local personal-training tool).
- No AI-based or generative solving of coding challenges — answers are a static
  lookup table maintained alongside the solver code.

## Architecture

```
juice-shop-automator/
├── main.py                     # CLI entrypoint: --setup, --all, --category X, --list, --report
├── setup.py                    # verifies Node.js, clones/installs juice-shop, starts it, waits for readiness
├── core/
│   ├── client.py                # requests.Session wrapper: login, JWT handling, base_url, retries
│   ├── browser.py                # Playwright wrapper: authenticated browser context (reuses client's JWT/cookies)
│   ├── challenge_api.py          # GET /api/Challenges — source of truth for solved:true/false per key
│   └── runner.py                  # discovers registered solvers, executes them, timeout/retry, structured logging
├── solvers/
│   ├── base.py                    # Solver base class: key, category, difficulty, run(ctx) -> bool
│   ├── injection.py
│   ├── xss.py
│   ├── broken_auth.py
│   ├── sensitive_data.py
│   ├── broken_access_control.py
│   ├── improper_input_validation.py
│   ├── vulnerable_components.py
│   ├── miscellaneous.py
│   ├── cryptographic_issues.py
│   ├── observability_failures.py
│   ├── broken_anti_automation.py
│   ├── security_misconfiguration.py
│   ├── security_through_obscurity.py
│   ├── insecure_deserialization.py
│   ├── unvalidated_redirects.py
│   └── xxe.py
├── coding_challenges.py            # shared find-it/fix-it answer map + submission helper,
│                                    # used by the 13 solvers whose key is tutorial-tagged
├── data/
│   └── challenges.yml             # snapshot of the official challenge list (key/category/difficulty source)
├── report.py                      # final table per category: solved / failed / skipped (with reason)
└── requirements.txt                # requests, playwright, pyyaml, pyjwt
```

### Data flow

1. `main.py --setup` runs `setup.py`: checks Node.js is installed, installs Juice
   Shop dependencies if needed, starts `npm start` in the background, polls
   `/rest/admin/application-version` until the app responds.
2. `runner.py` loads all registered `Solver` subclasses (one per challenge key),
   grouped by category, and executes each — using `core.client` for pure
   HTTP/API-driven challenges, `core.browser` (Playwright) for challenges that
   require real DOM/XSS execution.
3. After each solver runs, `runner.py` re-queries `challenge_api.py`
   (`/api/Challenges`) to confirm `solved: true` for that key — this is the only
   trusted success signal, not the solver's own return value.
4. `report.py` prints a final table: ✅ solved / ❌ failed / ⏭️ skipped (with a
   human-readable reason, e.g. "requires manual step: X").

### Error handling

- Each solver runs in isolation — an exception in one does not stop the others
  (caught and logged by `runner.py`).
- Per-solver timeout (default 15s for HTTP, 30s for browser-driven).
- Structured log line per challenge key: `key, category, outcome, duration, error?`.

### Testing / validation

- No mocking — solvers are validated by running them against a real local Juice
  Shop instance and checking the live score-board. This is the only meaningful
  test for exploit code against a real vulnerable app.
- `main.py --report` can be re-run standalone at any time to print current
  solved/unsolved status without re-running solvers.

## Delivery plan (incremental, this engagement)

1. Framework (setup, core/, base.py, runner, report) + **Injection + XSS + Broken
   Authentication** (32 challenges)
2. **Sensitive Data Exposure + Broken Access Control** (28 challenges)
3. **Improper Input Validation + Vulnerable Components** (20 challenges)
4. **Cryptographic Issues + Security Misconfiguration + Observability Failures +
   Miscellaneous** (19 challenges)
5. Remaining categories: **Broken Anti Automation, Security through Obscurity,
   Insecure Deserialization, Unvalidated Redirects, XXE** (14 challenges)

32 + 28 + 20 + 19 + 14 = 113. The 13 tutorial-tagged Find-it/Fix-it steps are
folded into whichever phase already covers their category — they add work to
existing solvers, not new phases or new counts.

Each phase is validated live before moving to the next.
